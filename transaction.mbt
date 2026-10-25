// APDU transaction log parsing and reporting.

pub(all) struct TxStep {
  direction : String
  bytes : Array[Int]
  apdu : Apdu?
  response : ApduResponse?
  tlv : Array[Tlv]
  note : String
}

pub(all) struct TxReport {
  steps : Array[TxStep]
  errors : Array[String]
  pan : String?
  expiry : String?
  cardholder : String?
  label : String?
}

fn describe_apdu_error(err : ApduError) -> String {
  match err {
    Truncated => "truncated APDU"
    BadLength => "bad APDU length"
    LeTooLarge(n) => "Le too large " + n.to_string()
    DataTooLarge(n) => "data too large " + n.to_string()
  }
}

pub fn parse_transaction_log(text : String) -> TxReport {
  let steps : Array[TxStep] = Array::new()
  let errors : Array[String] = Array::new()
  let mut pan : String? = None
  let mut expiry : String? = None
  let mut cardholder : String? = None
  let mut label : String? = None
  for raw_line in text.split("\n").to_array() {
    let line = raw_line.trim_space().to_string()
    if line.length() == 0 || line.has_prefix("#") {
      continue
    }
    let direction = if line.has_prefix(">>") {
      Some(">>")
    } else if line.has_prefix("C:") {
      Some(">>")
    } else if line.has_prefix("<<") {
      Some("<<")
    } else if line.has_prefix("R:") {
      Some("<<")
    } else {
      None
    }
    match direction {
      None => errors.push("unrecognized line: " + line)
      Some(dir) => {
        let body = line.substring(start=2)
        let bytes = match hex_decode(body.trim_space().to_string()) {
          Some(values) => values
          None => {
            errors.push("invalid hex in line: " + line)
            continue
          }
        }
        if dir == ">>" {
          let apdu = try {
            Some(parse_apdu(bytes))
          } catch {
            err => {
              errors.push(describe_apdu_error(err))
              None
            }
          }
          let note = match apdu {
            Some(command) => command_name(command)
            None => "unparseable command"
          }
          steps.push({
            direction: dir,
            bytes,
            apdu,
            response: None,
            tlv: [],
            note,
          })
        } else {
          let response = try {
            Some(parse_response(bytes))
          } catch {
            err => {
              errors.push(describe_apdu_error(err))
              None
            }
          }
          let tlv = match response {
            Some(resp) =>
              if resp.data.length() > 0 {
                try {
                  parse_tlv(resp.data)
                } catch {
                  _ => []
                }
              } else {
                []
              }
            None => []
          }
          let card = card_data_from_tlv(tlv)
          if pan is None {
            pan = card.pan
          }
          if expiry is None {
            expiry = card.expiry
          }
          if cardholder is None {
            cardholder = card.cardholder
          }
          if label is None {
            label = card.label
          }
          let note = match response {
            Some(resp) =>
              status_description(resp.sw) + " (" + hex_int(resp.sw, 4) + ")"
            None => "unparseable response"
          }
          steps.push({
            direction: dir,
            bytes,
            apdu: None,
            response,
            tlv,
            note,
          })
        }
      }
    }
  }
  { steps, errors, pan, expiry, cardholder, label }
}

pub fn render_transaction(report : TxReport) -> String {
  let out = StringBuilder()
  out.write_string(
    "steps: " + report.steps.length().to_string() + " errors: " +
    report.errors.length().to_string() + "\n",
  )
  for i in 0..<report.steps.length() {
    let step = report.steps[i]
    out.write_string(
      (i + 1).to_string() + " " + step.direction + " " + hex_encode(step.bytes) +
      "  " + step.note + "\n",
    )
    if step.tlv.length() > 0 {
      out.write_string("  tags:")
      for tag in collect_tags(step.tlv) {
        out.write_string(" " + tag_to_hex(tag) + "(" + tag_name(tag) + ")")
      }
      out.write_string("\n")
    }
  }
  match report.pan {
    Some(value) => {
      let luhn = if luhn_valid(value) { "luhn ok" } else { "luhn failed" }
      out.write_string("PAN: " + mask_pan(value) + " (" + luhn + ")\n")
    }
    None => ()
  }
  match report.expiry {
    Some(value) => out.write_string("expiry: " + format_expiry(value) + "\n")
    None => ()
  }
  match report.cardholder {
    Some(value) => out.write_string("cardholder: " + value + "\n")
    None => ()
  }
  match report.label {
    Some(value) => out.write_string("label: " + value + "\n")
    None => ()
  }
  for error in report.errors {
    out.write_string("error: " + error + "\n")
  }
  out.to_string()
}

fn json_escape(text : String) -> String {
  let out = StringBuilder()
  for i in 0..<text.length() {
    let c = text[i].to_int()
    if c == 34 {
      out.write_string("\\\"")
    } else if c == 92 {
      out.write_string("\\\\")
    } else if c == 10 {
      out.write_string("\\n")
    } else if c == 13 {
      out.write_string("\\r")
    } else if c == 9 {
      out.write_string("\\t")
    } else if c < 32 {
      out.write_string("\\u00")
      out.write_char(hex_nibble_char(c >> 4))
      out.write_char(hex_nibble_char(c))
    } else {
      out.write_char(Char::from_int(c))
    }
  }
  out.to_string()
}

fn json_string(text : String) -> String {
  "\"" + json_escape(text) + "\""
}

fn quoted_array(items : Array[String]) -> String {
  "[" + items.join(",") + "]"
}

fn step_json(index : Int, step : TxStep) -> String {
  let fields : Array[String] = [
    "\"index\":" + index.to_string(),
    "\"direction\":" + json_string(step.direction),
    "\"bytes\":" + json_string(hex_encode(step.bytes)),
    "\"note\":" + json_string(step.note),
  ]
  match step.apdu {
    Some(command) =>
      fields.push("\"command\":" + json_string(command_name(command)))
    None => ()
  }
  match step.response {
    Some(response) => {
      fields.push("\"sw\":" + json_string(hex_int(response.sw, 4)))
      fields.push("\"status\":" + json_string(status_description(response.sw)))
    }
    None => ()
  }
  if step.tlv.length() > 0 {
    let tags : Array[String] = Array::new()
    for tag in collect_tags(step.tlv) {
      tags.push(json_string(tag_to_hex(tag)))
    }
    fields.push("\"tags\":" + quoted_array(tags))
  }
  "{" + fields.join(",") + "}"
}

pub fn render_transaction_json(report : TxReport) -> String {
  let steps : Array[String] = Array::new()
  for i in 0..<report.steps.length() {
    steps.push(step_json(i + 1, report.steps[i]))
  }
  let errors : Array[String] = Array::new()
  for error in report.errors {
    errors.push(json_string(error))
  }
  let fields : Array[String] = [
    "\"steps\":" + report.steps.length().to_string(),
    "\"errors\":" + quoted_array(errors),
    "\"messages\":" + quoted_array(steps),
  ]
  match report.pan {
    Some(value) => {
      fields.push("\"pan\":" + json_string(mask_pan(value)))
      let luhn = if luhn_valid(value) { "true" } else { "false" }
      fields.push("\"luhn\":" + luhn)
    }
    None => ()
  }
  match report.expiry {
    Some(value) => fields.push("\"expiry\":" + json_string(format_expiry(value)))
    None => ()
  }
  match report.cardholder {
    Some(value) => fields.push("\"cardholder\":" + json_string(value))
    None => ()
  }
  match report.label {
    Some(value) => fields.push("\"label\":" + json_string(value))
    None => ()
  }
  "{" + fields.join(",") + "}"
}

pub fn render_transaction_csv(report : TxReport) -> String {
  let out = StringBuilder()
  out.write_string("index,direction,command,status,sw,bytes\n")
  for i in 0..<report.steps.length() {
    let step = report.steps[i]
    let command = match step.apdu {
      Some(apdu) => command_name(apdu)
      None => ""
    }
    let status = match step.response {
      Some(response) => status_description(response.sw)
      None => ""
    }
    let sw = match step.response {
      Some(response) => hex_int(response.sw, 4)
      None => ""
    }
    out.write_string(
      (i + 1).to_string() + "," + csv_field(step.direction) + "," +
      csv_field(command) + "," + csv_field(status) + "," + csv_field(sw) +
      "," + csv_field(hex_encode(step.bytes)) + "\n",
    )
  }
  out.to_string()
}

fn csv_field(text : String) -> String {
  let out = StringBuilder()
  out.write_char('"')
  for i in 0..<text.length() {
    let c = text[i].to_int()
    if c == 34 {
      out.write_string("\"\"")
    } else {
      out.write_char(Char::from_int(c))
    }
  }
  out.write_char('"')
  out.to_string()
}
