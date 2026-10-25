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
