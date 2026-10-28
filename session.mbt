// Stateful APDU/EMV transaction analysis.
// This layer is intentionally above TLV/APDU codecs: it checks application
// selection, command order, AFL-driven record access, mandatory data objects,
// CDOL length and terminal-visible status words.

pub(all) struct SessionIssue {
  step : Int
  code : String
  severity : String
  detail : String
}

pub(all) struct SessionReport {
  verdict : String
  candidates : Array[String]
  selected_aid : String?
  aip : String?
  afl : Array[AflEntry]
  records : Array[(Int, Int)]
  issues : Array[SessionIssue]
  steps : Int
}

fn hex_compact(bytes : Array[Int]) -> String {
  let out = StringBuilder()
  for b in bytes {
    out.write_char(hex_nibble_char(b >> 4))
    out.write_char(hex_nibble_char(b))
  }
  out.to_string()
}

fn issue(
  issues : Array[SessionIssue],
  step : Int,
  code : String,
  severity : String,
  detail : String,
) -> Unit {
  issues.push({ step, code, severity, detail })
}

pub fn collect_tag_values(items : Array[Tlv], tag : Int) -> Array[Array[Int]] {
  let out : Array[Array[Int]] = Array::new()
  for item in items {
    if item.tag == tag {
      out.push(item.value)
    }
    for child in collect_tag_values(item.children, tag) {
      out.push(child)
    }
  }
  out
}

pub fn parse_cdol(value : Array[Int]) -> Array[(Int, Int)] {
  let out : Array[(Int, Int)] = Array::new()
  let mut i = 0
  while i < value.length() {
    let first = value[i]
    i = i + 1
    let tag = if (first & 0x1f) == 0x1f && i < value.length() {
      let second = value[i]
      i = i + 1
      (first << 8) | second
    } else {
      first
    }
    if i >= value.length() {
      break
    }
    let len = value[i]
    i = i + 1
    out.push((tag, len))
  }
  out
}

pub fn cdol_total_length(fields : Array[(Int, Int)]) -> Int {
  let mut total = 0
  for field in fields {
    total = total + field.1
  }
  total
}

fn is_ppse_select(command : Apdu) -> Bool {
  command.ins == 0xa4 && command.p1 == 0x04 &&
  ascii_of(command.data).contains("2PAY")
}

fn record_items(response : ApduResponse) -> Array[Tlv] raise TlvError {
  let items = parse_tlv(response.data)
  match find_tag(items, 0x70) {
    Some(template) => template.children
    None => items
  }
}

pub fn analyze_session(report : TxReport) -> SessionReport {
  let issues : Array[SessionIssue] = Array::new()
  let candidates : Array[String] = Array::new()
  let records : Array[(Int, Int)] = Array::new()
  let mut selected_aid : String? = None
  let mut aip : String? = None
  let mut afl : Array[AflEntry] = Array::new()
  let mut gpo_seen = false
  let mut cdol_length = 0
  let mut i = 0
  while i < report.steps.length() {
    let step = report.steps[i]
    match step.apdu {
      None => i = i + 1
      Some(command) => {
        let step_no = i + 1
        let response = if i + 1 < report.steps.length() {
          report.steps[i + 1].response
        } else {
          None
        }
        let response_tlv = if i + 1 < report.steps.length() {
          report.steps[i + 1].tlv
        } else {
          []
        }
        match response {
          None => issue(issues, step_no, "MISSING_RESPONSE", "fail", "command has no following response")
          Some(resp) => {
            if resp.sw != 0x9000 {
              issue(
                issues,
                step_no,
                "STATUS_ERROR",
                "fail",
                "SW=" + hex_int(resp.sw, 4) + " " + status_description(resp.sw),
              )
            }
            if command.ins == 0xa4 && command.p1 == 0x04 {
              if is_ppse_select(command) {
                for value in collect_tag_values(response_tlv, 0x4f) {
                  candidates.push(hex_compact(value))
                }
                if candidates.length() == 0 {
                  issue(issues, step_no, "PPSE_NO_CANDIDATES", "review", "PPSE response has no 4F ADF names")
                }
              } else {
                let requested = hex_compact(command.data)
                selected_aid = Some(requested)
                let returned = match find_tag(response_tlv, 0x84) {
                  Some(tag) => hex_compact(tag.value)
                  None => {
                    issue(issues, step_no, "MISSING_DF_NAME", "fail", "SELECT response has no 84 DF name")
                    ""
                  }
                }
                if returned.length() > 0 && returned != requested {
                  issue(
                    issues,
                    step_no,
                    "AID_MISMATCH",
                    "fail",
                    "requested " + requested + " but card returned " + returned,
                  )
                }
                if candidates.length() > 0 {
                  let mut found = false
                  for candidate in candidates {
                    if candidate == requested {
                      found = true
                    }
                  }
                  if !found {
                    issue(issues, step_no, "AID_NOT_IN_CANDIDATES", "review", "selected AID is not in PPSE candidates")
                  }
                }
              }
            } else if command.ins == 0xa8 {
              gpo_seen = true
              let gpo = try {
                parse_gpo_response(resp.data)
              } catch {
                _ => None
              }
              match gpo {
                Some(info) => {
                  aip = Some(hex_compact(info.aip))
                  afl = parse_afl(info.afl)
                  if afl.length() == 0 {
                    issue(issues, step_no, "GPO_NO_AFL", "fail", "GPO response has an empty AFL")
                  }
                }
                None => issue(issues, step_no, "GPO_TEMPLATE", "fail", "GPO response is not 77/80")
              }
            } else if command.ins == 0xb2 {
              let sfi = (command.p2 >> 3) & 0x1f
              let record = command.p1
              let mut in_afl = false
              for entry in afl {
                if entry.sfi == sfi && record >= entry.first_record && record <= entry.last_record {
                  in_afl = true
                }
              }
              if !in_afl {
                issue(
                  issues,
                  step_no,
                  "RECORD_NOT_IN_AFL",
                  "fail",
                  "READ RECORD sfi=" + sfi.to_string() + " record=" + record.to_string() + " is outside AFL",
                )
              }
              records.push((sfi, record))
              let items = try {
                record_items(resp)
              } catch {
                _ => []
              }
              if items.length() == 0 {
                issue(issues, step_no, "RECORD_TEMPLATE", "fail", "READ RECORD response has no usable TLV")
              } else {
                let pan = find_tag(items, 0x5a).is_some() || find_tag(items, 0x57).is_some()
                if !pan {
                  issue(issues, step_no, "MISSING_PAN", "fail", "record has neither 5A nor 57")
                }
                if find_tag(items, 0x5f24).is_none() {
                  issue(issues, step_no, "MISSING_EXPIRY", "review", "record has no 5F24 expiry")
                }
                match find_tag(items, 0x8c) {
                  Some(tag) => cdol_length = cdol_total_length(parse_cdol(tag.value))
                  None => ()
                }
              }
            } else if command.ins == 0xae {
              if !gpo_seen {
                issue(issues, step_no, "GENERATE_AC_BEFORE_GPO", "fail", "GENERATE AC before GPO")
              }
              if records.length() == 0 {
                issue(issues, step_no, "GENERATE_AC_BEFORE_RECORD", "fail", "GENERATE AC before any READ RECORD")
              }
              if cdol_length == 0 {
                issue(issues, step_no, "MISSING_CDOL", "review", "no 8C CDOL1 was seen before GENERATE AC")
              } else if command.data.length() != cdol_length {
                issue(
                  issues,
                  step_no,
                  "CDOL_LENGTH_MISMATCH",
                  "fail",
                  "CDOL1 expects " + cdol_length.to_string() + " bytes but command has " + command.data.length().to_string(),
                )
              }
            }
          }
        }
        i = i + 2
      }
    }
  }
  let mut fail = false
  let mut review = false
  for item in issues {
    if item.severity == "fail" {
      fail = true
    } else {
      review = true
    }
  }
  {
    verdict: if fail { "fail" } else if review { "review" } else { "pass" },
    candidates,
    selected_aid,
    aip,
    afl,
    records,
    issues,
    steps: report.steps.length(),
  }
}

pub fn render_session(report : SessionReport) -> String {
  let out = StringBuilder()
  out.write_string("verdict: " + report.verdict + "\n")
  out.write_string("steps: " + report.steps.to_string() + "\n")
  out.write_string("candidates: " + report.candidates.join(",") + "\n")
  match report.selected_aid {
    Some(aid) => out.write_string("selected AID: " + aid + "\n")
    None => out.write_string("selected AID: -\n")
  }
  match report.aip {
    Some(value) => out.write_string("AIP: " + value + "\n")
    None => ()
  }
  out.write_string("AFL: " + report.afl.length().to_string() + "\n")
  out.write_string("records read: " + report.records.length().to_string() + "\n")
  for item in report.issues {
    out.write_string(
      "issue step=" + item.step.to_string() + " " + item.severity + " " +
      item.code + ": " + item.detail + "\n",
    )
  }
  out.to_string()
}
