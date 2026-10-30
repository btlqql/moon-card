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

pub(all) suberror DolError { InvalidDol }

// EMV DOL lengths are one-byte field widths, not BER value lengths.
pub fn parse_dol(bytes : Array[Int]) -> Array[(Int, Int)] raise DolError {
  let out : Array[(Int, Int)] = []
  let mut i = 0
  while i < bytes.length() {
    let first = bytes[i]
    if first <= 0 || first >= 255 { raise InvalidDol }
    let mut tag = first
    i = i + 1
    if (first & 31) == 31 {
      let mut count = 1
      while true {
        if i >= bytes.length() || count >= 4 { raise InvalidDol }
        let b = bytes[i]
        if count == 1 && (b & 127) == 0 { raise InvalidDol }
        tag = (tag << 8) | b
        i = i + 1
        count = count + 1
        if (b & 128) == 0 { break }
      }
    }
    if i >= bytes.length() { raise InvalidDol }
    let length = bytes[i]
    if length < 0 || length > 255 { raise InvalidDol }
    out.push((tag,length))
    i = i + 1
  }
  out
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

pub fn analyze_session(raw_report : TxReport) -> SessionReport {
  let report = resolve_apdu_procedures(raw_report)
  let issues : Array[SessionIssue] = Array::new()
  let candidates : Array[String] = Array::new()
  let records : Array[(Int, Int)] = Array::new()
  let mut selected_aid : String? = None
  let mut aip : String? = None
  let mut afl : Array[AflEntry] = Array::new()
  let mut gpo_seen = false
  let mut cdol_length = 0
  let mut pdol_length = 0
  let mut completed = false
  let mut pan_seen = false
  let mut expiry_seen = false
  for _ in report.errors {
    issue(issues, 0, "LOG_PARSE_ERROR", "fail", "log contains an unparseable line or APDU")
  }
  let mut i = 0
  while i < report.steps.length() {
    let step = report.steps[i]
    match step.apdu {
      None => {
        issue(issues, i + 1, "UNPAIRED_STEP", "fail", "response or malformed command without a paired command")
        i = i + 1
      }
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
              i = i + 2
              continue
            }
            if command.ins == 0xa4 && command.p1 == 0x04 {
              // An application selection starts a fresh transaction context.
              selected_aid = None
              aip = None
              afl = []
              records.clear()
              gpo_seen = false
              cdol_length = 0
              pdol_length = 0
              completed = false
              pan_seen = false
              expiry_seen = false
              if is_ppse_select(command) {
                candidates.clear()
                for value in collect_tag_values(response_tlv, 0x4f) {
                  candidates.push(hex_compact(value))
                }
                if candidates.length() == 0 {
                  issue(issues, step_no, "PPSE_NO_CANDIDATES", "review", "PPSE response has no 4F ADF names")
                }
              } else {
                let requested = hex_compact(command.data)
                let returned = match find_tag(response_tlv, 0x84) {
                  Some(tag) => hex_compact(tag.value)
                  None => {
                    issue(issues, step_no, "MISSING_DF_NAME", "fail", "SELECT response has no 84 DF name")
                    ""
                  }
                }
                selected_aid = Some(if returned.length() > 0 { returned } else { requested })
                match find_tag(response_tlv,0x9f38) {
                  Some(dol) => try {
                    pdol_length = cdol_total_length(parse_dol(dol.value))
                  } catch { _ => issue(issues,step_no,"INVALID_PDOL","fail","SELECT contains a malformed PDOL") }
                  None => ()
                }
                if requested.length() == 0 || returned.length() > 0 && !returned.has_prefix(requested) {
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
                    if candidate == returned {
                      found = true
                    }
                  }
                  if !found {
                    issue(issues, step_no, "AID_NOT_IN_CANDIDATES", "review", "selected AID is not in PPSE candidates")
                  }
                }
              }
            } else if command.ins == 0xa8 {
              let pdol = try { find_tag(parse_tlv(command.data),0x83) } catch { _ => None }
              match pdol {
                Some(tag) => if tag.value.length() != pdol_length {
                  issue(issues,step_no,"PDOL_LENGTH_MISMATCH","fail","GPO command does not match SELECT PDOL field lengths")
                }
                None => issue(issues,step_no,"GPO_COMMAND_TEMPLATE","fail","GPO command has no valid 83 PDOL template")
              }
              if selected_aid.is_none() {
                issue(issues, step_no, "GPO_BEFORE_SELECT", "fail", "GPO has no successful application selection")
              }
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
                pan_seen = pan_seen || pan
                expiry_seen = expiry_seen || find_tag(items, 0x5f24).is_some()
                match find_tag(items, 0x8c) {
                  Some(tag) => try { cdol_length = cdol_total_length(parse_dol(tag.value)) }
                    catch { _ => issue(issues,step_no,"INVALID_CDOL","fail","record contains a malformed CDOL1") }
                  None => ()
                }
              }
            } else if command.ins == 0xae {
              completed = true
              for entry in afl {
                for number in entry.first_record..<(entry.last_record + 1) {
                  if !records.contains((entry.sfi, number)) {
                    issue(issues, step_no, "AFL_RECORD_MISSING", "fail", "GENERATE AC before all AFL records were read")
                  }
                }
              }
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
        i = i + (if response.is_some() { 2 } else { 1 })
      }
    }
  }
  if !completed {
    issue(issues, report.steps.length(), "INCOMPLETE_TRANSACTION", "review", "capture has no successful GENERATE AC; no complete transaction verdict is available")
  }
  if records.length() > 0 && !pan_seen {
    issue(issues, report.steps.length(), "MISSING_PAN", "fail", "none of the application records has 5A or 57")
  }
  if records.length() > 0 && !expiry_seen {
    issue(issues, report.steps.length(), "MISSING_EXPIRY", "review", "no 5F24 expiry was found across application records")
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
