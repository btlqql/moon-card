// Collapse ISO 7816 procedure exchanges into a logical command/response pair.
// Malformed recovery sequences remain visible as errors, never silently pass.
pub fn resolve_apdu_procedures(raw : TxReport) -> TxReport {
  let steps : Array[TxStep] = []
  let errors = raw.errors.copy()
  let mut i = 0
  while i < raw.steps.length() {
    let original = raw.steps[i]
    match original.apdu {
      None => { steps.push(original); i = i + 1 }
      Some(command) => {
        let mut at = i + 1
        let data : Array[Int] = []
        let mut response : ApduResponse? = None
        let mut count = 0
        let mut current = command
        while at < raw.steps.length() {
          match raw.steps[at].response {
            None => break
            Some(resp) => {
              count = count + 1
              if count > 16 {
                errors.push("APDU recovery chain exceeds 16 exchanges")
                break
              }
              let sw1 = resp.sw >> 8
              let le = if (resp.sw & 255) == 0 { 256 } else { resp.sw & 255 }
              if sw1 == 0x61 || sw1 == 0x6c {
                if at + 2 >= raw.steps.length() {
                  errors.push("incomplete APDU recovery exchange")
                  response = Some(resp)
                  at = at + 1
                  break
                }
                match raw.steps[at + 1].apdu {
                  Some(next) => {
                    let valid = if sw1 == 0x61 {
                      next.cla == current.cla && next.ins == 0xc0 && next.p1 == 0 && next.p2 == 0 && next.data.length() == 0 && next.le == Some(le)
                    } else {
                      next.cla == current.cla && next.ins == current.ins && next.p1 == current.p1 && next.p2 == current.p2 && next.data == current.data && next.le == Some(le)
                    }
                    if !valid {
                      errors.push("APDU recovery command does not match procedure status")
                      response = Some(resp)
                      at = at + 1
                      break
                    }
                    if sw1 == 0x61 { for b in resp.data { data.push(b) } }
                    current = next
                    at = at + 2
                  }
                  None => {
                    errors.push("APDU recovery response has no next command")
                    at = at + 1
                    break
                  }
                }
              } else {
                for b in resp.data { data.push(b) }
                response = Some({ data, sw: resp.sw })
                at = at + 1
                break
              }
            }
          }
        }
        steps.push(original)
        match response {
          Some(resp) => {
            let tlv = try { parse_tlv(resp.data) } catch { _ => [] }
            steps.push({ direction: "<<", bytes: [], apdu: None, response: Some(resp), tlv, note: "logical APDU response" })
          }
          None => ()
        }
        i = if at > i + 1 { at } else { i + 1 }
      }
    }
  }
  { ..raw, steps, errors }
}
