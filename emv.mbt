// EMV command builders and response templates.

pub fn select_ppse() -> Apdu {
  Apdu::new(0x00, 0xa4, 0x04, 0x00, data=ascii_bytes("2PAY.SYS.DDF01"), le=0)
}

pub fn select_aid(aid : Array[Int]) -> Apdu {
  Apdu::new(0x00, 0xa4, 0x04, 0x00, data=aid, le=0)
}

pub fn gpo(pdol_data : Array[Int]) -> Apdu {
  let data : Array[Int] = [0x83]
  data.push(pdol_data.length() & 0xff)
  for b in pdol_data {
    data.push(b)
  }
  Apdu::new(0x80, 0xa8, 0x00, 0x00, data=data, le=0)
}

pub fn read_record(record : Int, sfi : Int) -> Apdu {
  Apdu::new(0x00, 0xb2, record, ((sfi & 0x1f) << 3) | 4, le=0)
}

pub fn generate_ac(p1 : Int, cdol_data : Array[Int]) -> Apdu {
  Apdu::new(0x80, 0xae, p1, 0x00, data=cdol_data, le=0)
}

pub fn verify_pin(pin_block : Array[Int]) -> Apdu {
  Apdu::new(0x00, 0x20, 0x00, 0x80, data=pin_block)
}

pub fn get_data(tag : Int) -> Apdu {
  Apdu::new(0x80, 0xca, (tag >> 8) & 0xff, tag & 0xff, le=0)
}

pub(all) struct GpoInfo {
  aip : Array[Int]
  afl : Array[Int]
}

pub fn parse_gpo_response(bytes : Array[Int]) -> GpoInfo? raise TlvError {
  let items = parse_tlv(bytes)
  match find_tag(items, 0x77) {
    Some(template) => {
      let aip = match find_tag(template.children, 0x82) {
        Some(t) => t.value
        None => []
      }
      let afl = match find_tag(template.children, 0x94) {
        Some(t) => t.value
        None => []
      }
      Some({ aip, afl })
    }
    None =>
      match find_tag(items, 0x80) {
        Some(t) =>
          if t.value.length() >= 2 {
            let aip : Array[Int] = [t.value[0], t.value[1]]
            let afl : Array[Int] = Array::new()
            for i in 2..<t.value.length() {
              afl.push(t.value[i])
            }
            Some({ aip, afl })
          } else {
            None
          }
        None => None
      }
  }
}

pub fn parse_record(bytes : Array[Int]) -> Array[Tlv]? raise TlvError {
  let items = parse_tlv(bytes)
  match find_tag(items, 0x70) {
    Some(template) => Some(template.children)
    None => Some(items)
  }
}
