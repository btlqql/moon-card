// Card data helpers: Luhn, compressed numeric (BCD), track 2, masking.

pub(all) struct Track2 {
  pan : String
  expiry : String
  service_code : String
}

pub(all) struct CardData {
  pan : String?
  expiry : String?
  cardholder : String?
  label : String?
}

pub fn luhn_valid(digits : String) -> Bool {
  let mut sum = 0
  let mut double = false
  let n = digits.length()
  if n == 0 {
    return false
  }
  for i in 0..<n {
    let idx = n - 1 - i
    let c = digits[idx].to_int()
    if c < 48 || c > 57 {
      return false
    }
    let mut d = c - 48
    if double {
      d = d * 2
      if d > 9 {
        d = d - 9
      }
    }
    sum = sum + d
    double = !double
  }
  sum % 10 == 0
}

pub fn bcd_to_string(bytes : Array[Int]) -> String? {
  let out = StringBuilder()
  for b in bytes {
    let high = (b >> 4) & 0xf
    let low = b & 0xf
    if high == 0xf {
      return Some(out.to_string())
    }
    if high > 9 {
      return None
    }
    out.write_char(Char::from_int(48 + high))
    if low == 0xf {
      return Some(out.to_string())
    }
    if low > 9 {
      return None
    }
    out.write_char(Char::from_int(48 + low))
  }
  Some(out.to_string())
}

pub fn pan_from_tlv(items : Array[Tlv]) -> String? {
  match find_tag(items, 0x5a) {
    Some(t) => bcd_to_string(t.value)
    None =>
      match find_tag(items, 0x57) {
        Some(t) =>
          match parse_track2(t.value) {
            Some(track) => Some(track.pan)
            None => None
          }
        None => None
      }
  }
}

pub fn expiry_from_tlv(items : Array[Tlv]) -> String? {
  match find_tag(items, 0x5f24) {
    Some(t) => bcd_to_string(t.value)
    None => None
  }
}

pub fn cardholder_from_tlv(items : Array[Tlv]) -> String? {
  match find_tag(items, 0x5f20) {
    Some(t) => Some(ascii_of(t.value))
    None => None
  }
}

pub fn label_from_tlv(items : Array[Tlv]) -> String? {
  match find_tag(items, 0x50) {
    Some(t) => Some(ascii_of(t.value))
    None => None
  }
}

pub fn card_data_from_tlv(items : Array[Tlv]) -> CardData {
  { pan: pan_from_tlv(items), expiry: expiry_from_tlv(items), cardholder: cardholder_from_tlv(items), label: label_from_tlv(items) }
}

pub fn parse_track2(value : Array[Int]) -> Track2? {
  let text = ascii_of(value)
  let mut sep = -1
  for i in 0..<text.length() {
    let c = text[i].to_int()
    if c == 68 || c == 100 || c == 61 {
      sep = i
      break
    }
  }
  if sep < 0 {
    return None
  }
  let pan = text.substring(start=0, end=sep)
  let rest = text.substring(start=sep + 1)
  if rest.length() < 7 {
    return None
  }
  Some({
    pan,
    expiry: rest.substring(start=0, end=4),
    service_code: rest.substring(start=4, end=7),
  })
}

pub fn mask_pan(pan : String) -> String {
  let n = pan.length()
  if n <= 10 {
    return pan
  }
  let out = StringBuilder()
  out.write_string(pan.substring(start=0, end=6))
  for _ in 0..<(n - 10) {
    out.write_char('*')
  }
  out.write_string(pan.substring(start=n - 4))
  out.to_string()
}

pub fn format_expiry(yymmdd : String) -> String {
  if yymmdd.length() < 4 {
    yymmdd
  } else {
    "20" + yymmdd.substring(start=0, end=2) + "-" +
    yymmdd.substring(start=2, end=4)
  }
}
