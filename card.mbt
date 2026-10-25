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

fn all_digits(text : String, start : Int, end : Int) -> Bool {
  if start < 0 || end > text.length() || start >= end {
    return false
  }
  for i in start..<end {
    let c = text[i].to_int()
    if c < 48 || c > 57 {
      return false
    }
  }
  true
}

fn digits_value(text : String, start : Int, end : Int) -> Int {
  let mut value = 0
  for i in start..<end {
    value = value * 10 + (text[i].to_int() - 48)
  }
  value
}

pub fn validate_pan(pan : String) -> Array[String] {
  let issues : Array[String] = Array::new()
  if pan.length() < 12 || pan.length() > 19 {
    issues.push("PAN length must be 12-19 digits")
  } else if !all_digits(pan, 0, pan.length()) {
    issues.push("PAN must contain only digits")
  } else if !luhn_valid(pan) {
    issues.push("PAN fails the Luhn check")
  }
  issues
}

pub fn validate_expiry(yymmdd : String) -> Array[String] {
  let issues : Array[String] = Array::new()
  if yymmdd.length() != 6 || !all_digits(yymmdd, 0, 6) {
    issues.push("expiry must be six digits (YYMMDD)")
  } else {
    let month = digits_value(yymmdd, 2, 4)
    let day = digits_value(yymmdd, 4, 6)
    if month < 1 || month > 12 {
      issues.push("expiry month must be 01-12")
    }
    if day < 1 || day > 31 {
      issues.push("expiry day must be 01-31")
    }
  }
  issues
}

pub fn validate_service_code(code : String) -> Array[String] {
  let issues : Array[String] = Array::new()
  if code.length() != 3 || !all_digits(code, 0, 3) {
    issues.push("service code must be three digits")
  }
  issues
}

pub fn service_code_text(code : String) -> String {
  if code.length() != 3 || !all_digits(code, 0, 3) {
    return "invalid service code"
  }
  let first = code[0].to_int() - 48
  let second = code[1].to_int() - 48
  let third = code[2].to_int() - 48
  let interchange = if first == 1 {
    "international"
  } else if first == 2 {
    "interbank"
  } else if first == 5 {
    "private"
  } else if first == 6 {
    "merchant"
  } else if first == 7 {
    "fuel"
  } else {
    "unknown"
  }
  let authorization = if second == 0 {
    "no restriction"
  } else if second == 2 {
    "normal"
  } else if second == 4 {
    "positive online"
  } else {
    "unknown"
  }
  let security = if third == 0 {
    "none"
  } else if third == 2 {
    "PIN"
  } else if third == 5 {
    "PIN if supported"
  } else {
    "unknown"
  }
  "interchange=" + interchange + ", authorization=" + authorization +
  ", security=" + security
}
