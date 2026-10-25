// BER-TLV parsing and encoding for EMV data objects.
// This is a data-object codec, not an ASN.1 schema compiler.

pub(all) suberror TlvError {
  Truncated
  BadTag
  BadLength
  TooDeep
}

pub(all) struct Tlv {
  tag : Int
  constructed : Bool
  value : Array[Int]
  children : Array[Tlv]
}

fn slice(bytes : Array[Int], start : Int, end : Int) -> Array[Int] {
  let out : Array[Int] = Array::new()
  for i in start..<end {
    out.push(bytes[i])
  }
  out
}

fn tag_width(tag : Int) -> Int {
  if tag <= 0xff {
    1
  } else if tag <= 0xffff {
    2
  } else if tag <= 0xffffff {
    3
  } else {
    4
  }
}

pub fn tag_to_hex(tag : Int) -> String {
  let digits = "0123456789ABCDEF"
  let width = tag_width(tag) * 2
  let out = StringBuilder()
  for i in 0..<width {
    let shift = (width - 1 - i) * 4
    match digits.get_char((tag >> shift) & 0xf) {
      Some(c) => out.write_char(c)
      None => out.write_char('?')
    }
  }
  out.to_string()
}

fn parse_one(
  bytes : Array[Int],
  pos : Int,
  depth : Int,
) -> (Tlv, Int) raise TlvError {
  if depth > 16 {
    raise TooDeep
  }
  if pos >= bytes.length() {
    raise Truncated
  }
  let first = bytes[pos]
  let mut cursor = pos + 1
  let mut tag = first
  if (first & 0x1f) == 0x1f {
    let mut count = 0
    while true {
      if cursor >= bytes.length() {
        raise Truncated
      }
      let b = bytes[cursor]
      cursor = cursor + 1
      tag = (tag << 8) | b
      count = count + 1
      if (b & 0x80) == 0 {
        break
      }
      if count > 3 {
        raise BadTag
      }
    }
  }
  if cursor >= bytes.length() {
    raise Truncated
  }
  let length_byte = bytes[cursor]
  cursor = cursor + 1
  let mut len = 0
  if length_byte < 0x80 {
    len = length_byte
  } else {
    let n = length_byte & 0x7f
    if n == 0 || n > 4 {
      raise BadLength
    }
    for _ in 0..<n {
      if cursor >= bytes.length() {
        raise Truncated
      }
      len = (len << 8) | bytes[cursor]
      cursor = cursor + 1
    }
  }
  if cursor + len > bytes.length() {
    raise Truncated
  }
  let value = slice(bytes, cursor, cursor + len)
  let constructed = (first & 0x20) != 0
  let children : Array[Tlv] = Array::new()
  if constructed {
    let mut child_pos = 0
    while child_pos < value.length() {
      if value[child_pos] == 0 {
        child_pos = child_pos + 1
      } else {
        let (child, next) = parse_one(value, child_pos, depth + 1)
        children.push(child)
        child_pos = next
      }
    }
  }
  ({ tag, constructed, value, children }, cursor + len)
}

pub fn parse_tlv(bytes : Array[Int]) -> Array[Tlv] raise TlvError {
  let out : Array[Tlv] = Array::new()
  let mut pos = 0
  while pos < bytes.length() {
    if bytes[pos] == 0 {
      pos = pos + 1
    } else {
      let (item, next) = parse_one(bytes, pos, 0)
      out.push(item)
      pos = next
    }
  }
  out
}

pub fn find_tag(items : Array[Tlv], tag : Int) -> Tlv? {
  for item in items {
    if item.tag == tag {
      return Some(item)
    }
    match find_tag(item.children, tag) {
      Some(found) => return Some(found)
      None => ()
    }
  }
  None
}

pub fn collect_tags(items : Array[Tlv]) -> Array[Int] {
  let out : Array[Int] = Array::new()
  for item in items {
    out.push(item.tag)
    for child_tag in collect_tags(item.children) {
      out.push(child_tag)
    }
  }
  out
}

pub fn tag_name(tag : Int) -> String {
  if tag == 0x4f {
    "ADF Name"
  } else if tag == 0x50 {
    "Application Label"
  } else if tag == 0x57 {
    "Track 2 Equivalent Data"
  } else if tag == 0x5a {
    "Primary Account Number"
  } else if tag == 0x5f20 {
    "Cardholder Name"
  } else if tag == 0x5f24 {
    "Application Expiration Date"
  } else if tag == 0x5f34 {
    "PAN Sequence Number"
  } else if tag == 0x6f {
    "FCI Template"
  } else if tag == 0x70 {
    "Record Template"
  } else if tag == 0x77 {
    "Response Message Template"
  } else if tag == 0x80 {
    "Response Message Template (old)"
  } else if tag == 0x82 {
    "Application Interchange Profile"
  } else if tag == 0x83 {
    "Command Template"
  } else if tag == 0x84 {
    "Dedicated File Name"
  } else if tag == 0x8c {
    "CDOL1"
  } else if tag == 0x8d {
    "CDOL2"
  } else if tag == 0x90 {
    "Issuer Public Key Certificate"
  } else if tag == 0x94 {
    "Application File Locator"
  } else if tag == 0x95 {
    "Terminal Verification Results"
  } else if tag == 0x9a {
    "Transaction Date"
  } else if tag == 0x9c {
    "Transaction Type"
  } else if tag == 0x9f02 {
    "Amount, Authorized"
  } else if tag == 0x9f03 {
    "Amount, Other"
  } else if tag == 0x9f10 {
    "Issuer Application Data"
  } else if tag == 0x9f1a {
    "Terminal Country Code"
  } else if tag == 0x9f26 {
    "Application Cryptogram"
  } else if tag == 0x9f27 {
    "Cryptogram Information Data"
  } else if tag == 0x9f33 {
    "Terminal Capabilities"
  } else if tag == 0x9f35 {
    "Terminal Type"
  } else if tag == 0x9f36 {
    "Application Transaction Counter"
  } else if tag == 0x9f37 {
    "Unpredictable Number"
  } else if tag == 0x9f39 {
    "POS Entry Mode"
  } else if tag == 0x9f41 {
    "Transaction Sequence Counter"
  } else if tag == 0x9f4e {
    "Merchant Name and Location"
  } else if tag == 0x9f53 {
    "Transaction Category Code"
  } else if tag == 0xa5 {
    "FCI Proprietary Template"
  } else if tag == 0xbf0c {
    "FCI Issuer Discretionary Data"
  } else if tag == 0x5f28 {
    "Issuer Country Code"
  } else if tag == 0x5f2d {
    "Language Preference"
  } else if tag == 0x5f30 {
    "Service Code"
  } else if tag == 0x5f36 {
    "Transaction Currency Code"
  } else if tag == 0x5f50 {
    "Issuer URL"
  } else if tag == 0x5f53 {
    "IBAN"
  } else if tag == 0x5f54 {
    "Bank Identifier Code"
  } else if tag == 0x5f56 {
    "Issuer Country Code (2)"
  } else if tag == 0x61 {
    "Application Template"
  } else if tag == 0x9f07 {
    "Application Usage Control"
  } else if tag == 0x9f08 {
    "Application Version Number"
  } else if tag == 0x9f0d {
    "Issuer Action Code - Default"
  } else if tag == 0x9f0e {
    "Issuer Action Code - Denial"
  } else if tag == 0x9f0f {
    "Issuer Action Code - Online"
  } else if tag == 0x9f42 {
    "Application Currency Code"
  } else if tag == 0x9f44 {
    "Application Currency Exponent"
  } else if tag == 0x9f45 {
    "Data Authentication Code"
  } else if tag == 0x9f46 {
    "ICC Public Key Certificate"
  } else if tag == 0x9f47 {
    "ICC Public Key Exponent"
  } else if tag == 0x9f48 {
    "ICC Public Key Remainder"
  } else if tag == 0x9f49 {
    "Dynamic Data Authentication Data Object List"
  } else if tag == 0x9f4a {
    "Static Data Authentication Tag List"
  } else if tag == 0x9f4b {
    "Signed Dynamic Application Data"
  } else if tag == 0x9f4c {
    "ICC Dynamic Number"
  } else if tag == 0x9f4d {
    "Log Entry"
  } else if tag == 0x9f4f {
    "Log Format"
  } else if tag == 0x9f51 {
    "Issuer Application Data (2)"
  } else if tag == 0x9f52 {
    "Application Default Action"
  } else if tag == 0x9f54 {
    "Transaction Category Code (2)"
  } else if tag == 0x9f5b {
    "DS Summary 1"
  } else if tag == 0x9f5d {
    "DS Summary 2"
  } else if tag == 0x9f62 {
    "PCVC3"
  } else if tag == 0x9f63 {
    "PUNATC"
  } else if tag == 0x9f66 {
    "Terminal Transaction Qualifiers"
  } else {
    "Unknown"
  }
}

fn encode_length(len : Int) -> Array[Int] {
  if len < 0x80 {
    [len]
  } else if len <= 0xff {
    [0x81, len]
  } else {
    [0x82, (len >> 8) & 0xff, len & 0xff]
  }
}

fn encode_tag(tag : Int) -> Array[Int] {
  let width = tag_width(tag)
  let out : Array[Int] = Array::new()
  for i in 0..<width {
    out.push((tag >> ((width - 1 - i) * 8)) & 0xff)
  }
  out
}

pub fn encode_tlv(item : Tlv) -> Array[Int] {
  let body = if item.constructed {
    let out : Array[Int] = Array::new()
    for child in item.children {
      for b in encode_tlv(child) {
        out.push(b)
      }
    }
    out
  } else {
    item.value
  }
  let out = encode_tag(item.tag)
  for b in encode_length(body.length()) {
    out.push(b)
  }
  for b in body {
    out.push(b)
  }
  out
}

pub fn encode_tlvs(items : Array[Tlv]) -> Array[Int] {
  let out : Array[Int] = Array::new()
  for item in items {
    for b in encode_tlv(item) {
      out.push(b)
    }
  }
  out
}
