// Hex helpers shared by the card codec and CLI.

pub fn hex_nibble_char(value : Int) -> Char {
  let digits = "0123456789ABCDEF"
  match digits.get_char(value & 0xf) {
    Some(c) => c
    None => '?'
  }
}

pub fn hex_int(value : Int, width : Int) -> String {
  let out = StringBuilder()
  for i in 0..<width {
    out.write_char(hex_nibble_char(value >> ((width - 1 - i) * 4)))
  }
  out.to_string()
}

pub fn hex_encode(bytes : Array[Int]) -> String {
  let out = StringBuilder()
  for i in 0..<bytes.length() {
    if i > 0 {
      out.write_char(' ')
    }
    out.write_char(hex_nibble_char(bytes[i] >> 4))
    out.write_char(hex_nibble_char(bytes[i]))
  }
  out.to_string()
}

fn hex_digit(c : Int) -> Int? {
  if c >= 48 && c <= 57 {
    Some(c - 48)
  } else if c >= 65 && c <= 70 {
    Some(c - 55)
  } else if c >= 97 && c <= 102 {
    Some(c - 87)
  } else {
    None
  }
}

pub fn hex_decode(text : String) -> Array[Int]? {
  let out : Array[Int] = Array::new()
  let mut high = -1
  for i in 0..<text.length() {
    let c = text[i].to_int()
    if c == 32 || c == 9 || c == 10 || c == 13 || c == 58 || c == 45 || c == 44 {
      continue
    }
    match hex_digit(c) {
      Some(v) =>
        if high < 0 {
          high = v
        } else {
          out.push((high << 4) | v)
          high = -1
        }
      None => return None
    }
  }
  if high >= 0 {
    None
  } else {
    Some(out)
  }
}

pub fn ascii_of(bytes : Array[Int]) -> String {
  let out = StringBuilder()
  for b in bytes {
    if b >= 32 && b <= 126 {
      out.write_char(Char::from_int(b))
    } else {
      out.write_char('.')
    }
  }
  out.to_string()
}

pub fn ascii_bytes(text : String) -> Array[Int] {
  let out : Array[Int] = Array::new()
  for i in 0..<text.length() {
    out.push(text[i].to_int() & 0xff)
  }
  out
}
