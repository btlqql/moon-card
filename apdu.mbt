// ISO 7816-4 command APDU construction and response parsing (short form).

pub(all) suberror ApduError {
  Truncated
  BadLength
  LeTooLarge(Int)
  DataTooLarge(Int)
}

pub(all) struct Apdu {
  cla : Int
  ins : Int
  p1 : Int
  p2 : Int
  data : Array[Int]
  le : Int?
}

pub fn Apdu::new(
  cla : Int,
  ins : Int,
  p1 : Int,
  p2 : Int,
  data? : Array[Int],
  le? : Int,
) -> Apdu {
  let body = match data {
    Some(values) => values
    None => Array::new()
  }
  { cla, ins, p1, p2, data: body, le }
}

pub fn Apdu::encode(self : Apdu) -> Array[Int] raise ApduError {
  if self.data.length() > 255 {
    raise DataTooLarge(self.data.length())
  }
  let out : Array[Int] = [self.cla, self.ins, self.p1, self.p2]
  if self.data.length() > 0 {
    out.push(self.data.length())
    for b in self.data {
      out.push(b)
    }
  }
  match self.le {
    Some(le) => {
      if le < 0 || le > 256 {
        raise LeTooLarge(le)
      }
      out.push(if le == 256 { 0 } else { le })
    }
    None => ()
  }
  out
}

pub fn Apdu::encode_extended(self : Apdu) -> Array[Int] raise ApduError {
  let le_needs_extended = match self.le {
    Some(le) => le > 256
    None => false
  }
  let needs_extended = self.data.length() > 255 || le_needs_extended
  if !needs_extended {
    return self.encode()
  }
  if self.data.length() > 65535 {
    raise DataTooLarge(self.data.length())
  }
  let out : Array[Int] = [self.cla, self.ins, self.p1, self.p2, 0]
  if self.data.length() > 0 {
    out.push((self.data.length() >> 8) & 0xff)
    out.push(self.data.length() & 0xff)
    for b in self.data {
      out.push(b)
    }
  }
  match self.le {
    Some(le) => {
      if le < 1 || le > 65536 {
        raise LeTooLarge(le)
      }
      let encoded = if le == 65536 { 0 } else { le }
      out.push((encoded >> 8) & 0xff)
      out.push(encoded & 0xff)
    }
    None => ()
  }
  out
}

pub fn parse_apdu(bytes : Array[Int]) -> Apdu raise ApduError {
  if bytes.length() < 4 {
    raise Truncated
  }
  if bytes.length() == 4 {
    return { cla: bytes[0], ins: bytes[1], p1: bytes[2], p2: bytes[3], data: [], le: None }
  }
  if bytes.length() == 5 {
    return {
      cla: bytes[0],
      ins: bytes[1],
      p1: bytes[2],
      p2: bytes[3],
      data: [],
      le: Some(if bytes[4] == 0 { 256 } else { bytes[4] }),
    }
  }
  if bytes[4] == 0 && bytes.length() > 5 {
    let rest = bytes.length() - 5
    if rest == 2 {
      let le = (bytes[5] << 8) | bytes[6]
      return {
        cla: bytes[0],
        ins: bytes[1],
        p1: bytes[2],
        p2: bytes[3],
        data: [],
        le: Some(if le == 0 { 65536 } else { le }),
      }
    }
    if rest < 2 {
      raise BadLength
    }
    let lc = (bytes[5] << 8) | bytes[6]
    if lc < 0 || bytes.length() < 7 + lc {
      raise Truncated
    }
    let data : Array[Int] = Array::new()
    for i in 0..<lc {
      data.push(bytes[7 + i])
    }
    let le = if bytes.length() == 7 + lc {
      None
    } else if bytes.length() == 9 + lc {
      let value = (bytes[7 + lc] << 8) | bytes[8 + lc]
      Some(if value == 0 { 65536 } else { value })
    } else {
      raise BadLength
    }
    return { cla: bytes[0], ins: bytes[1], p1: bytes[2], p2: bytes[3], data, le }
  }
  let lc = bytes[4]
  if bytes.length() < 5 + lc {
    raise Truncated
  }
  let data : Array[Int] = Array::new()
  for i in 0..<lc {
    data.push(bytes[5 + i])
  }
  let le = if bytes.length() == 5 + lc {
    None
  } else if bytes.length() == 6 + lc {
    Some(if bytes[5 + lc] == 0 { 256 } else { bytes[5 + lc] })
  } else {
    raise BadLength
  }
  { cla: bytes[0], ins: bytes[1], p1: bytes[2], p2: bytes[3], data, le }
}

pub(all) struct ApduResponse {
  data : Array[Int]
  sw : Int
}

pub fn parse_response(bytes : Array[Int]) -> ApduResponse raise ApduError {
  if bytes.length() < 2 {
    raise Truncated
  }
  let data : Array[Int] = Array::new()
  for i in 0..<(bytes.length() - 2) {
    data.push(bytes[i])
  }
  { data, sw: (bytes[bytes.length() - 2] << 8) | bytes[bytes.length() - 1] }
}

pub fn status_description(sw : Int) -> String {
  if sw == 0x9000 {
    "success"
  } else if sw >= 0x6100 && sw <= 0x61ff {
    "response available"
  } else if sw == 0x6200 {
    "warning: state unchanged"
  } else if sw == 0x6281 {
    "warning: part of returned data may be corrupted"
  } else if sw == 0x6282 {
    "warning: end of file reached"
  } else if sw == 0x6300 {
    "authentication failed"
  } else if sw >= 0x63c0 && sw <= 0x63cf {
    "verification failed, " + (sw & 0xf).to_string() + " tries left"
  } else if sw == 0x6700 {
    "wrong length"
  } else if sw == 0x6800 {
    "function in CLA not supported"
  } else if sw == 0x6881 {
    "logical channel not supported"
  } else if sw == 0x6882 {
    "secure messaging not supported"
  } else if sw == 0x6982 {
    "security status not satisfied"
  } else if sw == 0x6983 {
    "authentication method blocked"
  } else if sw == 0x6985 {
    "conditions of use not satisfied"
  } else if sw == 0x6986 {
    "command not allowed"
  } else if sw == 0x6a80 {
    "incorrect parameters in data field"
  } else if sw == 0x6a82 {
    "file or application not found"
  } else if sw == 0x6a83 {
    "record not found"
  } else if sw == 0x6a84 {
    "not enough memory"
  } else if sw == 0x6a86 {
    "incorrect P1/P2"
  } else if sw == 0x6a88 {
    "referenced data not found"
  } else if sw == 0x6b00 {
    "wrong parameters P1/P2"
  } else if sw == 0x6c00 {
    "wrong Le"
  } else if sw >= 0x6c01 && sw <= 0x6cff {
    "wrong Le, " + (sw & 0xff).to_string() + " available"
  } else if sw == 0x6d00 {
    "instruction not supported"
  } else if sw == 0x6e00 {
    "class not supported"
  } else if sw == 0x6f00 {
    "unknown error"
  } else {
    "unknown status"
  }
}

pub fn command_name(apdu : Apdu) -> String {
  if apdu.ins == 0xa4 {
    "SELECT"
  } else if apdu.ins == 0xb2 {
    "READ RECORD"
  } else if apdu.ins == 0x20 {
    "VERIFY"
  } else if apdu.ins == 0xca {
    "GET DATA"
  } else if apdu.ins == 0xa8 {
    "GET PROCESSING OPTIONS"
  } else if apdu.ins == 0xae {
    "GENERATE AC"
  } else if apdu.ins == 0x24 {
    "PROCESSING"
  } else if apdu.ins == 0x88 {
    "INTERNAL AUTHENTICATE"
  } else if apdu.ins == 0x84 {
    "GET CHALLENGE"
  } else {
    "UNKNOWN"
  }
}
