// Node is used only for file IO. All EMV/APDU work runs in MoonBit.

extern "js" fn read_text(path : String) -> String? =
  #| (path) => {
  #|   try {
  #|     const fs = process.getBuiltinModule('node:fs');
  #|     const text = fs.readFileSync(path, 'utf8');
  #|     return text.length > 4194304 ? undefined : text;
  #|   } catch { return undefined; }
  #| }

extern "js" fn stderr(text : String) -> Unit =
  #| (text) => { process.stderr.write(text + '\n'); }

extern "js" fn exit_code(code : Int) -> Unit =
  #| (code) => { process.exitCode = code; }

fn usage() -> Unit {
  println(
    "MoonCard 0.1.0\n" +
    "Usage:\n" +
    "  mooncard tlv <hex>                     parse BER-TLV\n" +
    "  mooncard response <hex>                parse APDU response + TLV\n" +
    "  mooncard apdu <hex>                    parse a command APDU\n" +
    "  mooncard select <aid-hex>              build SELECT by AID\n" +
    "  mooncard gpo <pdol-data-hex>           build GET PROCESSING OPTIONS\n" +
    "  mooncard read-record <record> <sfi>    build READ RECORD (decimal)\n" +
    "  mooncard gen-ac <p1> <cdol-data-hex>   build GENERATE AC\n" +
    "  mooncard log <transaction.log>         render a recorded APDU log\n" +
    "  mooncard luhn <pan>                    check the Luhn digit\n" +
    "  mooncard track2 <text>                 parse track 2 equivalent data",
  )
}

fn need_hex(text : String) -> Array[Int]? {
  match @card.hex_decode(text) {
    Some(bytes) => Some(bytes)
    None => {
      stderr("ERROR: invalid hex string")
      None
    }
  }
}

fn dec_parse(text : String) -> Int? {
  if text.length() == 0 {
    return None
  }
  let mut value = 0
  for i in 0..<text.length() {
    let c = text[i].to_int()
    if c < 48 || c > 57 {
      return None
    }
    value = value * 10 + (c - 48)
  }
  Some(value)
}

fn print_tlv(items : Array[@card.Tlv], indent : String) -> Unit {
  for item in items {
    let suffix = if item.constructed {
      " len=" + item.value.length().to_string()
    } else {
      " len=" + item.value.length().to_string() + " value=" +
      @card.hex_encode(item.value) + " \"" + @card.ascii_of(item.value) + "\""
    }
    println(
      indent + @card.tag_to_hex(item.tag) + " (" + @card.tag_name(item.tag) +
      ")" + suffix,
    )
    print_tlv(item.children, indent + "  ")
  }
}

fn run() -> Unit {
  let args = @env.args()
  if args.length() < 3 {
    usage()
    return
  }
  let command = args[2]
  if command == "help" || command == "--help" {
    usage()
  } else if command == "tlv" && args.length() == 4 {
    match need_hex(args[3]) {
      Some(bytes) =>
        try {
          print_tlv(@card.parse_tlv(bytes), "")
        } catch {
          _ => {
            stderr("ERROR: invalid BER-TLV")
            exit_code(1)
          }
        }
      None => exit_code(2)
    }
  } else if command == "response" && args.length() == 4 {
    match need_hex(args[3]) {
      Some(bytes) =>
        try {
          let response = @card.parse_response(bytes)
          println(
            "SW=" + @card.hex_int(response.sw, 4) + " " +
            @card.status_description(response.sw),
          )
          if response.data.length() > 0 {
            try {
              print_tlv(@card.parse_tlv(response.data), "")
            } catch {
              _ => println("data=" + @card.hex_encode(response.data))
            }
          }
        } catch {
          _ => {
            stderr("ERROR: response is shorter than two status bytes")
            exit_code(1)
          }
        }
      None => exit_code(2)
    }
  } else if command == "apdu" && args.length() == 4 {
    match need_hex(args[3]) {
      Some(bytes) =>
        try {
          let apdu = @card.parse_apdu(bytes)
          let le_text = match apdu.le {
            Some(v) => v.to_string()
            None => "-"
          }
          println(
            "CLA=" + @card.hex_int(apdu.cla, 2) + " INS=" +
            @card.hex_int(apdu.ins, 2) + " P1=" + @card.hex_int(apdu.p1, 2) +
            " P2=" + @card.hex_int(apdu.p2, 2) + " " +
            @card.command_name(apdu) + " data=" + @card.hex_encode(apdu.data) +
            " Le=" + le_text,
          )
        } catch {
          _ => {
            stderr("ERROR: invalid short APDU")
            exit_code(1)
          }
        }
      None => exit_code(2)
    }
  } else if command == "select" && args.length() == 4 {
    match need_hex(args[3]) {
      Some(aid) =>
        try {
          println(@card.hex_encode(@card.select_aid(aid).encode()))
        } catch {
          _ => {
            stderr("ERROR: AID is too long")
            exit_code(1)
          }
        }
      None => exit_code(2)
    }
  } else if command == "gpo" && args.length() == 4 {
    match need_hex(args[3]) {
      Some(pdol) =>
        try {
          println(@card.hex_encode(@card.gpo(pdol).encode()))
        } catch {
          _ => {
            stderr("ERROR: PDOL data is too long")
            exit_code(1)
          }
        }
      None => exit_code(2)
    }
  } else if command == "read-record" && args.length() == 5 {
    match (dec_parse(args[3]), dec_parse(args[4])) {
      (Some(record), Some(sfi)) =>
        try {
          println(
            @card.hex_encode(@card.read_record(record, sfi).encode()),
          )
        } catch {
          _ => {
            stderr("ERROR: invalid record APDU")
            exit_code(1)
          }
        }
      _ => {
        stderr("ERROR: record and SFI must be decimal")
        exit_code(2)
      }
    }
  } else if command == "gen-ac" && args.length() == 5 {
    match (dec_parse(args[3]), need_hex(args[4])) {
      (Some(p1), Some(cdol)) =>
        try {
          println(@card.hex_encode(@card.generate_ac(p1, cdol).encode()))
        } catch {
          _ => {
            stderr("ERROR: CDOL data is too long")
            exit_code(1)
          }
        }
      _ => {
        stderr("ERROR: P1 must be decimal and CDOL data hex")
        exit_code(2)
      }
    }
  } else if command == "log" && args.length() == 4 {
    match read_text(args[3]) {
      Some(text) => println(@card.render_transaction(@card.parse_transaction_log(text)))
      None => {
        stderr("ERROR: cannot read transaction log")
        exit_code(2)
      }
    }
  } else if command == "luhn" && args.length() == 4 {
    println(if @card.luhn_valid(args[3]) { "valid" } else { "invalid" })
  } else if command == "track2" && args.length() == 4 {
    match @card.parse_track2(@card.ascii_bytes(args[3])) {
      Some(track) =>
        println(
          "PAN=" + track.pan + " expiry=" + track.expiry + " service=" +
          track.service_code,
        )
      None => {
        stderr("ERROR: track 2 separator not found")
        exit_code(1)
      }
    }
  } else {
    usage()
    exit_code(2)
  }
}

///|
fn main {
  run()
}
