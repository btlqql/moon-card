// Core checks for the EMV/APDU toolkit.

fn h(text : String) -> Array[Int] raise Failure {
  match hex_decode(text) {
    Some(bytes) => bytes
    None => fail("invalid test hex: " + text)
  }
}

///|
test "TLV parses nested FCI and finds tags" {
  let items = parse_tlv(h("6F 09 84 07 A0 00 00 00 03 10 10"))
  assert_eq(items.length(), 1)
  assert_eq(items[0].tag, 0x6f)
  assert_true(items[0].constructed)
  match find_tag(items, 0x84) {
    Some(df) => assert_eq(df.value.length(), 7)
    None => fail("DF name should be present")
  }
}

///|
test "TLV encode round-trips a constructed template" {
  let child : Tlv = {
    tag: 0x84,
    constructed: false,
    value: h("A0 00 00 00 03 10 10"),
    children: [],
  }
  let fci : Tlv = { tag: 0x6f, constructed: true, value: [], children: [child] }
  let encoded = encode_tlv(fci)
  assert_eq(hex_encode(encoded), "6F 09 84 07 A0 00 00 00 03 10 10")
  let parsed = parse_tlv(encoded)
  assert_eq(collect_tags(parsed).length(), 2)
}

///|
test "TLV rejects truncated and bad length input" {
  let truncated = try {
    ignore(parse_tlv(h("6F 0A 84 07 A0")))
    false
  } catch {
    _ => true
  }
  assert_true(truncated)
  let bad_length = try {
    ignore(parse_tlv(h("70 80 00")))
    false
  } catch {
    _ => true
  }
  assert_true(bad_length)
}

///|
test "APDU short forms round-trip" {
  let case1 = Apdu::new(0x00, 0x84, 0x00, 0x00)
  assert_eq(hex_encode(case1.encode()), "00 84 00 00")
  let case2 = select_ppse()
  assert_eq(
    hex_encode(case2.encode()),
    "00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00",
  )
  let case3 = gpo(h(""))
  assert_eq(hex_encode(case3.encode()), "80 A8 00 00 02 83 00 00")
  let case4 = generate_ac(0x80, h("01 02 03 04"))
  assert_eq(hex_encode(case4.encode()), "80 AE 80 00 04 01 02 03 04 00")
  let parsed = parse_apdu(h("80 AE 80 00 04 01 02 03 04 00"))
  assert_eq(parsed.data.length(), 4)
  assert_eq(parsed.le, Some(256))
}

///|
test "response status words and data are split" {
  let response = parse_response(h("6F 09 84 07 A0 00 00 00 03 10 10 90 00"))
  assert_eq(response.sw, 0x9000)
  assert_eq(response.data.length(), 11)
  assert_eq(status_description(0x6a82), "file or application not found")
  assert_eq(status_description(0x63c2), "verification failed, 2 tries left")
}

///|
test "GPO structured and legacy forms decode" {
  match parse_gpo_response(h("77 0A 82 02 19 80 94 04 08 01 01 00")) {
    Some(info) => {
      assert_eq(hex_encode(info.aip), "19 80")
      assert_eq(hex_encode(info.afl), "08 01 01 00")
    }
    None => fail("77 form should parse")
  }
  match parse_gpo_response(h("80 06 19 80 08 01 01 00")) {
    Some(info) => assert_eq(hex_encode(info.aip), "19 80")
    None => fail("80 form should parse")
  }
}

///|
test "record data exposes PAN, expiry and cardholder" {
  let record = h(
    "70 15 5A 08 41 11 11 11 11 11 11 11 5F 24 03 25 12 31 5F 20 02 4A 4F",
  )
  let items = match parse_record(record) {
    Some(values) => values
    None => fail("record should parse")
  }
  let card = card_data_from_tlv(items)
  assert_eq(card.pan, Some("4111111111111111"))
  assert_eq(card.expiry, Some("251231"))
  assert_eq(card.cardholder, Some("JO"))
  assert_true(luhn_valid("4111111111111111"))
  assert_true(!luhn_valid("4111111111111112"))
  assert_eq(mask_pan("4111111111111111"), "411111******1111")
  assert_eq(format_expiry("251231"), "2025-12")
}

///|
test "track 2 parsing and masking" {
  let track = parse_track2(ascii_bytes("4111111111111111D25122011234567890"))
  match track {
    Some(t) => {
      assert_eq(t.pan, "4111111111111111")
      assert_eq(t.expiry, "2512")
      assert_eq(t.service_code, "201")
    }
    None => fail("track 2 should parse")
  }
}

///|
test "transaction log parses commands, responses and card data" {
  let log = [
    ">> 00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00",
    "<< 6F 09 84 07 A0 00 00 00 03 10 10 90 00",
    ">> 80 A8 00 00 02 83 00 00",
    "<< 77 0A 82 02 19 80 94 04 08 01 01 00 90 00",
    "<< 70 15 5A 08 41 11 11 11 11 11 11 11 5F 24 03 25 12 31 5F 20 02 4A 4F 90 00",
  ].join("\n")
  let report = parse_transaction_log(log)
  assert_eq(report.steps.length(), 5)
  assert_eq(report.errors.length(), 0)
  assert_eq(report.pan, Some("4111111111111111"))
  assert_eq(report.expiry, Some("251231"))
  let text = render_transaction(report)
  assert_true(text.contains("411111******1111"))
  assert_true(text.contains("success (9000)"))
  assert_true(text.contains("GET PROCESSING OPTIONS"))
}

///|
test "transaction log records malformed input" {
  let report = parse_transaction_log("garbage\n<< 90 00")
  assert_eq(report.steps.length(), 1)
  assert_eq(report.errors.length(), 1)
}

///|
test "JSON transaction report masks the PAN and keeps statuses" {
  let log = [
    ">> 00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00",
    "<< 6F 09 84 07 A0 00 00 00 03 10 10 90 00",
    "<< 70 15 5A 08 41 11 11 11 11 11 11 11 5F 24 03 25 12 31 5F 20 02 4A 4F 90 00",
  ].join("\n")
  let json = render_transaction_json(parse_transaction_log(log))
  assert_true(json.contains("\"pan\":\"411111******1111\""))
  assert_true(json.contains("\"luhn\":true"))
  assert_true(json.contains("\"status\":\"success\""))
  assert_true(json.contains("\"command\":\"SELECT\""))
  assert_true(json.contains("\"tags\""))
}

///|
test "TLV encoding matches the pyemv reference example" {
  let items : Array[Tlv] = [
    { tag: 0x9c, constructed: false, value: h("01"), children: [] },
    {
      tag: 0xe0,
      constructed: true,
      value: [],
      children: [{ tag: 0x5f2a, constructed: false, value: h("02 08"), children: [] }],
    },
    { tag: 0x9f02, constructed: false, value: [], children: [] },
  ]
  assert_eq(hex_encode(encode_tlvs(items)), "9C 01 01 E0 05 5F 2A 02 02 08 9F 02 00")
}

///|
test "extended APDU encoding and parsing" {
  let data : Array[Int] = Array::new()
  for _ in 0..<300 {
    data.push(0xaa)
  }
  let command = Apdu::new(0x00, 0xda, 0x01, 0x02, data=data, le=300)
  let encoded = command.encode_extended()
  assert_eq(encoded.length(), 4 + 1 + 2 + 300 + 2)
  assert_eq(hex_encode([encoded[0], encoded[1], encoded[2], encoded[3], encoded[4], encoded[5], encoded[6]]), "00 DA 01 02 00 01 2C")
  let parsed = parse_apdu(encoded)
  assert_eq(parsed.data.length(), 300)
  assert_eq(parsed.le, Some(300))
}

///|
test "AFL entries expose SFI and record range" {
  let entries = parse_afl(h("08 01 01 00"))
  assert_eq(entries.length(), 1)
  assert_eq(entries[0].sfi, 1)
  assert_eq(entries[0].first_record, 1)
  assert_eq(entries[0].last_record, 1)
  assert_eq(entries[0].oda_count, 0)
}

///|
test "card profile validation reports issues" {
  assert_eq(validate_pan("4111111111111111").length(), 0)
  assert_true(validate_pan("4111111111111112").length() > 0)
  assert_true(validate_pan("1234").length() > 0)
  assert_eq(validate_expiry("251231").length(), 0)
  assert_true(validate_expiry("251331").length() > 0)
  assert_eq(validate_service_code("201").length(), 0)
  assert_true(validate_service_code("20A").length() > 0)
}

///|
test "CSV transaction report has one row per step" {
  let log = [
    ">> 00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00",
    "<< 6F 09 84 07 A0 00 00 00 03 10 10 90 00",
  ].join("\n")
  let csv = render_transaction_csv(parse_transaction_log(log))
  assert_true(csv.has_prefix("index,direction,command,status,sw,bytes\n"))
  assert_true(csv.contains("\"SELECT\""))
  assert_true(csv.contains("\"9000\""))
}
