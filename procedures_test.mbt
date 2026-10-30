test "61xx GET RESPONSE is combined before application selection checks" {
  let raw = parse_transaction_log("send: 00A4040005A00000000300\nresp: 610B\nsend: 00C000000B\nresp: 6F098407A00000000310109000")
  let logical = resolve_apdu_procedures(raw)
  assert_eq(logical.errors.length(),0)
  assert_eq(logical.steps.length(),2)
  let report = analyze_session(raw)
  assert_eq(report.selected_aid,Some("A0000000031010"))
  assert_eq(report.verdict,"review")
  assert_true(!report.issues.any(fn(x) { x.code == "STATUS_ERROR" || x.code == "AID_MISMATCH" }))
}

test "6Cxx length correction and a chained response" {
  let raw = parse_transaction_log(">> 00A4040005A00000000300\n<< 6C01\n>> 00A4040005A00000000301\n<< 610B\n>> 00C000000B\n<< 6F098407A00000000310109000")
  let logical = resolve_apdu_procedures(raw)
  assert_eq(logical.errors.length(),0)
  assert_eq(logical.steps.length(),2)
  assert_eq(analyze_session(raw).selected_aid,Some("A0000000031010"))
}

test "wrong recovery command or missing retry never passes" {
  let bad = analyze_session(parse_transaction_log(">> 00A4040005A00000000300\n<< 6C01\n>> 00A4040005A00000000302\n<< 9000"))
  assert_eq(bad.verdict,"fail")
  assert_eq(analyze_session(parse_transaction_log(">> 00A4040005A00000000300\n<< 610B")).verdict,"fail")
}

test "record data may be split across successive GET RESPONSE chunks" {
  let logical = resolve_apdu_procedures(parse_transaction_log(">> 00B2010C00\n<< 70066103\n>> 00C0000003\n<< 5F24036103\n>> 00C0000003\n<< 2512319000"))
  assert_eq(logical.steps.length(),2)
  assert_eq(logical.errors.length(),0)
  assert_eq(logical.steps[1].tlv.length(),1)
}

test "PDOL lengths from SELECT constrain GPO command data" {
  let r = analyze_session(parse_transaction_log(">> 00A4040007A000000003101000\n<< 6F0F8407A00000000310109F38039F02069000\n>> 80A8000002830000\n<< 770A820219809404080101009000"))
  assert_true(r.issues.any(fn(x) { x.code == "PDOL_LENGTH_MISMATCH" }))
}

test "DOL parser refuses truncated tags and missing lengths" {
  assert_eq(parse_dol([0x9f,0x02,6,0x95,5]),[(0x9f02,6),(0x95,5)])
  assert_true(try { ignore(parse_dol([0x9f])); false } catch { _ => true })
  assert_true(try { ignore(parse_dol([0x9f,0x02])); false } catch { _ => true })
  assert_true(try { ignore(parse_dol([0])); false } catch { _ => true })
}
