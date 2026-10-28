// Generated session fixtures for the APDU/EMV semantic analyzer.

fn session_log_happy() -> String { ">> 00A404000E325041592E5359532E444446303100\n<< 6F26840E325041592E5359532E4444463031A514BF0C11610F4F07A0000000031010500456495341 90 00\n>> 00A4040007A000000003101000\n<< 6F098407A0000000031010 90 00\n>> 80A8000002830000\n<< 770A82021980940408010100 90 00\n>> 00B2010C00\n<< 70295A0841111111111111115F24032512315F20024A4F8C129F02069F03069F1A0295059F37049A039C01 90 00\n>> 80AE80001B00000000100000000000000008400000000000112233442510250000\n<< 770F9F2701809F360200019F1003112233 90 00" }

fn session_log_two() -> String { ">> 00A404000E325041592E5359532E444446303100\n<< 6F35840E325041592E5359532E4444463031A523BF0C20610F4F07A0000000031010500456495341610D4F07A000000004101050024D43 90 00\n>> 00A4040007A000000004101000\n<< 6F098407A0000000041010 90 00\n>> 80A8000002830000\n<< 770A82021980940408010100 90 00\n>> 00B2010C00\n<< 70295A0841111111111111115F24032512315F20024A4F8C129F02069F03069F1A0295059F37049A039C01 90 00\n>> 80AE80001B00000000100000000000000008400000000000112233442510250000\n<< 770F9F2701809F360200019F1003112233 90 00" }

fn session_log_wrong() -> String { ">> 00A404000E325041592E5359532E444446303100\n<< 6F26840E325041592E5359532E4444463031A514BF0C11610F4F07A0000000031010500456495341 90 00\n>> 00A4040007A000000003101000\n<< 6F098407A0000000031010 90 00\n>> 80AE80001B00000000100000000000000008400000000000112233442510250000\n<< 770F9F2701809F360200019F1003112233 90 00" }

fn session_log_missing_pan() -> String { ">> 00A404000E325041592E5359532E444446303100\n<< 6F26840E325041592E5359532E4444463031A514BF0C11610F4F07A0000000031010500456495341 90 00\n>> 00A4040007A000000003101000\n<< 6F098407A0000000031010 90 00\n>> 80A8000002830000\n<< 770A82021980940408010100 90 00\n>> 00B2010C00\n<< 701F5F24032512315F20024A4F8C129F02069F03069F1A0295059F37049A039C01 90 00" }

fn session_log_afl_bad() -> String { ">> 00A404000E325041592E5359532E444446303100\n<< 6F26840E325041592E5359532E4444463031A514BF0C11610F4F07A0000000031010500456495341 90 00\n>> 00A4040007A000000003101000\n<< 6F098407A0000000031010 90 00\n>> 80A8000002830000\n<< 770A82021980940408010100 90 00\n>> 00B2011400\n<< 70295A0841111111111111115F24032512315F20024A4F8C129F02069F03069F1A0295059F37049A039C01 90 00" }

fn session_log_cdol_bad() -> String { ">> 00A404000E325041592E5359532E444446303100\n<< 6F26840E325041592E5359532E4444463031A514BF0C11610F4F07A0000000031010500456495341 90 00\n>> 00A4040007A000000003101000\n<< 6F098407A0000000031010 90 00\n>> 80A8000002830000\n<< 770A82021980940408010100 90 00\n>> 00B2010C00\n<< 70295A0841111111111111115F24032512315F20024A4F8C129F02069F03069F1A0295059F37049A039C01 90 00\n>> 80AE80001A000000001000000000000000084000000000001122334425102500\n<< 770F9F2701809F360200019F1003112233 90 00" }

fn session_log_status_bad() -> String { ">> 00A404000E325041592E5359532E444446303100\n<< 6F26840E325041592E5359532E4444463031A514BF0C11610F4F07A0000000031010500456495341 90 00\n>> 00A4040007A000000003101000\n<< 6F098407A0000000031010 90 00\n>> 80A8000002830000\n<< 6A 82" }

///|
test "session happy path passes" {
  let report = analyze_session(parse_transaction_log(session_log_happy()))
  assert_eq(report.verdict, "pass")
  assert_eq(report.candidates.length(), 1)
  assert_eq(report.selected_aid, Some("A0000000031010"))
  assert_eq(report.aip, Some("1980"))
  assert_eq(report.afl.length(), 1)
  assert_eq(report.records.length(), 1)
  assert_eq(report.issues.length(), 0)
}

///|
test "session selects one of two PPSE candidates" {
  let report = analyze_session(parse_transaction_log(session_log_two()))
  assert_eq(report.verdict, "pass")
  assert_eq(report.candidates.length(), 2)
  assert_eq(report.selected_aid, Some("A0000000041010"))
}

///|
test "session rejects GENERATE AC before GPO and records" {
  let report = analyze_session(parse_transaction_log(session_log_wrong()))
  assert_eq(report.verdict, "fail")
  let mut has_gpo = false
  let mut has_record = false
  for issue in report.issues {
    if issue.code == "GENERATE_AC_BEFORE_GPO" { has_gpo = true }
    if issue.code == "GENERATE_AC_BEFORE_RECORD" { has_record = true }
  }
  assert_true(has_gpo)
  assert_true(has_record)
}

///|
test "session detects a record without PAN" {
  let report = analyze_session(parse_transaction_log(session_log_missing_pan()))
  assert_eq(report.verdict, "fail")
  let mut found = false
  for issue in report.issues {
    if issue.code == "MISSING_PAN" { found = true }
  }
  assert_true(found)
}

///|
test "session detects READ RECORD outside AFL" {
  let report = analyze_session(parse_transaction_log(session_log_afl_bad()))
  assert_eq(report.verdict, "fail")
  let mut found = false
  for issue in report.issues {
    if issue.code == "RECORD_NOT_IN_AFL" { found = true }
  }
  assert_true(found)
}

///|
test "session detects CDOL length mismatch" {
  let report = analyze_session(parse_transaction_log(session_log_cdol_bad()))
  assert_eq(report.verdict, "fail")
  let mut found = false
  for issue in report.issues {
    if issue.code == "CDOL_LENGTH_MISMATCH" { found = true }
  }
  assert_true(found)
}

///|
test "session reports status-word failure" {
  let report = analyze_session(parse_transaction_log(session_log_status_bad()))
  assert_eq(report.verdict, "fail")
  let mut found = false
  for issue in report.issues {
    if issue.code == "STATUS_ERROR" { found = true }
  }
  assert_true(found)
}

///|
test "CDOL parser extracts tag/length pairs" {
  let fields = parse_cdol(hex_decode("9F02069F03069505").unwrap())
  assert_eq(fields.length(), 3)
  assert_eq(cdol_total_length(fields), 17)
}
