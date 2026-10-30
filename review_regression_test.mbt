test "empty and malformed captures cannot pass" {
  assert_eq(analyze_session(parse_transaction_log("")).verdict, "review")
  assert_eq(analyze_session(parse_transaction_log(">> zz")).verdict, "fail")
}

test "failed GPO never installs AIP or AFL" {
  let r = analyze_session(parse_transaction_log(">> 80A8000002830000\n<< 770A820219809404080101006A82"))
  assert_eq(r.verdict, "fail")
  assert_eq(r.afl.length(), 0)
  assert_eq(r.aip, None)
}

test "reselection discards previous records and CDOL" {
  let r = analyze_session(parse_transaction_log(session_log_happy() +
    "\n>> 00A4040007A000000004101000\n<< 6F098407A00000000410109000\n>> 80AE800000\n<< 9000"))
  assert_eq(r.verdict, "fail")
  assert_eq(r.records.length(), 0)
  assert_eq(r.afl.length(), 0)
}

test "missing response does not swallow the next command" {
  let r = analyze_session(parse_transaction_log(">> 00A4040007A000000003101000\n>> 80A8000002830000\n<< 770A820219809404080101009000"))
  assert_eq(r.verdict, "fail")
  assert_eq(r.afl.length(), 1)
  assert_true(r.issues.any(fn(x) { x.code == "GPO_BEFORE_SELECT" }))
}

test "unread AFL records prevent a complete transaction verdict" {
  let log = session_log_happy().replace(old="08010100", new="08010200")
  let r = analyze_session(parse_transaction_log(log))
  assert_true(r.issues.any(fn(x) { x.code == "AFL_RECORD_MISSING" }))
}
