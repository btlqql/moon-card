# MoonCard 0.3.0 review evidence

The user task is recorded card/terminal APDU script regression: which application
was selected, which field lengths constrain the next command, whether all AFL
records were read, and where the script deviates from those constraints.

The reusable MoonBit library adds mechanisms beyond TLV decoding and fixed
command builders: procedure-byte recovery, application state reset, partial-AID
matching, PDOL/CDOL parsing and length checking, aggregate record requirements,
AFL completeness, and explicit pass/review/fail findings. The CLI maps fail to
exit 1; review is visible and remains exit 0 for human triage.

## External reproducible task

Run the two commands under examples/external/SOURCES.md. The Apache-2.0 upstream
reader fixtures contain a SELECT for partial AID A000000003 and either 61xx GET
RESPONSE or 6Cxx corrected-Le retry. Both resolve to A0000000031010. They yield
review because the capture ends after SELECT, without false STATUS_ERROR or
AID_MISMATCH. A GET RESPONSE chain may contain successive chunks; the library
combines them before TLV parsing. Wrong retries and incomplete chains fail.

The upstream files are software regression fixtures. They do not show a hardware
test run performed by this project or a complete EMV transaction. The local
complete happy-path transaction and fault mutations are explicitly synthetic.

## Validation

Current code passes 39 MoonBit tests on Windows JS, wasm and wasm-gc. Independent
consumer compilation exercises public APIs. CLI checks cover both external
fixtures, a complete synthetic transaction and an unread AFL record. Additional
regressions cover strict DOL syntax, PDOL/GPO mismatch, failed responses,
reselection, unpaired input, incomplete captures and CDOL constraints.

## Comparison and scope

pyemv is used as a development reference for TLV coding; it is not a runtime
dependency. ISO 8583/ISO 20022 network message packages address a different layer.
The contribution here is the stateful audit of card-facing interactions. There
is no claim of ecosystem uniqueness, production adoption or certification.

No cryptographic verification, EMV risk engine, reader driver or full EMV
certification is implemented. pass means only that implemented rules found no
violation. The primary target is a contact-style SELECT/GPO/AFL/record/AC script;
this is not a universal contactless-kernel correctness verdict. Reports must not
be treated as permission to process payment credentials.
