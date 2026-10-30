# External APDU procedure regression samples

Source: devnied/EMV-NFC-Paycard-Enrollment, commit
`a59820d4e979b17c1d1721fe2b03219d52ebcb35`.

- [wrapperTestSW_61](https://github.com/devnied/EMV-NFC-Paycard-Enrollment/blob/a59820d4e979b17c1d1721fe2b03219d52ebcb35/library/src/test/resources/data/wrapperTestSW_61)
- [wrapperTestSW_6C](https://github.com/devnied/EMV-NFC-Paycard-Enrollment/blob/a59820d4e979b17c1d1721fe2b03219d52ebcb35/library/src/test/resources/data/wrapperTestSW_6C)

Retrieved 2026-10-30. The files are copied unchanged except the final newline.
Upstream license: Apache-2.0, reproduced in LICENSE-EMV.txt. Copyright and
attribution remain with the upstream authors; no upstream implementation was
copied into MoonCard.

Both samples demonstrate a partial-AID SELECT with a successful recovery
exchange. MoonCard resolves 61xx/GET RESPONSE and 6Cxx/corrected-Le before
selection checks. A capture ending after SELECT is `review` (incomplete), not a
completed EMV transaction. These are upstream software test fixtures, not
evidence of a hardware test performed by this project.

Run `moon run cmd/main --target js -- session examples/external/wrapperTestSW_61.log`
and the corresponding `_6C.log` command.
