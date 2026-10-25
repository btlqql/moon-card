#!/usr/bin/env python3
"""Compare MoonCard TLV fixtures with the pyemv reference implementation.

Reference (dev-only, not a runtime dependency):
  pip install --target D:/Codex/tools/pyrefs pyemv==1.5.0

Run:
  MOONBIT_PYREFS=D:/Codex/tools/pyrefs python scripts/reference_compare.py
"""
import os
import sys

REFS = os.environ.get("MOONBIT_PYREFS", r"D:\Codex\tools\pyrefs")
sys.path.insert(0, REFS)

from pyemv import tlv  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"[{'PASS' if condition else 'FAIL'}] {name} {detail}")
    if not condition:
        failures.append(name)


# 1. FCI template.
fci = bytes.fromhex("6F098407A0000000031010")
decoded = tlv.decode(fci)
check(
    "FCI 6F/84",
    "6F" in decoded
    and "84" in decoded["6F"]
    and decoded["6F"]["84"].hex().upper() == "A0000000031010",
    f"decoded={decoded}",
)

# 2. Record template with PAN, expiry, cardholder.
record = bytes.fromhex(
    "70155A0841111111111111115F24032512315F20024A4F"
)
record_decoded = tlv.decode(record)
inner = record_decoded["70"]
check(
    "record 70/5A/5F24/5F20",
    inner["5A"].hex().upper() == "4111111111111111"
    and inner["5F24"].hex().upper() == "251231"
    and inner["5F20"].decode("ascii") == "JO",
    f"inner={inner}",
)

# 3. GPO response.
gpo = bytes.fromhex("770A82021980940408010100")
gpo_decoded = tlv.decode(gpo)
gpo_inner = gpo_decoded["77"]
check(
    "GPO 77/82/94",
    gpo_inner["82"].hex().upper() == "1980"
    and gpo_inner["94"].hex().upper() == "08010100",
    f"inner={gpo_inner}",
)

# 4. Encoding example from the pyemv documentation.
encoded = tlv.encode({"9C": "01", "E0": {"5F2A": "0208"}, "9F02": ""})
check(
    "encode pyemv example",
    encoded.hex().upper() == "9C0101E0055F2A0202089F0200",
    f"encoded={encoded.hex().upper()}",
)

# 5. Truncated TLV is rejected.
try:
    tlv.decode(bytes.fromhex("6F0A8407A0"))
    rejected = False
except tlv.DecodeError:
    rejected = True
check("truncated TLV rejected", rejected)

print()
if failures:
    print("FAILED:", ", ".join(failures))
    sys.exit(1)
print("All reference comparisons passed.")
