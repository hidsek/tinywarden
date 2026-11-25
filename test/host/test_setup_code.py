#!/usr/bin/env python3
"""Checks tools/setup_code.py: the image layout the firmware reads (auth.c, tw_auth_check_setup).

    python3 -I test/host/test_setup_code.py
"""
import hashlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
import setup_code as sc  # noqa: E402

failed = 0


def check(name, ok):
    global failed
    print(("PASS " if ok else "FAIL ") + name)
    failed += not ok


codes = {sc.make_code() for _ in range(2000)}
check("codes are 12 characters of the alphabet", all(len(c) == 12 and set(c) <= set(sc.ALPHABET) for c in codes))
check("codes do not repeat", len(codes) == 2000)
check("alphabet has 32 characters without 0 O 1 I", len(set(sc.ALPHABET)) == 32 and not set("0O1I") & set(sc.ALPHABET))
img = sc.image("ABCDEFGHJKLM", salt=bytes(range(16)))
check("image is 4096 bytes", len(img) == 4096)
check("magic SC 1 0", img[:4] == b"SC\x01\x00")
check("salt then SHA-256(salt || code)", img[4:20] == bytes(range(16))
      and img[20:52] == hashlib.sha256(bytes(range(16)) + b"ABCDEFGHJKLM").digest())
check("rest is erased flash (0xFF)", img[52:] == b"\xff" * (4096 - 52))
check("the code itself is not in the image", b"ABCDEFGHJKLM" not in img)
check("shown with dashes", sc.pretty("ABCDEFGHJKLM") == "ABCD-EFGH-JKLM")
with tempfile.TemporaryDirectory() as d:
    out = subprocess.run([sys.executable, "-I", os.path.join(HERE, "..", "..", "tools", "setup_code.py"),
                          os.path.join(d, "s.bin")], capture_output=True, text=True).stdout.strip()
    data = open(os.path.join(d, "s.bin"), "rb").read()
    code = out.replace("-", "")
    check("command prints the code that matches the file",
          len(out) == 14 and data[20:52] == hashlib.sha256(data[4:20] + code.encode()).digest())
print("\nall passed" if not failed else f"\n{failed} failed")
sys.exit(1 if failed else 0)
