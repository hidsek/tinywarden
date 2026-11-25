#!/usr/bin/env python3
"""Makes the one-time setup code and the 4 KB image for the board's "setup" partition (0x3F0000).

    python3 -I tools/setup_code.py setup.bin      # prints the code, writes the image

The code opens the board's status page until an account exists; creating the account erases the
partition. The image holds only a salted SHA-256 of the code, never the code itself:
    "SC" 0x01 0x00 | salt (16) | SHA-256(salt || code) (32) | 0xFF up to 4096 bytes
The web flasher (release/site/index.html) builds the same image in the browser.
"""
import hashlib
import secrets
import sys

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 32 characters, no 0/O, 1/I
LENGTH = 12                                    # 60 bits
SIZE = 4096


def make_code():
    return "".join(secrets.choice(ALPHABET) for _ in range(LENGTH))


def image(code, salt=None):
    salt = salt if salt is not None else secrets.token_bytes(16)
    body = b"SC\x01\x00" + salt + hashlib.sha256(salt + code.encode()).digest()
    return body + b"\xff" * (SIZE - len(body))


def pretty(code):
    return "-".join(code[i:i + 4] for i in range(0, LENGTH, 4))


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    code = make_code()
    with open(sys.argv[1], "wb") as f:
        f.write(image(code))
    print(pretty(code))


if __name__ == "__main__":
    main()
