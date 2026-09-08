#!/usr/bin/env python3
"""
Generate a fresh per-event secp256k1 private key for local/dev builds
(spec #24, sub-issue #26). Writes 32 random bytes as 64 lowercase hex chars
to keys/event_privkey.hex (gitignored). Refuses to overwrite an existing
key file -- delete it yourself first if you really want to rotate it,
per #10's per-event rotation model.

For a real cabinet build, replace the generated file's contents with the
actual per-event secret however your key-management process supplies it;
this script only covers the "I have nothing yet, give me something that
works" dev path.

Usage: gen_event_key.py [path]   (default path: keys/event_privkey.hex)
"""
import os
import secrets
import sys


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join("keys", "event_privkey.hex")
    if os.path.exists(path):
        sys.stderr.write(
            "gen_event_key.py: %s already exists -- refusing to overwrite. "
            "Delete it yourself first if you intend to rotate the key.\n" % path
        )
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    privkey = secrets.token_bytes(32)
    with open(path, "w") as f:
        f.write(privkey.hex() + "\n")
    print("Generated new dev event key at %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
