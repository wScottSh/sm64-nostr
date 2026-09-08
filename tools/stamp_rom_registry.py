#!/usr/bin/env python3
"""
Bind a finished ROM to the event identity baked into it, and append the
authoritative row to the gitignored keys/registry.md (spec #24, sub-issue #26).

This is the ONLY writer of the registry. It runs at ROM-completion time (from the
$(ROM) recipe), reads the manifest that gen_event_profile.py wrote for this build,
computes the ROM's sha1, and records both together. That closes the record-keeping
gap: every shipped .z64 has exactly one row that ties its sha1 to the created_at /
pubkey / commit baked inside it, so a scanned QR (which reveals created_at) or a
loose .z64 (its sha1) can each be mapped back to the build that made it.

Fails closed: a missing/malformed manifest or a missing ROM aborts the build rather
than silently shipping an unrecorded binary, matching the pipeline's fail-closed
handling of a missing key.

Usage:
  stamp_rom_registry.py --rom <path.z64> --manifest <path.json> --registry <path.md>
"""
import argparse
import hashlib
import json
import os
import sys

REQUIRED_FIELDS = ("label", "pubkey_hex", "npub", "created_at", "build_date", "commit")

HEADER_LINES = (
    "# Nostr pipeline event key registry (gitignored; spec #24, sub-issue #26)\n",
    "\n",
    "| label | pubkey (hex) | npub | created_at | build date | commit | rom sha1 |\n",
    "|---|---|---|---|---|---|---|\n",
)


def sha1_of_file(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def append_registry_row(registry_path, m, rom_sha1):
    os.makedirs(os.path.dirname(os.path.abspath(registry_path)) or ".", exist_ok=True)
    is_new = not os.path.exists(registry_path)
    with open(registry_path, "a") as f:
        if is_new:
            f.writelines(HEADER_LINES)
        f.write(
            "| %s | %s | %s | %s | %s | %s | %s |\n"
            % (
                m["label"],
                m["pubkey_hex"],
                m["npub"],
                m["created_at"],
                m["build_date"],
                m["commit"],
                rom_sha1,
            )
        )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rom", required=True, help="path to the finished ROM (.z64)")
    ap.add_argument("--manifest", required=True, help="path to the event identity manifest (JSON)")
    ap.add_argument("--registry", required=True, help="path to keys/registry.md")
    args = ap.parse_args()

    try:
        with open(args.manifest, "r") as f:
            manifest = json.load(f)
    except (OSError, ValueError) as e:
        sys.stderr.write(
            "stamp_rom_registry.py: FATAL: could not read event manifest %s: %s\n"
            % (args.manifest, e)
        )
        return 1

    missing = [k for k in REQUIRED_FIELDS if k not in manifest]
    if missing:
        sys.stderr.write(
            "stamp_rom_registry.py: FATAL: manifest %s is missing required field(s): %s\n"
            % (args.manifest, ", ".join(missing))
        )
        return 1

    if not os.path.exists(args.rom):
        sys.stderr.write(
            "stamp_rom_registry.py: FATAL: ROM %s does not exist\n" % args.rom
        )
        return 1

    rom_sha1 = sha1_of_file(args.rom)
    append_registry_row(args.registry, manifest, rom_sha1)

    sys.stderr.write(
        "stamp_rom_registry.py: recorded ROM %s (sha1 %s, created_at %s) in %s\n"
        % (os.path.basename(args.rom), rom_sha1, manifest["created_at"], args.registry)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
