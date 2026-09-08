#!/usr/bin/env python3
"""
Generate event_profile.h (spec #24, sub-issue #26) from include/event_profile.h.in
plus a per-event 32-byte hex secp256k1 private key, and write a manifest sidecar
(--manifest) describing the baked event identity.

The manifest is the hand-off to stamp_rom_registry.py: the registry row is written
at ROM-completion time (not here), so it can bind the finished ROM's sha1 to the
identity baked into it. Writing the registry here -- decoupled from the artifact --
was the record-keeping gap: a row recorded an identity but nothing tied it to which
ROM (if any) actually shipped, and rebuilds re-minted created_at with no way to map a
scanned QR (which only reveals created_at) or a .z64 back to a build.

Bakes both the derived x-only pubkey AND the raw privkey bytes into the
generated header (spec #24, sub-issue #31: the ROM's capture glue calls
build_event(capture, key, ...) with a real key, so it needs the same
per-event secret in byte form, not just its derived pubkey).

The build fails closed on a missing key: see the Makefile's PIPELINE_PRIVKEY_FILE
check, which runs before this script is ever invoked. This script additionally
validates the key file's contents so a malformed (not 32-byte-hex) secret
also fails the build, never silently producing a keyless/garbage-keyed binary.

Usage:
  gen_event_profile.py --privkey <path> --template <path> --out <path>
                        --label <str> --manifest <path> [--commit <sha>]
                        [--created-at <epoch>]
"""
import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nostr_secp256k1 as secp  # noqa: E402


def read_privkey_hex(path):
    with open(path, "r") as f:
        raw = f.read().strip()
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    if len(raw) != 64:
        raise ValueError(
            "%s: expected 64 hex chars (32 raw bytes), got %d" % (path, len(raw))
        )
    try:
        privkey_bytes = bytes.fromhex(raw)
    except ValueError as e:
        raise ValueError("%s: not valid hex (%s)" % (path, e))
    return privkey_bytes


def resolve_commit_sha(explicit):
    if explicit:
        return explicit
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "unknown"


def write_manifest(manifest_path, manifest):
    os.makedirs(os.path.dirname(os.path.abspath(manifest_path)) or ".", exist_ok=True)
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--privkey", required=True, help="path to raw 32-byte hex privkey file")
    ap.add_argument("--template", required=True, help="path to event_profile.h.in")
    ap.add_argument("--out", required=True, help="output event_profile.h path")
    ap.add_argument("--label", required=True, help="event label for the registry row")
    ap.add_argument("--manifest", required=True, help="path to write the event identity manifest (JSON)")
    ap.add_argument("--commit", default=None)
    ap.add_argument("--created-at", type=int, default=None)
    args = ap.parse_args()

    try:
        privkey_bytes = read_privkey_hex(args.privkey)
        pubkey_bytes = secp.derive_xonly_pubkey(privkey_bytes)
    except Exception as e:
        sys.stderr.write(
            "gen_event_profile.py: FATAL: could not derive event pubkey from %s: %s\n"
            % (args.privkey, e)
        )
        return 1

    pubkey_hex = pubkey_bytes.hex()
    npub = secp.npub_from_xonly_pubkey(pubkey_bytes)
    created_at = args.created_at if args.created_at is not None else int(time.time())
    commit_sha = resolve_commit_sha(args.commit)
    build_date = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(created_at)) + " UTC"

    with open(args.template, "r") as f:
        template = f.read()

    pubkey_bytes_literal = "{ " + ", ".join("0x%02x" % b for b in pubkey_bytes) + " }"
    privkey_bytes_literal = "{ " + ", ".join("0x%02x" % b for b in privkey_bytes) + " }"
    rendered = (
        template.replace("@CREATED_AT@", str(created_at))
        .replace("@PUBKEY_HEX@", pubkey_hex)
        .replace("@PUBKEY_BYTES@", pubkey_bytes_literal)
        .replace("@PRIVKEY_BYTES@", privkey_bytes_literal)
    )

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        f.write(rendered)

    write_manifest(
        args.manifest,
        {
            "label": args.label,
            "pubkey_hex": pubkey_hex,
            "npub": npub,
            "created_at": created_at,
            "build_date": build_date,
            "commit": commit_sha,
            "event_profile_h": os.path.basename(args.out),
        },
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
