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

Also bakes the per-game `t` tag (--tag, defaults to "sm64") into the generated
header's PIPELINE_EVENT_TAG_1_VALUE -- format v2 (spec #52, sub-issue #54)
packs this tag onto the wire, so a build for a different game passes its own
--tag here rather than editing include/event_profile.h.in. Validated against
TAG_VALUE_RE (an unreserved identifier charset -- letters, digits, `.`, `_`,
`-`) and against the wire's own per-game tag length budget, read straight
from src/pipeline/format_descriptor.json's TAG field (never a second,
hand-duplicated `10` literal here that could drift from the real wire limit)
-- fails closed, same discipline as the privkey check above. The charset
restriction (not just "ASCII") is deliberate: this tag is embedded RAW, byte
-for-byte, into two places that would otherwise be corruptible by a `"` or
`\` in the value -- the generated C string literal below (PIPELINE_EVENT_
TAG_1_VALUE), and the signed NIP-01 tags array (event_id.c does not, and per
docs/qr-handoff-spec.md's wire contract must not, JSON-escape the tag value
itself) -- so an unrestricted tag could inject into a build's own generated
header or corrupt its own signed serialization.

Usage:
  gen_event_profile.py --privkey <path> --template <path> --out <path>
                        --label <str> --manifest <path> [--commit <sha>]
                        [--created-at <epoch>] [--tag <str>]
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nostr_secp256k1 as secp  # noqa: E402

# Deliberately narrower than "ASCII": the per-game tag is embedded RAW into
# both a generated C string literal (PIPELINE_EVENT_TAG_1_VALUE) and the
# signed, UN-escaped NIP-01 tags array (see this file's own header comment),
# so `"`, `\`, and other C0-control/non-printable bytes must never be legal
# here -- this is the fail-closed gate for that, not the wire format's own
# per-byte contract (docs/qr-handoff-spec.md's TAG field itself is "0..10
# ASCII bytes", broader than this; this script is stricter on purpose for
# the values it will itself accept and bake).
TAG_VALUE_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Path to the single JSON source of truth for the wire layout (spec #52,
# sub-issue #54) -- this script reads TAG's own "max_size" from there rather
# than hand-duplicating the 10-byte v7-MEDIUM budget as a second literal
# that could silently drift from tools/gen_format_descriptor.py's own
# rendering of the same field.
FORMAT_DESCRIPTOR_JSON = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "src", "pipeline", "format_descriptor.json"
)


def load_tag_max_size(path):
    with open(path, "r") as f:
        descriptor = json.load(f)
    for field in descriptor["fields"]:
        if field.get("name") == "TAG" and field.get("var_len"):
            return field["max_size"]
    raise ValueError("%s: no var_len TAG field found" % path)


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
    ap.add_argument(
        "--tag",
        default="sm64",
        help="per-game `t` tag value baked into this build and packed onto the wire "
        "(format v2, spec #52 sub-issue #54); must match [A-Za-z0-9._-]+ and fit "
        "within format_descriptor.json's TAG.max_size (10 B at v7-MEDIUM). "
        "Defaults to \"sm64\" -- this repo's only game today.",
    )
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

    if not TAG_VALUE_RE.match(args.tag):
        sys.stderr.write(
            "gen_event_profile.py: FATAL: --tag %r contains a character outside "
            "[A-Za-z0-9._-] -- this value is embedded raw into a generated C string "
            "literal AND the signed, un-escaped NIP-01 tags array, so `\"`, `\\`, "
            "whitespace, and other punctuation/control bytes are rejected, not just "
            "non-ASCII\n" % args.tag
        )
        return 1

    try:
        tag_max_size = load_tag_max_size(FORMAT_DESCRIPTOR_JSON)
    except Exception as e:
        sys.stderr.write(
            "gen_event_profile.py: FATAL: could not read TAG's max_size from %s: %s\n"
            % (FORMAT_DESCRIPTOR_JSON, e)
        )
        return 1

    game_tag_bytes = args.tag.encode("ascii")
    if len(game_tag_bytes) > tag_max_size:
        sys.stderr.write(
            "gen_event_profile.py: FATAL: --tag %r is %d bytes, over the %d-byte "
            "per-game tag budget (format_descriptor.json's TAG.max_size); a longer "
            "tag requires moving to a wider format (docs/adr/0002), not a silent "
            "truncation\n" % (args.tag, len(game_tag_bytes), tag_max_size)
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
        .replace("@GAME_TAG@", args.tag)
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
            "game_tag": args.tag,
            "build_date": build_date,
            "commit": commit_sha,
            "event_profile_h": os.path.basename(args.out),
        },
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
