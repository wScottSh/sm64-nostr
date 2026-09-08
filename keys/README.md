# Nostr pipeline event keys (spec #24, sub-issue #26)

The ROM build fails closed without a per-event secp256k1 private key here.
Nothing under `keys/` other than this file is version-controlled --
`event_privkey.hex` and `registry.md` are gitignored.

## Local/dev build

Generate a throwaway dev key:

```
python3 tools/gen_event_key.py
```

This writes `keys/event_privkey.hex`: 64 lowercase hex characters (32 raw
bytes), no `0x` prefix, trailing newline optional. The script refuses to
overwrite an existing key file.

Then build as usual (e.g. `make`). The build derives the event's x-only
pubkey from this key and bakes it, along with the fixed event shape (kind
`8064`, the `t` tags, and the build-epoch `created_at`), into a generated
header under the build directory -- never into `src/`.

## Real cabinet build

Replace `keys/event_privkey.hex`'s contents with the actual per-event
secret from whatever key-management process supplies it (per #10's
per-event rotation model: one key per physical cabinet build/event). Same
64-hex-char raw format.

## Registry

Every build appends a row to the gitignored `keys/registry.md`: event
label, derived pubkey (hex and npub), build date, and commit SHA -- so a
scanned event can later be attributed to the build that produced it,
out-of-band. Set `PIPELINE_KEY_LABEL=<label>` when invoking `make` to
control the label (defaults to `dev-event`).
