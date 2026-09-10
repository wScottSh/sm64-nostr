#!/usr/bin/env node
/*
 * Reference-oracle script for spec #24, sub-issue #28's id-equals-reference
 * assertion. NOT part of any build path (no Makefile target calls this,
 * and it is never a ROM input) -- it exists purely so the hardcoded
 * expected-id vectors in tools/pipeline_test/main.c
 * (test_event_id_matches_reference) are reproducible and auditable against
 * an independent oracle: the real `nostr-tools` npm package's own
 * getEventHash(), not a second implementation of the same algorithm.
 *
 * `nostr-tools` is genuinely independent of this repo's C serializer
 * (event_id.c): it's the reference JS library real Nostr clients/relays
 * use, maintained upstream, unrelated code, unrelated language. Its
 * serializeEvent()/getEventHash() (node_modules/nostr-tools/lib/cjs/pure.js
 * at the time this was run) is exactly:
 *
 *   JSON.stringify([0, pubkey, created_at, kind, tags, content])
 *   sha256(utf8Encoder.encode(that string)), hex-encoded
 *
 * which is the canonical NIP-01 id derivation this repo's event_id.c
 * implements by hand (see event_id.c's own header comment).
 *
 * Usage (requires `npm install nostr-tools` in this directory or a parent
 * node_modules -- deliberately not committed/vendored, since this script
 * is a one-off oracle run, not a build dependency):
 *   node tools/reference_event_id.js
 *
 * The output hardcoded into main.c (kExpectedIdA/B/C) was produced against
 * nostr-tools 2.25.2 (the latest version on the npm registry as of this
 * writing -- `npm view nostr-tools version`). getEventHash()'s algorithm
 * (the JSON.stringify(...)+sha256(...) pair quoted in this file's own
 * header comment above, taken from that version's lib/cjs/pure.js) is a
 * straightforward, stable application of NIP-01 with no version-sensitive
 * behavior, so a version bump is not expected to change these outputs;
 * re-running this script after installing a newer nostr-tools is the way
 * to double-check that if ever in doubt.
 *
 * The pubkey/created_at/kind/tags below are the exact "baked serialization
 * prefix" tools/pipeline_test/Makefile bakes into its generated
 * event_profile.h (TEST_PRIVKEY_HEX = privkey 3 BIP-340 KAT,
 * TEST_CREATED_AT = 1700000000) -- see tools/pipeline_test/main.c's
 * kExpectedPubkeyHex, which must match PUBKEY_HEX here.
 *
 * Format v2 (spec #52, sub-issue #54): TAG_0 is now the spec-pinned
 * constant "ag-lb" (was "cabinet-leaderboard" pre-v2) -- see
 * src/pipeline/event_id.h's PIPELINE_EVENT_TAG0_VALUE (its single source)
 * and docs/adr/0001. TAG_1 ("sm64", the per-game tag) is unchanged.
 *
 * Format v3 (spec #109, sub-issue #111): a third tag, ["n","TEST"], is now
 * appended -- "TEST" is the exact --event-name tools/pipeline_test/Makefile
 * bakes into this host tool's generated event_profile.h (PIPELINE_EVENT_NAME),
 * shortened from the pre-#111 "HOST TEST" to fit the per-game tag + event
 * name inside the single-QR-symbol budget (see the Makefile's own comment).
 */
const { getEventHash } = require('nostr-tools');

const PUBKEY_HEX = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const CREATED_AT = 1700000000;
const KIND = 8064;
const TAGS = [['t', 'ag-lb'], ['t', 'sm64'], ['n', 'TEST']];

function makeEvent(course, act, coins, frames, nonce, keyId) {
  const content = JSON.stringify({ course, act, coins, frames, nonce, keyId });
  return { pubkey: PUBKEY_HEX, created_at: CREATED_AT, kind: KIND, tags: TAGS, content };
}

// The three StarCapture vectors asserted in main.c's
// test_event_id_matches_reference(). Every vector's content necessarily
// exercises the `"` -> `\"` content-escaping path (JSON keys are always
// quoted), which is why no separate non-escaping vector exists here.
const vectors = [
  { label: 'vector A (spec #24 format_descriptor test capture)', course: 15, act: 6, coins: 100, frames: 0x01020304, nonce: 0xcafe, keyId: 0 },
  { label: 'vector B (sub-issue #25 stub capture)', course: 9, act: 1, coins: 42, frames: 1234, nonce: 0xbeef, keyId: 0 },
  { label: 'vector C (all-zero edge case)', course: 0, act: 0, coins: 0, frames: 0, nonce: 0, keyId: 0 },
];

for (const v of vectors) {
  const event = makeEvent(v.course, v.act, v.coins, v.frames, v.nonce, v.keyId);
  console.log(v.label);
  console.log('  content:', event.content);
  console.log('  id:     ', getEventHash(event));
}
