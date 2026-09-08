#!/usr/bin/env node
/*
 * Reference-oracle script for spec #24, sub-issue #29's independent-
 * verifier acceptance criteria. NOT part of any build path (no Makefile
 * target calls this, and it is never a ROM input) -- exactly like
 * tools/reference_event_id.js, this exists purely so the hardcoded BIP-340
 * signing KAT in tools/pipeline_test/main.c
 * (test_schnorr_signing_known_answer) is independently checked against a
 * genuinely separate implementation, not just re-derived by this repo's
 * own C signer/verifier grading its own homework.
 *
 * `@noble/curves` (its secp256k1.js module, which includes a `schnorr`
 * BIP-340 implementation) is genuinely independent of this repo's C
 * signer/verifier (secp256k1.c/schnorr_adapter.c): it's a real,
 * separately-maintained, widely-used upstream JS elliptic-curve library
 * (also the library nostr-tools itself depends on for signing/
 * verification), unrelated code, unrelated language, unrelated
 * implementation strategy (constant-time, optimized field arithmetic vs.
 * this repo's from-scratch, correctness-first port -- see secp256k1.h's
 * header comment).
 *
 * Usage (requires `npm install @noble/curves` in this directory or a
 * parent node_modules -- deliberately not committed/vendored, since this
 * script is a one-off oracle run, not a build dependency, mirroring
 * reference_event_id.js's own npm-install note):
 *   node tools/verify_schnorr_reference.js
 *
 * Run against @noble/curves 2.4.0 (the latest version on the npm registry
 * as of this writing) when producing the checks below.
 */
const { schnorr } = require('@noble/curves/secp256k1.js');

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

// BIP-340 official test vector 0 (bitcoin/bips, bip-0340/test-vectors.csv):
//   secret key = 3, aux_rand = 0, message = 32 zero bytes.
// This is also the exact key/aux_rand/message this repo's
// pipeline_schnorr_sign() is pinned against in
// tools/pipeline_test/main.c's test_schnorr_signing_known_answer() (and
// the same privkey = 3 already baked into TEST_PRIVKEY_HEX in this
// directory's own Makefile, used for the unrelated pubkey KAT).
const PRIVKEY_HEX = '0000000000000000000000000000000000000000000000000000000000000003';
const MESSAGE_HEX = '0000000000000000000000000000000000000000000000000000000000000000';
const AUX_RAND_HEX = '0000000000000000000000000000000000000000000000000000000000000000';
const EXPECTED_SIG_HEX =
  'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821' +
  '525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0';
const EXPECTED_PUBKEY_HEX = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';

const privkey = hexToBytes(PRIVKEY_HEX); // 32 bytes (64 hex chars)
const message = hexToBytes(MESSAGE_HEX);
const auxRand = hexToBytes(AUX_RAND_HEX);

const pubkey = schnorr.getPublicKey(privkey);
const sig = schnorr.sign(message, privkey, auxRand);
const sigHex = bytesToHex(sig);

let failures = 0;

function check(ok, what) {
  console.log((ok ? 'PASS' : 'FAIL') + ': ' + what);
  if (!ok) failures++;
}

check(bytesToHex(pubkey) === EXPECTED_PUBKEY_HEX, 'derived pubkey matches BIP-340 KAT (privkey=3)');
check(sigHex === EXPECTED_SIG_HEX, '@noble/curves own signature matches the published BIP-340 test vector 0');

// The independent-verifier acceptance criterion itself: @noble/curves
// accepts the pinned KAT signature (the same bytes
// tools/pipeline_test/main.c asserts pipeline_schnorr_sign() produces)
// against the pinned pubkey and message.
const expectedSig = hexToBytes(EXPECTED_SIG_HEX);
check(schnorr.verify(expectedSig, message, pubkey) === true,
  'independent verifier (@noble/curves) ACCEPTS the pinned KAT signature');

// Tampered-id rejection: flip one bit of the signed message (the event id,
// in the real pipeline) and confirm the same signature is rejected.
const tamperedMessage = Buffer.from(message);
tamperedMessage[0] ^= 1;
check(schnorr.verify(expectedSig, tamperedMessage, pubkey) === false,
  'independent verifier (@noble/curves) REJECTS the same signature against a tampered id');

// Spec #24, sub-issue #30's end-to-end build_event() vector: privkey 3
// (same KAT key as above) signing StarCapture "vector A"'s event id --
// 0xba237b9e...83cc, the exact id already independently pinned against
// nostr-tools in tools/reference_event_id.js and tools/pipeline_test/
// main.c's test_event_id_matches_reference()/kExpectedIdA -- rather than
// BIP-340's own all-zero test vector 0's message. This is the oracle value
// tools/pipeline_test/main.c's kBuildEventExpectedSig is pinned against
// (test_build_event_end_to_end), independently reproducing build_event()'s
// own pipeline_schnorr_sign() output for a real, non-canned message.
const VECTOR_A_ID_HEX = 'ba237b9e891ede4212571ded17bce2a616191ec67a7632d28dc9c547d35483cc';
const VECTOR_A_EXPECTED_SIG_HEX =
  '608b0fb8994c167a91c99e1ecc0bb47e3ba6b10c305dac235a0602ff2b64c10' +
  'ff3cf87989dadd2fca0ce678dfa19fcbf35004a779398bc5b16eab75c1502067e';
const vectorAMessage = hexToBytes(VECTOR_A_ID_HEX);
const vectorASig = schnorr.sign(vectorAMessage, privkey, auxRand);
check(bytesToHex(vectorASig) === VECTOR_A_EXPECTED_SIG_HEX,
  '@noble/curves signature for spec #24/#30 vector A (privkey=3, aux_rand=0, msg=vector A event id) ' +
  'matches the value pinned in tools/pipeline_test/main.c (kBuildEventExpectedSig)');
check(schnorr.verify(vectorASig, vectorAMessage, pubkey) === true,
  'independent verifier (@noble/curves) ACCEPTS the vector A signature against the vector A id');

if (failures !== 0) {
  console.log(failures + ' check(s) FAILED');
  process.exit(1);
}
console.log('All independent Schnorr verifier checks PASSED');
