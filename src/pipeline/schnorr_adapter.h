#ifndef PIPELINE_SCHNORR_ADAPTER_H
#define PIPELINE_SCHNORR_ADAPTER_H

/*
 * The BIP-340 Schnorr signing adapter (spec #24, sub-issue #29) -- the
 * pipeline-internal seam in front of the ported secp256k1.c/h (hidden
 * behind this header), mirroring event_id.h/qr_adapter.h/pack_adapter.h.
 * Like those, this file is pure: no MarioState, no globals, no N64
 * headers. It is compiled a second time, unmodified, into the host test
 * tool (tools/pipeline_test).
 *
 * Implements BIP-340's default signing algorithm exactly:
 *   1. d' = int(seckey); fail if d' not in [1, n-1].
 *   2. P = d'*G; d = has_even_y(P) ? d' : n - d'  (the keygen negation).
 *   3. t = bytes(d) XOR tagged_hash("BIP0340/aux", aux_rand).
 *   4. rand = tagged_hash("BIP0340/nonce", t || bytes(P) || m).
 *   5. k' = int(rand) mod n; fail if k' = 0.
 *   6. R = k'*G; k = has_even_y(R) ? k' : n - k'.
 *   7. e = int(tagged_hash("BIP0340/challenge", bytes(R) || bytes(P) || m)) mod n.
 *   8. sig = bytes(R) || bytes((k + e*d) mod n).
 *
 * aux_rand is always the fixed all-zero 32 bytes here (spec #24's signing
 * decision: "live-deterministic k = f(d, m) at grab, aux_rand = 0, full
 * pipeline determinism" -- NOT the content nonce field, which is a
 * separate value computed by the capture glue, per StarCapture.nonce16).
 * Message m is always the 32-byte event id (event_id.h's
 * pipeline_event_compute_id output) -- the thing being signed is the id,
 * not the raw event JSON.
 *
 * Called only from within src/pipeline/ (this file, and in a later
 * sub-issue, build_event.c, which is where #30's real signature-in-payload
 * wiring lands -- out of scope here). Game glue never calls this adapter,
 * or secp256k1.h, directly.
 */

#include "build_event.h"

#define PIPELINE_SCHNORR_MSG_SIZE 32
#define PIPELINE_SCHNORR_PRIVKEY_SIZE 32
#define PIPELINE_SCHNORR_SIG_SIZE 64

/*
 * pipeline_schnorr_sign: signs msg32 (the 32-byte event id) with privkey32
 * per BIP-340, aux_rand fixed at all-zero, writing the 64-byte signature
 * (R || s) to sig64. Returns nonzero (true) on success; returns 0 only in
 * the astronomically unlikely case that privkey32 is out of the valid
 * [1, n-1] scalar range, or the derived nonce happens to be exactly 0 mod
 * n (BIP-340's own documented failure cases) -- callers must check the
 * return value, never assume success.
 */
int pipeline_schnorr_sign(const pipeline_u8 msg32[PIPELINE_SCHNORR_MSG_SIZE],
                           const pipeline_u8 privkey32[PIPELINE_SCHNORR_PRIVKEY_SIZE],
                           pipeline_u8 sig64[PIPELINE_SCHNORR_SIG_SIZE]);

/*
 * pipeline_schnorr_verify: BIP-340 verification of sig64 against msg32 and
 * the 32-byte x-only pubkey32. Returns nonzero (true) iff the signature is
 * valid. This is an INTERNAL self-consistency check only (e.g. so a host
 * test can assert sign-then-verify round-trips and a tampered message is
 * rejected by this same math) -- it is NOT the independent verifier spec
 * #24/#29's acceptance criteria call for; that role is filled by a
 * genuinely separate implementation (@noble/curves, a real independently-
 * maintained JS library -- see tools/verify_schnorr_reference.js), never
 * by this function grading its own signer's homework.
 */
int pipeline_schnorr_verify(const pipeline_u8 msg32[PIPELINE_SCHNORR_MSG_SIZE],
                             const pipeline_u8 pubkey32[PIPELINE_SCHNORR_PRIVKEY_SIZE],
                             const pipeline_u8 sig64[PIPELINE_SCHNORR_SIG_SIZE]);

#endif /* PIPELINE_SCHNORR_ADAPTER_H */
