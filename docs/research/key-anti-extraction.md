# Key Anti-Extraction Landscape (white-box / obfuscation / key-splitting on VR4300)

Research findings for GitHub issue #8 (Wayfinder RESEARCH ticket).

- **Repo:** wScottSh/sm64-nostr — SM64 C decompilation building an N64 ROM.
- **Platform:** VR4300 CPU (32-bit MIPS III, ~93.75 MHz), no hardware crypto, no secure element, no TEE, ~4–8 MB RAM, frequently run under emulators.
- **CRUCIAL constraint:** this is an **open-source decompilation** — the source is public, and the feature would have the ROM self-sign fresh Nostr events with a hard-coded key.
- **Scope of this document:** map the solution **landscape** — techniques × what each defeats vs. does NOT — plus reframings. This is PLANNING/SPEC work: **not** an implementation, **not** a go/no-go call.
- **Agreed framing (with the human):** a truly unextractable key in a public self-signing binary is generally considered **impossible**. We are not chasing a provable guarantee. The deliverable is "strongest-available hardening + honest threat model."

> **Note on verification (per working discipline):** claims below are tied to named primary sources. Where a source could not be fetched/read firsthand this session, it is flagged inline as *unverified-firsthand*. No inference is presented as a checked fact.

---

## 0. The one invariant that dominates everything

The private key (or the signing operation over it) **must be in the clear at the instant the signature is computed.** An attacker who holds the full binary and can single-step it under an accurate emulator can set a breakpoint at the signing routine and read the key from registers/RAM at the point of use.

Every technique in this document is therefore a **cost/time speed bump**, not cryptographic secrecy. Nothing on this platform changes the invariant, because the platform has no off-device secret store (see §3, §6). This is not a fixable engineering detail; it is a corollary of Kerckhoffs/Shannon (§5).

---

## 1. White-box cryptography for ECC / Schnorr / EdDSA

**State of the art — thin and essentially unsolved for asymmetric signing.** The white-box literature is mature for *symmetric* ciphers (AES/DES) and comprehensively *broken*. For public-key signing it is a small, young, mostly negative-result corner.

- The **only public benchmark** for asymmetric white-box is the WhibOx contest, which targeted **AES** in 2017/2019 and **ECDSA on NIST P-256** in **2021/2024**. WhibOx 2021 result: **no submission survived more than two days.**
  - "ECDSA White-Box Implementations: Attacks and Designs from the WhibOx 2021 Contest," Barbu et al., IACR ePrint 2022/385 / TCHES 2022 — *"securing ECDSA in the white-box model is an open and challenging problem, as no implementation survived more than two days."* https://eprint.iacr.org/2022/385
  - "Attacks Against White-Box ECDSA … WhibOx Contest 2021," Bauer et al., ePrint 2022/448 — systematizes the attacks; confirms **zero survivorship**. Absence of a trustworthy randomness source in-white-box is singled out as devastating for ECDSA (nonce leakage → key recovery). https://eprint.iacr.org/2022/448
  - "White-Box ECDSA: Challenges and Existing Solutions," CARDIS 2021 (LNCS 13173) — most *commercial* products advertise ECDSA, yet the asymmetric case "has been very little studied" academically: a gap between marketing and published science. https://link.springer.com/chapter/10.1007/978-3-030-89915-8_9
  - WhibOx contests: https://whibox.io/contests/2021/ , https://whibox.io/contests/2024/
- **No credible academic white-box for Schnorr or EdDSA/Ed25519** was found. Nostr uses BIP-340 Schnorr on secp256k1 (§6) — precisely the scheme with **no** robust white-box treatment. Treat any vendor claim of "white-box Schnorr/Ed25519" as unverified marketing.

**Known breaks (uniform, automated, low-skill-once-tooled):**
- **Differential Computation Analysis (DCA)** — Bos, Hubain, Michiels, **Teuwen**, CHES 2016 (best paper). Records software execution/memory-access traces via dynamic binary instrumentation and correlates — extracts the key from *all publicly available non-commercial white-box implementations* with **no** knowledge of the tables and **no** reverse engineering. (Associated open tooling: "SideChannelMarvels / Deadpool," Philippe Teuwen.) https://www.iacr.org/archive/ches2016/98130106/98130106.pdf
- **Differential Fault Analysis (DFA) on white-box AES** — Quarkslab. Attacker controls execution, injects a late-round fault (Piret–Quisquater style), recovers the round key. Very low effort. https://blog.quarkslab.com/differential-fault-analysis-on-white-box-aes-implementations.html
- Every published (non-proprietary) white-box AES/DES has been broken by structural or grey/white-box analysis ("Another Nail in the Coffin of White-Box AES," ePrint 2013/455).

**Code-size / performance blowup (order of magnitude):**
- Canonical table-based white-box **AES-128** is ~**508–752 KB** of lookup tables (Chow et al. SAC 2002 ≈ 752 KB; Muir tutorial ePrint 2013/104 ≈ 508 KB) — roughly a **~10,000×** blowup vs. the ~176-byte round-key schedule, plus order-of-magnitude(s) slower execution via encoded table-lookup chains. https://eprint.iacr.org/2013/104.pdf
- "Space-hard" designs (below) deliberately push tables into the **MB range** as the security feature itself.
- **Implication for N64:** an MB-scale table budget on a cartridge (and the RAM to touch it) is heavy but not impossible; however, it buys **incompressibility**, *not* key-hiding for a signing scheme that has no working white-box in the first place.

**The theoretical floor:**
- **Barak, Goldreich, Impagliazzo, Rudich, Sahai, Vadhan, Yang — "On the (Im)possibility of Obfuscating Programs," CRYPTO 2001 (J.ACM 2012), ePrint 2001/069.** A general-purpose **virtual-black-box (VBB) obfuscator does not exist**; they explicitly construct *unobfuscatable signature schemes*. This is why white-box crypto has no VBB proof and must aim lower. https://eprint.iacr.org/2001/069
- **Key-extraction vs. code-lifting** — Delerablée, Lepoint, Paillier, Rivain, SAC 2013. Even a white-box whose key never leaks is defeated by **code-lifting**: copy the whole binary and use it as a signing oracle without ever learning the key. Key-hiding alone is insufficient as a goal. https://www.matthieurivain.com/files/sac13a_full.pdf
- Because VBB is impossible and code-lifting is unavoidable when the binary is copyable, the field redefined success as **one-wayness / incompressibility / space-hardness / traceability** (Delerablée et al. 2013; Bogdanov–Isobe "Space-Hard Ciphers," CCS 2015, https://dl.acm.org/doi/10.1145/2810103.2813699 ; "The Blob," arXiv 2004.04457). These are strongest for *symmetric* designs; extending provable incompressibility to ECDSA/Schnorr signing is exactly where WhibOx showed the field has no answer.

> *Unverified-firsthand:* ePrint 2020/104 ("On the Security Goals of White-Box Cryptography," TCHES 2020) PDF did not parse; its claims are from the abstract/secondary sources.

---

## 2. Obfuscation & anti-debug / tamper-proofing

- **Taxonomy:** Collberg, Thomborson, Low, "A Taxonomy of Obfuscating Transformations," Univ. of Auckland TR #148, 1997 — classifies transforms by *potency / resilience / cost*; introduces opaque predicates.
- **Control-flow flattening / opaque predicates:** Wang et al., "Software Tamper Resistance: Obfuscating Static Analysis," UVA TR CS-2000-12, 2000 — flattens the CFG behind a dispatcher + aliased data-dependent branches; reduces precise static recovery to alias analysis (argued NP-hard).
- **Self-checksumming / tamper-proofing:** Aucsmith, "Tamper Resistant Software: An Implementation," Information Hiding 1996 (integrity verification kernels; run-time decrypt/re-encrypt) https://link.springer.com/chapter/10.1007/3-540-61996-8_49 ; Chang & Atallah, "Protecting Software Code by Guards," ACM DRM 2001 (a network of small mutually-checksumming guards) https://link.springer.com/chapter/10.1007/3-540-47870-1_10 .
- **N64-specific anti-emulation (feasible):** read **COP0 Count** register for cycle-timing anomalies; RDP/RCP timing & framebuffer side-effects that inaccurate emulators get wrong; open-bus / cache quirks.

**What obfuscation defeats vs. does NOT:**
- **Defeats:** casual RE — static string/entropy scans for the key, quick RAM peeks, naive automated extractors, and *low-accuracy* emulators (a timing/RDP check can trip a bad emulator). Raises attacker time/skill cost.
- **Does NOT defeat** a determined attacker on an accurate, instrumentable emulator:
  - Self-checksumming → bypassed by the classic **split-memory attack**: Wurster, van Oorschot, Somayaji, "A Generic Attack on Checksumming-Based Software Tamper Resistance," IEEE S&P 2005 — feed unmodified pages to checksum reads while executing patched pages; trivial under an emulator. https://carleton.ca/scs/wp-content/uploads/TR-04-09.pdf
  - Anti-emulation/timing checks → fail against a cycle-accurate emulator, or are single-stepped and NOP'd out; Count can be spoofed. Also risk false positives on legitimate emulators.
  - Flattening/opaque predicates → defeated **dynamically**: single-stepping records the actually-executed path regardless of static confusion.
  - Endgame unchanged: breakpoint at signing, read key from registers/RAM.

> *Unverified-firsthand:* Wang et al. 2000 TR and n64brew hardware pages corroborated via secondary citations, not the primary docs.

---

## 3. Key-splitting / threshold-in-ROM / key derivation

- **Shamir Secret Sharing** — Shamir, "How to Share a Secret," CACM 22(11), 1979. https://dl.acm.org/doi/10.1145/359168.359176
  - *Defeats:* partial memory disclosure (attacker captures < k shares).
  - *Does NOT defeat:* if all n shares ship in the same ROM, the full-binary attacker has ≥ k shares by definition and reconstructs the key. SSS also *fully reconstructs the key at signing time*, exposing it in the clear under single-step. On N64 it is pure obfuscation, not a secrecy gain.
- **Threshold signatures / MPC** — Desmedt & Frankel, "Threshold Cryptosystems," CRYPTO '89; NIST Multi-Party Threshold Cryptography project https://csrc.nist.gov/projects/threshold-cryptography ; threshold ECDSA: Gennaro & Goldfeder, CCS 2018. Strictly stronger than SSS (never reconstructs the full key) **but** its security assumes an honest fraction of *independent* parties. A single emulated binary provides none: the attacker controls every "party," observes every share and MPC message, reconstructs or simply forges by running the protocol himself. No secrecy gain on N64.
- **Key derivation from ROM/hardware / PUFs** — Pappu et al., "Physical One-Way Functions," Science 2002; Gassend et al., "Silicon Physical Random Functions," CCS 2002. Would let a key never exist at rest — **but the N64 has essentially no usable per-device secret**:
  - **CIC lockout chip (NUS-CIC-6102):** an anti-piracy *authentication* chip, not a key store; its seed is hardcoded **per region, not per device**, and the whole algorithm + every seed is publicly reverse-engineered. Zero unique entropy. https://en.wikipedia.org/wiki/CIC_(Nintendo)
  - EEPROM/SRAM/FlashRAM save chips hold save data only; no factory-injected secret.
  - **Under emulation the "hardware" is fully attacker-controlled** — the emulator supplies any CIC seed / response it likes, so even a hypothetical HW-derived key is trivially spoofed.

> *Unverified-firsthand:* n64brew CIC-NUS wiki returned HTTP 403; CIC specifics corroborated across the search index + Wikipedia + N64-dev sources, not read from the primary wiki text. Desmedt–Frankel and Gennaro–Goldfeder citations from knowledge, not re-fetched.

---

## 4. Techniques × what they defeat — matrix

| Technique | Primary source | Raises cost against | Does NOT defeat |
|---|---|---|---|
| White-box ECDSA/Schnorr | WhibOx 2021 (ePrint 2022/385, 2022/448) | Table-structure guessing; naive static extraction | DCA/DFA; **no scheme survived >2 days**; code-lifting (Barak; Delerablée) |
| Space-hard / incompressible WB | Bogdanov–Isobe CCS 2015 | Cheap *partial* code-lifting (must extract ~all MB of tables) | Full-binary copy; not demonstrated for signing |
| Shamir SSS | Shamir 1979 | Partial memory disclosure (< k shares) | Full-binary extraction; key in clear at signing |
| Threshold / MPC | Desmedt–Frankel 1989; NIST MPTC | Subset-of-parties compromise; no single full-key location | All "parties" in one emulated binary → reconstruct/forge |
| PUF / HW fingerprint | Pappu 2002; Gassend 2002 | Cloning & at-rest extraction **on HW with a real per-device secret** | N64 has none; emulator spoofs any HW response |
| Obfuscation / CFG flattening | Collberg 1997; Wang 2000 | Static analysis, string scans, casual RE | Dynamic single-step recovers real path |
| Anti-debug / anti-emulation | (COP0 Count / RCP timing) | Casual RAM peek; bad/inaccurate emulators | Accurate emulator + patched-out checks; false-positives on legit emulators |
| Self-checksumming / guards | Aucsmith 1996; Chang–Atallah 2001 | Naive binary patching | Split-memory / emulator attack (Wurster 2005) |

**Row conclusion:** every row is a speed bump. None crosses the §0 invariant.

---

## 5. What changes because the source is public (vs. a stripped binary)

**Essentially nothing improves; secrecy value collapses to ~zero.**

- **Kerckhoffs's principle (1883):** the system "must be able to fall into the hands of the enemy without inconvenience" — security must rest on the **key alone**, not the design. https://www.petitcolas.net/kerckhoffs/
- **Shannon's maxim (1949):** assume "the enemy knows the system being used." "Communication Theory of Secrecy Systems," BSTJ 28(4). https://archive.org/details/bstj28-4-656
- **Open Design principle** — Saltzer & Schroeder 1975 → restated by **NIST SP 800-123** and SP 800-27 Rev A: *system security should not depend on the secrecy of the implementation.* https://csrc.nist.gov/pubs/sp/800/123/final
- **Schneier:** "obscurity means insecurity"; hidden systems don't get the public scrutiny that produces security. https://www.schneier.com/blog/archives/2014/02/the_insecurity_2.html

**Consequence for this ticket:** obfuscation/anti-debug provide near-zero *extra* secrecy in an open-source ROM vs. a stripped binary — you cannot hide what is published; the attacker reads the algorithm in the repo and only has to locate the key bytes/derivation, which the source describes. A hard-coded key in a public self-signing client is extractable *in principle by anyone*. The only genuine fix is to remove the requirement that a client-held secret stay secret (§6).

> *Unverified-firsthand:* NIST SP 800-123 and SP 800-27 PDFs did not render; the "open design" wording is from NIST's indexed text + Saltzer–Schroeder, not a clean PDF body fetch.

---

## 6. Ackoff SOLVE / RESOLVE / DISSOLVE — reframings

Russell Ackoff, *The Art of Problem Solving* (1978): **dissolve** = redesign the system so the problem cannot arise.

- **SOLVE (optimize the embedded key):** best-available white-box + obfuscation + anti-debug. Verdict: raises cost, never prevents; §1–§4. A partial mitigation, not a solution.
- **RESOLVE (good-enough tradeoff):** accept the key *will* leak and **contain the blast radius** — per-copy keys + a revocation/registration list (below). Doesn't make any key unextractable; makes leakage *survivable*.
- **DISSOLVE (remove the need for a client-held secret to stay secret):** the strong move.

**Nostr-specific reason the premise needs dissolving.** A Nostr event (NIP-01) is authenticated *solely* by a **BIP-340 Schnorr signature over the event id on secp256k1** — its identity is "whoever holds the private key," full stop; the protocol has no notion of "this key may only sign truthful achievements." If that key is embedded in a public/shared ROM, **any holder can forge arbitrary events indistinguishable from legit ones**, so "self-signing ROM as source of truth" collapses. The trust cannot live in the client key.
- NIP-01: https://github.com/nostr-protocol/nips/blob/master/01.md
- BIP-340 (Wuille, Nick, Ruffing, 2020): https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

**Reframings (each moves trust off the client key):**

| # | Reframing | Load-bearing idea | Cost / trust moved | N64-feasible? |
|---|---|---|---|---|
| B1 | **Remote attestation / HW root of trust** (TPM, TEE, Apple App Attest, Google Play Integrity) | Secret lives in tamper-resistant silicon, not shipped software; device signs a challenge, verifier checks a cert chain to a HW root | Requires trustworthy HW + verifier server | **No** — N64 has no such hardware |
| B2 | **Per-copy / per-device keys + revocation** (AACS Media Key Block; Widevine keybox + CRL) | Unique key per copy; a new MKB/CRL excludes revoked keys → one compromise ≠ all; leaks revocable | Needs a central authority to provision & re-issue + a channel to push revocations. Contains blast radius; does NOT make a key unextractable | Partially (provisioning at flash/build time + online revocation) |
| B3 | **Challenge/response with a server holding the real signing key** | The *server* signs; the ROM only *proves* it did something → **no secret on the client at all** | Requires network + trusted server; hard part becomes making the client's evidence unforgeable (see B5) | Yes (needs connectivity) — **strongest dissolve** |
| B4 | **TOFU / web-of-trust / third-party attestation** (SSH known_hosts; PGP WoT) | "Source of truth" comes from a trusted third party attesting / accumulated reputation, not from client self-signing | Trusts first contact (MITM risk) or human key-signing effort | Yes conceptually |
| B5 | **Commitment / verifiable computation / ZK — "the achievement is the witness"** | ROM commits to the play trace / final state; server later verifies or re-simulates. No long-term client secret | **SNARK/STARK proving is far too heavy for a 93 MHz N64 — a non-starter on-console.** A plain hash-**commitment** of the play trace IS feasible; trust moves to server replay | Commitment: yes. ZK proofs: **no** |

**N64-feasible dissolve (synthesis): B3 + B2/B5.** The ROM produces an unforgeable **witness/commitment** of the achievement (or a challenge/response transcript); a trusted **server** validates it and holds the real Nostr/secp256k1 signing key; per-copy identifiers + a revocation list contain any abuse. **No unextractable secret ever ships on the cartridge.** Hardware attestation (B1) and ZK proofs (B5) are the "right" heavyweight answers but are unavailable/infeasible on this platform.

- Ackoff, *The Art of Problem Solving*, Wiley 1978.
- AACS spec / Media Key Block: https://aacsla.com/wp-content/uploads/2019/02/AACS_Spec_Common_Final_0953.pdf
- Widevine provisioning: https://docs.nxp.com/bundle/UG10158/page/topics/provisioning_widevine_l1_keybox.html
- TOFU: https://en.wikipedia.org/wiki/Trust_on_first_use
- ZK cost: https://eprint.iacr.org/2024/050

> *Unverified-firsthand:* Apple App Attest PDF did not render; B1 corroborated via TCG/Google specs + an ACM TEE-attestation survey.

---

## 7. Honest bottom line

1. **A hard-coded key in a public self-signing N64 ROM cannot be made unextractable.** This is settled by the §0 invariant + Kerckhoffs/Shannon/Barak — not a tooling gap.
2. **White-box crypto does not rescue it:** no working white-box exists for Schnorr/EdDSA, and the one asymmetric scheme with a public track record (ECDSA) had **zero survivors** in the WhibOx contest. Even an unbroken white-box is defeated by code-lifting.
3. **Obfuscation / key-splitting / anti-debug are speed bumps** — worthwhile against casual attackers, string scanners, and low-accuracy emulators; worthless against a determined attacker single-stepping an accurate emulator. **Open source erodes even the speed-bump value.**
4. **The N64 has no hardware root of trust and no usable per-device secret**, so hardware-anchored approaches (B1, PUF) are inapplicable.
5. **The real design move is to DISSOLVE:** stop requiring a client-held secret to be secret. The feasible path is a **server-held signing key** + an **unforgeable client witness/commitment** + **per-copy keys with revocation**. That touches the (out-of-scope) trust layer, which is expected — it is where the problem actually lives.

*This document maps the landscape only. It is not an implementation and not a go/no-go recommendation.*
