# Software Self-Attestation on No-TEE Hardware (can a public ROM prove its own integrity?)

Research findings for GitHub issue #19 (Wayfinder RESEARCH ticket). Part of #4; explores **Model B** (ephemeral runtime key, provenance offloaded) and blocks the key-provenance decision (#10).

- **Repo:** wScottSh/sm64-nostr — SM64 C decompilation building an N64 ROM.
- **Platform:** VR4300 CPU (32-bit MIPS III, ~93.75 MHz), **no hardware crypto, no secure element, no TEE**, ~4–8 MB RAM, frequently run under **cycle-accurate, single-steppable emulators**.
- **New premise vs. #8:** Model B makes the ROM potentially **PUBLIC** and uses a throwaway (ephemeral) key generated at power-on. #8 already settled that a *hard-coded self-signing key* cannot be protected in a distributed binary. This ticket asks the adjacent question: can a public binary, on hardware with no root of trust, **prove its own code integrity to a remote verifier** — so provenance could be restored to a public ROM without an embedded secret?
- **Scope:** map the **landscape** of self-attestation techniques × what each defeats vs. does NOT — plus reframings. This is PLANNING/SPEC work: **not** an implementation, **not** a go/no-go call.

> **Note on verification (per working discipline):** claims below are tied to named primary sources. Where a source could not be fetched/read firsthand this session, it is flagged inline as *unverified-firsthand*. No inference is presented as a checked fact.

---

## 0. The one invariant that dominates everything

**Remote attestation is only as trustworthy as a root of trust the target cannot forge.** A verifier believes attestation Evidence *not* because the target computed it, but because a component the target **cannot control or emulate** vouched for it. On a device that is fully attacker-controlled — a single-steppable emulator, or open N64 hardware with no secret silicon — there is no such component: every byte of "measurement," every timing signal, every signature the device can produce, the attacker can also produce (or precompute) from the same public binary.

This is the exact mirror of #8's invariant. #8: *the signing key is in the clear at signing time, so it leaks.* #19: *the integrity Evidence is computed in an attacker-controlled environment, so it is forgeable.* Both collapse for the same structural reason — **no off-device / on-device secret or unforgeable anchor exists on this platform.** Every technique below is therefore a **speed bump or an honest-participant integrity hint**, never a proof against a motivated adversary. This is not a tooling gap; it is a corollary of the trust-anchor definition in the remote-attestation architecture itself (§2) and of Kerckhoffs/Shannon (§7).

---

## 1. Checksum-in-payload / runtime self-hashing

**The tempting idea:** embed a SHA/checksum of the ROM in the Nostr event payload (or have the ROM hash itself at runtime and emit the digest), so a verifier can confirm the event came from an unmodified build.

**Why it does not authenticate:**
- A program cannot straightforwardly *contain* a hash of its own full image (that requires a quine/fixed-point construction), but it can trivially **hash itself at runtime and emit the digest**. Either way the scheme is **spoofable**: the expected digest of a *public* ROM is itself **public**, so an attacker running a modified/emulated build simply computes the genuine ROM's digest and emits that constant. Nothing secret binds the emitted digest to genuine, unmodified execution.
- This is the classic **self-checksumming defeat (memory-split / split-TLB attack)**: Wurster, van Oorschot, Somayaji, *"A Generic Attack on Checksumming-Based Software Tamper Resistance,"* IEEE S&P 2005 — modern processors let instruction fetches diverge from data reads, so the checksum routine reads *clean* code while *modified* code executes; the attack is automated and is trivial under an emulator. https://conferences.computer.org/sp/pdfs/sp/2005/05_04_01.pdf (ACM DL: https://dl.acm.org/doi/10.1109/SP.2005.2) — *core claim verified via search excerpt + conference PDF; full-text read unverified-firsthand (local PDF renderer unavailable).*

**PARTIAL CREDIT — the one thing a payload checksum genuinely buys:**
- Against **honest, non-adversarial** participants a checksum catches **accidental corruption** (bad flash write, truncated download, bit-rot) — exactly the role of a CRC or of **W3C Subresource Integrity (SRI)**. SRI is the canonical "hash-as-integrity-hint, **not** authentication" case, and it is explicit that the guarantee comes from the digest arriving over a **trusted separate channel**: SRI mechanisms "authenticate only the server, not the content," and "Network attackers can alter the digest in-flight" if it is not delivered over a Secure Context. https://www.w3.org/TR/SRI/
- **Translation for this ticket:** a ROM checksum in the event payload is worth keeping as a *non-adversarial integrity hint* — it lets honest verifiers spot a garbled/corrupt client among themselves. It provides **zero** protection against a deliberate forger, because the forger controls the very value being checked and there is no trusted side-channel carrying the "true" digest.

---

## 2. Hardware-anchored remote attestation (the "right" answer — and why it needs silicon the N64 lacks)

**IETF RATS Architecture, RFC 9334** — *verified firsthand.*
- Roles (§4.1): **Attester** produces Evidence; **Verifier** appraises it into Attestation Results; **Relying Party** acts on the result.
- The load-bearing unforgeability assumption (§12.1.1): *"It is assumed that an Attesting Environment is sufficiently isolated from the Target Environment it collects Claims about and that it signs the resulting Claims set with an attestation key so that the Target Environment cannot forge Evidence about itself."*
- **Root of Trust** (§7.4): RoTs are the components "vouched for via Endorsements (because **no Evidence is generated about them**)" — i.e., they are trusted a priori because hardware makes them unforgeable, not because anything proves them. A trust anchor (§7.1) is "an authoritative entity via a public key… used to verify digital signatures."
- URL: https://www.rfc-editor.org/rfc/rfc9334

**The crux for a no-TEE device (synthesized, anchored to RFC 9334 firsthand):** §12.1.1's guarantee holds *only* if the Attesting Environment is "sufficiently isolated" from the Target and signs with a key the Target cannot reach. **The N64 provides no such isolation** — the entire environment is attacker-controlled (fully emulable/single-steppable), so the "Target" can read any signing key and compute any measurement or quote it likes. Attestation unforgeability is a property of the **hardware root of trust, not of the protocol**; remove the anchor and every measurement and signature becomes forgeable, so the Evidence carries no trust value.

**Measured / trusted-loader boot** (the "trusted loader" branch of the ticket) — *TCG detail unverified-firsthand (PDF not parsed); anchored to the firsthand RFC + kernel.org below.*
- TCG measured boot chains each stage's digest into a hardware-protected, append-only **PCR** via a **Root of Trust for Measurement (RTM)** before/as control passes; remote attestation "quotes" are signed by a **TPM-resident** Attestation Key. This requires an **immutable hardware anchor (RTM/CRTM)** plus a hardware-protected signing key. TCG PC Client Platform Firmware Profile: https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/
- **DRTM** (dynamic root of trust, Intel TXT / AMD SKINIT) does not escape hardware either — Intel TXT's measured launch is initiated by the CPU's `GETSEC[SENTER]` instruction with an Intel-signed Authenticated Code Module, all measurements sealed in TPM PCRs; there is no software-only DRTM. https://www.kernel.org/doc/html/next/x86/intel_txt.html — *verified firsthand.*
- **NIST SP 800-193** (Platform Firmware Resiliency): its mechanisms "are founded in Roots of Trust (RoT)" that must themselves be trusted and are realized in hardware anchors (TPMs, secure elements, immutable/ROM firmware). https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf — *unverified-firsthand (PDF unextractable; content from NIST summary + canonical URL).*

**Verdict:** measured/trusted-loader boot is real and strong — on platforms with an immutable measured anchor and a hardware-protected key. The N64 boot chain (§4) has neither.

---

## 3. Software-based (timing) attestation — SWATT, Pioneer — and why they break

This is the academic corner that *tries* to do attestation with **no extra hardware** — precisely the N64's situation. All papers below **verified firsthand** (PDFs downloaded and text-extracted).

**SWATT** — Seshadri, Perrig, van Doorn, Khosla, *"SWATT: SoftWare-based ATTestation for Embedded Devices,"* IEEE S&P 2004.
- Mechanism: verifier sends a nonce; the device does a **pseudo-random traversal of its entire memory** computing a checksum, which must return within a **tight expected time** — tampering forces "a detectable slowdown." "To circumvent SWATT, we expect that an attacker needs to change the hardware."
- **Load-bearing assumption:** "the verifier knows the exact hardware architecture and the expected memory contents of the device… the clock speed, the memory architecture and the instruction set architecture (ISA)… and the size of the device's memory."
- URL: https://netsec.ethz.ch/publications/papers/swatt.pdf

**Pioneer** — Seshadri, Luk, Shi, Perrig, van Doorn, Khosla, *"Pioneer: Verifying Code Integrity and Enforcing Untampered Code Execution on Legacy Systems,"* SOSP 2005.
- Primitive: **verifiable code execution** — a self-checking function returns a checksum; "if the checksum… is correct and is returned within the expected time," the dispatcher infers a dynamic root of trust exists and the target ran untampered.
- **Explicit assumptions (§2.2):** "the dispatcher knows the exact hardware configuration… the CPU model, the CPU clock speed, and the memory latency… the CPU… is not overclocked." And it must **assume away the proxy attack**: "We make this assumption to eliminate the proxy attack, where the untrusted platform asks a faster computing device (proxy) to compute the checksum on its behalf," and the adversary does "not replace the CPU with a faster one."
- URL: https://netsec.ethz.ch/publications/papers/pioneer.pdf

**THE KEY BREAK** — Castelluccia, Francillon, Perito, Soriente, *"On the Difficulty of Software-Based Attestation of Embedded Devices,"* ACM CCS 2009.
- Two generic attacks, implemented on real MicaZ/TelosB sensors: (a) a **return-oriented (ROP) rootkit** hiding malicious code in un-attested memory ("attesting only code memory is not sufficient"); and (b) a **code-compression attack** — "compress the original code in program memory and gain enough free space to store and run its malicious program," decompressing on-the-fly during attestation. Plus a "memory shadowing" attack on SWATT.
- On exact-hardware fragility: "the security of SWATT relies on some unique characteristic of the devices… Porting SWATT on a new device with a new instruction set or a different memory size dramatically changes the rules for both the attacker and the verifier, which can undermine the security of the scheme."
- **Conclusion:** *"secure time-based attestation schemes are very difficult, if not impossible, to design correctly. Time-based attestation schemes must rely on very tight timing bounds… Those properties rule out cryptographic functions… Design choices are then restricted to ad-hoc functions… which very often provide only weak security."*
- URL: https://s3.eurecom.fr/docs/ccs09_Castelluccia.pdf (ACM DL: https://dl.acm.org/doi/10.1145/1653662.1653711)

**Genuinity and its refutation** (the desktop precedent):
- Kennell & Jamieson, *"Establishing the Genuinity of Remote Computer Systems,"* USENIX Security 2003 — a **software-only** test: the machine computes a checksum over memory **plus architecture-sensitive processor side effects** ("execution fingerprint"), returned fast enough that a simulator/imposter supposedly cannot keep up; "requires no additional hardware." https://www.usenix.org/legacy/events/sec03/tech/kennell/kennell.pdf
- Shankar, Chew, Tygar, *"Side Effects Are Not Sufficient to Authenticate Software,"* USENIX Security 2004 — implements a **substitution attack** that defeats it, and concludes: *"These criticisms are not specific to Genuinity but apply to any system that uses side effect information to authenticate software. Therefore, we strongly believe that trusted hardware is necessary for practical, secure remote client authentication."* https://www.princeton.edu/~rblee/ELE572Papers/Fall04Readings/SideEffects.pdf (USENIX: https://www.usenix.org/conference/13th-usenix-security-symposium/side-effects-are-not-sufficient-authenticate-software)

**Why this whole family is a dead end for an emulated N64:**
- Every scheme's security rests on the checksum arriving **"within the expected time," which requires the verifier to pin exact hardware AND the prover to be unable to outsource the computation.** An **emulator violates both**: (1) the "hardware" is whatever the operator says it is — clock, memory latency, ISA timing are all attacker-supplied — so the verifier can never pin the exact configuration; and (2) the operator can run the genuine checksum on a **faster host / proxy** and answer within the window (the exact "proxy attack" Pioneer must assume away). The substitution and compression attacks (Shankar; Castelluccia) fit malicious code inside the timing margin even on the *genuine* device.
- Survey corroboration — Banks, Kisiel, Korsholm, *"Remote Attestation: A Literature Review"* (arXiv 2105.02466, 2020, *verified firsthand*): software attestation "relies on stronger assumptions than other types of remote attestation" — namely "that adversaries cannot collude with other devices, that the checksum and attestation code cannot be optimized further and that the attestation cannot be parallelized," and it "only work[s] if the Verifier communicates directly to the Prover" (one-hop); "if the local adversary has stronger computational capability the attestation could be computed on a faster machine thus breaking the attestation." https://arxiv.org/pdf/2105.02466

---

## 4. N64 boot chain, hardware fingerprinting, flashcarts

*n64brew.dev returns HTTP 403 to WebFetch; the CIC-NUS and PIF-NUS pages were read firsthand via the browser tool. Quotes below are firsthand from those pages unless flagged.*

- **The CIC lockout chip is per-REGION, not per-device — zero per-device entropy.** Its only "secrets" are per-variant IPL2/IPL3 seeds + checksum; the region bit is "hardcoded in the firmware, which makes the CIC region-locked." Seeds tie to the *variant*, not the individual cart/console. https://n64brew.dev/wiki/CIC-NUS
- **Seeds and algorithm are fully reverse-engineered and public** (firmware dumped via decapping/test-mode; faithful C reimplementation `jago85/UltraCIC_C` exists; full seed/checksum table published, e.g. 6102 seed 0x3F). https://n64brew.dev/wiki/PIF-NUS
- **The IPL3 boot checksum is an anti-piracy check, publicly recomputable.** IPL3 DMAs the first 1 MB of ROM, runs an 8-byte checksum, and compares it "against the checksum stored at offset 0x10 in the ROM"; mismatch halts the VR4300. But the expected value lives **in the ROM header itself** and the algorithm is public (the `n64crc` tool implements it) — "When building a homebrew ROM… it is necessary to compute this checksum… and store the result in the header." An attacker/emulator recomputes it freely. https://n64brew.dev/wiki/PIF-NUS
- **No factory-injected per-device secret exists anywhere on N64 hardware.** The CIC challenge/response (fully implemented only on 6105/7105) is a *shared* algorithm + ROM tables, all reverse-engineered — a shared secret, not a device-unique key/fuse/serial. Corroborating: https://www.retroreversing.com/n64bootcode
- **Flashcarts expose no unspoofable per-device secret.** SummerCart64 (the most-documented, fully open-source cart): its only identity command `IDENTIFIER_GET` returns a **fixed constant** ("always `SCv2` in ASCII"); `VERSION_GET` returns firmware version; no config option is a serial. https://github.com/Polprzewodnikowy/SummerCart64/blob/main/docs/03_usb_interface.md , https://github.com/Polprzewodnikowy/SummerCart64/blob/main/docs/04_config_options.md . Flashcarts implement CIC via an FPGA/MCU "UltraCIC" clone — nothing binds a running ROM to genuine hardware. https://n64brew.dev/wiki/CIC-NUS
- **Under an accurate emulator the entire "hardware" is attacker-supplied.** ares ("focusing on accuracy and preservation") and cen64 (cycle-accurate) synthesize CIC responses, PIF behavior, COP0 `Count`/timing, and every cart register — so *any* hardware-derived signal (checksum, CIC challenge, cart serial, timing entropy) is forgeable by the operator. https://ares-emu.net/about , https://github.com/ares-emulator/ares

**Verdict:** the "hardware/flashcart fingerprinting" and "measured/trusted-loader boot" branches both die here — there is no per-device secret to fingerprint and no immutable, non-emulable anchor to measure from.

---

## 5. Proof-of-work commitments

- A PoW (hashcash-style) proves a prover "has performed a certain amount of computational work in a specified interval of time" — Back, *"Hashcash – A Denial of Service Counter-Measure."* http://www.hashcash.org/hashcash.pdf — *content verified via search; full-text unverified-firsthand.*
- **PoW does not bind to code identity.** It attests *effort*, not *which* binary produced it or that the binary was unmodified. An attacker's modified/emulated build produces an equally valid PoW. **PoW ≠ code attestation.** (A PoW *can* serve unrelated goals — rate-limiting / anti-spam / making mass forgery costlier — but it says nothing about integrity.)

---

## 6. Techniques × what they defeat — matrix

| Technique | Primary source | Raises cost / catches | Does NOT defeat |
|---|---|---|---|
| Checksum-in-payload / runtime self-hash | Wurster et al. S&P 2005; W3C SRI | **Accidental corruption among honest peers** (CRC/SRI-style hint) | Deliberate forger recomputes the public digest; split-memory attack; no trusted side-channel for the "true" value |
| Hardware remote attestation (TPM/RATS) | RFC 9334 §7.4/§12.1.1 | Tamper on platforms **with** a HW root of trust | N64 has no isolated Attesting Environment / HW key → Evidence forgeable |
| Measured / trusted-loader boot | TCG PCFP; NIST SP 800-193 | Boot tamper **with** immutable RTM + TPM | No immutable, non-emulable anchor on N64; IPL3 check is public/recomputable |
| Software/timing attestation (SWATT, Pioneer) | SWATT S&P'04; Pioneer SOSP'05 | Tamper **iff** verifier pins exact HW & no proxy | Emulator supplies any HW timing; proxy/faster-host; ROP + compression (Castelluccia CCS'09) |
| Genuinity-style side-effect fingerprint | Kennell-Jamieson '03 | (claimed) simulator too slow | Substitution attack (Shankar '04); "trusted hardware is necessary" |
| HW / flashcart fingerprinting | n64brew CIC/PIF; SC64 docs | Nothing usable | No per-device secret; CIC per-region & public; serials constant/clonable; emulator spoofs all |
| Proof-of-work commitment | Hashcash | Rate-limits mass forgery; raises spam cost | Says nothing about code identity/integrity |

**Row conclusion:** every row is a speed bump or an honest-participant hint. **None crosses the §0 invariant** — none proves integrity to a verifier against an adversary who holds the public ROM and runs it under an emulator.

---

## 7. What the PUBLIC-ROM premise changes (vs. #8's hidden-key premise)

**Making the ROM public does not create an attestation channel; if anything it removes the last friction.**

- **Kerckhoffs (1883):** security must rest on the **key alone**, not the design. https://www.petitcolas.net/kerckhoffs/
- **Shannon (1949):** assume "the enemy knows the system." *Communication Theory of Secrecy Systems,* BSTJ 28(4). https://archive.org/details/bstj28-4-656
- Once the ROM is public, the **expected self-hash, the IPL3 checksum, the CIC seeds, and the entire attestation routine are all public**, so a forger reproduces every "integrity signal" from the published artifact. The public-ROM move (Model B) is *fine for openness* but buys **nothing** for provenance: it trades a non-protectable embedded key (#8) for a non-attestable public binary (#19). Provenance cannot be recovered from within the client.

---

## 8. Ackoff SOLVE / RESOLVE / DISSOLVE

Russell Ackoff, *The Art of Problem Solving* (Wiley, 1978): **dissolve** = redesign the system so the problem cannot arise.

- **SOLVE (make the ROM attest itself):** self-hashing + timing checks + anti-emulation + flashcart reads. Verdict: **fails** against the target threat model (§1, §3, §4). Provides only casual-attacker friction and an accidental-corruption hint. Not a solution.
- **RESOLVE (accept un-provable integrity; contain the blast radius):** treat any self-attestation signal as a **non-adversarial integrity hint only** — keep a payload checksum to catch corrupt/garbled honest clients (CRC/SRI role), while explicitly assuming a determined party can forge events. Pair with per-copy identifiers + a revocation/registration list so abuse is *survivable*, not *prevented* (mirrors #8's RESOLVE). Move real trust off the client.
- **DISSOLVE (stop requiring the client to prove its own integrity):** the strong move — put the root of trust where one can actually exist.

**Why the premise needs dissolving (Nostr-specific).** A Nostr event (NIP-01) is authenticated *solely* by a BIP-340 Schnorr signature over the event id — "whoever holds the key" is the author, full stop; the protocol has **no** notion of "this event was produced by unmodified code." Even a *perfect* integrity proof wouldn't attach to a Nostr event without a trusted party to appraise it and vouch for the result. https://github.com/nostr-protocol/nips/blob/master/01.md , https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

**Where trust can actually live (dissolve options):**

| # | Reframing | Load-bearing idea | N64-feasible? |
|---|---|---|---|
| D1 | **Server-held signing key + unforgeable client witness** | The ROM never proves *itself*; it produces a witness/commitment of the achievement (a challenge/response transcript or play-trace commitment) that a **trusted server** validates and then signs the Nostr event. Root of trust = the server. | **Yes** (needs connectivity) — strongest dissolve; same conclusion as #8 |
| D2 | **Per-copy keys + revocation** | Contain blast radius of any forgery; leaks are revocable (AACS MKB / Widevine keybox + CRL style). Does not make integrity provable; makes abuse survivable. | Partially (provision at build/flash + online revocation) |
| D3 | **Server-side replay / re-simulation** | Server re-simulates the submitted play trace and validates the outcome itself — integrity of the *result* is checked by the trusted party, not attested by the client. | Yes (heavy server side; ZK on-console is infeasible per #8 §6) |
| D4 | **Non-adversarial integrity hint retained** | Keep the payload checksum purely to catch accidental corruption among honest participants; document it as NOT a security control. | Yes, trivially — the only honest "win" salvageable from §1 |

**N64-feasible synthesis:** there is **no on-client path** to provable integrity on this platform. The only real recovery of provenance is **D1 (+ D2/D3)** — a trusted server holds the signing key and validates an unforgeable witness — which is the same destination #8 reached from the key-secrecy side. A payload checksum (D4) is worth keeping as an honest-participant corruption hint, clearly labeled as non-security.

- Ackoff, *The Art of Problem Solving,* Wiley 1978.
- AACS Media Key Block: https://aacsla.com/wp-content/uploads/2019/02/AACS_Spec_Common_Final_0953.pdf
- Widevine keybox provisioning: https://docs.nxp.com/bundle/UG10158/page/topics/provisioning_widevine_l1_keybox.html

---

## 9. Honest bottom line

1. **A public N64 ROM cannot prove its own code integrity to a remote verifier by any surveyed means.** The wall holds. This is settled by the §0 invariant + RFC 9334's trust-anchor definition + the software-attestation literature's own stated assumptions — not a tooling gap.
2. **Checksum-in-payload / self-hashing is spoofable** (the expected digest of a public ROM is public; split-memory attack, Wurster 2005). It survives only as a **non-adversarial integrity hint** (CRC/SRI role) that catches **accidental** corruption among honest participants — *partial credit, clearly labeled*.
3. **Hardware and measured-boot attestation are real but require an immutable HW root of trust and a hardware-protected key** (RFC 9334; TCG; NIST SP 800-193) that the N64 does not have and an emulator fully supplies.
4. **Software/timing attestation (SWATT, Pioneer) is broken for this threat model:** it assumes the verifier pins exact hardware and the prover cannot proxy — both false under emulation — and is defeated by substitution/ROP/compression attacks (Shankar 2004; Castelluccia CCS 2009), whose authors conclude such schemes are "very difficult, if not impossible, to design correctly" and that "trusted hardware is necessary."
5. **The N64 has no per-device secret** (CIC is per-region and fully public; IPL3 checksum is a recomputable anti-piracy check; flashcart serials are constant/clonable) and **proof-of-work does not bind to code identity.**
6. **Model B does not restore provenance on-client.** It trades #8's non-protectable embedded key for #19's non-attestable public binary. The real move is to **DISSOLVE**: a trusted server holds the signing key and validates an unforgeable client witness (D1 + D2/D3) — the same destination #8 reached. Keep a payload checksum only as an honest-corruption hint (D4).

*This document maps the landscape only. It is not an implementation and not a go/no-go recommendation.*
