# Offline Airgapped-Signer Provenance Patterns (hardware wallets / SeedSigner / Coldcard / PSBT-over-QR)

Research findings for GitHub issue #20 (RESEARCH ticket).

- **Repo:** wScottSh/sm64-nostr — SM64 C decompilation building an N64 ROM that, on star completion, produces a signed **Nostr** event (BIP-340 Schnorr / secp256k1) rendered as an **on-screen QR code** for a companion phone app to scan.
- **Platform constraint (dominates everything below):** the N64 has **no real-time clock**, **no network**, **no secure element / TEE / hardware root of trust**, and the ROM is an **open-source decompilation** (source is public). See sibling research `docs/research/key-anti-extraction.md` (issue #8) for the key-secrecy corollaries.
- **Context — "Model B":** the team is weighing an **ephemeral-key** provenance model in which the game is a *pure offline signer* handing a QR to an *online companion*, and provenance/timestamping is offloaded to that companion. This document surveys how established offline-signer ecosystems already do exactly that split, and extracts the reusable patterns.
- **Scope:** map the **landscape** of how airgapped-signer ecosystems (a) establish provenance / bind signer→identity, (b) timestamp with no RTC, (c) split trust between offline device and online coordinator. This is PLANNING/SPEC work — not an implementation, not a go/no-go.

> **Verification note (per working discipline):** every claim is tied to a named primary source with a URL. Where a source was read via search index rather than a firsthand page fetch, it is flagged inline as *unverified-firsthand*. No inference is stated as a checked fact.

---

## 0. The single structural insight the whole ecosystem is built on

Bitcoin airgapped signing works because it **splits one job into two roles that need different things**:

- the **offline signer** needs only the *private key* + the *intent to authorize* (and a trusted display to confirm what it is signing). It needs **no network and no clock**.
- the **online coordinator** needs *current state* (UTXOs, chain tip, fees), the *network* (to broadcast), and *time* (block height / timestamps).

Neither side alone can complete a transaction; neither side needs to trust the other with the thing the other holds. This is the pattern Model B is reaching for, and it is already fully standardized in Bitcoin as **PSBT + a transport + a coordinator**. Everything below is a specialization of this split.

---

## 1. The role split, standardized: BIP-174 PSBT

**BIP-174 (Partially Signed Bitcoin Transaction)** is the canonical formalization of "offline signer + online coordinator." Its stated purpose: *"This transaction format will allow offline signers such as air-gapped wallets and hardware wallets to be able to sign transactions without needing direct access [to the UTXO set]."*

The spec defines explicit **roles**, and the airgap runs along the role boundary:

| Role | Runs where | What it holds |
|---|---|---|
| **Creator** | online | builds the unsigned tx skeleton |
| **Updater** | online | adds UTXOs, scripts, BIP-32 derivation paths |
| **Signer** | **offline** | *"must only use the UTXOs provided in the PSBT to produce signatures"* — operates entirely from data inside the PSBT, no network |
| **Combiner** | online | merges partial signatures |
| **Finalizer / Extractor** | online | assembles + emits the network-ready tx |

Reusable takeaway: the offline device is deliberately **the smallest, dumbest, most auditable** role. It is handed a fully-specified thing-to-sign, it verifies + signs, it hands back a signature. It never learns state and never touches the network.
- BIP-174: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki

---

## 2. The transport: binary payloads across a QR airgap

An on-screen/animated QR is a lossy, capacity-limited channel. Two mature specs solve "push a multi-KB binary blob across it," and both are directly relevant to the sm64-nostr QR.

### 2a. Uniform Resources (UR) — Blockchain Commons, BCR-2020-005
Design goals quoted from the spec: *"Transport binary data of arbitrary content and length using a sequence of one or more URIs or QR codes"*; *"Use the alphanumeric QR code mode for efficiency."* Key mechanisms:
- **CBOR** for deterministic binary structure.
- **QR alphanumeric mode only** (the 45-char set) — because QR *binary* mode support is inconsistent across readers and Base64 (mixed-case) cannot use alphanumeric mode.
- **Multi-part / animated** sequences for payloads over one QR's capacity (a v40 QR maxes at 2,953 bytes).
- **Fountain codes (rateless encoding)** so a scanner can recover the whole message from *any* sufficient subset of an indefinitely-cycling animation — robust under missed frames.
- **CRC-32 of the whole message in each part** for integrity.
- UR spec: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md

### 2b. BBQr — Coinkite
An alternative multi-QR framing, built by the Coldcard team, optimizing pixel/byte density for constrained hardware signers: *"encodes larger files into a series of QR codes so they can cross air gaps."* Details: **Hex / Base32 / Zlib** encodings (Base32 = 5.5 bits per char within QR alphanumeric mode); optional **ZLIB** gives ~30% shrink even on high-entropy Bitcoin data; supports up to 3,470,600 bytes across 1,295 v40 QRs.
- BBQr: https://github.com/coinkite/BBQr

**Relevance to Model B:** a single Nostr event is small (~hundreds of bytes), so it likely fits in **one static QR** — the animated/fountain machinery is only needed if the payload grows (e.g., bundling a play-trace witness). The reusable lesson is the *encoding discipline* (alphanumeric mode, checksum per frame), not necessarily multi-part.

---

## 3. (a) Establishing provenance / binding the offline signer to an identity

Two fundamentally different philosophies exist. This is the axis that matters most for an open-source ROM with no secure element.

### 3a. Hardware root-of-trust + attestation (Ledger, Coldcard, Trezor)
The secret and the identity live in **tamper-resistant silicon provisioned at manufacture**:

- **Ledger:** during production *"each device's secure element generates a unique key pair … The private key is stored inside the secure element and cannot be extracted."* The public key is sent to Ledger's HSM, which *"signs the public key with the Ledger Root of Trust and sends it back to the device."* At runtime an HSM issues a **challenge**; the SE signs it; the server verifies the signature *and* that the SE's public key bears Ledger's root signature. This proves "a genuine Ledger SE signed this." Explicit limitation: *"A Genuine check cannot detect unauthorized physical modifications to the hardware … if the original Secure Element remains intact"* — attestation proves silicon genuineness, **not** end-to-end supply-chain integrity.
  - https://donjon.ledger.com/threat-model/device-genuineness/
- **Ledger "attestation proving code execution":** a stronger variant — an application signs a message *"concatenated with the running application hash by the Attestation key,"* so a verifier learns **both** the device is genuine **and** *which exact firmware/app version produced the output*. This binds an output to a specific trusted code identity.
  - https://www.ledger.com/attestation-redux-proving-code-execution-on-the-ledger-platform
- **Coldcard:** provenance is layered — a **numbered tamper-evident bag** (user confirms bag number matches the number the device displays), a boot-time **secure-element integrity check** driving **GENUINE (green) / CAUTION (red) LEDs** (*"the secure element checks the flash contents against its recorded checksum before lighting GENUINE"*), **signed-firmware** verification (release hash + PGP signature), **dual secure elements** from two vendors (Microchip ATECC608 + Maxim DS28C36B) for defense-in-depth, and per-device **anti-phishing words**.
  - https://coldcard.com/resources/security/coldcard-security-and-verification
  - Dual-SE / hardware detail (search-indexed): https://coldcard.com/docs/hardware/ — *unverified-firsthand*.

### 3b. Transparency / reproducibility instead of attestation (SeedSigner)
SeedSigner deliberately has **no secure element and no attestation**. It runs on generic hardware (Raspberry Pi Zero, radios physically disabled) and establishes trust through **openness + statelessness**: the entire OS is open source and users can *"build from the source code"* for *"maximum signer's trustlessness."* It is **stateless** — keys exist only in volatile RAM during a session; *"users can remove the MicroSD card"* and no key is ever persisted, defeating theft/forensic extraction.
- https://seedsigner.com/

**The decisive contrast for sm64-nostr:**
- 3a (attestation) binds an output to *a genuine, unique, tamper-checked device running known code*. **This is precisely what the N64 cannot do** — no SE, no per-device secret, no HW root of trust (see issue #8 findings). An open-source ROM under an emulator can be made to say anything.
- 3b (reproducibility) proves *"this is the real, unmodified firmware"* — which an open-source ROM **can** offer (reproducible build → known ROM hash). But note the ceiling: reproducibility proves *what the code is*, it does **not** prove *this running instance is authorized/unique/genuine*. On a copyable ROM, "the code is genuine" is true for every clone simultaneously. SeedSigner gets away with this because the *human owner* supplies the unique secret (their seed) into genuine code; sm64-nostr has no equivalent human-supplied per-instance secret.

---

## 4. (b) Timestamping with no real-time clock

This is where the ecosystem's answer is cleanest and most reusable: **the offline signer does not timestamp — time is treated as an online/consensus property, never generated on the airgapped device.**

- **Bitcoin offline signers never assert wall-clock time.** Where time matters (timelocks), it is expressed against **network consensus time**, not a device RTC. BIP-113 defines **Median Time Past (MTP)**: time-based `nLockTime`/CLTV are compared to *"the median timestamp of the 11 blocks preceding"* the including block — introduced *because "nodes couldn't be trusted to provide accurate timestamps."* MTP is **monotonic** (never goes backward) and lags real time by ~1 hour. The offline signer is simply *told* the current height/MTP by the coordinator; it never needs a clock of its own.
  - nLockTime / MTP: https://en.bitcoin.it/wiki/NLockTime
  - BIP-113 rationale (search-indexed via Bitcoin wiki Timelock): https://en.bitcoin.it/wiki/Timelock — *unverified-firsthand*.
- **OpenTimestamps** offloads timestamping *entirely* to an online anchor: hash the artifact locally, submit the hash to a **calendar server** which batches it into the Bitcoin blockchain; *"a timestamp proves that some data existed prior to some point in time"* and verification is trustless — *"anyone can independently verify that a document's hash was recorded on-chain at a particular block height."* No trusted timestamp authority, no device clock. This is the canonical "prove-existed-before-T without an RTC" primitive.
  - https://opentimestamps.org/

**Reusable pattern:** an offline device proves **"I authorized X"**; a separate online/consensus layer proves **"X existed by time T."** The two are decoupled. The signer supplies *authorization*, the network supplies *time* — and the timestamp is only as trustworthy as that online layer, never as the clockless device.

---

## 5. (c) Splitting trust between offline device and online coordinator

The universal division of labor across all of these systems:

| Concern | Offline signer | Online coordinator / companion |
|---|---|---|
| Private key custody | ✅ holds it, never emits it | ❌ never sees it |
| Current state (UTXOs / chain tip / relays) | ❌ | ✅ |
| Network / broadcast / publish | ❌ | ✅ |
| **Time** (height / MTP / created_at / anchor) | ❌ (no clock) | ✅ |
| **Intent confirmation** ("what am I signing?") | ✅ **trusted display** | ❌ (untrusted) |
| Provenance to the world | via signature + (attestation, if any) | relays/broadcasts + may add its own attestation/timestamp |

The load-bearing security invariant is **"don't trust the coordinator — verify on the trusted display."** The coordinator is assumed possibly-hostile; it can only ever *propose* a thing to sign. The offline device's screen is the one trusted surface where the human confirms the actual payload (destination, amount — or, for Nostr, the event content). This is why PSBT ships full derivation paths and UTXOs *to* the signer: so the airgapped device can independently verify the request rather than trust the coordinator's summary.

**Where this cracks for sm64-nostr:** the security of the split rests on (i) the offline device keeping its key secret and (ii) a *human* verifying intent on a *trusted* display. An open-source ROM under emulation satisfies neither — the "key" is extractable (issue #8) and the "display" is attacker-controlled. So the honest reading is that the N64 can borrow the *architecture* of the split but not its *security guarantees*.

---

## 6. The reusable pattern(s) for Model B

Distilled, the ecosystem hands Model B a ready-made blueprint:

1. **Keep the offline device tiny and dumb (PSBT Signer role).** The game should only ever *produce a signed artifact*; it should never try to be authoritative about state, network, or time. ✅ directly reusable.
2. **Treat the QR as the airgap transport, with encoding discipline.** Alphanumeric-mode encoding + per-frame checksum (UR/BBQr). Use multi-part/fountain only if the payload outgrows one QR. ✅ directly reusable.
3. **Never generate time on the clockless device; offload it to the online layer.** The companion stamps `created_at` and/or anchors the event's hash (OpenTimestamps-style) into a consensus layer. ✅ directly reusable — this *is* Model B's timestamping answer, and it is exactly how Bitcoin signers already behave.
4. **Provenance is the hard, only-partly-transferable part.** The ecosystem's strong answer (3a: HW root of trust + attestation binding output→genuine device→known code hash) is **unavailable on N64**. The available answer (3b: reproducible-build transparency) proves *the code*, not *the instance* — and on a copyable open-source ROM every clone is equally "genuine," so it cannot uniquely bind provenance to a legitimate play-through.

---

## 7. Ackoff SOLVE / RESOLVE / DISSOLVE

Russell Ackoff, *The Art of Problem Solving* (1978): **dissolve** = redesign the system so the problem cannot arise.

- **SOLVE (make the offline ROM itself a trustworthy signer):** add a per-device secret + attestation like a hardware wallet. **Verdict: impossible on N64** — no secure element, no HW root of trust, no per-device entropy, key extractable from a public ROM (issue #8). A hardware-wallet-grade *solve* is off the table on this platform.
- **RESOLVE (adopt the architecture, accept a weaker guarantee):** ship the *role split* — game as pure PSBT-style Signer, companion as coordinator that timestamps + publishes. Provenance rests on reproducible-build transparency (3b) + the companion's own online attestation. This buys a clean, standard, auditable structure and a real no-RTC timestamping story; it does **not** make the game's signature unforgeable. Blast-radius thinking (per-copy identifiers + revocation, per issue #8 §6) contains abuse.
- **DISSOLVE (move provenance off the clockless, keyless device entirely):** this is where the ecosystem quietly points. Notice that **SeedSigner's real root of trust is the human's seed injected into genuine code**, and **Bitcoin's real root of trust for time is the blockchain, not the signer.** The dissolve for Model B is symmetrical: **the game's ephemeral signature is not the provenance — it is only a *witness/commitment*; the authoritative identity, timestamp, and provenance all live in the online companion layer** (which *does* have a clock, a network, and can hold or gate a real key / anchor to a consensus timeline). The N64 stops trying to be a hardware wallet and instead becomes the *thing being attested about*, with the companion as the attesting party. This aligns with issue #8's DISSOLVE (server/companion-held real key + unforgeable client witness + per-copy revocation) — the offline-signer literature independently converges on the same move: **push identity, time, and provenance to the online side; leave the airgapped device holding only a confirmable intent.**

---

## 8. Honest bottom line

1. **The role split Model B wants is a solved, standardized pattern** (BIP-174 PSBT + UR/BBQr transport + coordinator). The *architecture* is directly reusable and worth adopting verbatim.
2. **Timestamping-without-RTC is cleanly solved by offloading time to the online/consensus layer** (Bitcoin MTP; OpenTimestamps). The airgapped device should never generate time. ✅ this is a genuine, transferable answer for Model B.
3. **Provenance is the part that does not transfer.** Every strong provenance mechanism in the ecosystem (Ledger/Coldcard/Trezor) depends on a **hardware root of trust the N64 lacks**; the one attestation-free approach (SeedSigner) still relies on a **human-supplied per-instance secret** that sm64-nostr has no analog for.
4. **Therefore the offline-signer literature reinforces issue #8's conclusion:** on this platform, provenance must be **dissolved off the device** — the game's (ephemeral) signature is a *witness*, and identity + time + provenance belong to the online companion. Adopt the *structure* of hardware-wallet airgap flows; do **not** expect their *security guarantees* on an open-source, clockless, secure-element-less ROM.

*This document maps the landscape only. It is not an implementation and not a go/no-go recommendation.*

---

## Sources

- BIP-174 PSBT — https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
- Uniform Resources (UR), BCR-2020-005 — https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md
- BBQr (Coinkite) — https://github.com/coinkite/BBQr
- SeedSigner — https://seedsigner.com/
- Coldcard security & verification — https://coldcard.com/resources/security/coldcard-security-and-verification
- Coldcard hardware features — https://coldcard.com/docs/hardware/ *(unverified-firsthand)*
- Ledger device genuineness / root of trust — https://donjon.ledger.com/threat-model/device-genuineness/
- Ledger attestation proving code execution — https://www.ledger.com/attestation-redux-proving-code-execution-on-the-ledger-platform
- Bitcoin nLockTime / Median Time Past (BIP-113) — https://en.bitcoin.it/wiki/NLockTime
- Bitcoin Timelock (MTP rationale) — https://en.bitcoin.it/wiki/Timelock *(unverified-firsthand)*
- OpenTimestamps — https://opentimestamps.org/
- Ackoff, *The Art of Problem Solving*, Wiley 1978.
- Sibling research: `docs/research/key-anti-extraction.md` (issue #8)
