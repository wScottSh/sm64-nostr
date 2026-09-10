# Animated / fountain-coded QR (UR / MUR / SeedQR) vs. the ADR-0005 generic-camera invariant

**Question.** Could an animated / multi-frame / fountain-coded QR (Uniform Resources
UR/MUR, or SeedQR) "dissolve" the single-frame capacity limit so the airgapped
SM64 cabinet never has to aggressively strip its signed Nostr event — **without**
breaking ADR-0005's invariant (a *generic phone camera* reads one URL QR, opens
it in a browser, installs nothing, far side reconstructs nothing)?

**Bottom line (decision-grade):**
- **(A) Do UR / MUR / SeedQR require a dedicated reader app? YES.** All three are
  bare, non-URL payload formats. None is an `http(s)` URL a stock camera can open.
  MUR additionally requires a reader that *accumulates frames over time* — a stock
  camera reads exactly one frame and cannot accumulate a stream at all.
- **(B) Can animated QR coexist with ADR-0005's generic-camera / no-app invariant?
  NO — not in the "static QR pattern" form.** Any multi-frame stream needs an
  accumulating reader. The *only* way to keep "open a URL, install nothing" is to
  invert the flow: the static URL QR opens a **web page (PWA)** that then uses the
  phone camera (`getUserMedia`) to scan the animated frames. That is feasible, but
  it resurrects a dedicated frame-accumulating *reader* (just delivered as a web
  page instead of an app store install) — exactly the "dedicated companion" role
  ADR-0001 was retracted for and ADR-0005 forbids for the primary path.
- **(C) Does our payload even need it? NO.** At 65–103 B packed the event already
  fits one frozen v7-MEDIUM (45×45) frame. Multi-frame buys nothing at this size;
  it only becomes relevant if we deliberately abandon stripping and carry a much
  larger (rich / multi-star / metadata-heavy) payload beyond single-frame capacity.

---

## 1. SeedQR (SeedSigner)

**Source:** `https://raw.githubusercontent.com/SeedSigner/seedsigner/dev/docs/seed_qr/README.md`

**Encoding.** BIP-39 mnemonic → each word's index in the 2048-word English list →
zero-padded to exactly 4 digits → concatenated → a single **numeric-mode** QR.
Spec: *"Each index must be exactly four digits, so shorter numbers must be
zero-padded (`12` becomes `0012`)."* E.g. "vacuum" (1924) → `1924`, "bridge"
(222) → `0222`.

**Digit math.**
- 12 words × 4 digits = **48 digits** (fits a 25×25 QR).
- 24 words × 4 digits = **96 digits** (fits a 29×29 QR).

**Single-frame vs. animated.** **Single-frame.** Standard SeedQR and CompactSeedQR
are both one static QR, never an animated sequence.

**Reader requirement.** The QR content is a **bare digit string** (e.g.
`192400221...`), not a URL. A stock camera *can* decode the digits (the spec notes
"any smartphone can decode the numeric digit stream"), but a raw decimal string is
meaningless to a browser — it opens nothing and does nothing. Turning those digits
back into a seed requires software that knows the SeedQR convention (the SeedSigner
device or an equivalent app). CompactSeedQR is binary mode and *"requires
specialized tools (like ZBar or zxing.org) for recovery."* **Verdict: dedicated
interpreter required; not browser-openable.** SeedQR is also irrelevant to our need
— it is single-frame and only encodes a 12/24-word mnemonic, not an arbitrary
signed event.

## 2. Single-part UR (BCR-2020-005)

**Source:** `https://raw.githubusercontent.com/BlockchainCommons/Research/master/papers/bcr-2020-005-ur.md`

**Base text encoding.** Bytewords. Spec: *"The method of encoding binary data as
printable characters specified in this proposal is Bytewords."* (Not bc32; not a
minimal alphanumeric scheme.)

**Form.** *"A single-part UR has the following form: `ur:<type>/<message>`"*, e.g.
`ur:seed/oyadhdeynteelblrcygldwvarflojtcywyjytpdkfwprylienshnjnplu...`.

**URL or private scheme?** `ur:` is its own **URI scheme**, not `http`/`https`.
A stock phone camera / browser will **not** navigate to it (there is no host to
GET); it is a scheme only a wallet/app that registered/understands `ur:` decodes.
**Verdict: not a browser-openable URL.**

**Byte-expansion overhead.** UR carries a **CRC-32** and is Bytewords-encoded. The
Bytewords *minimal* style (BCR-2020-012) is **2 characters per byte** — *"Only two
letters of each word (the first and last) are required to uniquely identify each
byte value, making a minimal Bytewords encoding as efficient as hexadecimal (2
characters per byte)."* So the payload roughly **doubles** in characters (like hex),
plus a 4-byte CRC (8 chars) plus the `ur:<type>/` prefix. Note Bytewords minimal is
**lowercase**; QR **alphanumeric mode requires uppercase** — so `ur:...` as written
does **not** pack into QR alphanumeric mode efficiently (it drops to byte mode, the
least dense). This is strictly *worse* on a per-frame basis than the tight numeric/
URL-safe packing ADR-0005 already uses.

## 3. Multipart UR / fountain codes (MUR, BCR-2024-001)

**Source:** `https://raw.githubusercontent.com/BlockchainCommons/Research/master/papers/bcr-2024-001-multipart-ur.md`
(pointed to from BCR-2020-005: *"For all the details, see the Multipart UR (MUR)
Implementation Guide."*)

**Form.** *"A multi-part UR has the following form: `ur:<type>/<seq>/<fragment>`"*
where `seq` = `<seqNum>-<seqLen>`. Each frame is one such UR string, rendered as one
QR, cycled as an animation.

**Fountain mechanism (Luby transform, hybrid).** First `seqLen` parts are
fixed-rate: *"The first `seqLen` parts of the message are fixed-rate and can by
themselves be used to reconstruct the original message."* Beyond that it goes
rateless: *"When requested to generate parts where `seqNum` > `seqLen`, will
generate rateless parts. Hence values like `seq = 11-10` and up are normal, and
indicate rateless codes."* Each rateless part is a pseudo-random **XOR mix** of a
subset of fragments (BCR-2020-005: *"MUR fountain codes … include a pseudo-random
'mix' of one or more fragments in each part where `seqNum` > `seqLen` … overlaid
using XOR."*). Which fragments mix into a part is **deterministic** from the part's
seqNum + the message checksum, so *"no additional metadata needs to be
transmitted."*

**Reconstruction — the decisive property.** The receiver must **collect parts over
time** until it has enough to solve for every fragment: decoding proceeds *"until
the set of received fragments is now equal to the set of expected fragments,"* and
*"Any sufficiently large set of codes can be used to reconstruct the entire
message,"* any order. Fountain codes need modestly **more parts than pure fragments**
(overhead typically ~1.05–2× the raw fragment count, the resilience tax for
lossy/any-order capture). **This fundamentally requires a stateful reader that
buffers and XOR-solves across many frames.** A stock phone camera captures a single
still and opens a single URL — it has **no mechanism to accumulate an animated
stream**, so it cannot read MUR at all.

**Per-frame overhead.** Every frame re-pays `ur:<type>/` + `seq` + a CBOR header
(`seqNum, seqLen, messageLen, checksum, data`) + Bytewords 2×-expansion + CRC. So
total transmitted characters ≈ (payload × ~2 for Bytewords) × (~1.05–2 fountain
overhead) + per-frame framing — several times the raw byte count spread across
frames.

## 4. The decisive question for this project

**Do UR / MUR / SeedQR let animated QR keep the ADR-0005 property (generic camera
opens a URL, installs nothing)? No.**

- None of the three is an `http(s)` URL. SeedQR is a bare digit string; `ur:`/MUR
  is a private URI scheme. A stock camera opens nothing useful from any of them.
- MUR additionally *requires* a frame-accumulating decoder — the exact opposite of
  a one-shot camera scan.

So all of UR / MUR / SeedQR **fundamentally require a dedicated reader
application** that captures, buffers, and reconstructs. Adopting any of them for the
primary path **resurrects the "dedicated companion app" premise that ADR-0001 was
retracted for and ADR-0005 explicitly forbids.**

## 5. If a dedicated reader is unavoidable: the minimal form

The lightest dedicated reader is a **browser PWA**, no app-store install:
1. A **static** URL QR (ADR-0005 style) is scanned by the stock camera → opens a
   web page **once**.
2. That page requests camera access via **`getUserMedia`** and runs a JS QR decoder
   plus a UR/fountain decoder (e.g. `@gandlaf21/bc-ur`, `ngraveio/bc-ur`) to scan
   the **animated frames** and XOR-reconstruct the payload in-page.

**Feasibility: yes** — "open a URL once from a static QR, then let the web page scan
the animated stream" is technically sound and needs no install. **But** note two
things honestly: (a) it is still a dedicated frame-accumulating reader — just
delivered as a web page rather than an installed app, so it re-introduces the role
ADR-0005 rejects for the primary flow, and inverts the invariant (the far side now
*reconstructs* from fountain parts, which ADR-0005's "zero far-side reconstruction"
bans for signed values unless framed strictly as lossless decode); (b) the cabinet
must now render and cycle an animated QR, which the current frozen-single-frame
design does not do. This is an *architecture change*, not a drop-in.

## 6. Does our payload need animated QR at all?

**No — not at current size.** Per ADR-0005 and the v7 capacity work (#98/#99), the
signed event is **65–103 B packed and already fits ONE frozen v7-MEDIUM (45×45)
frame** as a plaintext URL. Single-frame QR at v7-M has ample room; animated /
fountain QR buys **nothing** here and costs a stateful reader.

**When multi-frame becomes necessary vs. optional:**
- **Necessary** only if we deliberately abandon aggressive stripping and carry a
  payload that **exceeds single-frame capacity** — e.g. an un-stripped rich event,
  multi-star batch, embedded media/metadata, or anything pushing well past ~a few
  hundred URL-safe characters at the chosen ECC level.
- **Merely optional / not applicable** at 65–103 B. There is no capacity problem to
  "dissolve."

## Sources (primary, fetched)
- SeedSigner SeedQR spec — `https://raw.githubusercontent.com/SeedSigner/seedsigner/dev/docs/seed_qr/README.md`
- BCR-2020-005 Uniform Resources (UR) — `https://raw.githubusercontent.com/BlockchainCommons/Research/master/papers/bcr-2020-005-ur.md`
- BCR-2024-001 Multipart UR (MUR) fountain codes — `https://raw.githubusercontent.com/BlockchainCommons/Research/master/papers/bcr-2024-001-multipart-ur.md`
- BCR-2020-012 Bytewords (encoding / 2-chars-per-byte) — `https://raw.githubusercontent.com/BlockchainCommons/Research/master/papers/bcr-2020-012-bytewords.md`
- Local: `docs/adr/0005-airgap-reader-is-phone-camera-url-qr-zero-reconstruction.md`, `docs/adr/0001-companion-is-read-only-qr-is-self-contained.md`
