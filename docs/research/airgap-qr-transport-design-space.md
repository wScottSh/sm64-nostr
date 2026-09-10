# Airgap QR transport design space: is there a design strictly better than the animated-hook?

Decision-grade research for the **open-source, multi-operator** SM64-Nostr standard.
Investigates, against PRIMARY sources only, whether any transport beats the owner's
"animated-hook" given the newly-imposed constraints: **open standard (many
games/operators), no fixed or securable per-game URL, install-nothing / generic
camera, passive single-snap as the UX ideal, animation only as an offload, and the
zero-far-side-reconstruction invariant (ADR-0005).**

## Bottom line

**Yes — there is a design strictly better than the animated-hook for the owner's
stated value order, and it is the hybrid the owner already suspected:**

> **A canonical-resolver STATIC single frame as the default** — every operator's
> cabinet shows one static QR of the form `https://<one-shared-standard-domain>/<compressed-event>`
> pointing at ONE open-source, stateless, mirrorable decoder domain secured by the
> **standard** (not by each game) — **with the animated-hook demoted to a documented
> offload** used only when a payload genuinely exceeds one frame.

This is strictly better than "always animate" because it wins the passive single-snap
UX on the default path (a stock camera opens a real https URL and the event broadcasts
with **no** `getUserMedia`, no in-app-browser camera lottery), while still keeping the
animated-hook available for the overflow case. It costs the owner **exactly one
irreducible tradeoff: a single shared canonical resolver domain (a soft centralization /
liveness point)** — which is far cheaper than the per-game short domain the owner
correctly rejected, and is mitigable (mirrors, multiple fallback domains, offline PWA
cache, and — decisively — the event is self-verifying so the resolver can forge nothing).

**The irreducible tradeoff the owner must choose among** (proven as an impossibility
triangle in §5): you cannot simultaneously have (a) install-nothing/generic-camera,
(b) zero dependence on ANY canonical/fixed domain, and (c) passive single-snap. Any two
are achievable; all three are not. The owner must sacrifice exactly one:

- Sacrifice (b) → **canonical-resolver static QR** (the recommendation). One shared
  domain; passive snap; nothing installed.
- Sacrifice (c) → **animated-hook** (owner's current idea). No app, but the passive snap
  is an illusion: a stock camera only ever grabs ONE frame, so reassembly forces an
  active in-page `getUserMedia` scan loop — which is *itself* served from a canonical
  hook domain anyway, so it does not even buy you (b).
- Sacrifice (a) → **`nostr:`/`nevent` URI or BC-UR/BBQr dedicated reader** (the Bitcoin
  model). Decentralized and passive-ish, but requires an installed app and — separately —
  cannot even carry a whole self-contained signed event (§1).

**A second, harder truth the owner must confront (§0):** at the repo's *own* stated
format-v2 payload size (~112–122 B packed; the named-honest floor is ~119–121 B per
`nip01-signed-event-floor.md`), **no single v7-MEDIUM frame fits the event under ANY
URL wrapping** — not the canonical-resolver static QR, not a bare-binary QR. So "static
single frame" is only truly the default if the frozen footprint grows (v8/v9 or lower
ECC) OR the payload is trimmed to ≤~100 B. If the ~119–121 B floor is firm at v7-M, the
offload is not optional — it is the *only* path, and the animated-hook becomes load-
bearing rather than a fallback. This is the single most important thing to resolve before
committing to "static-by-default."

---

## 0. The payload-size reality check (do this first — it changes everything)

The task framing says the signed event is "~65–103 packed bytes and fits ONE QR frame
IF the URL is tiny." The repo's own deeper analysis says otherwise for a *named, honest*
event:

- `CONTEXT.md` (Format descriptor): "the **packed payload** (~112–122 B in **format v2**…)".
- `docs/research/nip01-signed-event-floor.md` bottom line: "The practical floor for a
  *named, honest* event is ~119–121 raw bytes, which needs a larger QR version (or a
  lower EC level / different geometry) than the frozen v7-M can provide." It shows the
  barest honest event *with no name* already ~885 bits > the 864-bit v7-M **L**-adjacent
  figure it used, and ~1080 bits with a name.

Reconciling the two capacity numbers used across the repo: `qr-v7-capacity-envelope.md`
uses **992 data bits (v7-M = 124 data codewords × 8)**; the floor doc uses **864 bits**
(a 108-codeword figure). The 992-bit figure is the correct v7-M number (Thonky/ISO-18004:
v7-M = 124 data codewords). This report uses **992 bits**. Even at 992 bits the named
event overflows (below).

**v7-M single-frame budget, recomputed (Design A: one all-uppercase, path-based
ALPHANUMERIC segment; header = 4-bit mode + 9-bit count = 13 bits; 5.5 bits/char):**

```
usable = 992 − 13 = 979 bits ;  T = floor(979 / 5.5) = 178 alphanumeric chars
```

Payload chars by URL-safe encoding, and the resulting URL-prefix budget
(`prefix = 178 − payload_chars`):

| Payload N (B) | base32 chars (8·⌈N/5⌉) | prefix budget | base42* chars (3·⌈N/2⌉) | prefix budget |
|---:|---:|---:|---:|---:|
| 65  | 104 | **+74** | 99  | **+79** |
| 96  | 160 | **+18** | 144 | **+34** |
| 100 | 160 | **+18** | 150 | **+28** |
| 103 | 168 | **+10** | 156 | **+22** |
| 112 | 184 | **−6 (overflow)** | 168 | **+10** |
| 121 | 200 | **−22 (overflow)** | 183 | **−5 (overflow)** |

*base42 = the bespoke URL-safe QR-alphanumeric base from `qr-v7-capacity-envelope.md` §5
(2 bytes → 3 chars over the ~42 QR-alnum-and-URL-safe chars). Non-standard; must be
co-implemented ROM-side and resolver-side.

**Reading of the table (verified arithmetic):**
- **≤~100 B:** a canonical-resolver **static** single frame fits comfortably with
  standard base32 and a real domain prefix (18-char budget → e.g. `HTTPS://SM64.LOL/`).
- **~103 B:** fits base32 only with a ~10-char prefix (very tight — `HTTPS://X.IO/`
  class), or comfortably with base42.
- **~112 B:** overflows base32 entirely; fits **only** with the bespoke base42 and a
  ≤10-char domain.
- **~119–121 B (repo's named-honest floor):** overflows v7-M under **every** encoding,
  even bare binary (base42 overflows by ~5 chars; base32 by ~22). No URL wrapping saves
  it. **This is the crux number.**

**Consequence for the whole decision:** "static single frame as default" is real and
recommended **iff** the committed payload is ≤~100–112 B (which may require dropping the
filterable event-name slug from the wire, or growing the frozen footprint to v8/v9 or
dropping to ECC-L). If the ~119–121 B named floor is firm at frozen v7-M, then **the
event does not fit one frame at all**, the offload is mandatory, and the design question
collapses to "which multi-frame reader" — where the animated-hook (web `getUserMedia`)
and a dedicated app are the only options. **Resolve the payload/footprint question first;
it dominates.**

---

## 1. Prior art in airgap payload-over-QR transport (primary sources)

### 1a. Bitcoin hardware-wallet animated QR — BC-UR, BBQr, and the reader model

Already established in `docs/research/animated-qr-ur-mur-seedqr.md` (BC-UR / MUR / SeedQR)
and confirmed/extended here for **BBQr** and the **wallet reader model**.

**BBQr (Coinkite)** — spec `raw.githubusercontent.com/coinkite/BBQr/master/BBQr.md`,
`bbqr.org`:
- **Encoding = Base32** (encoding letter `2`), chosen for QR alphanumeric-mode density.
  Verbatim: *"Base32 puts 5.0 bits into 5.5 bits of QR data and is closer to optimium in
  terms of packing"* (vs hex, which *"yields data transfer rate comparable to the QR
  code's native binary rate"*). Same density lever this repo already picked.
- **Multi-frame, FIXED INDEXED frames — not fountain codes.** 8-char header
  `B$` + encoding + file-type + 2 base-36 digits (total frames) + 2 base-36 digits (index).
  Verbatim: *"All 'N' QR codes must be scanned, there is no way to 'skip' one, but they do
  not have to be seen in any particular order."* (Contrast BC-UR's rateless fountain
  fragments.)
- **Bare payload, NOT a URL.** A frame looks like `B$2P0200…` — an opaque string. A stock
  camera gets nothing openable. Requires a dedicated BBQr-aware reader.

**Reader model — do they ALL assume a dedicated app/device? CONFIRMED YES.** None relies
on a generic stock phone camera with nothing installed:

| Wallet | Reader | Format | First-party source |
|---|---|---|---|
| Sparrow | Desktop coordinator + webcam | UR + BBQr | sparrowwallet.com/docs/airgapped-wallet-qr.html |
| SeedSigner | Device's own camera + a coordinator (Sparrow/Specter/Electrum/BlueWallet/Nunchuk) | UR | seedsigner.com |
| Keystone | Device's own camera + Keystone companion app | BC-UR | blog.keyst.one; KeystoneHQ dev hub |
| Foundation Passport | Device's own camera + Envoy app or Sparrow webcam | UR (+BBQr per firmware) | docs.foundation.xyz |
| Coldcard Q | Device's own QR scanner + Sparrow webcam | BBQr | coldcard.com/docs/qr-scanner |

**Why they chose bare-payload animated QR + dedicated reader over a URL/stock camera:**
deliberate **network isolation** of a cold signer. A URL is anathema — it implies
something that could phone home. **This is the decisive threat-model difference from this
project:** in the Bitcoin world the reading side must stay OFFLINE and must NOT resolve a
URL, so a stock-camera "scan → open link" flow is a *security regression*. In this
project the far side is **allowed to be online and merely broadcasts**, so a
stock-camera-openable https URL is a *feature, not a leak*. Their reasons for rejecting
URLs do not bind this design; only their **density engineering** (QR alphanumeric mode +
Base32, indexed multi-frame chunking) transfers.

### 1b. LNURL / Lightning Address — the compact-endpoint & shared-domain resolver pattern

Sources: `github.com/lnurl/luds/.../01.md`, `.../16.md`, `.../06.md`; BIP-173/BIP-350.

- **LUD-01:** *"LNURL is a bech32-encoded HTTPS/Onion URL that can be interacted with
  automatically by a WALLET in a standard way."* QR carries `LNURL1…`. Verbatim on QR:
  *"When used in QR-Codes they SHOULD be uppercase"* — to enable alphanumeric mode
  (BIP-173: uppercase in QR *"permit the use of alphanumeric mode, which is 45% more
  compact than the normal byte mode"*). bech32 expansion ≈ **1.6× raw URL bytes + 12
  fixed chars** — strictly *larger* data than the raw URL; the only win is alnum packing +
  a checksum.
- **`lightning:` scheme:** a **custom URI scheme**. On a phone with **no wallet
  installed**, nothing handles it (OS URI-scheme mechanics; reasoned, not a single quotable
  spec line — the LUDs always name `WALLET` as the actor). Dead end for stock camera.
- **LUD-16 Lightning Address — the KEY shared-domain pattern.** *"Upon seeing such an
  address, WALLET makes a GET request to `https://<domain>/.well-known/lnurlp/<username>`."*
  The username is a **path segment**, not a subdomain or its own domain, so **unlimited
  identities share ONE canonical domain + one well-known base path**, routed server-side —
  **no per-user DNS, no per-user cert, no per-user domain.** A `SERVICE` MAY also expose a
  domain default via `_` as username.
- **Brutally clear entry point:** LNURL's human-facing actor is **a dedicated Lightning
  WALLET, never a stock camera.** So LNURL is **prior art for the resolver/naming design**
  (compact QR names an https endpoint; many identities share one canonical domain via a
  well-known path) but a **counter-example on the entry point** — and its own fix is
  exactly the move recommended here: put an **actual `https://` URL** in the QR (which a
  stock camera opens) instead of a bech32 blob or a custom scheme.

**Takeaway:** LNURL is the single strongest external validation that *many operators can
share one canonical domain without any per-operator domain* — precisely dissolving the
owner's "can't secure a per-game URL" objection — but it also proves that if you want the
**stock-camera** entry, the QR must be a plain https URL, not an encoded scheme blob.

### 1c. Nostr's own URI story — NIP-19 / NIP-21 / njump (and why none of it fits)

Sources: `raw.githubusercontent.com/nostr-protocol/nips/master/{19,21,89}.md`;
`github.com/fiatjaf/njump` (`nostr.go`).

- **NIP-19 sizes.** `note1…` = HRP(4) + `1` + ⌈256/5⌉=52 data + 6 checksum = **63 chars**.
  `nevent1…` (TLV) minimal id-only ≈ **68 chars**; typical id+1-relay ≈ **~100–110 chars**;
  +author ≈ **~145–150**. Uppercasing (`NEVENT1…`) is protocol-legal and QR-alnum-safe.
- **DECISIVE limitation — no NIP-19 entity carries a complete signed event.** Every entity
  is a **reference/pointer**, not a payload. `note`/`nevent` carry only the 32-byte event
  **id** (+ optional relay/author/kind *hints*) — never pubkey+sig+content+tags inline.
  Verbatim: *"The bech32 encodings of keys and ids are not meant to be used inside the
  standard NIP-01 event formats…they're meant for human-friendlier display and input
  only."* A client must **fetch** the event from a relay. **Unusable for an airgap crossing
  that must carry the WHOLE signed event** — this violates ADR-0005's whole point.
- **NIP-21 `nostr:` scheme:** custom scheme, no OS default handler. A stock camera/browser
  with no nostr app does **nothing useful** with `nostr:nevent1…` (iOS "cannot open"/
  Android `ActivityNotFoundException`). Dead end for install-nothing.
- **njump.me:** plain **https**, so a stock camera CAN open `https://njump.me/<nevent>`.
  **But** njump `getEvent()` **decodes a pointer then fetches from relays**
  (`sys.FetchSpecificEvent(...)`); there is **no path to ingest a full event embedded in
  the URL**. So the event must already be **published**. njump resolves a pointer by
  fetching; it **cannot broadcast a brand-new airgapped event.**
- **Is there ANY nostr standard putting a COMPLETE signed event into a shared-domain URL?
  No.** NIP-21 = pointers; NIP-89 = app-handler *recommendations* (kinds 31989/31990), no
  `web+nostr`, no event-in-URL; NIP-27/NIP-07 = references/injection. Nothing carries a
  whole event inline to a stock-camera-openable canonical resolver. **This project must
  define that transport itself.**

### 1d. Payload-in-URL toward a canonical ecosystem resolver

The generic pattern (URL shorteners; `web+` protocol handlers; the LNURL well-known
resolver) all converge on: **one shared canonical host + the identifier in the path**,
resolved server-side. `registerProtocolHandler('web+…')` exists (HTML spec) but requires
a prior page visit + user opt-in per browser — not passive, not stock-camera. The only
member of this family that a **stock camera opens with nothing installed** is a **plain
https URL to a canonical host with the payload in the path** — i.e. exactly the
canonical-resolver static QR.

---

## 2. The canonical-resolver pattern — evaluated hard

**Claim under test:** if the STANDARD (not each game) secures ONE open-source decoder
domain — stateless, mirrorable, `https://<X>/<compressed-event>` — and every game's
static QR points at it, does that dissolve the owner's "can't secure a per-game short
URL" problem?

**Yes, on the naming axis — and this is the strongest result in the report.** LNURL
Lightning Addresses prove the exact pattern at ecosystem scale: unlimited identities
share ONE domain via a path/well-known convention, zero per-identity domains. Applied
here: **zero per-game domains are required.** Each operator embeds the *same* shared
prefix. The owner's objection ("no way to secure a short per-game domain") is real but
aimed at the wrong unit — the standard secures **one** domain, amortized across all
operators forever.

**Domain length realistically securable, and the fit:** the standard can register a
genuinely short domain (e.g. a 7–9 char `X.LOL`/`X.IO`/`SM64.LOL`-class name; note QR
alnum mode is uppercase, and scheme+host are case-insensitive per RFC 3986 so
`HTTPS://SM64.LOL/` normalizes fine). Per §0's table, `HTTPS://<7–9 char host>/` (~17-char
prefix) leaves room for **~96–100 B** of base32 payload, or **~112 B** with base42. So
the ~65–103 B floor fits a static single frame with a real, securable, *shared* domain.
Only the repo's ~119–121 B named floor overflows (see §0).

**Brutal assessment of the centralization / liveness / censorship cost:**
- **It IS a centralization point.** If the one domain dies (lapsed registration, DNS
  seizure, takedown), every cabinet's default QR breaks at once. This is a real regression
  from a fully decentralized `nostr:` URI — the owner must own this honestly.
- **BUT the damage ceiling is low, because the event is self-verifying.** The resolver
  **decodes and broadcasts only** (ADR-0005 invariant). It holds no key, injects no value,
  and the Schnorr signature binds every signed field — so a malicious or compromised
  resolver **can forge nothing** and can at worst *refuse to broadcast* (liveness), not
  *corrupt* (integrity). Censorship risk is denial-of-service, not falsification.
- **Mitigations that shrink the residual risk to "annoyance":**
  1. **Multiple fallback domains** baked into the standard; the ROM can render a QR whose
     payload is resolver-agnostic (the path is just the compressed event), so any mirror
     resolves it. A human who knows the standard can retype the event under any mirror.
  2. **Mirrorable + stateless + open-source resolver** — anyone can stand one up; the
     compressed-event path is portable across all of them. This is the LNURL property
     (any wallet, any implementation).
  3. **Offline-capable PWA cache** — once loaded, the decoder is a static SPA that can be
     cached/served from anywhere, even IPFS/`file://`-ish mirrors.
  4. **The event is independently rebroadcastable** — because the QR carries the *whole*
     signed event, ANY nostr-aware party (not just the canonical resolver) can decode and
     broadcast it. The canonical domain is a *convenience entry point*, not a
     single-point-of-integrity.

**Verdict:** the canonical-resolver pattern **does dissolve the per-game-domain problem**
at the cost of **one soft, integrity-safe, mirror-mitigable liveness/centralization
point** shared by the whole ecosystem. For an open standard optimizing passive UX, this is
the cheapest coherent tradeoff available.

---

## 3. Stock-camera + animated QR reality (verified)

**Confirmed from primary sources:** stock camera QR detection is **strictly single-frame.**
- Android/Lens uses ML Kit, whose own docs assume per-frame independent decodes:
  *"the recognizer might produce different results from frame to frame. You should wait
  until you get a consecutive series of the same value…"* (developers.google.com/ml-kit/
  vision/barcode-scanning/android). There is **no accumulate/append API** on any stock
  scanner.
- iOS Camera (Vision `VNBarcodeObservation`) surfaces one payload per successful decode
  and hands off to the browser.

**Implication (verified):** pointed at an animated/rotating QR whose frames are *different*
payloads, a stock camera **locks onto whichever single frame it decodes first** (or
flickers between per-frame values) — it **never reassembles**. So for a stock-camera-ONLY
user, **an animated design delivers exactly one frame's worth of bytes.** Multi-frame
reassembly is impossible on a stock scanner and **REQUIRES an in-page `getUserMedia`
scanner running only after a website has taken over the camera.** The animated-hook's
multi-frame benefit is therefore realized **only after** its landing page seizes the
camera — the passive "single snap" never reassembles anything. The chain the owner
proposed is real, but its "passive" first hop is a single-frame hop.

---

## 4. getUserMedia-from-a-scanned-URL feasibility (make-or-break for the animated-hook)

**Bottom line: FRAGILE, not robust.** Verified matrix:

| Context | in-page camera scan | Note |
|---|---|---|
| iOS full Safari (Camera-app QR default) | ✅ | HTTPS + user tap required |
| iOS WKWebView in-app (FB/IG/LinkedIn) | ⚠️ iOS 14.3+ **and only if host app declared camera**; ❌ pre-14.3 | Not fixable from web side (WebKit bug 208667; webkit.org/blog/11353) |
| iOS SFSafariViewController in-app (X/Twitter) | ⚠️ often silently denied under default "Ask" | Apple Forums 711073 |
| iOS PWA/standalone | ⚠️ flaky ("indicator flashes then dies") | html5-qrcode #713 |
| Android full Chrome (Lens/Camera QR default) | ✅ | HTTPS + user tap |
| Android Chrome Custom Tabs | ✅ generally | Chrome-backed |
| Android raw WebView in-app | ❌ unless host app implements `onPermissionRequest` + CAMERA perm | Not fixable from web side |
| Any context over HTTP | ❌ `navigator.mediaDevices` is `undefined` | Secure-context hard req (MDN/W3C) |

**Key primary facts:** `getUserMedia` requires a **secure context** (HTTPS) — *"in
insecure contexts, `navigator.mediaDevices` is `undefined`"* (MDN). It requires a user
permission (and a user gesture in practice — start the camera on a "Scan" tap, not on
load). It was **entirely unavailable in iOS WKWebView before iOS 14.3** (WebKit bug
208667), and even after only if the embedding app opted in. Web QR-scanner libraries
(html5-qrcode #544/#713, nimiq/qr-scanner) document failures clustered in
**in-app browsers / webviews / non-HTTPS**, never in full Safari/Chrome.

**Conclusion for the animated-hook:** it works on the *happy path* (Camera app → full
Safari/Chrome over HTTPS) but breaks whenever the URL lands in an in-app browser/webview —
a **very common** real-world occurrence (users reaching the link via a social app, QR
apps that embed a webview, etc.). The animated-hook therefore has a **fragile
second stage** that the static-QR default **does not have at all** (the static default
broadcasts on URL-open with zero camera re-acquisition). That asymmetry is the core
reason static-by-default beats animate-by-default.

---

## 5. The impossibility triangle (the core deliverable)

Enumerate the constraints:

- **(a) install-nothing / generic camera** — human entry is a stock phone camera.
- **(b) no dependence on any fixed/canonical domain** — fully decentralized addressing.
- **(c) passive single-snap** — one still capture; no active in-page scan loop.
- **(d) arbitrary/large payload** — beyond one frame.
- **(e) zero far-side reconstruction** — whole signed event crosses; far side only
  decodes+broadcasts (ADR-0005 invariant).
- **(f) decentralized / censorship-resistant delivery.**

**The sharp result is a triangle among (a), (b), (c).** You can have any two; not all
three:

```
                (a) install-nothing / generic camera
                       /\
                      /  \
     canonical-      /    \   animated-hook
     resolver       /      \  (sacrifices c:
     STATIC QR     /        \  stock cam grabs 1 frame;
   (sacrifices b: /          \ real capture is an active
    one shared   /            \ getUserMedia loop)
    domain)     /______________\
             (c) passive     (b) no canonical/fixed domain
              single-snap
```

Proof sketch of the three edges:
- **(a)+(c) ⇒ ¬(b).** A stock camera can *passively* act on only two things: a plain
  `https://` URL (needs a host = a domain) or a self-contained payload in a scheme the OS
  handles natively — and the OS handles **no** scheme that decodes+broadcasts a nostr
  event without an installed app (`nostr:`/`lightning:`/`ur:` all need a handler; §1).
  So passive + install-nothing forces a plain https URL, which forces **a domain**. You
  cannot be domain-free. ⇒ the **canonical-resolver static QR** corner.
- **(a)+(b) ⇒ ¬(c).** Drop the domain but keep install-nothing: the QR must carry a
  self-contained payload a stock camera can act on with no app and no host. Nothing
  qualifies passively (previous bullet). The only escape is to make the *first* frame a
  plain https bootstrap that then runs an **active** in-page scanner — i.e. you give up the
  passive single-snap. ⇒ the **animated-hook** corner. **And note:** that https bootstrap
  *still* needs a hook domain, so (a)+(b) does not actually purchase real domain-freedom —
  the animated-hook is domain-dependent too, just at the hook.
- **(b)+(c) ⇒ ¬(a).** Fully decentralized + passive single-snap is achievable with a
  self-contained URI (`nostr:nevent…`/`ur:…`) in one static frame — but only a
  **dedicated installed app** registered for that scheme can act on it. ⇒ the
  **`nostr:`/nevent-URI (or BC-UR) dedicated-reader** corner. (Additional defeat: no
  nostr URI even carries the whole event — §1c — so this corner also fights (e).)

Placing the payload constraints:
- **(d) large payload** intersects everything: at ≤~100–112 B a static single frame
  suffices (canonical-resolver corner is fully passive). Beyond one frame, **(a)+(c)+(d)
  is impossible** — a stock camera cannot reassemble multiple frames (§3), so large +
  passive + install-nothing cannot co-exist; you must give up (c) (animate + in-page
  scan) or (a) (dedicated multi-frame app). This is why the **animated-hook is the correct
  *offload*** for the overflow case: once you're forced past one frame, (c) is already lost
  no matter what, so animation costs nothing extra there.
- **(e) zero far-side reconstruction** eliminates the entire NIP-19/21/njump family
  (pointers that must be fetched — they *reconstruct nothing locally* but *carry nothing
  either*; they need the event already published). It is satisfiable by the
  canonical-resolver and animated-hook corners (both carry the whole event and only
  decode+broadcast) and by a dedicated app that carries the whole event (BC-UR-style over
  a nostr payload).
- **(f) censorship-resistance** is *maximized* at the `nostr:`/dedicated corner and
  *softened* at the canonical-resolver corner (one shared liveness point) — but recovered
  substantially because the event is self-verifying and rebroadcastable by anyone (§2).

**Honest statement of no-free-lunch:** there is **no option that has (a), (b), (c), and
(d) simultaneously.** The owner cannot have install-nothing, domain-free, passive, and
large all at once. The design question is *only* which to concede.

---

## 6. Recommendation

**Adopt the hybrid: canonical-resolver ultra-compressed STATIC single frame as the
DEFAULT, animated-hook as the documented OFFLOAD.** Argue for it against the alternatives:

**Why it beats the animated-hook-as-default:**
1. **It actually delivers the passive-snap ideal the owner ranks highest.** On the default
   path, a stock camera opens a plain https URL and the event broadcasts — **no
   `getUserMedia`, no in-app-browser camera lottery, no user gesture to start a scan
   loop.** The animated-hook's "passive snap" is an illusion (§3): a stock camera grabs one
   frame; real capture is an *active* second-stage scan that is *fragile* cross-platform
   (§4). Static-by-default removes the entire fragile stage from the common case.
2. **It does not cost more decentralization than the animated-hook already costs.** The
   animated-hook's every frame is *"a full valid https URL (constant hook + fragment)"* —
   that constant hook **is itself a canonical domain**. So the animated-hook is *already*
   domain-dependent; it does not buy (b). Given both designs depend on one shared domain,
   prefer the one that also wins passive UX and dodges the getUserMedia fragility. The
   static default strictly dominates the animated default on the owner's own value order.
3. **It requires zero per-game domains** — dissolving the owner's stated blocker — via the
   LNURL-proven shared-canonical-domain pattern (§1b, §2).

**The single irreducible tradeoff it forces the owner to accept:** **one shared canonical
resolver domain** — a soft centralization / liveness point for the whole standard. This is
**integrity-safe** (self-verifying event; resolver can forge nothing, only refuse) and
**mirror-mitigable** (multiple fallback domains, stateless open-source PWA, anyone can
rebroadcast the whole event). The owner is trading *full addressing decentralization*
(which the animated-hook does **not** actually provide either) for *passive UX +
robustness + zero per-game domains*. That is the right trade for an open, consumer-facing
standard.

**Keep the animated-hook — but only as the offload — because §5(d) proves it is the
correct tool once a payload exceeds one frame** (past one frame, passive single-snap is
*already impossible* on a stock camera, so animation costs nothing extra, and BC-UR/BBQr
give proven fountain/indexed chunking to borrow). Document it as: *"if the packed event
exceeds single-frame capacity at the frozen footprint, the cabinet animates; the same
canonical resolver page uses `getUserMedia` to reassemble."* Note honestly that this
offload inherits the §4 fragility and the §2 mild reconstruction-flavored concern
(reassembling fountain parts is still a lossless decode of signed bytes, invariant-safe,
but it is a heavier reader).

**Alternatives, rejected for the default:**
- **`nostr:`/`nevent` URI (single static frame, fully decentralized):** rejected — needs a
  dedicated installed app (violates (a)); and no NIP-19 entity even carries the whole
  self-contained event (violates (e)). It is a pointer-fetch model that cannot broadcast a
  brand-new airgapped event. Good *inspiration* for a future `web+nostr`-style decentralized
  handler, not a shippable install-nothing default today.
- **BC-UR/BBQr dedicated-reader (Bitcoin model):** rejected — assumes a dedicated
  app/device (violates (a)); its whole raison d'être (network-isolated signer that must
  not touch a URL) is the *opposite* of this project's permitted-online far side (§1a).

**The one thing that can invalidate this recommendation:** the §0 payload-size question.
If the committed format-v2 payload is firmly ~119–121 B at frozen v7-M, **no static single
frame fits under any encoding**, "static-by-default" is impossible, and the animated-hook
(or a footprint bump to v8/v9, or trimming the event to ≤~100–112 B, e.g. dropping the
on-wire filterable name and using the bespoke base42) becomes mandatory rather than
optional. **Decide the payload/footprint budget before committing to static-by-default —
it is the gating fact.**

---

## Sources (primary)

- **QR capacity / encoding:** ISO/IEC 18004 (via Thonky mirror
  thonky.com/qr-code-tutorial/character-capacities, /error-correction-table — v7-M = 124
  data codewords = 992 data bits, 178 alnum chars); RFC 4648 (§5 base64url, §6 base32);
  RFC 9285 (base45, non-URL-safe warning); RFC 3986 (scheme/host case-insensitivity).
  Cross-refs: local `qr-v7-capacity-envelope.md`, `nip01-signed-event-floor.md`.
- **Bitcoin animated QR:** BCR-2020-005 (UR), BCR-2024-001 (MUR fountain), BCR-2020-012
  (Bytewords) — BlockchainCommons/Research; BBQr spec
  raw.githubusercontent.com/coinkite/BBQr/master/BBQr.md, bbqr.org; wallet docs
  sparrowwallet.com/docs/airgapped-wallet-qr.html, seedsigner.com, blog.keyst.one,
  docs.foundation.xyz, coldcard.com/docs/qr-scanner. Cross-ref local
  `animated-qr-ur-mur-seedqr.md`.
- **LNURL:** github.com/lnurl/luds 01.md, 16.md, 06.md; BIP-173 (bech32), BIP-350
  (bech32m).
- **Nostr:** nostr-protocol/nips 19.md, 21.md, 89.md; njump github.com/fiatjaf/njump
  (nostr.go). NIP-01/BIP-340 via local floor doc.
- **Platform behavior:** MDN MediaDevices.getUserMedia (secure-context/permissions);
  developers.google.com/ml-kit/vision/barcode-scanning/android (per-frame decode); WebKit
  bug 208667 + webkit.org/blog/11353 (iOS 14.3 WKWebView getUserMedia); Apple Developer
  Forums 711073 (SFSafariViewController camera); html5-qrcode issues #544/#713;
  github.com/nimiq/qr-scanner (HTTPS requirement); Apple support 102680 (iOS Camera QR).

**Verification caveats (per the "don't trust, verify" discipline):**
- The `lightning:`/`nostr:`/`ur:` "inert on a wallet-less stock phone" claim is **OS
  URI-scheme mechanics reasoned from the specs' consistent actor framing**, not a single
  quotable spec sentence — flagged as reasoned, not quoted.
- The iOS in-app-browser engine mapping (FB/IG=WKWebView, X=SFSafariViewController) is
  search-aggregated + the Apple forum thread, not one canonical Apple doc; apps switch
  engines over time. The **iOS-14.3 WKWebView fix and the HTTPS secure-context requirement
  are primary-confirmed.**
- v7-M capacity: this report uses **992 data bits** (the correct v7-M figure); the repo's
  `nip01-signed-event-floor.md` uses 864 bits (a 108-codeword figure). Both are cited; the
  overflow conclusion for the ~119–121 B named event holds under **either**.
- BBQr max-frame ceiling and Passport BBQr support are header-implied / secondary, not
  verbatim-primary-confirmed.
