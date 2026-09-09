# QR v7 / ECC-MEDIUM capacity envelope: event payload alongside a plaintext URL

Resolves the RESEARCH question in issue #98 (part of the map issue #97).

**Locked constraints honored:** footprint frozen at QR **version 7, ECC MEDIUM**
(45x45 modules, 2px/module); QR content is a **plaintext URL** with the signed
Nostr event carried behind it as an encoded parameter; ~96 B of the payload is
incompressible crypto material (64 B Schnorr sig + 32 B x-only pubkey per
BIP-340 / NIP-01). Entropy compression is not a lever; QR encoding-mode
efficiency, field elimination, and URL minimization are.

## TL;DR — the envelope

- **v7-M raw BYTE capacity = 122 B — CONFIRMED** (ADR-0002 figure is correct),
  but that number is **binary-only, with no URL**. It is not the usable budget
  once a plaintext URL wraps the payload.
- Best **URL-safe** encoding is **uppercase base32 (RFC 4648 §6) carried in a QR
  ALPHANUMERIC segment**: 1.6 chars/B, **8.8 bits per payload byte**.
- **base45 is denser (8.25 bits/B) but NOT URL-safe** (RFC 9285 warns its
  alphabet contains space `%` `+` `/`) -> repudiated for a plaintext URL.
- **base64url is URL-safe but forced into BYTE mode** (lowercase + `-_`) ->
  10.67 bits/B -> worst of the three.
- **Max event payload alongside a plaintext URL at v7-M is ~100 B** (path-based,
  all-uppercase, single alphanumeric segment, leaving ~13-16 chars for
  scheme+host+path). **The 112 B format-v2 payload does NOT fit any URL-safe
  text wrapping at v7-M with standard encodings.**
- The **query-param** framing (`?p=`) is expensive: `?` and `=` are not in the
  QR alphanumeric charset, forcing a BYTE segment for the prefix. At the 96 B
  floor it collapses the URL budget to ~10 chars — infeasible for a real host.
  A **path-based, all-uppercase URL** is required to make the envelope usable.

## 1. v7 capacity, verified against primary sources

QR data capacity is fixed by the number of **data codewords** (8 bits each).
For **version 7** (ISO/IEC 18004; tabulated by Thonky's ISO-18004 mirror):

| ECC | Data codewords | Data bits |
|-----|----------------|-----------|
| L   | 156            | 1248      |
| M   | **124**        | **992**   |
| Q   | 88             | 704       |
| H   | 66             | 528       |

Per-symbol overhead (v7 is in the version 1-9 band):
- **Mode indicator:** 4 bits per segment.
- **Character-count indicator:** numeric 10 bits, alphanumeric 9 bits, byte 8 bits.

Character capacities per mode at v7 (ISO/IEC 18004 capacity table), and the
arithmetic that reproduces them from the M row (992 bits):

| Mode         | L   | M       | Q   | H   | M derivation |
|--------------|-----|---------|-----|-----|--------------|
| Numeric      | 370 | 293     | 207 | 154 | floor: (992-4-10)=978 b; 97x10b (291 ch) + 8 b -> 2 ch = **293** |
| Alphanumeric | 224 | **178** | 125 | 93  | (992-4-9)=979 b; 979/11 = 89 pairs = **178** ch |
| Byte         | 154 | **122** | 86  | 64  | (992-4-8)=980 b; 980/8 = **122** B |
| Kanji        | 95  | 75      | 53  | 39  | — |

**Verdict on ADR-0002:** the "122 B byte-mode at v7-M" figure is **CONFIRMED**.
Caveat: 122 B is the raw-binary capacity of the whole symbol. It is *not*
available for "URL + payload," because a plaintext URL cannot contain arbitrary
binary — the payload must first be re-encoded into URL-safe text, which costs
more than 8 bits per payload byte (below).

## 2. Cost of encoding the ~96 B floor (+ small fields) into URL-safe text

Bits consumed per payload byte, by encoding, accounting for the QR mode the
alphabet forces:

| Encoding | Ratio (chars/B) | QR mode forced | Bits/char | **Bits per payload byte** | URL-safe? |
|----------|-----------------|----------------|-----------|---------------------------|-----------|
| raw byte | 1.000 | byte | 8.0 | **8.00** | NO — arbitrary binary is not URL text |
| base45 (RFC 9285) | 1.5 (2 B -> 3 ch) | alphanumeric | 5.5 | **8.25** | **NO** — alphabet has space `%` `+` `/` |
| **base32 (RFC 4648 §6)** | 1.6 (5 B -> 8 ch) | **alphanumeric** | 5.5 | **8.80** | **YES** — `A-Z 2-7`, all unreserved & QR-alnum |
| base64url (RFC 4648 §5) | 1.333 (3 B -> 4 ch) | byte | 8.0 | **10.67** | YES, but `-_` + lowercase force byte mode |

Where "bits/char = 5.5" is the QR alphanumeric packing: two chars share 11 bits
(value = c1*45 + c2, 0..2024 < 2^11), i.e. **11 bits per pair**.

Key facts from the primary sources:
- **RFC 9285 (base45):** alphabet `0-9 A-Z <space> $ % * + - . / :` — the exact
  QR alphanumeric set — and encodes **2 bytes in 3 characters**. But the RFC
  explicitly warns the output "might include non-URL-safe characters so if the
  URL ... has to be URL-safe, one has to use percent-encoding." Space, `%`, `+`,
  `/` in a query/path either break parsing or need `%NN` escaping, which erases
  the density win. **base45 is the densest QR-alphanumeric shape but is
  disqualified by the plaintext-URL constraint.**
- **RFC 4648 §6 (base32):** alphabet `A-Z 2-7`, **40-bit groups -> 8 chars**
  (5 B -> 8 ch). Every char is a URI *unreserved* character **and** a member of
  the QR alphanumeric charset. This is the only candidate that is simultaneously
  URL-safe and alphanumeric-mode-native. **Winner.**
- **RFC 4648 §5 (base64url):** base64 with `+ -> -` and `/ -> _`; **3 B -> 4 ch**.
  URL-safe, but the alphabet contains lowercase and `-_`, none usable in QR
  alphanumeric mode, so it is stuck in byte mode at 8 bits/char -> 10.67 bits/B.

**Consequence:** the 96 B incompressible floor costs, once made URL-safe:
- base32: `8 * ceil(96/5)` = `8 * 20` = **160 alnum chars** = 160 * 5.5 = **880 bits**.
- base45 (were it usable): `3 * (96/2)` = **144 chars** = 792 bits.
- base64url: `4 * ceil(96/3)` = **128 chars** in byte mode = 1024 bits — already
  **exceeds** the 992-bit v7-M budget on its own. Disqualified for the floor.

## 3. One symbol, mixed segments; case-sensitivity rules

QR alphanumeric charset: `0-9 A-Z <space> $ % * + - . / :` — **no lowercase, no
`?`, `=`, `&`, `_`**. URL case rules (RFC 3986 §3.1, §6.2.2.1): **scheme and
host are case-insensitive** (a client normalizes `HTTPS://EXAMPLE.IO` to
lowercase); **path and query are case-sensitive** — but we own those bytes and
base32 is uppercase, so an uppercase path is self-consistent and decodes cleanly.

Two symbol layouts:

**(A) All-uppercase, path-based, single ALPHANUMERIC segment.**
Put the payload in the *path*, uppercase the scheme+host:
`HTTPS://SM64.IO/<base32>`. Every character is in the QR alphanumeric set, so the
whole URL is one alnum segment. Segment overhead = 4 + 9 = **13 bits** only.
Requires avoiding `?`, `=`, `&`, `_` and any lowercase.

**(B) Query-param, mixed BYTE + ALPHANUMERIC segments.**
`?` and `=` are not in the QR-alnum charset, so `https://host/?p=` must ride in a
BYTE segment (also lets the host stay lowercase), then the base32 payload rides
in an ALPHANUMERIC segment. Two segments cost 4+8 (byte) + 4+9 (alnum) =
**25 bits** of headers, and every prefix char costs 8 bits instead of 5.5.

Mode-switch cost, concretely, for a 13-char prefix:
- (A) prefix in alnum: 5.5 * 13 = **71.5 bits**, sharing the single 13-bit header.
- (B) prefix in byte: 12 (extra header) + 8 * 13 = **116 bits**.
- Layout (A) saves ~57 bits (~10 base32 chars ~= 6 payload bytes) over (B).

## 4. URL-prefix character budget — the arithmetic

Let `T` = total alphanumeric chars, `U` = uppercase URL-prefix chars,
`N` = event payload bytes, base32 payload chars = `8 * ceil(N/5)`.

### Design A (best case: path-based, single alnum segment)
```
992 data bits - 13 bits (mode + count) = 979 bits for characters
979 / 5.5 = 178 alnum chars  ->  T <= 178
T = U + 8*ceil(N/5)  <=  178
```
With prefix `HTTPS://A.IO/` (U = 13):
```
178 - 13 = 165 chars for payload
floor(165 / 8) = 20 base32 groups = 160 chars = 20 * 5 = 100 B payload   (5 chars slack)
```
=> **~100 B payload with a ~13-16 char uppercase URL prefix.**
For the format-v2 target N = 112: base32 = 8*ceil(112/5) = 8*23 = **184 > 178**
-> **overflows v7-M even with an empty prefix.**

### Design B (query-param, mixed segments)
```
25 bits headers + 8*U (byte prefix) + 5.5*(8*ceil(N/5)) (alnum base32)  <=  992
8*U + 44*ceil(N/5)  <=  967
```
At the bare floor N = 96 (ceil(96/5) = 20):
```
44 * 20 = 880 bits ;  8*U <= 87  ->  U <= 10 chars
```
`https://a.io/?p=` is already 16 chars. **Only ~10 prefix bytes fit** — not enough
for scheme + a real host + a param name. The query-param convention is
effectively infeasible at v7-M for the 96 B floor.

### Leftover URL budget — summary
| Layout | Encoding | Max payload | URL prefix budget |
|--------|----------|-------------|-------------------|
| A path, all-uppercase, 1 alnum seg | base32 | **~100 B** | **~16-18 uppercase chars** (`HTTPS://X.IO/` class; no query) |
| B query-param, byte+alnum segs | base32 | ~96 B (floor only) | **~10 bytes** — infeasible for a real host+param |

## 5. The only lever that reaches 112 B: a custom URL-safe QR-alnum base

The QR-alnum characters that are **also** URL-safe (unreserved or path/query
`pchar`, excluding the parse-breakers space `%`, and the ambiguous `+`) number
~42: `0-9 A-Z $ * - . / :`. A **custom base-~42** that chunks **2 bytes -> 3
chars** (since `42^3 = 74088 >= 65536`) matches base45's 1.5 chars/B **while
staying URL-safe**:
```
N = 112 B  ->  3 * (112/2) = 168 chars ;  168 + prefix(<=10) = 178  -> fits Design A
```
So a bespoke URL-safe base-42 over the QR-alnum charset is the **only** route to
carry the full 112 B format-v2 payload alongside a (short, path-based, uppercase)
URL at frozen v7-M. It is non-standard (must be co-implemented on ROM and
companion) and outside the three encodings the ticket asked to evaluate, but it
is the decisive future lever if the 112 B floor is firm. Standard base32 tops out
at ~100 B.

## Sources

- **ISO/IEC 18004** QR Code specification — capacity tables, mode indicators,
  character-count indicator bit lengths, error-correction block structure.
  Tabulated mirrors: Thonky QR tutorial
  <https://www.thonky.com/qr-code-tutorial/character-capacities> and
  <https://www.thonky.com/qr-code-tutorial/error-correction-table>
  (v7: data codewords L156/M124/Q88/H66; byte cap L154/M122/Q86/H64;
  alnum L224/M178/Q125/H93).
- **RFC 9285** — The Base45 Data Encoding
  <https://www.rfc-editor.org/rfc/rfc9285.txt> (45-char alphabet =
  `0-9 A-Z <space> $ % * + - . / :`; 2 bytes -> 3 chars; explicit non-URL-safe
  warning requiring percent-encoding).
- **RFC 4648** — Base16/Base32/Base64 Data Encodings
  <https://www.rfc-editor.org/rfc/rfc4648.txt> (§6 base32 `A-Z 2-7`, 5 B -> 8 ch;
  §5 base64url `+ -> -`, `/ -> _`, 3 B -> 4 ch).
- **RFC 3986** — URI Generic Syntax (§3.1 scheme case-insensitive; §6.2.2.1
  host case-insensitive, path/query case-sensitive; §3.3/§3.4 pchar/query
  allowed characters).
- **BIP-340** — Schnorr signatures: 64-byte signature, 32-byte x-only pubkey.
- **NIP-01** — Nostr event structure; `id` is a recomputable SHA-256 (not carried).
