# QR encoder port landscape (Reed-Solomon / masking)

Research findings for [issue #15](https://github.com/wScottSh/sm64-nostr/issues/15) — part of the Wayfinder map [#4](https://github.com/wScottSh/sm64-nostr/issues/4).

**Posture:** map the solution landscape (Ackoff solve / resolve / **dissolve**), not a go/no-go call, not an implementation. Every capacity/RAM/algorithm claim below is traced to a primary source (library source/header, official spec mirror, project docs).

**Target context:** N64, VR4300 @ ~93.75 MHz, 32-bit MIPS III, IDO/MIPS toolchain, tight ROM/RAM budgets. The encoder runs **one-shot, off the hot path** (on star completion, once, before rendering), so cycle cost is nearly irrelevant; ROM footprint, RAM footprint, toolchain portability, and license are the real axes.

---

## 1. What "porting a QR encoder" actually entails

A QR encoder is four stages, all pure integer / bit work, no floating point, no OS, no I/O:

1. **Data encoding** — pick mode (numeric / alphanumeric / **byte** / kanji), pack the payload into a bitstream with mode + character-count headers, add terminator + pad bytes.
2. **Reed-Solomon ECC** — split data codewords into blocks, compute ECC codewords per block over GF(2^8), interleave.
3. **Matrix construction + masking** — lay finder/timing/alignment patterns, place data, try up to 8 mask patterns, score each with the four ISO penalty rules, keep the best.
4. **Format & version information** — encode ECC level + mask (BCH) and, for version ≥ 7, the version bits; write into reserved modules.

For a signed Nostr event the payload is opaque binary/UTF-8 JSON of a few hundred bytes → **byte mode**, so numeric/alphanumeric/kanji optimization is irrelevant here (see #14 for payload→capacity strategy).

---

## 2. Candidate libraries

### 2a. Nayuki `QR-Code-generator` (C port) — primary candidate

Sources: [repo](https://github.com/nayuki/QR-Code-generator), [`c/qrcodegen.h`](https://raw.githubusercontent.com/nayuki/QR-Code-generator/master/c/qrcodegen.h), [`c/qrcodegen.c`](https://raw.githubusercontent.com/nayuki/QR-Code-generator/master/c/qrcodegen.c), [library page](https://www.nayuki.io/page/qr-code-generator-library).

- **License: MIT.** Cleanest possible for a decomp/ROM (no copyleft, permissive, attribution only).
- **Scope:** all 40 versions, all 4 ECC levels (LOW ~7% / MEDIUM ~15% / QUARTILE ~25% / HIGH ~30%), automatic mask selection with penalty scoring, optional ECC-level "boosting". `qrcodegen_VERSION_MAX = 40`.
- **Memory model:** **zero dynamic allocation** — the caller supplies every buffer (static, stack, or heap). Library page: *"The complete lack of heap allocation makes this code suitable for constrained environments such as operating system kernels and small microcontrollers."* This maps perfectly onto the N64 (no `malloc` in the star-dance path; can point at a static or stack buffer).
- **Buffer sizing** (from the header, exact macros):
  - `qrcodegen_BUFFER_LEN_FOR_VERSION(n) = ((((n) * 4 + 17) * ((n) * 4 + 17) + 7) / 8 + 1)` — one **bit-packed** module bitmap (≈ 1 bit/module), not 1 byte/module.
  - `qrcodegen_BUFFER_LEN_MAX = 3918` (version-40 worst case).
  - An encode needs **two** such buffers (`qrcode` + `tempBuffer`, must not overlap). Worked sizes:

    | Version | Modules | 1 buffer | 2 buffers (encode RAM) |
    |--------:|--------:|---------:|-----------------------:|
    | 10 | 57×57 | 408 B | ~0.80 KB |
    | 13 | 69×69 | 597 B | ~1.17 KB |
    | 15 | 77×77 | 743 B | ~1.45 KB |
    | 20 | 97×97 | 1178 B | ~2.30 KB |
    | 40 | 177×177 | 3918 B | ~7.65 KB |

    (The library page cites a real deployment on a PJRC Teensy 3.1 with ~8 KB RAM handling worst-case v40 — consistent with the ~7.65 KB above.)
- **Portability to IDO/MIPS:** requires a **C99** compiler and only `<stdbool.h>`, `<stddef.h>`, `<stdint.h>`. IDO is a pre-C99 (C89-ish) compiler, so the realistic path is compiling `qrcodegen.c` with the decomp's **GCC/modern toolchain** (this repo already builds `tools/` and uses `asm-processor`; mixed-compiler objects are normal in the decomp world) and/or a small shim providing `stdint`/`stdbool` typedefs. No libc runtime calls beyond `memset`/`memcpy`-style loops and integer math — no `malloc`, no float, no I/O.
- **Code size:** ~1000 lines, no dependencies beyond the C stdlib (design goal stated by the project). This is the small end of the field.

### 2b. `ricmoo/QRCode` — Nayuki-derived, embedded-first

Source: [repo / README](https://raw.githubusercontent.com/ricmoo/QRCode/master/README.md).

- **License: MIT** (*"do with this as you please"*). Explicitly **derived from Nayuki's C++ library**.
- All 40 versions, all 4 ECC levels (`ECC_LOW/MEDIUM/QUARTILE/HIGH`).
- **Stack-based, no mandatory heap** (heap optional). Same "caller owns memory" story as Nayuki.
- Ergonomics tuned for MCUs (simple `qrcode_initText` / per-module getter API). Effectively a friendlier packaging of the same algorithm; same portability profile as Nayuki. A reasonable fallback if Nayuki's API feels heavy, but it buys nothing Nayuki lacks and adds an indirection to upstream.

### 2c. `libqrencode` (Kentaro Fukuchi) — the "industrial" option

Sources: [repo](https://github.com/fukuchi/libqrencode), [project page](https://fukuchi.org/en/works/qrencode/).

- **License: LGPL-2.1** (with BSD-3 portions); its Reed-Solomon comes from Phil Karn's (KA9Q) FEC library, **also LGPL**. Copyleft — heavier legal footprint on an open-source decomp ROM than MIT, and LGPL's dynamic-relink premise is meaningless on a statically-linked N64 image, so it effectively pulls the whole ROM toward LGPL obligations. **License is the main strike against it.**
- Full-featured (structured-append, micro-QR, ECI, etc.) and battle-tested, but **uses `malloc`** internally and is materially larger/more complex than qrcodegen. Overkill for "one static QR, one-shot."
- **Verdict:** technically capable, worst license + memory fit of the three. Not recommended unless a feature only it provides is required (none appear needed here).

### 2d. `tz1/qrduino` — extreme-RAM-minimizer (AVR)

Sources: [repo](https://github.com/tz1/qrduino), [`qrframe.c`](https://github.com/tz1/qrduino/blob/master/qrframe.c), wiki.

- **License: GPLv3** — **viral**; poorest license fit of the set for a ROM you may distribute.
- Built for AVR/Arduino: bit-packed pixels, division/modulo replaced by counters, and a `dofbits` utility that **pre-generates a C source file holding the fixed frame for one version/ECC** to save RAM. That last idea is the seed of the dissolve reframing in §5, even though the library itself is a poor license fit.

### Library summary

| Library | License | Versions / ECC | Memory | Toolchain fit | Notes |
|---|---|---|---|---|---|
| **Nayuki qrcodegen (C)** | **MIT** | 1–40 / L,M,Q,H | caller buffers, **no malloc**, ~0.8–7.7 KB | C99 (compile w/ GCC side) | ~1000 LOC, best fit |
| ricmoo/QRCode | MIT | 1–40 / L,M,Q,H | stack, heap optional | C99 | Nayuki-derived, MCU-friendly |
| libqrencode | LGPL-2.1/BSD | 1–40 / all + micro | **malloc**, larger | C, portable | copyleft, overkill |
| qrduino | **GPLv3** | (subset, embedded) | bitfields, tiny RAM | C (AVR) | precompute-frame trick, bad license |

---

## 3. Version / ECC coverage vs. a several-hundred-byte payload

Byte-mode (8-bit) capacity, in **bytes**, from the ISO/IEC 18004 capacity tables (mirrored at [Thonky](https://www.thonky.com/qr-code-tutorial/character-capacities); v10/v20 cross-checked against [DENSO WAVE](https://www.qrcode.com/en/about/version.html)):

| Version | Modules | L | M | Q | H |
|--------:|--------:|----:|----:|----:|----:|
| 10 | 57×57 | 271 | 213 | 151 | 119 |
| 11 | 61×61 | 321 | 251 | 177 | 137 |
| 12 | 65×65 | 367 | 287 | 203 | 155 |
| 13 | 69×69 | 425 | 331 | 241 | 177 |
| 14 | 73×73 | 458 | 362 | 258 | 194 |
| 15 | 77×77 | 520 | 412 | 292 | 220 |
| 20 | 97×97 | 858 | 666 | 482 | 382 |

Reading for the payload (a signed Nostr event JSON — see #13/#14 for exact size):

- The ticket's "version #10 implies" gives byte-mode headroom of **271 B @ L … 119 B @ H**. A signed Nostr event (64-byte hex sig alone is 128 chars, plus 32-byte pubkey + id as hex, plus JSON scaffolding) is comfortably several hundred bytes, so **v10 only fits with low ECC and a lean payload**.
- For a genuinely "several-hundred-byte" payload (~350–520 B) the natural landing zone is **v13–v15 at L/M** (e.g. v15-M = 412 B, v15-L = 520 B), or lower version if the payload is trimmed.
- **All candidate libraries (except the version-limited qrduino builds) cover the entire 1–40 range**, so version coverage is not a differentiator between Nayuki / ricmoo / libqrencode — the constraint lives in the payload↔capacity↔ECC↔module-density trade (owned by #14 for capacity and #16 for scannability, since higher version = smaller modules on the framebuffer).

**Key coupling to flag upstream:** version choice is a three-way tension — payload size (#13/#14) pushes version **up**, RS/RAM cost pushes it **down** slightly, and framebuffer scannability / module pixel size (#16) pushes it **down**. The encoder port itself is agnostic; it will happily emit whatever version the capacity decision lands on.

---

## 4. Reed-Solomon compute cost on the VR4300

From reading Nayuki's [`qrcodegen.c`](https://raw.githubusercontent.com/nayuki/QR-Code-generator/master/c/qrcodegen.c) RS routines directly:

- **No lookup tables.** GF(2^8) multiply is *Russian-peasant* bitwise multiply-and-reduce mod 0x11D:
  ```c
  uint8_t z = 0;
  for (int i = 7; i >= 0; i--) {
      z = (uint8_t)((z << 1) ^ ((z >> 7) * 0x11D));
      z ^= ((y >> i) & 1) * x;
  }
  ```
  → **8 iterations of shift/XOR/AND per multiply, integer-only, no divide, no FPU.** This matters on the VR4300: it avoids a 256×256 (64 KB) or even 512-byte log/antilog table in ROM, at the cost of a few more ALU ops per multiply — a good trade when the op is one-shot and ROM/RAM are tight.
- **Cost model:** `reedSolomonComputeRemainder` does ≈ `dataLen × blockEccLen` GF multiplies (per block); `reedSolomonComputeDivisor` is a one-per-version O(degree²) precompute. For a mid-size code (v13–v15) total data codewords are ~270–520 and ECC codewords per block are on the order of tens → **order 10^4 GF multiplies**, i.e. **order 10^5–10^6 primitive VR4300 integer ops** for the whole ECC stage.
- At ~93.75 MHz that is **well under a millisecond** — utterly negligible against a 33 ms (30 fps) frame, and it runs **once**, off the hot path, before the QR is drawn. Even the mask-penalty scoring (8 masks × full-matrix scan) — usually the heaviest CPU stage of a QR encode — is a handful of matrix passes on a ≤97×97 grid, still sub-frame.
- **Conclusion:** compute is a non-issue on the VR4300. The Russian-peasant (no-table) approach is actually the *preferred* trade here because it spends cheap-and-plentiful cycles to save scarce ROM/RAM. If cycles ever mattered (they don't here), a 512-byte log/antilog table would speed multiply ~8× — noted only for completeness.

---

## 5. Ackoff lens — solve / resolve / dissolve

- **Solve (optimal):** port a full general encoder (Nayuki), compute everything at runtime for an arbitrary payload/version. Maximum flexibility; ~1 KB LOC + ~1–2.5 KB scratch RAM for the chosen version. Overkill relative to the actual need (one QR shape, once).
- **Resolve (good-enough, recommended default):** port **Nayuki qrcodegen (MIT)**, `#define`-clamp to the single target version/ECC the capacity decision picks, feed it a static/stack buffer. Minimal integration risk, no `malloc`, trivial CPU, clean license. This is the low-regret baseline.
- **Dissolve (reframe the problem away):** the QR's *structure* is almost entirely fixed once version + ECC + mask are fixed — only the data+ECC bits change per event. Options, each still emitting a **fully standard, scannable QR**:
  1. **Precompute the static frame** (finder/timing/alignment/format-BCH/version-BCH patterns and the module-placement path) at **build time on the host**, ship it as a `const` table in ROM, and at runtime only (a) byte-encode the payload, (b) run RS, (c) XOR-in the chosen fixed mask, (d) drop bits into the precomputed positions. This is exactly qrduino's `dofbits` idea (GPL — reimplement the concept, don't copy the code). It removes matrix layout + multi-mask penalty search from the ROM entirely and shrinks runtime code to "encode + RS + place."
  2. **Fix the mask at build time** (skip the 8-mask penalty search). The spec allows any mask; a scanner reads the mask bits from the format info regardless of how it was chosen. If we pin one payload-independent mask (or even the specific mask that the host tool determined is fine across expected payloads), we delete the single heaviest CPU stage and its code. (Caveat: a truly pathological payload could produce a lower-quality-but-still-valid symbol; low risk given the one-shot, controlled payload, but worth a validation pass in #16.)
  3. **Fix version + ECC** (from §3) so all size-dependent tables (block structure, alignment positions, ECC codeword counts) collapse to single constants instead of full 1–40 tables in ROM — meaningful ROM savings and simpler code.
  - **What does NOT dissolve:** RS ECC and the data bitstream are payload-dependent by definition and must run at runtime; and "use a simpler code" is not available without leaving the QR standard (a scanner expects QR RS/format encoding). So the dissolve gain is real but bounded: it removes *structure/layout/mask-search* work, not *data/ECC* work.

**Landscape recommendation (not a decision):** baseline = **Nayuki qrcodegen, MIT, version/ECC-clamped, static buffer**. If ROM/RAM later proves tight or a smaller/simpler runtime is wanted, escalate to the **dissolve path** (host-precomputed fixed frame + fixed mask + fixed version), which keeps a standard scannable QR while stripping the encoder down to data-encode + RS + bit-placement. libqrencode and qrduino are dominated (license/size), kept only as references.

---

## Open couplings to sibling tickets

- **#13 / #14** — exact serialized event size and payload→version/ECC choice drive §3; this port is agnostic to the outcome.
- **#16** — framebuffer rendering & scannability constrains version up-bound (module pixel size) and must validate any *fixed-mask* dissolve choice.
- No dependency on the crypto tickets (#5–#8, #12) beyond "they produce the byte payload."

## Sources
- Nayuki QR-Code-generator: https://github.com/nayuki/QR-Code-generator · header https://raw.githubusercontent.com/nayuki/QR-Code-generator/master/c/qrcodegen.h · source https://raw.githubusercontent.com/nayuki/QR-Code-generator/master/c/qrcodegen.c · https://www.nayuki.io/page/qr-code-generator-library
- ricmoo/QRCode: https://github.com/ricmoo/QRCode · https://raw.githubusercontent.com/ricmoo/QRCode/master/README.md
- libqrencode: https://github.com/fukuchi/libqrencode · https://fukuchi.org/en/works/qrencode/
- qrduino: https://github.com/tz1/qrduino · https://github.com/tz1/qrduino/blob/master/qrframe.c
- Capacity tables: https://www.thonky.com/qr-code-tutorial/character-capacities · https://www.qrcode.com/en/about/version.html
