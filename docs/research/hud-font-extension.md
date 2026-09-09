# Extending the HUD font: reusable full-alphabet glyphs?

Follow-up to `docs/research/hud-glyph-inventory.md` (issue #67). Question: has the decomp
community already solved the "incomplete HUD font" (J Q V X Z missing, no lowercase, no space) so we
can **reuse, with correct attribution/license,** an existing glyph set to render the full alphabet
through the `print_text` / `main_hud_lut` HUD path? Build target here is **`VERSION = us`**.

All claims below were checked against the actual repo source files via the GitHub API on 2026-09-08,
not forum hearsay. URLs are to the files inspected.

---

## Summary / recommendation

- **Yes, for uppercase A–Z: HackerSM64 solved it, with community-drawn glyphs.** It ships original
  16×16 rgba16 PNGs for exactly the five US-missing letters — `hud_char_j/q/v/x/z` — and wires them
  into the previously-null `main_hud_lut` slots. These are drop-in compatible with our vanilla HUD
  glyph format (verified 16×16). No change to `char_to_glyph_index` is needed (A–Z already maps to
  those indices; the slots are just null in US). This is the reusable piece we want.
- **License caveat (important):** HackerSM64 has **no LICENSE file** (README only). The J/Q/V/X/Z
  PNGs are original community art (added in HackerSM64 v2.0.0 by `thecozies`, 2021-12-30), *not* ripped
  from a ROM, so they are physically redistributable — but there is **no explicit open-source grant**
  attached to them. Treat as "intended as a romhack base, low legal risk, attribute to HackerSM64 /
  thecozies," not as a formally licensed asset. This is far safer than the alternative (ripping the
  Nintendo JP-ROM glyphs, which is Nintendo IP and **not** redistributable).
- **Lowercase + space: not solved on the `print_text` path anywhere.** Even HackerSM64 still collapses
  `a`–`z` onto the uppercase glyphs (`char_to_glyph_index`: `a`–`z` → `c - 87`, same indices as
  uppercase). No distinct lowercase HUD tiles exist in any decomp's `main_hud_lut`. Space already
  "works" (it's a blank advance, `GLYPH_SPACE`), so the only real gap we can close by reuse is the
  five uppercase letters. Real lowercase would require a different font/engine (see §4).
- **Base decomps (n64decomp/sm64, sm64-port, sm64ex, sm64ex-coop) and Render96ex do NOT fix it** for
  US — they keep the identical null gaps in the US `main_hud_lut`. Verified below.

**Bottom line:** There is a reusable, correctly-*styled*, redistributable full-**uppercase** HUD font
fix: adopt HackerSM64's five `hud_char_{j,q,v,x,z}.rgba16.png` glyphs into our null LUT slots and
attribute HackerSM64/thecozies. Full lowercase is not available for the `print_text` path. Formal
license is ambiguous (no LICENSE in HackerSM64) — flag before shipping.

---

## Solution 1 — HackerSM64 (the one that solves it)

Repo: `github.com/HackerN64/HackerSM64` (default branch `master`). A romhacking base built on
CrashOveride95/ultrasm64; explicitly meant to be forked into hacks.

### Glyph textures (community-authored, redistributable)

Checked into the repo as real PNGs (not ROM-extracted at build time):
- `textures/segment2/segment2.hud_char_j.rgba16.png` — verified **16×16**, 189 bytes
- `textures/segment2/segment2.hud_char_q.rgba16.png`
- `textures/segment2/segment2.hud_char_v.rgba16.png`
- `textures/segment2/segment2.hud_char_x.rgba16.png`
- `textures/segment2/segment2.hud_char_z.rgba16.png`
- also present and community-drawn: `segment2.exclamation/double_exclamation/question/ampersand/percent.rgba16.png`,
  `segment2.decimal_point.rgba16.png`, `segment2.beta_key.rgba16.png`, `segment2.red_coin.rgba16.png`
  (verified 16×16), `segment2.silver_coin.rgba16.png`, `segment2.blue_coin.rgba16.png`,
  `segment2.minus.rgba16.png`, `segment2.minus2.rgba16.png`, `segment2.umlaut_us.rgba16.png`.
  URL: `https://github.com/HackerN64/HackerSM64/tree/master/textures/segment2`

### Mechanism — how they're wired in

`bin/segment2.c`
(`https://github.com/HackerN64/HackerSM64/blob/master/bin/segment2.c`):

Each JP-only glyph is defined twice behind an `#ifdef`. Default (US, non-JP) branch pulls the
**community PNG**; the JP/SH branch (and an opt-in `COMPLETE_EN_US_SEGMENT2`) pulls the **ripped
JP-ROM** texture at a numeric ROM offset:

```c
#if defined(VERSION_JP) || defined(VERSION_SH) || defined(COMPLETE_EN_US_SEGMENT2)
ALIGNED8 static const Texture texture_hud_char_J[] = {
#include "textures/segment2/segment2.02600.rgba16.inc.c"   // ripped from JP ROM = Nintendo IP
};
#else
ALIGNED8 static const Texture texture_hud_char_J[] = {
#include "textures/segment2/segment2.hud_char_j.rgba16.inc.c"  // community-drawn, redistributable
};
#endif
```

(Same pattern for Q/V/X/Z at `segment2.c` ~lines 269–328, and for `! !! ? & %`, decimal_point,
beta_key.)

`main_hud_lut[]` is **unconditional** (single table, no VERSION branch) and now references every
letter A–Z plus the punctuation and new coins — no `0x0` letter slots remain
(`bin/segment2.c` ~lines 2016–2032):

```c
    texture_hud_char_G, texture_hud_char_H, texture_hud_char_I, texture_hud_char_J,
    ... texture_hud_char_Q, texture_hud_char_R, ...
    ... texture_hud_char_U, texture_hud_char_V,
    texture_hud_char_W, texture_hud_char_X, texture_hud_char_Y, texture_hud_char_Z,
    texture_hud_char_exclamation, ..., texture_hud_char_percent, 0x0, 0x0, 0x0, ...
    texture_hud_char_multiply, texture_hud_char_coin, texture_hud_char_red_coin, texture_hud_char_silver_coin,
    texture_hud_char_mario_head, texture_hud_char_star, texture_hud_char_decimal_point, texture_hud_char_beta_key,
    texture_hud_char_apostrophe, texture_hud_char_double_quote, texture_hud_char_umlaut,
```

`char_to_glyph_index` (`src/game/print.c` ~lines 286–359,
`https://github.com/HackerN64/HackerSM64/blob/master/src/game/print.c`) is essentially unchanged
from vanilla: `A`–`Z` → `c - 55`, `a`–`z` → `c - 87` (**still collapses lowercase to uppercase**),
`0`–`9` → `c - 48`, space → `GLYPH_SPACE`. So the *only* thing HackerSM64 changed to make J/Q/V/X/Z
render was **filling the null LUT slots with textures** — the char→index mapping already pointed at
those indices. This is exactly what our in-repo research predicted (fill slots 19/26/31/33/35).

### Coverage

- Full **uppercase** A–Z (the five missing letters now drawable). ✔
- Also gains punctuation (`! !! ? & %`), `.`, red/silver/blue coins, minus — beyond our ask.
- **No distinct lowercase** (still uppercase glyphs). ✘
- Space unchanged (blank advance). (n/a — already fine)

### License & provenance — VERDICT

- Repo LICENSE: **none.** Only `README.md` at root (confirmed via contents listing). The README states
  the repo *requires both a US ROM and a JP ROM to build* — because the numeric-offset includes
  (`02400` … = the base letters A–I/K–P/R–U/W/Y, mario head, star, camera icons) are still extracted
  from a ROM. So HackerSM64's HUD font *as a whole* is a mix of **ripped Nintendo glyphs** (the base
  letters, star, mario head) and **community fill glyphs** (J/Q/V/X/Z, punctuation, coins).
- The five `hud_char_{j,q,v,x,z}.rgba16.png` specifically are **original community art**, committed as
  PNGs (first appear in commit `f3e61a31`, "HackerSM64 v2.0.0", author `thecozies`, 2021-12-30). They
  are **not** Nintendo ROM rips, so redistributing *these five files* does not redistribute Nintendo
  IP. But there is **no explicit license grant** on them → legally ambiguous; safest to attribute
  "glyphs by thecozies / HackerSM64" and, if this matters commercially, confirm with the authors.
- Do **NOT** reuse the `segment2.02600` / `COMPLETE_EN_US_SEGMENT2` path — those glyphs are extracted
  from Nintendo's JP ROM and are Nintendo copyright, not redistributable.

---

## Solution 2 — Render96 / Render96ex (does NOT solve it)

Repo: `github.com/Render96/Render96ex` (default branch `master`).
`bin/segment2.c` (`https://github.com/Render96/Render96ex/blob/master/bin/segment2.c`): the US branch
of `main_hud_lut` still has the vanilla null gaps — verified rows:

```c
    texture_hud_char_G, texture_hud_char_H, texture_hud_char_I,               0x0,   // J null
    texture_hud_char_O, texture_hud_char_P,               0x0, texture_hud_char_R,   // Q null
    texture_hud_char_S, texture_hud_char_T, texture_hud_char_U,               0x0,   // V null
```

`texture_hud_char_J` etc. are only defined under `#if defined(VERSION_JP)||defined(VERSION_SH)`.
Render96ex's "HD font" is a **separate external texture-pack** replacement system (runtime texture
swap), not a change to `main_hud_lut`; because the US LUT slot for J/Q/V/X/Z is `0x0`, the standard
`print_text` path has nothing to swap. So Render96ex does not extend the `print_text` HUD alphabet,
and its HD textures are HD *re-paintings of ROM assets* (Nintendo-derivative) anyway. Not a source
for our fix.

---

## Solution 3 — Base decomps: n64decomp/sm64, sm64-port, sm64ex, sm64ex-coop (do NOT solve it)

These share the same `bin/segment2.c` lineage. Verified against sm64ex
(`https://github.com/sm64pc/sm64ex/blob/master/bin/segment2.c`), whose US `main_hud_lut` branch keeps
every gap identical to vanilla US (and to our repo):

```c
    ...texture_hud_char_I,   0x0,   // J
    ...texture_hud_char_P,   0x0, texture_hud_char_R,   // Q
    ...texture_hud_char_U,   0x0,   // V
    texture_hud_char_W,      0x0, texture_hud_char_Y,   0x0,   // X, Z
```

`texture_hud_char_J/Q/V/X/Z` are defined **only** under `#if defined(VERSION_JP)||defined(VERSION_SH)`
(ripped JP-ROM offsets `02600`…). So on a US build these decomps have the exact JQVXZ gap we already
documented. n64decomp/sm64 is the upstream of all of them and is identical here; sm64-port and
sm64ex-coop inherit sm64ex's table. None provides community glyphs. (Our own repo is one of these
forks, which is why the gap exists.)

---

## 4. Lowercase / full-alphabet on other paths (not `print_text`)

- HackerSM64 also bundles an **s2d ("Screen-2D") engine** with complete-alphabet fonts including
  lowercase: `src/s2d_engine/fonts/{comicsans,impact,papyrus,timesnewroman,ubuntu,delfino,ifunny,
  newsm64}.c` (`https://github.com/HackerN64/HackerSM64/tree/master/src/s2d_engine/fonts`). But this is
  a **different renderer** (`s2d_print`), not the `print_text` / `main_hud_lut` path this project uses,
  and several of those fonts are **copyrighted commercial typefaces** (Comic Sans, Impact, Papyrus,
  Times New Roman, Ubuntu) → their own font-license problems. Not a clean reuse for the HUD path.
- HackerSM64's `puppyprint` debug text and `textures/crash_custom/` crash-screen font are also full
  alphabets. The crash font has a real license — **CC BY-SA 3.0**, adapted from
  `http://uzebox.org/wiki/File:Font6x7.png` (`textures/crash_custom/LICENSE`) — but it's a tiny 6×7
  monochrome debug font, not a HUD-style colorful 16×16 glyph, and again not on the `print_text` path.
- Net: no drop-in, correctly-licensed **lowercase** set exists for the `print_text` HUD font. Real
  lowercase would mean authoring new 16×16 tiles and either (a) adding lowercase glyph indices +
  `char_to_glyph_index` cases + LUT entries, or (b) switching that HUD text to a different font engine.

---

## Bottom line

- **Reusable full-UPPERCASE HUD fix: yes.** Adopt HackerSM64's five community glyphs
  `textures/segment2/segment2.hud_char_{j,q,v,x,z}.rgba16.png`, drop them into our null US LUT slots
  (indices 19/26/31/33/35 in `bin/segment2.c`), define the corresponding `texture_hud_char_*` arrays.
  No `char_to_glyph_index` change needed. Verified 16×16 rgba16, drop-in with our format.
- **Attribution:** credit HackerSM64 / `thecozies` (HackerSM64 v2.0.0). Note the repo has **no
  LICENSE file**, so the grant is implicit ("base for romhacks") rather than formal — flag before any
  commercial/redistribution use.
- **Do not** pull the `segment2.02600`-style glyphs or the `COMPLETE_EN_US_SEGMENT2` path — those are
  Nintendo JP-ROM rips, not redistributable.
- **Lowercase + real space glyphs:** not available for reuse on this HUD path from any surveyed repo.
  Uppercase-only is the realistic reuse outcome; space already renders blank.

### Unverified / caveats

- HackerSM64 has no LICENSE; the "redistributable, attribute-only" conclusion for the five PNGs is a
  reasonable inference from (a) they are original PNGs not ROM rips, and (b) the repo's stated purpose
  as a hack base — but it is **not** a written license grant. Confirm with the authors if it matters.
- I inspected file contents and PNG dimensions directly (J and red_coin PNGs confirmed 16×16); I did
  **not** build HackerSM64 or render its glyphs in-game, so visual style match to our vanilla US font
  is asserted from the shared 16×16 rgba16 format, not from a rendered screenshot.
- Line numbers for HackerSM64 `segment2.c`/`print.c` are approximate (from the fetched master copy on
  2026-09-08) and may drift.
