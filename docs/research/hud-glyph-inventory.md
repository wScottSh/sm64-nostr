# HUD glyph inventory: what `print_text` can draw

Research for issue #67. Build target is **`VERSION = us`** (`Makefile:46` → `VERSION ?= us`), so all
version-specific claims below are for the US ROM. Where JP/EU/CN differ it is called out.

The in-game HUD "colorful" font is the `print_text` family in `src/game/print.c`. It is a **separate
system** from the dialog/menu small font (`render_generic_char` + `main_font_lut` in
`src/game/ingame_menu.c:286`), which is not covered here except to note it exists and has a fuller
character set including real lowercase.

---

## 1. Character → glyph mapping (what is drawable)

Two stages are involved:

1. `char_to_glyph_index(char c)` — `src/game/print.c:299-361` maps an ASCII byte to a glyph index.
2. `render_text_labels` → `add_glyph_texture(glyphIndex)` — `src/game/print.c:366-376` indexes
   `main_hud_lut[]` (`bin/segment2.c:10916`) to fetch the texture. If the LUT slot is `0x0` (null),
   the glyph is **not drawable** even though `char_to_glyph_index` returned a valid-looking index.

### Stage 1: `char_to_glyph_index` (`src/game/print.c:299-361`)

| Input char(s)        | Returned index                       | Source line |
|----------------------|--------------------------------------|-------------|
| `A`–`Z`              | `c - 55` → 10..35                    | print.c:300 |
| `a`–`z`              | `c - 87` → 10..35 (same as UPPER)    | print.c:304 |
| `0`–`9`              | `c - 48` → 0..9                      | print.c:308 |
| space               | `GLYPH_SPACE` (-1) → skipped/blank   | print.c:312 |
| `!`                  | `GLYPH_EXCLAMATION_PNT` (36)         | print.c:316 |
| `#`                  | `GLYPH_TWO_EXCLAMATION` (37)         | print.c:320 |
| `?`                  | `GLYPH_QUESTION_MARK` (38)           | print.c:324 |
| `&`                  | `GLYPH_AMPERSAND` (39)               | print.c:328 |
| `%`                  | `GLYPH_PERCENT` (40)                 | print.c:332 |
| `*`                  | `GLYPH_MULTIPLY` (50) — the "×" glyph| print.c:336 |
| `+`                  | `GLYPH_COIN` (51) — yellow coin      | print.c:340 |
| `,`                  | `GLYPH_MARIO_HEAD` (52)              | print.c:344 |
| `-`                  | `GLYPH_STAR` (53)                    | print.c:348 |
| `.`                  | `GLYPH_PERIOD` (54)                  | print.c:352 |
| `/`                  | `GLYPH_BETA_KEY` (55)                | print.c:356 |
| anything else        | `GLYPH_SPACE` (-1) → blank           | print.c:360 |

Glyph index constants: `src/game/print.h:11-26`. Note `char_to_glyph_index` has **no** case for `'`
`"` `(` `)` `:` `;` `=` digits-with-decimal etc. — they all fall through to `GLYPH_SPACE` (blank).
The apostrophe/double-quote textures (`GLYPH_APOSTROPHE` 56 / `GLYPH_DOUBLE_QUOTE` 57) exist but are
**only reachable directly** from `render_hud_tex_lut` in the timer code (`src/game/hud.c:354-355`),
never from `print_text`.

### Stage 2: US `main_hud_lut` (`bin/segment2.c`, US branch lines 10934-10944)

The US LUT leaves several slots **null (`0x0`)**, so some indices from stage 1 point at nothing:

- Letters present: `A B C D E F G H I K L M N O P R S T U W Y` (`bin/segment2.c:10917-10938`).
- **Letters NULL in US** (render as garbage/nothing): **`J` (19), `Q` (26), `V` (31), `X` (33),
  `Z` (35)** — `bin/segment2.c:10934-10938`. These letters simply were not in Nintendo's US HUD font.
  Because lowercase maps to the same indices (print.c:304), lowercase `j q v x z` are equally absent.
- Indices 36-49 are all `0x0` in US (`bin/segment2.c:10939-10942`). That means `! # ? & %`
  (indices 36-40) — which are JP-only glyphs — are **NULL in US** and not drawable.
- `50` = `texture_hud_char_multiply` (×), `51` = `texture_hud_char_coin` (yellow coin),
  `52` = `texture_hud_char_mario_head`, `53` = `texture_hud_char_star` — all present
  (`bin/segment2.c:10942-10943`).
- `54` (`GLYPH_PERIOD`, from `.`) and `55` (`GLYPH_BETA_KEY`, from `/`) are **`0x0` in US**
  (`bin/segment2.c:10943`). So `.` and `/` are **not drawable** in US via `print_text` (they index a
  null texture pointer → garbage/nothing). The `decimal_point`/`beta_key` textures are compiled only
  under `VERSION_JP || VERSION_SH` (`bin/segment2.c:219-229`).
- `56 apostrophe`, `57 double_quote` present (`bin/segment2.c:10944`) but unreachable from `print_text`
  (see above).

For contrast, the JP/SH default branch (`bin/segment2.c:10979-10989`) *does* populate J Q V X Z and
`! !! ? & %` and decimal-point and beta-key; EU (`10921-10932`) drops X, and reuses beta-key slot as Ü
(`src/game/print.c:468-476`).

### Concrete drawable set via `print_text` on the US build

**Drawable:**
- Digits `0`–`9`.
- Uppercase and lowercase letters **except J Q V X Z** (lowercase renders as the uppercase glyph — there
  is no distinct lowercase in the HUD font).
- `*` → "×" multiply glyph, `+` → yellow coin, `,` → Mario head, `-` → star.

**Not drawable (blank):** space, and any char with no mapping (`'` `"` `(` `)` `:` `=` `<` `>` `@`
`$` `^` `_` etc.) → `GLYPH_SPACE`.

**Not drawable (indexes a null LUT slot → garbage, avoid):** `.`, `/`, `!`, `#`, `?`, `&`, `%`, and the
letters `J Q V X Z`. There is **no** "middle dot"/bullet glyph anywhere in the HUD font.

---

## 2. Per-character cell width / advance

The HUD colorful font is **fixed-width**. Within a single `print_text` string, glyph *n* is placed at:

```
rectBaseX = x + pos * 12;     // src/game/print.c:409 (non-CN, i.e. US)
```

So the **horizontal advance per character is 12 px** (CN uses a passed-in width, 12 or 16; US is the
hard-coded 12). Each glyph is drawn as a **16×16 px** textured rectangle regardless of advance:

```
gSPTextureRectangle(..., rectX<<2, rectY<<2, (rectX+15)<<2, (rectY+15)<<2, ...);  // print.c:421-422
```

i.e. glyph cells overlap slightly (16 px wide sprites on a 12 px pitch). Y is `224 - y`
(`src/game/print.c:411`).

The **16 px** figure the ticket mentions is *not* the internal advance — it is the manual spacing HUD
code uses when it emits **separate** `print_text` calls per element, e.g. the coin counter lays out the
coin, the "×", and the number as three labels 16 px apart (`src/game/hud.c:270-272`), and the star
count offsets by `+16` (`src/game/hud.c:298`). Inside one string the advance is 12 px.

---

## 3. Red-coin (or coin-color) glyph?

**No red-coin glyph exists.** The only coin glyph in the HUD LUT is `texture_hud_char_coin`
(`bin/segment2.c:207-209`), a single yellow coin at index `GLYPH_COIN` (51). It is what
`render_hud_coins` draws via the `"+"` char (`src/game/hud.c:270`, `print.c:340`). There is no
red/blue/color-variant coin texture among the HUD glyphs, and none among the reachable menu glyphs.

To show a red coin on the HUD you would have to **add a new 16×16 rgba16 texture and wire it into a LUT
slot**, then either add a new `GLYPH_*` constant + a `char_to_glyph_index` case, or reuse an existing
mapped-but-unwanted char. Convenient hosts: the US LUT has many free `0x0` slots
(`bin/segment2.c:10938-10943`) — indices 19, 26, 31, 33, 35, 36-49, 54, 55 — so a new glyph could be
dropped into e.g. slot 54/55 (the currently-dead `.`/`/` mappings) without disturbing anything drawable
in US. (Cross-version caution: those same slots are live in JP/EU.)

---

## 4. Practical maximum HUD line length

Three independent limits:

- **Buffer size:** each label stores into `char buffer[50]` (`src/game/print.c:20`). `print_text`
  copies until NUL with **no bounds check** (`src/game/print.c:239-244`), so strings must stay under
  ~49 chars or they overflow the struct. Treat **~49 chars** as the hard cap per label.
- **Screen width:** the ortho projection is `0..SCREEN_WIDTH` with `SCREEN_WIDTH = 320`
  (`src/game/print.c:446`, `include/config.h:38`). At 12 px pitch that is ⌊320/12⌋ ≈ **26 glyph cells**
  edge to edge.
- **Text-rect clipping (non-widescreen only):** `render_textrect` clamps every glyph's X to
  `[TEXRECT_MIN_X=10, TEXRECT_MAX_X=300]` via `clip_to_bounds` (`src/game/print.c:382-398`,
  `src/game/print.h:6-7`). Usable span 10..300 = 290 px ⇒ ⌊290/12⌋ ≈ **24 glyphs** before glyphs pile
  up on the right edge. Under `WIDESCREEN` this clamp is compiled out (`src/game/print.c:378,415-418`).

**Practical answer:** roughly **24 characters** of visible HUD text across the standard 320-px screen
(non-widescreen), and never more than ~49 in a single `print_text` call before buffer overflow.

---

## Caveats / things to verify before relying on this

- "Renders as garbage" for null-slot indices (`.` `/` `J` `Q` `V` `X` `Z` etc. in US) is inferred from
  `add_glyph_texture` dereferencing a `0x0` LUT entry (`src/game/print.c:366-376`); the exact on-screen
  result (blank vs. corrupt tile vs. crash on hardware) was not tested here — only read from source.
- The lowercase-→-uppercase collapse is from the arithmetic in `char_to_glyph_index` (print.c:304); no
  distinct lowercase HUD tiles exist in `main_hud_lut`.
