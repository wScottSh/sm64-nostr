#!/usr/bin/env python3
"""
Rewrite the boot-splash 3D logo's top word from SUPER to NOSTR (issue #93).

Reads the vanilla US logo mesh from levels/intro/leveldata.c at VANILLA_REV,
deletes the S/U/P/E solids, and builds N/O/S/T into the freed slots (R stays):
copies are moved by translation only inside the word's shared tilted frame so
their baked per-face lighting stays valid; N and T are extruded from 2D
outlines with the same four-ring bevel profile every vanilla letter uses.
Writes levels/intro/leveldata.c (minimal edit) and levels/intro/nostr_logo.inc.c.
Output is a pure function of the pinned input, so reruns are byte-identical.

    python3 tools/gen_nostr_title_logo.py [--preview out.png]
"""
import argparse
import os
import re
import subprocess
from collections import namedtuple

import numpy as np

VANILLA_REV = "a39ac1f59273e26ec427f6d4c3086185ed81ca9f"
LEVELDATA = "levels/intro/leveldata.c"
INCLUDE = "levels/intro/nostr_logo.inc.c"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DL_MATERIAL = {
    "intro_seg7_dl_07008EA0": "tex1",
    "intro_seg7_dl_07009E38": "tex0",
    "intro_seg7_dl_0700ADC0": "shade",
}
NEW_DL = {"tex1": "intro_seg7_dl_nostr_tex1", "tex0": "intro_seg7_dl_nostr_tex0"}
DL_MATERIAL.update({name: material for material, name in NEW_DL.items()})

# The whole logo is tilted back 30 degrees about X; letters are laid out in
# this frame (x along the word, y up the letter, n out of the front face).
TILT = np.radians(30)
EX = np.array([1.0, 0.0, 0.0])
EN = np.array([0.0, np.sin(TILT), np.cos(TILT)])
EY = np.cross(EN, EX)

# (inset from the outline, depth below the front face) of every vanilla
# letter's rings: flat front, 45-degree tex1 bevel, steep wood bevel, wood side.
RINGS = ((41, 0), (20, -21), (0, -62), (0, -285))
RING_MATERIAL = ("tex1", "tex0", "tex0")

Copy = namedtuple("Copy", "word index")
Outline = namedtuple("Outline", "points")
Slot = namedtuple("Slot", "glyph replaces x y top")

# CCW outlines in tilted-frame units. Counters are narrow wedges like the
# vanilla U's slit; strokes stay wider than twice the front inset.
GLYPH_N = Outline((
    (0, 45), (40, 0), (165, 8), (175, 255), (225, 12), (425, 20), (465, 65),
    (470, 530), (300, 528), (292, 270), (245, 520), (50, 505), (8, 470),
))
GLYPH_T = Outline((
    (130, 0), (310, 10), (300, 345), (430, 362), (440, 525), (25, 510),
    (0, 360), (125, 350),
))

# SUPER -> NOSTR. `replaces` indexes SUPER: the new letter takes that slot's
# color. x, y place the glyph's bounding-box corner and top is its front-face
# depth, all in the tilted frame; letters further left sit further forward.
NOSTR = (
    Slot(GLYPH_N, 0, -1517, 430, 90),
    Slot(Copy("MARIO", 4), 1, -1137, 410, 80),
    Slot(Copy("SUPER", 0), 2, -644, 425, 69),
    Slot(GLYPH_T, 3, -220, 420, 51),
)

VTX_RE = re.compile(
    r"\{\{\{\s*(-?\d+),\s*(-?\d+),\s*(-?\d+)\},\s*0,\s*\{\s*(-?\d+),\s*(-?\d+)\},"
    r"\s*\{(0x\w+),\s*(0x\w+),\s*(0x\w+),\s*(0x\w+)\}\}\}")
LOAD_RE = re.compile(r"\s*gsSPVertex\((\w+), (\d+), 0\),")
TRI_RE = re.compile(r"\s*gsSP[12]Triangles?\(([\d\s,x]+)\),")


def tri_indices(match):
    return [int(x) for x in match.group(1).replace("0x0", "").replace(",", " ").split()]


def us_branch_mask(lines):
    """True for lines compiled by the US build (outside VERSION_CN-only code)."""
    mask, stack = [], []
    for line in lines:
        s = line.strip()
        if s.startswith("#if"):
            stack.append("cn" if s == "#if defined(VERSION_CN)" else "other")
        elif s.startswith(("#else", "#elif")) and stack and stack[-1] in ("cn", "notcn"):
            stack[-1] = "notcn"
        elif s.startswith("#endif"):
            stack.pop()
        mask.append("cn" not in stack)
    return mask


Mesh = namedtuple("Mesh", "arrays faces")
# A face remembers where its triangle command lives so it can be deleted.
Face = namedtuple("Face", "material verts line half")


def parse_mesh(lines):
    mask = us_branch_mask(lines)
    arrays, faces = {}, []
    i = 0
    while i < len(lines):
        m = re.match(r"static const (Vtx|Gfx) (\w+)\[\] = \{", lines[i])
        if not (m and mask[i]):
            i += 1
            continue
        end = lines.index("};", i)
        if m.group(1) == "Vtx":
            verts = [tuple(int(g, 0) for g in v.groups()) for v in map(VTX_RE.search, lines[i + 1:end]) if v]
            arrays[m.group(2)] = (i, end, verts)
        elif m.group(2) in DL_MATERIAL:
            material = DL_MATERIAL[m.group(2)]
            buf = []
            for j in range(i + 1, end):
                load = LOAD_RE.match(lines[j])
                tri = TRI_RE.match(lines[j])
                if load:
                    buf = arrays[load.group(1)][2]
                    assert len(buf) == int(load.group(2)), load.group(1)
                elif tri:
                    idx = tri_indices(tri)
                    for half in range(len(idx) // 3):
                        faces.append(Face(material, tuple(buf[k] for k in idx[3 * half:3 * half + 3]), j, half))
        i = end + 1
    return Mesh(arrays, faces)


def to_local(p):
    p = np.asarray(p, float)
    return np.array([p @ EX, p @ EY, p @ EN])


def normal(verts):
    a, b, c = (np.array(v[:3], float) for v in verts)
    n = np.cross(b - a, c - a)
    norm = np.linalg.norm(n)
    return n / norm if norm else n


def group_letters(faces):
    """Union faces that share a vertex position; returns lists of faces."""
    parent = list(range(len(faces)))

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    owner = {}
    for i, f in enumerate(faces):
        for v in f.verts:
            parent[find(i)] = find(owner.setdefault(v[:3], i))
    groups = {}
    for i, f in enumerate(faces):
        groups.setdefault(find(i), []).append(f)
    return list(groups.values())


Letter = namedtuple("Letter", "faces lo hi top front bevels")


def is_front(face):
    return face.material == "tex1" and normal(face.verts) @ EN > 0.99


def make_letter(faces):
    pts = np.array([to_local(v[:3]) for f in faces for v in f.verts])
    fronts = [f for f in faces if is_front(f)]
    front = max({f.verts[0][5:8] for f in fronts}, key=lambda c: sum(f.verts[0][5:8] == c for f in fronts))
    bevels = [f for f in faces if f.material == "tex1" and not is_front(f)]
    return Letter(faces, pts[:, :2].min(0), pts[:, :2].max(0), pts[:, 2].max(), front, bevels)


def words(faces):
    """The SUPER and MARIO letters, left to right; "64" has no front face."""
    letters = [make_letter(g) for g in group_letters(faces) if any(map(is_front, g))]
    top = sorted((l for l in letters if l.lo[1] > 300), key=lambda l: l.lo[0])
    bottom = sorted((l for l in letters if l.lo[1] <= 300), key=lambda l: l.lo[0])
    assert len(top) == 5 and len(bottom) == 5, (len(top), len(bottom))
    return {"SUPER": top, "MARIO": bottom}


def nearest_color(normal, samples):
    normals, colors = samples
    return colors[int(np.argmax(normals @ normal))]


def color_samples(faces):
    faces = [f for f in faces if np.any(normal(f.verts))]
    return np.array([normal(f.verts) for f in faces]), [f.verts[0][5:8] for f in faces]


def fit_uv(faces):
    """Vanilla UVs are one planar projection per material; fit it."""
    proj = {}
    for material in ("tex1", "tex0"):
        rows = [v for f in faces if f.material == material for v in f.verts]
        X = np.array([(*v[:3], 1) for v in rows], float)
        proj[material], *_ = np.linalg.lstsq(X, np.array([v[3:5] for v in rows], float), rcond=None)
    return proj


def ring(points, inset):
    """Inset a CCW outline: mitered at convex and shallow reflex corners,
    square-capped at sharp reflex ones (notch tips) so the vertex count is the
    same at every inset and miters never shoot down a narrow notch."""
    P = np.array(points, float)
    out = []
    for i in range(len(P)):
        t_in = P[i] - P[i - 1]
        t_out = P[(i + 1) % len(P)] - P[i]
        t_in, t_out = t_in / np.linalg.norm(t_in), t_out / np.linalg.norm(t_out)
        n_in, n_out = np.array([-t_in[1], t_in[0]]), np.array([-t_out[1], t_out[0]])
        if t_in[0] * t_out[1] - t_in[1] * t_out[0] < 0 and t_in @ t_out < 0:
            out += [P[i] + inset * (n_in + t_in), P[i] + inset * (n_out - t_out)]
        else:
            out.append(P[i] + inset * (n_in + n_out) / (1 + n_in @ n_out))
    return np.array(out)


def ear_clip(poly):
    idx = list(range(len(poly)))
    tris = []

    def cross(o, a, b):
        return (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0])

    while len(idx) > 3:
        for k in range(len(idx)):
            a, b, c = idx[k - 1], idx[k], idx[(k + 1) % len(idx)]
            if cross(poly[a], poly[b], poly[c]) <= 1e-6:
                continue
            others = (j for j in idx if j not in (a, b, c))
            if any(cross(poly[a], poly[b], poly[j]) >= 0 and cross(poly[b], poly[c], poly[j]) >= 0
                   and cross(poly[c], poly[a], poly[j]) >= 0 for j in others):
                continue
            tris.append((a, b, c))
            idx.pop(k)
            break
        else:
            raise ValueError("outline is not a simple CCW polygon")
    tris.append(tuple(idx))
    return tris


def world(x, y, depth):
    return tuple(int(round(c)) for c in EX * x + EY * y + EN * depth)


def extrude(outline, x0, y0, top):
    """(material, 3 world points) faces of a letter solid, wound outward."""
    local = [ring(outline.points, inset) for inset, _ in RINGS]
    rings = [[world(x0 + x, y0 + y, top + depth) for x, y in pts] for pts, (_, depth) in zip(local, RINGS)]
    faces = [("front", tuple(rings[0][k] for k in tri)) for tri in ear_clip(local[0])]
    for a, b, material in zip(rings, rings[1:], RING_MATERIAL):
        for i in range(len(a)):
            j = (i + 1) % len(a)
            for tri in ((a[i], b[i], b[j]), (a[i], b[j], a[j])):
                if len(set(tri)) == 3:
                    faces.append((material, tri))
    return faces


def build_nostr(vanilla):
    word = words(vanilla)
    uv = fit_uv([f for l in word["SUPER"] for f in l.faces])
    wood = color_samples([f for l in word["SUPER"] + word["MARIO"] for f in l.faces if f.material == "tex0"])

    def vtx(p, material, color):
        s, t = (int(round(c)) for c in np.array((*p, 1), float) @ uv[material])
        return (*p, s, t, *color, 0xFF)

    new = []
    for slot in NOSTR:
        target = word["SUPER"][slot.replaces]
        bevel = color_samples(target.bevels)
        if isinstance(slot.glyph, Copy):
            src = word[slot.glyph.word][slot.glyph.index]
            shift = world(slot.x - src.lo[0], slot.y - src.lo[1], slot.top - src.top)
            for f in src.faces:
                pts = [tuple(a + b for a, b in zip(v[:3], shift)) for v in f.verts]
                if f.material == "tex0":
                    new.append(("tex0", tuple(vtx(p, "tex0", v[5:8]) for p, v in zip(pts, f.verts))))
                    continue
                color = target.front if is_front(f) else nearest_color(normal(f.verts), bevel)
                new.append(("tex1", tuple(vtx(p, "tex1", color) for p in pts)))
        else:
            for kind, pts in extrude(slot.glyph, slot.x, slot.y, slot.top):
                material = "tex1" if kind == "front" else kind
                color = (target.front if kind == "front"
                         else nearest_color(normal(pts), bevel if material == "tex1" else wood))
                new.append((material, tuple(vtx(p, material, color) for p in pts)))
    return word, new


def fmt_vtx(v):
    return ("    {{{%6d, %6d, %6d}, 0, {%6d, %6d}, {0x%02x, 0x%02x, 0x%02x, 0x%02x}}},"
            % v)


def fmt_tris(idx):
    if len(idx) == 6:
        return "    gsSP2Triangles(%2d, %2d, %2d, 0x0, %2d, %2d, %2d, 0x0)," % idx
    return "    gsSP1Triangle(%2d, %2d, %2d, 0x0)," % idx


def emit_include(new):
    out = ["// Generated by tools/gen_nostr_title_logo.py; do not edit.", ""]
    dls = {}
    for material in ("tex1", "tex0"):
        faces = [verts for m, verts in new if m == material]
        batches = []
        for verts in faces:
            if not batches or len(set(batches[-1][0]) | set(verts)) > 16:
                batches.append(([], []))
            buf, tris = batches[-1]
            for v in verts:
                if v not in buf:
                    buf.append(v)
            tris.append(tuple(buf.index(v) for v in verts))
        body = []
        for n, (buf, tris) in enumerate(batches):
            name = f"intro_seg7_vertex_nostr_{material}_{n:02d}"
            out += [f"static const Vtx {name}[] = {{", *map(fmt_vtx, buf), "};", ""]
            body.append(f"    gsSPVertex({name}, {len(buf)}, 0),")
            body += [fmt_tris(sum(tris[k:k + 2], ())) for k in range(0, len(tris), 2)]
        dls[material] = body
    for material, body in dls.items():
        out += [f"static const Gfx {NEW_DL[material]}[] = {{", *body, "    gsSPEndDisplayList(),", "};", ""]
    return "\n".join(out[:-1]) + "\n"


def edit_leveldata(lines, mesh, doomed):
    """Drop the doomed faces' triangle commands, then any vertex load and Vtx
    array left without a triangle, and call the NOSTR display lists."""
    lines = list(lines)
    mask = us_branch_mask(lines)
    keep = {}
    for f in mesh.faces:
        keep.setdefault(f.line, {})[f.half] = f not in doomed
    for j, halves in keep.items():
        if all(halves.values()):
            continue
        idx = tri_indices(TRI_RE.match(lines[j]))
        survivors = sum((tuple(idx[3 * h:3 * h + 3]) for h, k in sorted(halves.items()) if k), ())
        lines[j] = fmt_tris(survivors) if survivors else None

    used = set()
    for j, line in enumerate(lines):
        load = line is not None and mask[j] and LOAD_RE.match(line)
        if not load:
            continue
        following = next(l for l in lines[j + 1:] if l is not None)
        if TRI_RE.match(following):
            used.add(load.group(1))
        else:
            lines[j] = None

    for name, (start, end, _) in mesh.arrays.items():
        if name in used:
            continue
        assert lines[start - 1].startswith("// 0x"), name
        for k in range(start - 1, end + 1):
            lines[k] = None
        if lines[end + 1] == "":
            lines[end + 1] = None

    for j, line in enumerate(lines):
        if not (line is not None and mask[j]):
            continue
        if line == "const Gfx intro_seg7_dl_logo[] = {":
            lines[j - 1] = f'#include "{INCLUDE}"\n\n' + lines[j - 1]
        for old, new in (("intro_seg7_dl_07008EA0", "tex1"), ("intro_seg7_dl_07009E38", "tex0")):
            if line == f"    gsSPDisplayList({old}),":
                lines[j] = f"{line}\n    gsSPDisplayList({NEW_DL[new]}),"
    return "\n".join(l for l in lines if l is not None) + "\n"


def logo_faces(lines, include):
    """Every logo face the US build draws, parsed back from the written files."""
    text = "\n".join(lines).replace(f'#include "{INCLUDE}"', include)
    return parse_mesh(text.splitlines()).faces


def render(faces, out, W=960, H=720, cam=3200, fov=45):
    tex = {}
    for material, png in (("tex0", "0.rgba16.png"), ("tex1", "1.rgba16.png")):
        raw = subprocess.run(["magick", os.path.join(ROOT, "levels/intro", png), "-depth", "8", "rgb:-"],
                             check=True, capture_output=True).stdout
        tex[material] = np.frombuffer(raw, np.uint8).reshape(32, 32, 3) / 255.0
    img = np.zeros((H, W, 3))
    zbuf = np.full((H, W), np.inf)
    focal = (H / 2) / np.tan(np.radians(fov / 2))
    for f in faces:
        P = [(W / 2 + focal * v[0] / (cam - v[2]), H / 2 - focal * v[1] / (cam - v[2]), cam - v[2]) for v in f.verts]
        (ax, ay, az), (bx, by, bz), (cx, cy, cz) = P
        den = (by - cy) * (ax - cx) + (cx - bx) * (ay - cy)
        if abs(den) < 1e-9:
            continue
        x0, x1 = max(int(min(ax, bx, cx)), 0), min(int(max(ax, bx, cx)) + 1, W - 1)
        y0, y1 = max(int(min(ay, by, cy)), 0), min(int(max(ay, by, cy)) + 1, H - 1)
        if x0 > x1 or y0 > y1:
            continue
        gx, gy = np.meshgrid(np.arange(x0, x1 + 1) + 0.5, np.arange(y0, y1 + 1) + 0.5)
        w0 = ((by - cy) * (gx - cx) + (cx - bx) * (gy - cy)) / den
        w1 = ((cy - ay) * (gx - cx) + (ax - cx) * (gy - cy)) / den
        w2 = 1 - w0 - w1
        z = w0 * az + w1 * bz + w2 * cz
        sub = zbuf[y0:y1 + 1, x0:x1 + 1]
        hit = (w0 >= 0) & (w1 >= 0) & (w2 >= 0) & (z < sub)
        if not hit.any():
            continue
        w = np.stack([w0, w1, w2], -1)
        color = w @ (np.array([v[5:8] for v in f.verts], float) / 255.0)
        if f.material in tex:
            st = w @ (np.array([v[3:5] for v in f.verts], float) / 32.0)
            color *= tex[f.material][np.floor(st[..., 1]).astype(int) % 32, np.floor(st[..., 0]).astype(int) % 32]
        sub[hit] = z[hit]
        img[y0:y1 + 1, x0:x1 + 1][hit] = color[hit]
    ppm = b"P6 %d %d 255\n" % (W, H) + (np.clip(img, 0, 1) * 255).astype(np.uint8).tobytes()
    subprocess.run(["magick", "ppm:-", out], input=ppm, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--preview", metavar="PNG", help="also render the resulting logo to this PNG")
    args = parser.parse_args()

    vanilla = subprocess.run(["git", "-C", ROOT, "show", f"{VANILLA_REV}:{LEVELDATA}"],
                             check=True, capture_output=True, text=True).stdout.splitlines()
    mesh = parse_mesh(vanilla)
    word, new = build_nostr(mesh.faces)
    doomed = {f for slot in NOSTR for f in word["SUPER"][slot.replaces].faces}
    include = emit_include(new)
    leveldata = edit_leveldata(vanilla, mesh, doomed)
    kept = [(f.material, f.verts) for f in parse_mesh(leveldata.splitlines()).faces]
    assert kept == [(f.material, f.verts) for f in mesh.faces if f not in doomed], "edit touched a kept face"
    for path, text in ((LEVELDATA, leveldata), (INCLUDE, include)):
        with open(os.path.join(ROOT, path), "w") as fh:
            fh.write(text)
    if args.preview:
        render(logo_faces(leveldata.splitlines(), include), args.preview)


if __name__ == "__main__":
    main()
