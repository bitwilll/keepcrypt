#!/usr/bin/env python3
"""Draws docs/img/seed-pipeline.svg, design.md's seed-pipeline figure (tasks/todo.md, M7 H1; owner item 13, Q108 (b)).

The figure's numbers are computed here, never typed (tasks/lessons.md, 2026-10-09): the roll quotas are read from
core/src/dice.rs, the bits per roll are log2(6), and the bits of a quota are the two multiplied, to one decimal.
The output is plain text with no date or tool version, so the same tree always draws the same bytes.

Usage:
  python3 -I tools/figures/seed_pipeline.py           writes docs/img/seed-pipeline.svg
  python3 -I tools/figures/seed_pipeline.py --check   fails unless the committed file is what this draws (CI)

Exit: 0 written or matching; 1 the committed file differs or core's quotas cannot be read; 2 bad usage.
"""

import math
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DICE = os.path.join(ROOT, "core", "src", "dice.rs")
OUT = os.path.join(ROOT, "docs", "img", "seed-pipeline.svg")

INK = "#1f2328"
MUTED = "#57606a"
LINE = "#b9bcb0"
EDGE = "#c8cac2"
BLUE = "#2f6fd0"
BLUE_FILL = "#e5eef9"
FONT = "-apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"


class Fail(Exception):
    pass


def quotas():
    """core's three roll quotas, by name; each must appear exactly once."""
    with open(DICE, encoding="utf-8") as f:
        text = f.read()
    out = {}
    for name in ("MIN_ROLLS_12_WORDS", "MIN_ROLLS_24_WORDS", "MIN_ROLLS_AFTER_COLLISION"):
        found = re.findall(rf"\bconst {name}: u16 = (\d+);", text)
        if len(found) != 1:
            raise Fail(f"{DICE}: {name} found {len(found)} times, not once")
        out[name] = int(found[0])
    return out


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text(x, y, s, size, weight="normal", fill=INK):
    w = ' font-weight="600"' if weight == "bold" else ""
    return f'<text x="{x}" y="{y}" font-size="{size}"{w} fill="{fill}">{esc(s)}</text>'


def box(x, y, w, h, title, lines, kind="plain"):
    if kind == "combine":
        frame = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{BLUE_FILL}" stroke="{BLUE}" stroke-width="3"/>'
    elif kind == "dashed":
        frame = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="#ffffff" stroke="{EDGE}" stroke-width="2" stroke-dasharray="7 6"/>'
    else:
        frame = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="#ffffff" stroke="{EDGE}" stroke-width="2"/>'
    parts = [frame, text(x + 22, y + 42, title, 23, "bold")]
    for i, line in enumerate(lines):
        parts.append(text(x + 22, y + 72 + 29 * i, line, 20, fill=MUTED))
    return parts


def arrow(points, dashed=False):
    d = " ".join(f"{'M' if i == 0 else 'L'}{x} {y}" for i, (x, y) in enumerate(points))
    dash = ' stroke-dasharray="7 6"' if dashed else ""
    return f'<path d="{d}" fill="none" stroke="{LINE}" stroke-width="2"{dash} marker-end="url(#head)"/>'


def draw():
    q = quotas()
    per_roll = math.log2(6)
    r12, r24, rcol = q["MIN_ROLLS_12_WORDS"], q["MIN_ROLLS_24_WORDS"], q["MIN_ROLLS_AFTER_COLLISION"]
    bits12, bits24 = r12 * per_roll, r24 * per_roll
    if bits12 < 128:
        raise Fail(f"{r12} rolls give {bits12:.1f} bits, under the 128 a 12-word seed needs")

    w, h = 1344, 1010
    lx, lw, rx, rw = 42, 652, 764, 538
    s = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" font-family="{FONT}">',
        "<title>KeepCrypt-Entropy seed pipeline: two legs, one combine step</title>",
        "<defs>",
        f'<marker id="head" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" orient="auto-start-reverse"><path d="M0 1 L9 5 L0 9 z" fill="{LINE}"/></marker>',
        "</defs>",
        f'<rect width="{w}" height="{h}" fill="#ffffff"/>',
        text(lx, 50, "The seed stays safe if either the device leg or the dice leg is honest", 27, "bold"),
        text(lx, 86, "Every state stays at least 256 bits wide; any failed test or missed quota halts generation", 20, fill=MUTED),
        text(lx, 134, "Device leg D", 23, "bold"),
        text(rx, 134, "User leg R", 23, "bold"),
    ]
    # The device leg.
    s += box(lx, 160, lw, 156, "Device sources", [
        "hardware RNG and getrandom(): credited",
        "open TRNG in phase 2: credited",
        "camera, mic, IMU, keys: mixed, never counted",
    ])
    s += box(lx, 358, lw, 128, "Health tests on raw samples", [
        "Repetition Count and Adaptive Proportion",
        "any failure halts; no fallback path",
    ])
    s += box(lx, 528, lw, 128, "SHA-512 pool, 512 bits wide", [
        "tag, length and data for every record",
        "D = first 32 bytes of the digest",
    ])
    s += [arrow([(368, 316), (368, 356)]), arrow([(368, 486), (368, 526)])]
    # The user leg.
    s += box(rx, 160, rw, 128, "Commitment C shown first", [
        "C = SHA-256(tag, D)",
        "on screen before any roll is typed",
    ])
    s += box(rx, 358, rw, 128, "Physical dice", [
        f"{r12} rolls for 12 words, {r24} for 24",
        f"{rcol} after a collision; typed in privately",
    ])
    s += box(rx, 528, rw, 128, "Roll string R", [
        f"{per_roll:.3f} bits per roll (log2 6)",
        f"{r12} rolls give {bits12:.1f} bits; {r24} give {bits24:.1f}",
    ])
    s += [arrow([(1033, 288), (1033, 356)]), arrow([(1033, 486), (1033, 526)])]
    # D to the commitment.
    s += [arrow([(694, 592), (729, 592), (729, 224), (762, 224)]), text(740, 414, "D", 20, fill=MUTED)]
    # The combine step and the words.
    s += box(283, 712, 778, 128, "Combine: E = SHA-256(tag, D, len(R), R)", [
        "strong if either leg is honest",
        "dice-only mode: E = SHA-256(R), as Coldcard",
    ], "combine")
    s += [arrow([(368, 656), (368, 710)]), arrow([(1033, 656), (1033, 710)])]
    s += box(354, 878, 636, 112, "BIP39 encoding: 12 words (24 optional)", [
        "12: first 128 bits of E; 24: all 256; plus checksum",
    ])
    s += [arrow([(672, 840), (672, 876)])]
    s += box(1046, 878, 256, 112, "Offline verifier", ["recomputes C and E"], "dashed")
    s += [arrow([(1044, 934), (992, 934)], dashed=True)]
    s.append("</svg>")
    return "\n".join(s) + "\n"


def main(argv):
    if argv not in ([], ["--check"]):
        print(__doc__.strip().split("\n\n")[2], file=sys.stderr)
        return 2
    try:
        svg = draw()
    except (Fail, OSError) as e:
        print(f"FAIL: seed_pipeline: {e}", file=sys.stderr)
        return 1
    if argv == ["--check"]:
        try:
            with open(OUT, encoding="utf-8", newline="") as f:
                same = f.read() == svg
        except OSError as e:
            print(f"FAIL: seed_pipeline: {e}", file=sys.stderr)
            return 1
        if not same:
            print(f"FAIL: seed_pipeline: {OUT} is not what this script draws; run it and commit the result", file=sys.stderr)
            return 1
        print(f"seed_pipeline: {os.path.relpath(OUT, ROOT)} matches what this script draws")
        return 0
    with open(OUT, "w", encoding="utf-8", newline="") as f:
        f.write(svg)
    print(f"seed_pipeline: wrote {os.path.relpath(OUT, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
