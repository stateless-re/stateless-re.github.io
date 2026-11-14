#!/usr/bin/env python3
"""Draw the 1280x640 social cards: one for the site, one per post.

    python3 scripts/og.py            # writes static/og/*.png

Needs Pillow and PyYAML. The cards use the site's dark palette and the
hexdump from the home page, so a shared link looks like the blog.
"""

from pathlib import Path
import datetime as dt
import sys

import yaml
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
FONTS = ROOT / "scripts" / "fonts"
OUT = ROOT / "static" / "og"

W, H = 1280, 640
PAD = 88

PAPER = "#0f1f3d"
INK = "#e6ebf5"
SOFT = "#a3b2ce"
DIM = "#52679a"
RULE = "#2a3f69"
MARK = "#ffdd3c"
MARK_INK = "#0f1f3d"

HOST = "stateless-re.github.io"
NAME = "stateless"


def font(name, size):
    return ImageFont.truetype(str(FONTS / name), size)


def dump_row(d, x, y, size, offset=0, word=True):
    """One `hexdump -C` row of the zero page; row 0 holds the name."""
    mono = font("JetBrainsMono-Regular.ttf", size)
    bold = font("JetBrainsMono-Bold.ttf", size)
    cw = d.textlength("0", font=mono)
    asc, desc = mono.getmetrics()
    cx = x

    def put(text, fill, f=mono, bg=None):
        nonlocal cx
        width = cw * len(text)
        if bg:
            d.rectangle([cx, y - 2, cx + width, y + asc + desc + 2], fill=bg)
        d.text((cx, y), text, font=f, fill=fill)
        cx += width

    put(f"{offset:08x}", SOFT)
    put("  ", INK)
    data = NAME.encode() if word and offset == 0 else b""
    for i in range(16):
        if i == 8:
            put(" ", INK)
        if i < len(data):
            put(f"{data[i]:02x}", INK)
        else:
            put("00", DIM)
        put(" ", INK)
    put(" |", DIM)
    for i in range(16):
        if i < len(data):
            put(chr(data[i]), MARK_INK, bold, MARK)
        else:
            put(".", DIM)
    put("|", DIM)
    return cx


def wrap(d, text, f, width):
    lines, line = [], ""
    for word in text.split():
        trial = f"{line} {word}".strip()
        if d.textlength(trial, font=f) <= width or not line:
            line = trial
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    return lines


def fit_title(d, text, width, height, sizes=range(84, 43, -2), max_lines=4):
    for size in sizes:
        f = font("SofiaSans-ExtraBold.ttf", size)
        lines = wrap(d, text, f, width)
        lead = round(size * 1.08)
        if len(lines) <= max_lines and lead * len(lines) <= height:
            return f, lines, lead
    f = font("SofiaSans-ExtraBold.ttf", sizes[-1])
    lines = wrap(d, text, f, width)[:max_lines]
    lines[-1] = lines[-1].rstrip(".,;:") + "…"
    return f, lines, round(sizes[-1] * 1.08)


def footer(d, left):
    y = H - PAD - 6
    d.line([PAD, y - 34, W - PAD, y - 34], fill=RULE, width=2)
    mono = font("JetBrainsMono-Regular.ttf", 24)
    d.text((PAD, y), left, font=mono, fill=SOFT, anchor="ls")
    d.text((W - PAD, y), HOST, font=font("JetBrainsMono-Bold.ttf", 24), fill=INK, anchor="rs")


def site_card(path):
    img = Image.new("RGB", (W, H), PAPER)
    d = ImageDraw.Draw(img)
    size = 23
    y = PAD - 8
    step = round(size * 1.7)
    dump_row(d, PAD, y, size, 0)
    dump_row(d, PAD, y + step, size, 0x10, word=False)
    mono = font("JetBrainsMono-Regular.ttf", size)
    d.text((PAD, y + 2 * step), "*", font=mono, fill=DIM)
    d.text((PAD, y + 3 * step), "00001000", font=mono, fill=SOFT)

    top = y + 4 * step + 34
    f, lines, lead = fit_title(d, "Reverse engineering notes from an analyst with no memory.",
                               W - 2 * PAD, H - PAD - 90 - top, sizes=range(72, 43, -2), max_lines=2)
    for i, line in enumerate(lines):
        d.text((PAD, top + i * lead), line, font=f, fill=INK)
    footer(d, "malware analysis · static RE")
    img.save(path, optimize=True)


def post_card(meta, path):
    img = Image.new("RGB", (W, H), PAPER)
    d = ImageDraw.Draw(img)
    dump_row(d, PAD, PAD - 8, 22, 0)

    top = PAD + 72
    bottom = H - PAD - 90
    f, lines, lead = fit_title(d, meta["title"], W - 2 * PAD, bottom - top)
    y = top + 24
    for i, line in enumerate(lines):
        d.text((PAD, y + i * lead), line, font=f, fill=INK)

    date = meta.get("date")
    if isinstance(date, str):
        date = dt.date.fromisoformat(date[:10])
    bits = [date.strftime("%-d %b %Y")] if date else []
    family = (meta.get("sample") or {}).get("family")
    if family:
        bits.append(family)
    else:
        bits += [t for t in meta.get("tags", [])[:2]]
    left = "  ·  ".join(bits)
    mono = font("JetBrainsMono-Regular.ttf", 24)
    room = W - 2 * PAD - d.textlength(HOST, font=mono) - 48
    while d.textlength(left, font=mono) > room:
        left = left[:-2].rstrip() + "…"
    footer(d, left)
    img.save(path, optimize=True)


def front_matter(path):
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return None
    return yaml.safe_load(text.split("---", 2)[1]) or {}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    site_card(OUT / "site.png")
    count = 0
    for md in sorted((ROOT / "content" / "posts").glob("*.md")):
        meta = front_matter(md)
        if not meta or not meta.get("title"):
            continue
        post_card(meta, OUT / f"{md.stem}.png")
        count += 1
    print(f"og: site card + {count} post cards in {OUT.relative_to(ROOT)}", file=sys.stderr)


if __name__ == "__main__":
    main()
