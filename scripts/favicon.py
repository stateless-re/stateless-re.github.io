"""Draw the site icon as files Google can crawl: favicon.ico (16/32/48),
a 192px PNG, the 180px Apple touch icon, and the SVG browsers prefer.

The mark is 0x73, the byte for "s", in the highlighter on the night paper.
Run from the repository root; output goes to static/. Needs Pillow.
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "static"
FONT = ROOT / "scripts" / "fonts" / "JetBrainsMono-Bold.ttf"
NIGHT = "#0f1f3d"
MARK = "#ffdd3c"

SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    f'<rect width="32" height="32" rx="4" fill="{NIGHT}"/>'
    '<text x="16" y="22" font-family="JetBrains Mono, ui-monospace, monospace" '
    f'font-size="15" font-weight="700" fill="{MARK}" text-anchor="middle">73</text>'
    "</svg>\n"
)


def draw(size, radius=True, scale=4):
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    r = round(s * 4 / 32) if radius else 0
    d.rounded_rectangle((0, 0, s - 1, s - 1), radius=r, fill=NIGHT)
    f = ImageFont.truetype(str(FONT), round(s * 15 / 32))
    d.text((s / 2, s * 22 / 32), "73", font=f, fill=MARK, anchor="ms")
    return img.resize((size, size), Image.LANCZOS)


def main():
    OUT.mkdir(exist_ok=True)
    (OUT / "favicon.svg").write_text(SVG)
    draw(48).save(OUT / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
    draw(192).save(OUT / "favicon-192.png", optimize=True)
    draw(180, radius=False).convert("RGB").save(OUT / "apple-touch-icon.png", optimize=True)


if __name__ == "__main__":
    main()
