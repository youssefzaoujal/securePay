"""Génère docs/assets/demo-carding.gif — storyboard du lab (pas un screen record)."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parents[1] / "docs" / "assets" / "demo-carding.gif"
FRAMES = [
    ("1. Attaque carding", "25 PAN / même IP  T1657", "#2a1218", "#ff4d6d"),
    ("2. JSONL → Sigma", "seuil 10 échecs / 5 min", "#101028", "#6d7cff"),
    ("3. SOAR block IP", "gateway 403  TTL 1h", "#132a22", "#3dffb0"),
    ("4. TheHive + ATT&CK", "ticket + layer auto", "#2a2210", "#ffb020"),
]


def _font(size: int):
    for name in ("segoeui.ttf", "arial.ttf", "DejaVuSans.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    images = []
    title_f, body_f = _font(28), _font(18)
    for title, body, bg, fg in FRAMES:
        img = Image.new("RGB", (720, 220), bg)
        draw = ImageDraw.Draw(img)
        draw.text((36, 48), title, fill=fg, font=title_f)
        draw.text((36, 110), body, fill="#e8e8ff", font=body_f)
        draw.text((36, 170), "SecurePay lab  ·  simulation  ·  pas de PAN réel", fill="#8b8bb0", font=_font(14))
        images.append(img)
    images[0].save(
        OUT,
        save_all=True,
        append_images=images[1:],
        duration=1400,
        loop=0,
        optimize=True,
    )
    print(OUT)


if __name__ == "__main__":
    main()
