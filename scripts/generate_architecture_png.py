"""Generate the SecurePay architecture poster as a reproducible PNG."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

WIDTH, HEIGHT = 2400, 1480
ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "assets" / "securepay-architecture.png"

BG = "#07151b"
PANEL = "#0c2229"
PANEL_ALT = "#102c34"
TEXT = "#effaf7"
MUTED = "#91afb3"
LINE = "#24515a"
CYAN = "#62d9df"
GREEN = "#5ae0ae"
ORANGE = "#f1b867"
RED = "#ff7888"
BLUE = "#86b8ff"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    name = "seguisb.ttf" if bold else "segoeui.ttf"
    path = Path("C:/Windows/Fonts") / name
    return ImageFont.truetype(str(path), size)


def rounded(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], fill: str, outline: str = LINE, radius: int = 16, width: int = 2) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def label(draw: ImageDraw.ImageDraw, xy: tuple[int, int], value: str, size: int, color: str = TEXT, bold: bool = False) -> None:
    draw.text(xy, value, font=font(size, bold), fill=color)


def node(draw: ImageDraw.ImageDraw, x: int, y: int, w: int, h: int, title: str, detail: str, accent: str = CYAN, tag: str | None = None) -> None:
    rounded(draw, (x, y, x + w, y + h), PANEL_ALT, LINE, 14)
    draw.rectangle((x, y, x + 7, y + h), fill=accent)
    label(draw, (x + 24, y + 20), title, 21 if len(title) > 18 else 25, TEXT, True)
    label(draw, (x + 24, y + 58), detail, 16, MUTED)
    if tag:
        tw = draw.textbbox((0, 0), tag, font=font(14, True))[2] + 24
        rounded(draw, (x + w - tw - 18, y + 18, x + w - 18, y + 45), BG, accent, 12, 1)
        label(draw, (x + w - tw - 6, y + 23), tag, 14, accent, True)


def arrow(draw: ImageDraw.ImageDraw, start: tuple[int, int], end: tuple[int, int], color: str = CYAN, width: int = 4) -> None:
    draw.line((*start, *end), fill=color, width=width)
    x1, y1 = start
    x2, y2 = end
    if abs(x2 - x1) >= abs(y2 - y1):
        direction = 1 if x2 > x1 else -1
        points = [(x2, y2), (x2 - 18 * direction, y2 - 10), (x2 - 18 * direction, y2 + 10)]
    else:
        direction = 1 if y2 > y1 else -1
        points = [(x2, y2), (x2 - 10, y2 - 18 * direction), (x2 + 10, y2 - 18 * direction)]
    draw.polygon(points, fill=color)


def section(draw: ImageDraw.ImageDraw, x: int, y: int, w: int, h: int, title: str, accent: str) -> None:
    rounded(draw, (x, y, x + w, y + h), BG, LINE, 20, 2)
    draw.line((x + 26, y + 60, x + w - 26, y + 60), fill=LINE, width=2)
    label(draw, (x + 26, y + 20), title.upper(), 17, accent, True)


def main() -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)

    # Subtle grid gives the poster a technical, presentation-ready texture.
    for x in range(0, WIDTH, 80):
        draw.line((x, 0, x, HEIGHT), fill="#0a2027", width=1)
    for y in range(0, HEIGHT, 80):
        draw.line((0, y, WIDTH, y), fill="#0a2027", width=1)

    label(draw, (90, 58), "SECUREPAY", 25, CYAN, True)
    label(draw, (90, 98), "Payment platform · Detection engineering · Hardened cloud foundation", 32, TEXT, True)
    label(draw, (90, 148), "Architecture overview / lab-to-production path", 18, MUTED)
    rounded(draw, (1885, 62, 2308, 122), PANEL, GREEN, 28, 2)
    label(draw, (1920, 81), "ZERO TRUST · PCI-INSPIRED", 16, GREEN, True)

    section(draw, 80, 220, 2240, 190, "01 / Edge & identity", CYAN)
    node(draw, 120, 285, 420, 90, "Merchant / Admin", "OAuth2 client credentials · OIDC + MFA", BLUE, "CLIENT")
    node(draw, 650, 285, 420, 90, "NGINX WAF", "TLS 1.3 · rate limits · security headers", CYAN, "EDGE")
    node(draw, 1180, 285, 420, 90, "Keycloak", "JWT RS256 · JWKS · anti-replay jti", ORANGE, "AUTH")
    node(draw, 1710, 285, 560, 90, "API Gateway", "FastAPI · correlation-id · BOLA enforcement", GREEN, "CONTROL PLANE")
    arrow(draw, (540, 330), (650, 330), CYAN)
    arrow(draw, (1070, 330), (1180, 330), CYAN)
    arrow(draw, (1600, 330), (1710, 330), CYAN)

    section(draw, 80, 450, 1460, 550, "02 / Payment processing plane", GREEN)
    node(draw, 120, 520, 420, 115, "Tokenization", "AES-256-GCM vault · CVV destroyed", CYAN, "CDE")
    node(draw, 600, 520, 420, 115, "Fraud engine", "Velocity + Isolation Forest · risk score", ORANGE, "RISK")
    node(draw, 1080, 520, 420, 115, "3DS Server", "EMV 3DS 2.3.1 · frictionless / challenge", BLUE, "SCA")
    node(draw, 120, 715, 420, 115, "Payment service", "Idempotence · capture · HMAC webhook", GREEN, "LEDGER")
    node(draw, 600, 715, 420, 115, "Core adapter", "mTLS · argv sanitization · fail closed", RED, "mTLS")
    node(draw, 1080, 715, 420, 115, "GnuCOBOL core", "Account balance validation", ORANGE, "LEGACY")
    arrow(draw, (540, 578), (600, 578), GREEN)
    arrow(draw, (1020, 578), (1080, 578), GREEN)
    arrow(draw, (810, 635), (810, 715), GREEN)
    arrow(draw, (330, 635), (330, 715), GREEN)
    arrow(draw, (540, 772), (600, 772), GREEN)
    arrow(draw, (1020, 772), (1080, 772), GREEN)
    arrow(draw, (1500, 330), (1500, 520), GREEN)
    label(draw, (170, 920), "PAN stays in the tokenization boundary · decisions emit redacted JSON events", 16, MUTED)

    section(draw, 1580, 450, 740, 550, "03 / Security operations", RED)
    node(draw, 1620, 520, 300, 115, "Event bus", "JSONL · OpenTelemetry", CYAN, "TRACE")
    node(draw, 1980, 520, 300, 115, "Sigma engine", "MITRE ATT&CK mapping", ORANGE, "DETECT")
    node(draw, 1620, 715, 300, 115, "SOAR", "Blocklist IP · TTL · 403", RED, "RESPOND")
    node(draw, 1980, 715, 300, 115, "TheHive / OpenCTI", "Cases · STIX enrichment", BLUE, "CASE")
    arrow(draw, (1920, 578), (1980, 578), RED)
    arrow(draw, (2130, 635), (2130, 715), RED)
    arrow(draw, (1980, 772), (1920, 772), RED)
    arrow(draw, (1710, 635), (1710, 715), RED)
    arrow(draw, (1500, 820), (1620, 578), RED)
    label(draw, (1620, 920), "Detect → enrich → contain → audit", 16, MUTED)

    section(draw, 80, 1040, 2240, 300, "04 / Delivery & platform guardrails", BLUE)
    node(draw, 120, 1115, 400, 120, "GitHub Actions", "Tests · Ruff · Bandit · CodeQL · Semgrep", BLUE, "CI")
    node(draw, 590, 1115, 400, 120, "Supply chain", "Trivy · SBOM · Cosign · SLSA provenance", ORANGE, "TRUST")
    node(draw, 1060, 1115, 400, 120, "GHCR", "Immutable image digests · signed artifacts", CYAN, "REGISTRY")
    node(draw, 1530, 1115, 400, 120, "Kubernetes", "Kyverno · OPA · Falco · NetworkPolicy", GREEN, "RUNTIME")
    node(draw, 2000, 1115, 280, 120, "Vault", "Secrets injection", RED, "SECRETS")
    arrow(draw, (520, 1175), (590, 1175), BLUE)
    arrow(draw, (990, 1175), (1060, 1175), BLUE)
    arrow(draw, (1460, 1175), (1530, 1175), BLUE)
    arrow(draw, (1930, 1175), (2000, 1175), BLUE)

    draw.line((90, 1400, 2310, 1400), fill=LINE, width=2)
    label(draw, (90, 1422), "SECUREPAY  /  architecture poster  /  generated from scripts/generate_architecture_png.py", 15, MUTED)
    label(draw, (1970, 1422), "LAB • 2026", 15, CYAN, True)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT, "PNG", optimize=True)
    print(f"Generated {OUTPUT} ({WIDTH}x{HEIGHT})")


if __name__ == "__main__":
    main()
