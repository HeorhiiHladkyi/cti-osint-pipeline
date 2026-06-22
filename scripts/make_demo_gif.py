"""Generate examples/demo.gif — an animated terminal demo of a real pipeline run.
Content mirrors the actual stdout/loguru output (English logs + Ukrainian summary).
Pure Pillow, no external recorder needed. Usage: python scripts/make_demo_gif.py"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

W, H = 940, 600
PAD = 18
LINE_H = 23
VISIBLE = (H - 2 * PAD) // LINE_H
BG = (13, 17, 23)

C = {
    "grey": (201, 209, 217), "cyan": (88, 166, 255), "green": (63, 185, 80),
    "yellow": (210, 153, 34), "white": (240, 246, 252), "dim": (139, 148, 158),
    "red": (248, 81, 73), "low": (63, 185, 80),
}
FONT = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 16)
FONTB = ImageFont.truetype("C:/Windows/Fonts/consolab.ttf", 16)

import json
RUN = "output\\2026-06-22_15-58-32"
FONT_BIG = ImageFont.truetype("C:/Windows/Fonts/consolab.ttf", 30)
FONT_MED = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 18)
LVL_COLOR = {"critical": C["red"], "high": C["yellow"], "medium": (210, 170, 60),
             "low": C["green"], "unknown": C["dim"]}
frames: list[tuple[Image.Image, int]] = []
buffer: list[list[tuple]] = []  # each line = list of (text, color, bold)


def card_frame(draw_fn, ms):
    img = Image.new("RGB", (W, H), BG)
    draw_fn(ImageDraw.Draw(img))
    frames.append((img, ms))


def render(partial=None, cursor=True):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    lines = buffer + ([partial] if partial else [])
    shown = lines[-VISIBLE:]
    y = PAD
    for segs in shown:
        x = PAD
        for (txt, color, bold) in segs:
            d.text((x, y), txt, font=(FONTB if bold else FONT), fill=color)
            x += d.textlength(txt, font=(FONTB if bold else FONT))
        if cursor and segs is shown[-1] and (partial is not None or segs is buffer[-1] if buffer else False):
            d.rectangle([x + 1, y + 2, x + 9, y + 18], fill=C["white"])
        y += LINE_H
    return img


def snap(ms, partial=None, cursor=True):
    frames.append((render(partial, cursor), ms))


def line(*segs):
    buffer.append(list(segs))


def log(level, msg):
    col = {"INFO": C["green"], "WARNING": C["yellow"], "ERROR": C["red"]}[level]
    return [(f"{level:<8}", col, True), (" | ", C["dim"], False), (msg, C["grey"], False)]


# ── Scene 0: title card ──────────────────────────────────────────────────────
def title(d):
    d.text((PAD + 6, 120), "CTI OSINT Pipeline", font=FONT_BIG, fill=C["white"])
    d.text((PAD + 8, 165), "Напрям 3 — Cyber Threat Intelligence", font=FONT_MED, fill=C["cyan"])
    d.text((PAD + 8, 230), "автоматичне збагачення IoC:  збір → збереження → звіт",
           font=FONT_MED, fill=C["grey"])
    d.text((PAD + 8, 262), "джерела: DNS · WHOIS · crt.sh · RDAP/ASN · URLScan · VT · AbuseIPDB · Shodan · OTX",
           font=FONT, fill=C["dim"])
    d.text((PAD + 8, 300), "вихід: HTML-звіт + STIX 2.1 + JSON + граф зв'язків + SQLite-архів",
           font=FONT, fill=C["dim"])
    d.rectangle([PAD, 360, W - PAD, 362], fill=(48, 54, 61))
    d.text((PAD + 8, 380), "$ python run.py -i examples/iocs.txt", font=FONTB, fill=C["green"])
card_frame(title, 2200)

# ── Scene 1: typing the command ──────────────────────────────────────────────
prompt = [("PS ", C["cyan"], True), ("C:\\Users\\User\\cti-osint-pipeline> ", C["dim"], False)]

# show the input IoC list first
buffer.append(prompt[:1] + [("PS> ", C["dim"], False), ("type examples\\iocs.txt", C["white"], False)])
snap(700, cursor=False)
for ip in ["8.8.8.8", "example.com", "http://testphp.vulnweb.com/",
           "44d88612fea8a8f36de82e1278abb02f", "185.220.101.44", "phishy-login-portal.test"]:
    buffer.append([("  " + ip, C["cyan"], False)])
    snap(260, cursor=False)
buffer.append([("", C["grey"], False)])
snap(400, cursor=False)

cmd = "python run.py -i examples/iocs.txt"
for i in range(0, len(cmd) + 1, 2):
    snap(70, partial=prompt + [(cmd[:i], C["white"], False)])
buffer.append(prompt + [(cmd, C["white"], False)])
snap(700)

# ── Scene 2: collection logs (real loguru output) ────────────────────────────
seq = [
    (log("INFO", f"Artifact directory: {RUN}"), 450),
    (log("INFO", "Keys present: {'virustotal': False, 'abuseipdb': False,"), 250),
    ([("                'shodan': False, 'otx': False, 'urlscan': True}", C["grey"], False)], 450),
    ([("Collecting:   0%|          | 0/6 [00:00<?, ?ioc/s]", C["dim"], False)], 300),
    (log("WARNING", "[virustotal] skipped: no VIRUSTOTAL_API_KEY"), 220),
    (log("WARNING", "[abuseipdb] skipped: no ABUSEIPDB_API_KEY"), 220),
    (log("WARNING", "[shodan]    skipped: no SHODAN_API_KEY"), 220),
    (log("WARNING", "[otx]       skipped: no OTX_API_KEY"), 220),
    ([("Collecting:  33%|###       | 2/6 [00:05<00:10, 2.5s/ioc]", C["dim"], False)], 350),
    ([("Collecting:  67%|######    | 4/6 [00:11<00:05, 2.7s/ioc]", C["dim"], False)], 350),
    ([("Collecting: 100%|##########| 6/6 [00:17<00:00, 2.9s/ioc]", C["green"], False)], 450),
    (log("INFO", "SQLite evidence DB written: evidence.sqlite"), 350),
    (log("INFO", "Interactive graph: graph.html"), 350),
    (log("INFO", f"HTML report: {RUN}\\report.html"), 350),
    (log("WARNING", "weasyprint not installed - skipping PDF (HTML is primary)."), 300),
    (log("INFO", f"Evidence archive: {RUN}.zip"), 350),
    (log("INFO", "Done. Overall threat level: LOW"), 600),
]
for segs, ms in seq:
    buffer.append(segs)
    snap(ms, cursor=False)

# ── Scene 3: Ukrainian summary box ───────────────────────────────────────────
bar = "=" * 60
def kv(k, v, vcol=C["white"]):
    return [("  " + k.ljust(24) + " : ", C["dim"], False), (v, vcol, False)]
summary = [
    ([(bar, C["dim"], False)], 200),
    (kv("Загальний рівень загрози", "LOW", C["low"]), 250),
    (kv("Проаналізовано IoC", "6"), 200),
    (kv("HTML-звіт", f"{RUN}\\report.html", C["cyan"]), 200),
    (kv("Інтерактивний граф", f"{RUN}\\graph.html", C["cyan"]), 200),
    (kv("STIX 2.1 bundle", f"{RUN}\\stix_bundle.json", C["cyan"]), 200),
    (kv("Архів доказів", f"{RUN}.zip", C["cyan"]), 200),
    ([(bar, C["dim"], False)], 900),
]
for segs, ms in summary:
    buffer.append(segs)
    snap(ms, cursor=False)

# ── Scene 4: artifacts listing ───────────────────────────────────────────────
buffer.append(prompt[:1] + [("PS> ", C["dim"], False), (f"ls {RUN}", C["white"], False)])
snap(500, cursor=False)
arts = [
    "report.html      graph.html       graph.json",
    "iocs.json        stix_bundle.json evidence.sqlite",
    "run.log          raw\\  (сирі відповіді джерел по кожному IoC)",
]
for a in arts:
    buffer.append([("  " + a, C["green"], False)])
    snap(450, cursor=False)
buffer.append([("", C["grey"], False)])
buffer.append([("  ✓ автоматичний пайплайн: збір → збереження → звіт", C["white"], True)])
snap(1600, cursor=False)

# ── Scene 5: verdict card (real per-IoC threat levels from iocs.json) ─────────
try:
    verdicts = json.loads(Path("examples/sample-output/iocs.json").read_text(encoding="utf-8"))
except Exception:
    verdicts = []

def verdict_card(d):
    d.text((PAD + 6, 24), "Звіт CTI — оцінка загрози по кожному IoC", font=FONT_BIG, fill=C["white"])
    d.text((PAD + 8, 66), "(згенеровано автоматично · report.html / iocs.json / stix_bundle.json)",
           font=FONT, fill=C["dim"])
    y = 120
    for v in verdicts[:6]:
        lvl = v.get("threat_level", "unknown")
        col = LVL_COLOR.get(lvl, C["dim"])
        d.text((PAD + 8, y), v["indicator"][:46], font=FONT_MED, fill=C["grey"])
        d.text((PAD + 470, y), f"[{v.get('type','')}]", font=FONT, fill=C["dim"])
        # level chip
        chip = lvl.upper()
        cw = d.textlength(chip, font=FONTB) + 18
        d.rounded_rectangle([W - PAD - cw - 6, y - 2, W - PAD - 6, y + 22], radius=6,
                            outline=col, width=2)
        d.text((W - PAD - cw + 3, y, ), chip, font=FONTB, fill=col)
        y += 40
    d.rectangle([PAD, y + 6, W - PAD, y + 8], fill=(48, 54, 61))
    d.text((PAD + 8, y + 22),
           "LOW без ключів — додай VIRUSTOTAL/ABUSEIPDB у .env → HIGH/CRITICAL + MITRE ATT&CK",
           font=FONT, fill=C["yellow"])
card_frame(verdict_card, 4500)

# ── save ─────────────────────────────────────────────────────────────────────
out = Path("examples/demo.gif")
imgs = [f[0] for f in frames]
durs = [f[1] for f in frames]
imgs[0].save(out, save_all=True, append_images=imgs[1:], duration=durs, loop=0, optimize=True)
total = sum(durs) / 1000
print(f"wrote {out} | frames={len(imgs)} | duration={total:.1f}s | size={out.stat().st_size//1024} KB")
