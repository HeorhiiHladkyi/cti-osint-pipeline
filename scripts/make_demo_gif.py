"""Generate examples/demo.gif from a REAL pipeline run.
It executes `python run.py -i examples/iocs.txt`, then renders the actual run.log
(verbatim) + the real per-IoC verdicts from iocs.json into an animated terminal GIF.
No hand-written output — everything shown is produced by a genuine execution.
Pure Pillow. Usage: python scripts/make_demo_gif.py"""
import os, sys, glob, json, subprocess
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

# ── 1. run the pipeline for real ─────────────────────────────────────────────
env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
subprocess.run([sys.executable, "run.py", "-i", "examples/iocs.txt"],
               check=True, capture_output=True, env=env)
run = max(glob.glob("output/*/"), key=os.path.getmtime).rstrip("/\\")
runname = os.path.basename(run)
loglines = [l for l in Path(run, "run.log").read_text(encoding="utf-8").splitlines() if l.strip()]
verdicts = json.loads(Path(run, "iocs.json").read_text(encoding="utf-8"))
iocs_in = [l.strip() for l in Path("examples/iocs.txt").read_text(encoding="utf-8").splitlines()
           if l.strip() and not l.startswith("#")]
order = ["unknown", "low", "medium", "high", "critical"]
overall = max((v["threat_level"] for v in verdicts), key=order.index).upper()

# ── 2. drawing setup ─────────────────────────────────────────────────────────
W, H, PAD, LINE_H = 960, 600, 18, 22
VISIBLE = (H - 2 * PAD) // LINE_H
BG = (13, 17, 23)
C = {"grey": (201, 209, 217), "cyan": (88, 166, 255), "green": (63, 185, 80),
     "yellow": (210, 153, 34), "white": (240, 246, 252), "dim": (139, 148, 158),
     "red": (248, 81, 73)}
LVL = {"critical": C["red"], "high": C["yellow"], "medium": (210, 170, 60),
       "low": C["green"], "unknown": C["dim"], "INFO": C["green"],
       "WARNING": C["yellow"], "ERROR": C["red"]}
FONT = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 15)
FONTB = ImageFont.truetype("C:/Windows/Fonts/consolab.ttf", 15)
BIG = ImageFont.truetype("C:/Windows/Fonts/consolab.ttf", 30)
MED = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 17)

frames = []
buffer = []  # list of lines; each line = list of (text, color, bold)


def render(partial=None):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    lines = buffer + ([partial] if partial else [])
    for segs in lines[-VISIBLE:]:
        x, y = PAD, PAD + LINE_H * (lines[-VISIBLE:].index(segs))
        for (t, col, b) in segs:
            d.text((x, y), t, font=(FONTB if b else FONT), fill=col)
            x += d.textlength(t, font=(FONTB if b else FONT))
    return img


def snap(ms, partial=None):
    frames.append((render(partial), ms))


def card(fn, ms):
    img = Image.new("RGB", (W, H), BG)
    fn(ImageDraw.Draw(img))
    frames.append((img, ms))


# ── 3. title ─────────────────────────────────────────────────────────────────
def title(d):
    d.text((PAD + 6, 120), "CTI OSINT Pipeline", font=BIG, fill=C["white"])
    d.text((PAD + 8, 165), "Напрям 3 — Cyber Threat Intelligence", font=MED, fill=C["cyan"])
    d.text((PAD + 8, 230), "автоматичне збагачення IoC:  збір → збереження → звіт", font=MED, fill=C["grey"])
    d.text((PAD + 8, 264), "джерела: DNS · WHOIS · crt.sh · RDAP/ASN · URLScan · VT · AbuseIPDB · Shodan · OTX", font=FONT, fill=C["dim"])
    d.text((PAD + 8, 300), "вихід: HTML-звіт + STIX 2.1 + JSON + граф зв'язків + SQLite-архів", font=FONT, fill=C["dim"])
    d.rectangle([PAD, 356, W - PAD, 358], fill=(48, 54, 61))
    d.text((PAD + 8, 378), "$ python run.py -i examples/iocs.txt", font=FONTB, fill=C["green"])
card(title, 2200)

# ── 4. input list ────────────────────────────────────────────────────────────
buffer.append([("PS> ", C["dim"], False), ("type examples\\iocs.txt", C["white"], False)])
snap(650)
for ip in iocs_in:
    buffer.append([("  " + ip, C["cyan"], False)])
    snap(240)
buffer.append([("", C["grey"], False)])
snap(350)

# ── 5. typed command ─────────────────────────────────────────────────────────
prompt = [("PS> ", C["dim"], False)]
cmd = "python run.py -i examples/iocs.txt"
for i in range(0, len(cmd) + 1, 3):
    snap(55, partial=prompt + [(cmd[:i], C["white"], False)])
buffer.append(prompt + [(cmd, C["white"], False)])
snap(500)

# ── 6. REAL run.log, verbatim ────────────────────────────────────────────────
for ln in loglines:
    parts = ln.split(" | ")
    if len(parts) >= 3:
        ts = parts[0].split()[1]
        lvl = parts[1].strip()
        msg = " | ".join(parts[2:])
        if len(msg) > 86:
            msg = msg[:85] + "…"
        segs = [(ts + " ", C["dim"], False), (f"{lvl:<8}", LVL.get(lvl, C["grey"]), True),
                (" │ ", C["dim"], False), (msg, C["grey"], False)]
    else:
        segs = [(ln[:96], C["grey"], False)]
    buffer.append(segs)
    snap(230)
snap(700)

# ── 7. summary (real values) ─────────────────────────────────────────────────
bar = "=" * 58
def kv(k, v, vc=C["white"]):
    return [("  " + k.ljust(24) + " : ", C["dim"], False), (v, vc, False)]
for segs, ms in [
    ([(bar, C["dim"], False)], 180),
    (kv("Загальний рівень загрози", overall, LVL.get(overall.lower(), C["white"])), 220),
    (kv("Проаналізовано IoC", str(len(verdicts))), 180),
    (kv("HTML-звіт", f"{runname}\\report.html", C["cyan"]), 180),
    (kv("STIX 2.1 bundle", f"{runname}\\stix_bundle.json", C["cyan"]), 180),
    (kv("Архів доказів", f"{runname}.zip", C["cyan"]), 180),
    ([(bar, C["dim"], False)], 800),
]:
    buffer.append(segs)
    snap(ms)

# ── 8. verdict card (real iocs.json) ─────────────────────────────────────────
def verdict(d):
    d.text((PAD + 6, 22), "Звіт CTI — оцінка загрози по кожному IoC", font=BIG, fill=C["white"])
    d.text((PAD + 8, 64), "(автоматично · report.html / iocs.json / stix_bundle.json)", font=FONT, fill=C["dim"])
    y = 116
    for v in verdicts[:6]:
        lvl = v["threat_level"]
        col = LVL.get(lvl, C["dim"])
        d.text((PAD + 8, y), v["indicator"][:46], font=MED, fill=C["grey"])
        d.text((PAD + 500, y), f"[{v['type']}]", font=FONT, fill=C["dim"])
        chip = lvl.upper()
        cw = d.textlength(chip, font=FONTB) + 18
        d.rounded_rectangle([W - PAD - cw - 6, y - 2, W - PAD - 6, y + 22], radius=6, outline=col, width=2)
        d.text((W - PAD - cw + 3, y), chip, font=FONTB, fill=col)
        y += 40
    d.rectangle([PAD, y + 6, W - PAD, y + 8], fill=(48, 54, 61))
    d.text((PAD + 8, y + 22), "LOW без ключів → додай VIRUSTOTAL/ABUSEIPDB у .env → HIGH/CRITICAL + MITRE ATT&CK",
           font=FONT, fill=C["yellow"])
card(verdict, 4500)

# ── 9. save ──────────────────────────────────────────────────────────────────
out = Path("examples/demo.gif")
imgs = [f[0] for f in frames]
imgs[0].save(out, save_all=True, append_images=imgs[1:], duration=[f[1] for f in frames],
             loop=0, optimize=True)
print(f"wrote {out} | frames={len(imgs)} | {sum(f[1] for f in frames)/1000:.1f}s | "
      f"{out.stat().st_size//1024} KB | real run={runname} | overall={overall}")
