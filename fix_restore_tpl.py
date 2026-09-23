from pathlib import Path
import re

# ═══ ) auth_register: chrome اپ ═══
pf = Path("templates/auth_register.html")
t = pf.read_text(encoding="utf-8")
if 'extends "app.html"' not in t:
    t = t.replace('{% extends "base.html" %}', '{% extends "app.html" %}', 1)
    m = re.search(r'\{% block (body|content|main) %\}', t)
    if m:
        t = t[:m.start()] + '{% block app_content %}' + t[m.end():]
    pf.write_text(t, encoding="utf-8")
    print("✅ auth_register → app.html")

# ═══ ) ساختار صفحه شماره جدید ═══
ps = Path("templates/settings_phone_new.html")
s = ps.read_text(encoding="utf-8")
print("─── ساختار settings_phone_new ───")
for i, ln in enumerate(s.splitlines(), 1):
    if any(k in ln for k in ("step", "inputmode", 'name="code"', 'name="phone', "<form", "extends", "block ")):
        print(f"{i}: {ln.strip()[:100]}")
print("─── route های settings phone ───")
for pf2 in Path(".").glob("*.py"):
    src = pf2.read_text(encoding="utf-8")
    for m in re.finditer(r'.*settings_phone.*', src):
        print(f"{pf2.name}: {m.group(0).strip()[:110]}")
