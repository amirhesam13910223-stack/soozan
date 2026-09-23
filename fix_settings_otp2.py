from pathlib import Path
import re

src = Path("app.py").read_text(encoding="utf-8")
funcs = re.finditer(r'def (settings_\w*phone\w*|\w*phone_verify\w*|\w*verify_phone\w*)\([^)]*\):([\s\S]*?)(?=\ndef |\Z)', src)
found = []
for m in funcs:
    body = m.group(2)
    for tm in re.finditer(r'(?:_set_render|_read)\("([\w\-.]+\.html)"', body):
        found.append((m.group(1), tm.group(1)))
print("route → template:")
for fn, tpl in found:
    print(f"   {fn} → {tpl}")

WRAP = '''{% extends "app.html" %}
{% block head %}<link rel="stylesheet" href="/static/mgmt.css">{% endblock %}
{% block title %}سوزان — تأیید کد{% endblock %}
{% block app_content %}
{% include "otp_shared.html" %}
{% endblock %}
'''
SKIP = {"settings_phone_new.html"}
n = 0
for fn, tpl in found:
    if tpl in SKIP:
        continue
    pf = Path("templates") / tpl
    if not pf.exists():
        continue
    t = pf.read_text(encoding="utf-8")
    if "otp_shared" in t:
        continue
    if "کد" in t or 'name="code"' in t or "inputmode" in t:
        pf.write_text(WRAP, encoding="utf-8")
        print(f"✅ تبدیل شد: {tpl} (route: {fn})")
        n += 1
if not n:
    print("⚠ هیچ template OTP در route های phone تبدیل نشد")
