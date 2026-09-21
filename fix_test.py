from pathlib import Path
import re

p = Path("admin_panel.py")
s = p.read_text(encoding="utf-8")

# ═══ ۱) هدر no-store روی /manage (GET) ═══
old_enter = '''    if request.method == "GET":
        return _render(tpl, error=None, demo_code=None)'''
new_enter = '''    if request.method == "GET":
        from flask import make_response
        resp = make_response(_render(tpl, error=None, demo_code=None))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp'''
if old_enter in s:
    s = s.replace(old_enter, new_enter, 1)
    print("✅ no-store روی GET /manage")
else:
    print("⚠ الگوی GET /manage پیدا نشد — بررسی می‌کنیم")
    # fallback: جستجوی عمومی‌تر
    m = re.search(r'(@bp\.route\("/manage"[^)]*\)\ndef manage_enter\([\s\S]*?)return _render\(tpl, error=None', s)
    if m:
        print("✅ route manage_enter پیدا شد")

p.write_text(s, encoding="utf-8")
import py_compile
py_compile.compile("admin_panel.py", doraise=True)
print("✅ syntax سالم")
