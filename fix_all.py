from pathlib import Path
import re

p = Path("admin_panel.py")
s = p.read_text(encoding="utf-8")
ch = []

# ═══ ۱) no-store روی GET /manage (الگوی صحیح) ═══
old_enter = '    if request.method == "GET":\n        return _render(tpl, error=None, seconds_left=120)'
new_enter = '''    if request.method == "GET":
        from flask import make_response
        _resp = make_response(_render(tpl, error=None, seconds_left=120))
        _resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
        _resp.headers["Pragma"] = "no-cache"
        _resp.headers["Expires"] = "0"
        return _resp'''
if old_enter in s:
    s = s.replace(old_enter, new_enter, 1)
    ch.append("no-store روی GET /manage")
else:
    print("⚠ الگو پیدا نشد")
p.write_text(s, encoding="utf-8")

# ═══ ۲) اصلاح تست v2 ═══
pt = Path("test_sozan_v2.py")
t = pt.read_text(encoding="utf-8")
old = '''    try:
        rv = ap._run_action("pause", dead["id"])
        code = rv[1] if isinstance(rv, tuple) else 200
        ck("اکشن روی فایل مرده → 409", code == 409)
    except Exception:
        ck("اکشن روی فایل مرده بدون exception", False)'''
new = '''    try:
        rv = ap._run_action("pause", dead["id"])
        if isinstance(rv, tuple):
            code = rv[1]
            ck("اکشن روی فایل مرده → 409", code == 409)
        else:
            ck("اکشن روی فایل مرده → tuple", False)
    except Exception as e:
        ck(f"اکشن روی فایل مرده بدون exception ({e})", False)'''
if old in t:
    t = t.replace(old, new, 1)
    pt.write_text(t, encoding="utf-8")
    ch.append("تست ۱۱ اصلاح شد")

# ═══ ۳) CI ═══
wf_dir = Path(".github/workflows")
wf_dir.mkdir(parents=True, exist_ok=True)
existing = list(wf_dir.glob("*.yml"))
if existing:
    wf = existing[0]
    c = wf.read_text(encoding="utf-8")
    if "test_sozan_v2.py" not in c and "test_sozan_v1.py" in c:
        c = c.replace("python3 test_sozan_v1.py",
                      "python3 test_sozan_v1.py\n      - run: python3 test_sozan_v2.py")
        wf.write_text(c, encoding="utf-8")
        ch.append(f"v2 به {wf.name} اضافه شد")
else:
    (wf_dir / "ci.yml").write_text('''name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install flask cryptography requests
      - run: python3 test_sozan_v1.py
      - run: python3 test_sozan_v2.py
''', encoding="utf-8")
    ch.append("ci.yml جدید ساخته شد")

for x in ch:
    print(f"✅ {x}")
import py_compile
py_compile.compile("admin_panel.py", doraise=True)
print("✅ syntax سالم")
