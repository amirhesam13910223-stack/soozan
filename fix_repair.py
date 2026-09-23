from pathlib import Path
import re

p = Path("auth.py")
s = p.read_text(encoding="utf-8")
n1 = s.count("otp_cancel_url='/'))")
n2 = s.count("otp_cancel_url='/login'))")
s = s.replace("otp_cancel_url='/'))", "otp_cancel_url='/')")
s = s.replace("otp_cancel_url='/login'))", "otp_cancel_url='/login')")
p.write_text(s, encoding="utf-8")
print(f"✅ پرانتز اضافه: {n1 + n2} مورد تعمیر شد")

import py_compile
py_compile.compile("auth.py", doraise=True)
print("✅ syntax auth سالم")

# ═══ شرط‌های app.html ═══
pa = Path("templates/app.html")
a = pa.read_text(encoding="utf-8")
cands = re.findall(r'\{%[-\s]*if [^%]*%\}', a)
print("شرط‌های app.html:")
for c in cands:
    print("   ", c)
