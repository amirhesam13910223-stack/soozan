from pathlib import Path

pa = Path("templates/app.html")
s = pa.read_text(encoding="utf-8")

start = s.find("{% if request.path != '/wizard' %}")
mid = s.find("{% block app_content %}")
endblock = s.find("{% endblock %}", mid)
end2 = s.find("</body>")

if start == -1 or mid == -1 or end2 == -1:
    print("❌ لنگرها پیدا نشدند")
    raise SystemExit(1)

top = s[start:mid]
bottom = s[endblock + len("{% endblock %}"):end2]

Path("templates/chrome_top.html").write_text(top, encoding="utf-8")
Path("templates/chrome_bottom.html").write_text(bottom, encoding="utf-8")

new = s[:start] + '{% include "chrome_top.html" %}\n' + s[mid:endblock + len("{% endblock %}")] + '\n{% include "chrome_bottom.html" %}\n' + s[end2:]
pa.write_text(new, encoding="utf-8")
print("✅ app.html → partial های chrome_top/chrome_bottom")

for name in ("auth.html", "auth_register.html"):
    pf = Path("templates") / name
    if not pf.exists():
        print(f"⚠ {name} نیست")
        continue
    t = pf.read_text(encoding="utf-8")
    if "chrome_top" in t:
        continue
    import re as _re
    m = _re.search(r'<body[^>]*>', t)
    if m:
        t = t[:m.end()] + '\n{% include "chrome_top.html" %}\n' + t[m.end():]
        t = t.replace("</body>", '{% include "chrome_bottom.html" %}\n</body>', 1)
        pf.write_text(t, encoding="utf-8")
        print(f"✅ chrome به {name} اضافه شد")
    else:
        print(f"⚠ <body> در {name} پیدا نشد")

from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader("templates"))
for tpl in ("app.html", "auth.html", "auth_register.html", "auth_otp.html"):
    env.get_template(tpl)
    print(f"✅ Jinja {tpl}")
