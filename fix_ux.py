from pathlib import Path
import re

ch = []

# ═══ ۰) کشف‌ها ═══
wiz_tpl = None
for f in Path("templates").glob("*.html"):
    t = f.read_text(encoding="utf-8")
    if 'type="password"' in t and ("رمز عبور فایل" in t or "رمز فایل" in t or "wizard" in f.name.lower() or "upload" in f.name.lower()):
        wiz_tpl = f
        break
print("template ویزارد:", wiz_tpl)
otp_tpls = []
for f in Path("templates").glob("*.html"):
    if f.name == "manage_otp.html":
        continue
    t = f.read_text(encoding="utf-8")
    if re.search(r'<input[^>]*name="code"', t):
        otp_tpls.append(f)
print("template های OTP:", [f.name for f in otp_tpls])

# ═══ ) قوانین رمز سمت سرور ═══
p = Path("core.py")
s = p.read_text(encoding="utf-8")
if "def check_pw_rules" not in s:
    s += '''

def check_pw_rules(pw: str):
    """قوانین رمز فایل ویزارد. خروجی: (ok, پیام)"""
    import re as _re2
    if not pw or len(pw) < 8:
        return False, "رمز باید حداقل ۸ کاراکتر باشد"
    if _re2.search(r"[\\u0600-\\u06FF]", pw):
        return False, "رمز نباید حروف فارسی/عربی داشته باشد"
    if pw.isdigit():
        return False, "رمز نباید فقط عدد باشد"
    if not (_re2.search(r"[A-Za-z]", pw) and _re2.search(r"\\d", pw)):
        return False, "رمز باید شامل حرف انگلیسی و عدد باشد"
    if " " in pw:
        return False, "رمز نباید فاصله داشته باشد"
    return True, ""
'''
    p.write_text(s, encoding="utf-8")
    ch.append("check_pw_rules در core")

# اعمال سمت سرور در مسیر آپلود
ap = Path("app.py")
a = ap.read_text(encoding="utf-8")
m = re.search(r'(\n[ \t]*)(pw_hash|hashed|file_pw|password)\s*=[^\n]*hash_file_password\(', a)
if m and "check_pw_rules" not in a:
    ind = m.group(1)
    a = a.replace(m.group(0), f'''{ind}_okpw, _pwmsg = check_pw_rules((request.form.get("password") or request.form.get("pw") or ""))
{ind}if not _okpw:
{ind}    return render_template_string(_tplsrc if False else open(Path(__file__).parent/"templates"/"wizard.html", encoding="utf-8").read(), error=_pwmsg) if False else (flash(_pwmsg) if False else None) or redirect(request.referrer or "/")
''' + m.group(0), 1)
    ch.append("⚠ نیاز به تنظیم دستی دارد — خروجی را ببین")
# ساده‌تر: فقط چاپ کن اگر الگو پیچیده بود
ap_found = "hash_file_password" in a
print("hash_file_password در app.py:", ap_found)

# ═══ ۲) کامپوننت جعبه‌های OTP ═══
Path("templates/otp_boxes.html").write_text('''<div class="ob-wrap" dir="ltr">
  <input class="ob-box" maxlength="1" inputmode="numeric" autocomplete="one-time-code" aria-label="رقم ۱">
  <input class="ob-box" maxlength="1" inputmode="numeric" aria-label="رقم ۲">
  <input class="ob-box" maxlength="1" inputmode="numeric" aria-label="رقم ۳">
  <input class="ob-box" maxlength="1" inputmode="numeric" aria-label="رقم ۴">
  <input class="ob-box" maxlength="1" inputmode="numeric" aria-label="رقم ۵">
  <input class="ob-box" maxlength="1" inputmode="numeric" aria-label="رقم ۶">
</div>
<input type="hidden" name="code" id="ob-hidden" value="">
''', encoding="utf-8")
Path("static/otp_boxes.js").write_text('''(function(){
  var boxes = document.querySelectorAll(".ob-box");
  var hidden = document.getElementById("ob-hidden");
  if(!boxes.length || !hidden) return;
  function sync(){ hidden.value = Array.prototype.map.call(boxes, function(b){ return b.value; }).join(""); }
  boxes.forEach(function(b, i){
    b.addEventListener("input", function(){
      b.value = b.value.replace(/\\D/g, "").slice(-1);
      sync();
      if(b.value && i < 5) boxes[i+1].focus();
    });
    b.addEventListener("keydown", function(e){
      if(e.key === "Backspace" && !b.value && i > 0) boxes[i-1].focus();
      sync();
    });
    b.addEventListener("paste", function(e){
      e.preventDefault();
      var d = ((e.clipboardData || window.clipboardData).getData("text") || "").replace(/\\D/g, "").slice(0, 6);
      for(var j = 0; j < 6; j++){ boxes[j].value = d[j] || ""; }
      sync();
      if(d.length) boxes[Math.min(d.length, 5)].focus();
    });
  });
  sync();
})();
''', encoding="utf-8")
ch.append("کامپوننت otp_boxes + JS")

# CSS با fallback برای هر تم
cssp = Path("static/style.css")
if cssp.exists():
    c = cssp.read_text(encoding="utf-8")
    if ".ob-wrap" not in c:
        c += '''
/* ══ جعبه‌های کد ۶ رقمی (سازگار با همه تم‌ها) ══ */
.ob-wrap{display:flex;gap:8px;justify-content:center;margin:16px 0}
.ob-box{width:44px;height:54px;border-radius:14px;border:1.5px solid var(--border,#d1d5db);
  background:var(--card,#ffffff);color:var(--fg,#111827);font-size:22px;font-weight:800;text-align:center;
  font-family:var(--mono,ui-monospace,monospace);outline:none;transition:border .15s, box-shadow .15s}
.ob-box:focus{border-color:var(--accent,#f97316);box-shadow:0 0 0 4px rgba(249,115,22,.18)}
'''
        cssp.write_text(c, encoding="utf-8")
        ch.append("CSS جعبه‌ها")

# ═══ ) جایگزینی input تکی code با جعبه‌ها ═══
for f in otp_tpls:
    t = f.read_text(encoding="utf-8")
    t2 = re.sub(r'[ \t]*<input[^>]*name="code"[^>]*>\n?', '  {% include "otp_boxes.html" %}\n  <script src="/static/otp_boxes.js" defer></script>\n', t, count=1)
    if t2 != t:
        f.write_text(t2, encoding="utf-8")
        ch.append(f"جعبه‌ها در {f.name}")

# ═══ ۳) ویزارد: تکرار رمز + قوانین زنده ═══
if wiz_tpl:
    t = wiz_tpl.read_text(encoding="utf-8")
    m = re.search(r'([ \t]*)(<input[^>]*type="password"[^>]*>)', t)
    if m and "pw-confirm" not in t:
        ind = m.group(1)
        add = m.group(2) + f'''
{ind}<input type="password" name="pw_confirm" id="pw-confirm" placeholder="تکرار رمز عبور" style="margin-top:10px">
{ind}<ul id="pw-rules" style="list-style:none;padding:0;margin:10px 0 0;font-size:11.5px;color:var(--dim,#6b7280);line-height:2">
{ind}  <li data-r="len">○ حداقل ۸ کاراکتر</li>
{ind}  <li data-r="fa">○ بدون حروف فارسی/عربی</li>
{ind}  <li data-r="mix">○ شامل حرف انگلیسی و عدد</li>
{ind}  <li data-r="space">○ بدون فاصله</li>
{ind}  <li data-r="match">○ تکرار رمز یکسان</li>
{ind}</ul>
{ind}<script>
{ind}(function(){{
{ind}  var pw = document.querySelector('input[type="password"]');
{ind}  var cf = document.getElementById("pw-confirm");
{ind}  if(!pw || !cf) return;
{ind}  var rules = {{
{ind}    len: function(v){{ return v.length >= 8; }},
{ind}    fa: function(v){{ return !/[\\u0600-\\u06FF]/.test(v); }},
{ind}    mix: function(v){{ return /[A-Za-z]/.test(v) && /\\d/.test(v); }},
{ind}    space: function(v){{ return !/ /.test(v); }},
{ind}    match: function(v){{ return v.length > 0 && v === cf.value; }}
{ind}  }};
{ind}  function paint(){{
{ind}    var okAll = true;
{ind}    for(var k in rules){{
{ind}      var li = document.querySelector('#pw-rules li[data-r="' + k + '"]');
{ind}      var ok = rules[k](pw.value);
{ind}      if(k === "match") ok = ok && cf.value.length > 0;
{ind}      if(!ok) okAll = false;
{ind}      li.textContent = (ok ? "✅ " : "○ ") + li.textContent.replace(/^[✅○]\\s*/, "");
{ind}      li.style.color = ok ? "#22c55e" : "";
{ind}    }}
{ind}    return okAll;
{ind}  }}
{ind}  pw.addEventListener("input", paint);
{ind}  cf.addEventListener("input", paint);
{ind}  var form = pw.closest("form");
{ind}  if(form) form.addEventListener("submit", function(e){{ if(!paint()){{ e.preventDefault(); alert("رمز عبور طبق قوانین نیست"); }} }});
{ind}})();
{ind}</script>'''
        t = t[:m.start()] + add + t[m.end():]
        wiz_tpl.write_text(t, encoding="utf-8")
        ch.append(f"تکرار رمز + قوانین زنده در {wiz_tpl.name}")

for x in ch:
    print(f"✅ {x}")
