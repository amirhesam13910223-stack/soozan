from pathlib import Path

ch = []

# ═══ ۱) otp_shared: اکشن پیش‌فرض = همین صفحه ═══
pt = Path("templates/otp_shared.html")
t = pt.read_text(encoding="utf-8")
t = t.replace('action="{{ otp_action|default(\'/manage/otp\') }}" id="ot-form"',
              'action="{{ otp_action|default(request.path) }}" id="ot-form"')
t = t.replace('action="{{ otp_resend_url|default(otp_action|default(\'/manage/otp\')) }}"',
              'action="{{ otp_resend_url|default(otp_action|default(request.path if request.path.startswith(\'/manage\') else request.path + \'/resend\')) }}"')
pt.write_text(t, encoding="utf-8")
ch.append("فرم‌ها به URL خود صفحه POST می‌کنند")

# ═══ ) auth.py: تکمیل خط‌محور با نگاه به خط قبل ═══
p = Path("auth.py")
lines = p.read_text(encoding="utf-8").split("\n")
REG = "seconds_left=max(0, int(pend.get('exp', 0) - _time.time())), otp_action='/register', otp_submit='ثبت‌نام ←', otp_desc='کد تأیید ثبت‌نام', otp_resend_url='/register/resend', otp_cancel_url='/')"
LOG = "seconds_left=max(0, int(pend.get('exp', 0) - _time.time())), otp_action='/login/phone', otp_submit='ورود ←', otp_desc='کد یک‌بار مصرف ورود', otp_resend_url='/login/phone/resend', otp_cancel_url='/login')"
out = []
i = 0
while i < len(lines):
    ln = lines[i]
    st = ln.strip()
    prev = out[-1] if out else ""

    if st == 'if request.form.get("step") == "2":':
        out.append(ln.replace(st, 'if session.get("reg_pending") and request.form.get("code") is not None:'))
        ch.append("مرحله ۲ ثبت‌نام"); i += 1; continue

    if 'error="کد نادرست است.")' in st and "seconds_left" not in st and "seconds_left" not in prev:
        extra = REG if "auth_verify.html" in prev else LOG
        out.append(ln[:ln.rfind(")")] + ", " + extra + ")")
        ch.append("کد غلط + زمان: " + ("ثبت‌نام" if "auth_verify" in prev else "ورود"))
        i += 1; continue

    if 'phone_mask=_mask(pend["phone"]))' in st and "demo_code" in st and "seconds_left" not in st:
        out.append(ln[:ln.rfind(")")] + ", " + LOG + ")")
        ch.append("ورود GET + زمان"); i += 1; continue

    if 'error="تلاش بیش از حد؛ دوباره وارد شوید.")' in st:
        ind = ln[:len(ln) - len(ln.lstrip())]
        out.append(ind + 'return render(_read("auth_otp.html"), phone_mask=_mask(pend["phone"]), error="کد باطل شد؛ ارسال مجدد را بزن., "'.replace('., "', '.', 1)[:-1] + '", otp_action="/login/phone", otp_submit="ورود ←", otp_desc="کد یک‌بار مصرف ورود", otp_resend_url="/login/phone/resend", otp_cancel_url="/login")')
        ch.append("قفل ورود"); i += 1; continue

    if 'error="تلاش بیش از حد؛ از ابتدا ثبت‌نام کنید.")' in st:
        ind = ln[:len(ln) - len(ln.lstrip())]
        out.append(ind + 'return render(_read("auth_verify.html"), phone=pend["phone"], error="کد باطل شد؛ ارسال مجدد را بزن.", otp_action="/register", otp_submit="ثبت‌نام ←", otp_desc="کد تأیید ثبت‌نام", otp_resend_url="/register/resend", otp_cancel_url="/")')
        ch.append("قفل ثبت‌نام"); i += 1; continue

    if st == 'if not pend or _time.time() > pend.get("exp", 0):' and i + 2 < len(lines) and "login_pending" in lines[i + 1]:
        ind = ln[:len(ln) - len(ln.lstrip())]
        out.append(ind + 'if not pend:')
        out.append(ind + '    return redirect("/login")')
        out.append(ind + 'if _time.time() > pend.get("exp", 0):')
        out.append(ind + '    return render(_read("auth_otp.html"), phone_mask=_mask(pend["phone"]), error="کد منقضی شد؛ ارسال مجدد را بزن.", otp_action="/login/phone", otp_submit="ورود ←", otp_desc="کد یک‌بار مصرف ورود", otp_resend_url="/login/phone/resend", otp_cancel_url="/login")')
        ch.append("انقضای ورود"); i += 3; continue

    if '_read("totp.html"), mode="login",' in st:
        out.append(ln.replace('_read("totp.html"), mode="login",', '_read("totp_login.html"),')); ch.append("TOTP چندوقتی"); i += 1; continue
    if '_read("totp.html"), mode="login")' in st:
        ind = ln[:len(ln) - len(ln.lstrip())]
        out.append(ind + 'return render(_read("totp_login.html"), otp_action="/login/totp", otp_submit="تأیید ←", otp_desc="کد برنامه authenticator یا کد پشتیبان", otp_no_timer=True, otp_no_resend=True, otp_cancel_url="/login")')
        ch.append("TOTP تکی"); i += 1; continue

    if st == 'return render(_read("auth_register.html"))' and not any("reg_pending" in o for o in out[-4:]):
        j = i + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        if j < len(lines) and lines[j].strip().startswith('@bp.route("/login/phone"'):
            ind = ln[:len(ln) - len(ln.lstrip())]
            out.append(ind + 'if session.get("reg_pending"):')
            out.append(ind + '    pend = session["reg_pending"]')
            out.append(ind + '    rem = max(0, int(pend.get("exp", 0) - _time.time()))')
            out.append(ind + '    return render(_read("auth_verify.html"), demo_code=pend.get("code") or None, phone=pend["phone"], seconds_left=rem, error=None if rem else "کد منقضی شد؛ ارسال مجدد را بزن.", otp_action="/register", otp_submit="ثبت‌نام ←", otp_desc="کد تأیید ثبت‌نام", otp_resend_url="/register/resend", otp_cancel_url="/")')
            out.append(ln)
            ch.append("GET ثبت‌نام pending"); i += 1; continue

    out.append(ln)
    i += 1
p.write_text("\n".join(out), encoding="utf-8")

# ═══ ۳) هدر/ناوبری/فاب: حذف شرط نشست در app.html ═══
pa = Path("templates/app.html")
a = pa.read_text(encoding="utf-8")
import re
m = re.search(r'\{% if session\.get\("user_id"\) %\}(\s*<!--?\s*(header|هدر|nav))?', a)
before = a
a = a.replace('{% if session.get("user_id") %}', '{% if true %}')
if a != before:
    pa.write_text(a, encoding="utf-8")
    ch.append("هدر/ناوبری/فاب برای همه صفحات")
else:
    # تشخیص الگوی دیگر
    for pat in re.findall(r'\{% if [^%]*user_id[^%]*%\}', a):
        print("الگوی شرط:", pat)
    ch.append("⚠ شرط هدر پیدا نشد — الگوهای بالا را بفرست")

for x in ch:
    print(f"✅ {x}")
import py_compile
py_compile.compile("auth.py", doraise=True)
print("✅ syntax auth سالم")
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader("templates"))
for tpl in ["otp_shared.html", "auth_otp.html", "app.html"]:
    env.get_template(tpl)
print("✅ Jinja سالم")
