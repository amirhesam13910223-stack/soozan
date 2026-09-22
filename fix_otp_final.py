from pathlib import Path
import re

ch = []
p = Path("auth.py")
s = p.read_text(encoding="utf-8")

# ═══ ۱) ثبت‌نام: کد غلط با زمان باقی‌مانده ═══
pat1 = r'(pend\["tries"\]\s*=\s*pend\.get\("tries",\s*0\)\s*\+\s*1\s+session\["reg_pending"\]\s*=\s*pend\s+return render\(_read\("auth_verify\.html"\),\s*demo_code=pend\["code"\],\s+phone=pend\["phone"\],\s*error="کد نادرست است\."\))'
m1 = re.search(pat1, s)
if m1:
    new1 = '''pend["tries"] = pend.get("tries", 0) + 1
        session["reg_pending"] = pend
        return render(_read("auth_verify.html"), demo_code=pend["code"],
                      phone=pend["phone"], error="کد نادرست است.",
                      seconds_left=max(0, int(pend.get("exp", 0) - _time.time())),
                      otp_action="/register", otp_submit="ثبت‌نام ←", otp_desc="کد تأیید ثبت‌نام",
                      otp_resend_url="/register/resend", otp_cancel_url="/")'''
    s = s[:m1.start()] + new1 + s[m1.end():]
    ch.append("ثبت‌نام: کد غلط با زمان باقی‌مانده")
else:
    print("⚠ الگوی ثبت‌نام کد غلط پیدا نشد — روش ساده‌تر")
    s = s.replace(
        'error="کد نادرست است.")',
        'error="کد نادرست است.",\n                      seconds_left=max(0, int(pend.get("exp", 0) - _time.time())),\n                      otp_action="/register", otp_submit="ثبت‌نام ←", otp_desc="کد تأیید ثبت‌نام",\n                      otp_resend_url="/register/resend", otp_cancel_url="/")',
        1)
    ch.append("ثبت‌نام: کد غلط (ساده)")

# ═══ ) ثبت‌نام GET: اگر pending هست → صفحه کد ═══
old2 = '    return render(_read("auth_register.html"))\n\n\n@bp.route("/login/phone", methods=["GET", "POST"])'
new2 = '''    if session.get("reg_pending"):
        pend = session["reg_pending"]
        rem = max(0, int(pend.get("exp", 0) - _time.time()))
        return render(_read("auth_verify.html"), demo_code=pend.get("code") or None, phone=pend["phone"],
                      seconds_left=rem, error=None if rem else "کد منقضی شد؛ ارسال مجدد را بزن.",
                      otp_action="/register", otp_submit="ثبت‌نام ←", otp_desc="کد تأیید ثبت‌نام",
                      otp_resend_url="/register/resend", otp_cancel_url="/")
    return render(_read("auth_register.html"))


@bp.route("/login/phone", methods=["GET", "POST"])'''
if old2 in s:
    s = s.replace(old2, new2, 1)
    ch.append("ثبت‌نام GET: اگر pending → صفحه کد")
else:
    print("⚠ الگوی ثبت‌نام GET پیدا نشد")

# ═══ ۳) ورود: کد غلط با زمان باقی‌مانده ═══
pat3 = r'(pend\["tries"\]\s*=\s*pend\.get\("tries",\s*0\)\s*\+\s*1\s+session\["login_pending"\]\s*=\s*pend\s+return render\(_read\("auth_otp\.html"\),\s*demo_code=pend\["code"\],\s+phone_mask=_mask\(pend\["phone"\]\),\s*error="کد نادرست است\."\))'
m3 = re.search(pat3, s)
if m3:
    new3 = '''pend["tries"] = pend.get("tries", 0) + 1
        session["login_pending"] = pend
        return render(_read("auth_otp.html"), demo_code=pend["code"],
                      phone_mask=_mask(pend["phone"]), error="کد نادرست است.",
                      seconds_left=max(0, int(pend.get("exp", 0) - _time.time())),
                      otp_action="/login/phone", otp_submit="ورود ←", otp_desc="کد یک‌بار مصرف ورود",
                      otp_resend_url="/login/phone/resend", otp_cancel_url="/login")'''
    s = s[:m3.start()] + new3 + s[m3.end():]
    ch.append("ورود: کد غلط با زمان باقی‌مانده")
else:
    print("⚠ الگوی ورود کد غلط پیدا نشد — روش ساده‌تر")
    s = s.replace(
        'phone_mask=_mask(pend["phone"]), error="کد نادرست است.")',
        'phone_mask=_mask(pend["phone"]), error="کد نادرست است.",\n                                                    seconds_left=max(0, int(pend.get("exp", 0) - _time.time())),\n                                                    otp_action="/login/phone", otp_submit="ورود ←", otp_desc="کد یک‌بار مصرف ورود",\n                                                    otp_resend_url="/login/phone/resend", otp_cancel_url="/login")',
        1)
    ch.append("ورود: کد غلط (ساده)")

# ═══ ۴) TOTP → template جدید ═══
old4 = 'return render(_read("totp.html"), mode="login",'
if old4 in s:
    s = s.replace(old4, 'return render(_read("totp_login.html"),', 1)
    ch.append("TOTP → template جدید")
else:
    print("⚠ TOTP پیدا نشد")

# ═══ ) ورود GET: زمان باقی‌مانده ═══
pat5 = r'(    return render\(_read\("auth_otp\.html"\), demo_code=pend\["code"\], phone_mask=_mask\(pend\["phone"\]\)\))'
m5 = re.search(pat5, s)
if m5:
    new5 = '''    return render(_read("auth_otp.html"), demo_code=pend["code"], phone_mask=_mask(pend["phone"]),
                    seconds_left=max(0, int(pend.get("exp", 0) - _time.time())),
                    otp_action="/login/phone", otp_submit="ورود ←", otp_desc="کد یک‌بار مصرف ورود",
                    otp_resend_url="/login/phone/resend", otp_cancel_url="/login")'''
    s = s[:m5.start()] + new5 + s[m5.end():]
    ch.append("ورود GET: زمان باقی‌مانده")

p.write_text(s, encoding="utf-8")
for x in ch:
    print(f"✅ {x}")

import py_compile
py_compile.compile("auth.py", doraise=True)
print("✅ syntax auth سالم")
