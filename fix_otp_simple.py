from pathlib import Path

p = Path("auth.py")
s = p.read_text(encoding="utf-8")

# ═══ ۱) ثبت‌نام: کد غلط + زمان باقی‌مانده ═══
s = s.replace(
    '''                      pend["tries"] = pend.get("tries", 0) + 1
                                                    session["reg_pending"] = pend
                                                    return render(_read("auth_verify.html"), demo_code=pend["code"],
                                                                  phone=pend["phone"], error="کد نادرست است.")''',
    '''                      pend["tries"] = pend.get("tries", 0) + 1
                                                    session["reg_pending"] = pend
                                                    return render(_read("auth_verify.html"), demo_code=pend["code"],
                                                                  phone=pend["phone"], error="کد نادرست است.",
                                                                  seconds_left=max(0, int(pend.get("exp", 0) - _time.time())),
                                                                  otp_action="/register", otp_submit="ثبت‌نام ←", otp_desc="کد تأیید ثبت‌نام",
                                                                  otp_resend_url="/register/resend", otp_cancel_url="/")''',
    1)

# ═══ ) ورود: کد غلط + زمان باقی‌مانده ═══
s = s.replace(
    '''                pend["tries"] = pend.get("tries", 0) + 1
                session["login_pending"] = pend
                return render(_read("auth_otp.html"), demo_code=pend["code"],
                                                    phone_mask=_mask(pend["phone"]), error="کد نادرست است.")''',
    '''                pend["tries"] = pend.get("tries", 0) + 1
                session["login_pending"] = pend
                return render(_read("auth_otp.html"), demo_code=pend["code"],
                                                    phone_mask=_mask(pend["phone"]), error="کد نادرست است.",
                                                    seconds_left=max(0, int(pend.get("exp", 0) - _time.time())),
                                                    otp_action="/login/phone", otp_submit="ورود ←", otp_desc="کد یک‌بار مصرف ورود",
                                                    otp_resend_url="/login/phone/resend", otp_cancel_url="/login")''',
    1)

# ═══ ۳) ورود GET: زمان باقی‌مانده ═══
s = s.replace(
    '    return render(_read("auth_otp.html"), demo_code=pend["code"], phone_mask=_mask(pend["phone"]))',
    '''    return render(_read("auth_otp.html"), demo_code=pend["code"], phone_mask=_mask(pend["phone"]),
                    seconds_left=max(0, int(pend.get("exp", 0) - _time.time())),
                    otp_action="/login/phone", otp_submit="ورود ←", otp_desc="کد یک‌بار مصرف ورود",
                    otp_resend_url="/login/phone/resend", otp_cancel_url="/login")''',
    1)

# ═══ ۴) TOTP → template جدید ═══
s = s.replace('return render(_read("totp.html"), mode="login",', 'return render(_read("totp_login.html"),', 1)

# ═══ ) ورود: قفل → صفحه مرده ═══
s = s.replace(
    '            return render(_read("auth.html"), mode="login", error="تلاش بیش از حد؛ دوباره وارد شوید.")',
    '            return render(_read("auth_otp.html"), phone_mask=_mask(pend["phone"]), error="کد باطل شد؛ ارسال مجدد را بزن.",\n                                            otp_action="/login/phone", otp_submit="ورود ←", otp_desc="کد یک‌بار مصرف ورود",\n                                            otp_resend_url="/login/phone/resend", otp_cancel_url="/login")',
    1)

# ═══ ) ثبت‌نام: قفل → صفحه مرده ═══
s = s.replace(
    '                return render(_read("auth_register.html"), error="تلاش بیش از حد؛ از ابتدا ثبت‌نام کنید.")',
    '                return render(_read("auth_verify.html"), phone=pend["phone"], error="کد باطل شد؛ ارسال مجدد را بزن.",\n                                            otp_action="/register", otp_submit="ثبت‌نام ←", otp_desc="کد تأیید ثبت‌نام",\n                                            otp_resend_url="/register/resend", otp_cancel_url="/")',
    1)

p.write_text(s, encoding="utf-8")

# شمارش
cnt = 0
for needle in [
    'otp_action="/register"',
    'otp_action="/login/phone"',
    'totp_login.html',
]:
    cnt += s.count(needle)
print(f"✅ جایگزینی‌های موفق: {cnt}")

import py_compile
py_compile.compile("auth.py", doraise=True)
print("✅ syntax auth سالم")
