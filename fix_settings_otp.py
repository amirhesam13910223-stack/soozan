from pathlib import Path
import re

# خواندن app.py
p = Path("app.py")
s = p.read_text(encoding="utf-8")

# تابع قدیمی
old_func = '''@app.route("/settings/otp/verify", methods=["POST"])
def settings_otp_verify():
    import time as _t
    from flask import session, redirect
    from core import get_db
    pend = session.get("set_otp")
    if not pend or _t.time() > pend.get("exp", 0):
        session.pop("set_otp", None)
        session["demo_sms"] = "❌ کد منقضی شد"
        return redirect("/settings")
    code = request.form.get("code", "").strip()
    if pend.get("tries", 0) >= 4:
        session.pop("set_otp", None)
        session["demo_sms"] = "❌ تلاش بیش از حد؛ کد باطل شد"
        return redirect("/settings")
    if not _otp_eq(code, pend.get("code", "")):
        pend["tries"] = pend.get("tries", 0) + 1
        session["set_otp"] = pend
        return _set_render("settings_otp.html", demo_code=pend["code"], desc=pend["desc"],
                                           phone=_mask_phone(pend["phone"]), error="کد نادرست است")
    purpose = pend.get("purpose")
    session.pop("set_otp", None)
    u = _set_user()
    if purpose == "phone_old":
        session["phone_old_ok"] = _t.time() + 300
        return redirect("/settings/phone/new")
    if purpose == "phone_new" and u:
        np = pend.get("new_phone")
        with get_db() as c:
            c.execute("UPDATE users SET phone=?, phone_verified=1 WHERE id=?", (np, u["id"]))
        session.pop("phone_old_ok", None); session.pop("phone_pw_ok", None)
        session["demo_sms"] = f"✅ شماره موبایل حساب شما به {np} تغییر یافت. · 📨 پیامک به شماره قدیمی {_mask_phone(u['phone'])}: شماره موبایل حساب سوزان شما به شماره دیگری تغییر کرد."
        return redirect("/settings")
    if purpose == "pw_change":
        session["pw_ok_until"] = _t.time() + 300
        return redirect("/settings/password/new")
    return redirect("/settings")'''

# تابع جدید
new_func = '''@app.route("/settings/otp/verify", methods=["POST"])
def settings_otp_verify():
    import time as _t
    from flask import session, redirect, render_template
    from core import get_db
    
    pend = session.get("set_otp")
    if not pend or _t.time() > pend.get("exp", 0):
        session.pop("set_otp", None)
        session["demo_sms"] = "❌ کد منقضی شد"
        return redirect("/settings")
    
    code = request.form.get("code", "").strip()
    
    # بررسی تعداد تلاش (۴ بار = قفل)
    if pend.get("tries", 0) >= 4:
        session.pop("set_otp", None)
        session["demo_sms"] = "❌ تلاش بیش از حد؛ کد باطل شد"
        return redirect("/settings")
    
    if not _otp_eq(code, pend.get("code", "")):
        pend["tries"] = pend.get("tries", 0) + 1
        session["set_otp"] = pend
        remaining_attempts = 4 - pend["tries"]
        return render_template("settings_otp.html",
                             demo_code=pend["code"],
                             desc=pend["desc"],
                             phone=_mask_phone(pend["phone"]),
                             error=f"کد اشتباه است. {remaining_attempts} تلاش باقی مانده",
                             remaining_time=int(pend["exp"] - _t.time()),
                             remaining_attempts=remaining_attempts)
    
    # موفقیت
    purpose = pend.get("purpose")
    session.pop("set_otp", None)
    u = _set_user()
    
    if purpose == "phone_old":
        session["phone_old_ok"] = _t.time() + 300
        return redirect("/settings/phone/new")
    
    if purpose == "phone_new" and u:
        np = pend.get("new_phone")
        with get_db() as c:
            c.execute("UPDATE users SET phone=?, phone_verified=1 WHERE id=?", (np, u["id"]))
        session.pop("phone_old_ok", None)
        session.pop("phone_pw_ok", None)
        session["demo_sms"] = f"✅ شماره موبایل حساب شما به {np} تغییر یافت. · 📨 پیامک به شماره قدیمی {_mask_phone(u['phone'])}: شماره موبایل حساب سوزان شما به شماره دیگری تغییر کرد."
        return redirect("/settings")
    
    if purpose == "pw_change":
        session["pw_ok_until"] = _t.time() + 300
        return redirect("/settings/password/new")
    
    return redirect("/settings")'''

# جایگزینی
if old_func in s:
    s = s.replace(old_func, new_func, 1)
    p.write_text(s, encoding="utf-8")
    print("✅ settings_otp_verify آپدیت شد")
else:
    print("⚠ تابع قدیمی پیدا نشد — بررسی می‌کنیم")
    # جستجوی الگوی ساده‌تر
    if 'def settings_otp_verify():' in s:
        print("✅ تابع وجود دارد ولی فرمت متفاوت است")
    else:
        print("❌ تابع اصلاً وجود ندارد")

import py_compile
py_compile.compile("app.py", doraise=True)
print("✅ syntax app.py سالم")
