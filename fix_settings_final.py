from pathlib import Path

p = Path("app.py")
s = p.read_text(encoding="utf-8")

# بلوک فعلی (دقیقاً همان چیزی که در خروجی دیدم)
old_block = '''    if not _otp_eq(code, pend.get("code", "")):
        pend["tries"] = pend.get("tries", 0) + 1
        session["set_otp"] = pend
        return _set_render("settings_otp.html", demo_code=pend["code"], desc=pend["desc"],
                                           phone=_mask_phone(pend["phone"]), error="کد نادرست است")'''

# بلوک جدید با remaining_time و remaining_attempts
new_block = '''    if not _otp_eq(code, pend.get("code", "")):
        pend["tries"] = pend.get("tries", 0) + 1
        session["set_otp"] = pend
        remaining_attempts = 4 - pend["tries"]
        from flask import render_template as _rt
        return _rt("settings_otp.html",
                             demo_code=pend["code"],
                             desc=pend["desc"],
                             phone=_mask_phone(pend["phone"]),
                             error=f"کد اشتباه است. {remaining_attempts} تلاش باقی مانده",
                             remaining_time=int(pend["exp"] - _t.time()),
                             remaining_attempts=remaining_attempts)'''

if old_block in s:
    s = s.replace(old_block, new_block, 1)
    p.write_text(s, encoding="utf-8")
    print("✅ بلوک کد اشتباه جایگزین شد")
else:
    print("❌ بلوک پیدا نشد")
    # جستجوی فازی
    if "_otp_eq(code, pend.get" in s:
        print("ℹ️ تابع _otp_eq وجود دارد ولی فرمت متفاوت")

import py_compile
py_compile.compile("app.py", doraise=True)
print("✅ syntax app.py سالم")
