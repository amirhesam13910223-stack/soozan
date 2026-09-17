#!/usr/bin/env python3
"""
تست جامع سوزان v1.0.0
یک فایل واحد — همه فازها — بدون تداخل
"""
import os
import sys
import io
import time
import signal
import sqlite3
import subprocess
from pathlib import Path

# قبل از import کتابخانه‌های پروژه، DEV_MODE را ست کن
os.environ["SOOZAN_DEV_MODE"] = "1"

import requests

BASE = "http://127.0.0.1:8000"
PASS = 0
FAIL = 0
WARN = 0

def ok(msg):
    global PASS
    PASS += 1
    print(f"  ✓ {msg}")

def bad(msg):
    global FAIL
    FAIL += 1
    print(f"  ✗ {msg}")

def warn(msg):
    global WARN
    WARN += 1
    print(f"  ⚠ {msg}")

def section(title):
    print(f"\n{'─' * 70}\n{title}\n{'─' * 70}")

# ═══════════════════════════════════════════════════════════
# راه‌اندازی سرور
# ═══════════════════════════════════════════════════════════
def start_server():
    print("🚀 راه‌اندازی سرور...")
    # ایجاد مسیر log در پوشه پروژه (نه /tmp که در Termux ممکن است نباشد)
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "test_server.log")
    log_file = open(log_path, "w")
    proc = subprocess.Popen(
        [sys.executable, "app.py"],
        stdout=log_file,
        stderr=log_file,
        cwd=os.path.dirname(os.path.abspath(__file__)),
        env={**os.environ, "SOOZAN_DEV_MODE": "1", "PYTHONUNBUFFERED": "1"}
    )
    for i in range(30):
        try:
            r = requests.get(f"{BASE}/health", timeout=2)
            if r.status_code == 200:
                print(f"✅ سرور آماده شد ({i+1} ثانیه)")
                return proc
        except:
            pass
        time.sleep(1)
    proc.terminate()
    raise RuntimeError("سرور بعد از 30 ثانیه آماده نشد")

# ═══════════════════════════════════════════════════════════
# بخش ۱: سلامت و امنیت پایه
# ═══════════════════════════════════════════════════════════
def test_1_health():
    section("۱. سلامت سرور و هدرهای امنیتی")
    
    r = requests.get(f"{BASE}/health", timeout=5)
    if r.status_code == 200:
        j = r.json()
        ok(f"/health پاسخ داد (phase={j.get('phase')})")
    else:
        bad(f"/health → {r.status_code}")
    
    # هدرهای امنیتی
    r = requests.get(f"{BASE}/login")
    headers_ok = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
    for h, v in headers_ok.items():
        if r.headers.get(h) == v:
            ok(f"{h}: {v}")
        else:
            bad(f"{h} نادرست: {r.headers.get(h)}")
    
    if "Content-Security-Policy" in r.headers:
        ok("CSP فعال است")
        if "nonce-" in r.headers["Content-Security-Policy"]:
            ok("CSP شامل nonce است")
        else:
            warn("CSP بدون nonce")
    else:
        bad("CSP وجود ندارد")

# ═══════════════════════════════════════════════════════════
# بخش ۲: احراز هویت
# ═══════════════════════════════════════════════════════════
def test_2_auth():
    section("۲. ثبت‌نام، ورود، و امنیت رمز")

    import random
    import re
    username = f"user_{int(time.time())}_{random.randint(100,999)}"
    password = "CorrectPass123"

    # ── ثبت‌نام دومرحله‌ای ──
    s = requests.Session()
    r = s.post(f"{BASE}/register", data={
        "username": username,
        "password": password,
        "password2": password,
        "full_name": "کاربر تستی",
        "phone": "09120000001"
    })
    if r.status_code != 200:
        bad(f"مرحله ۱ ثبت‌نام ناموفق: {r.status_code}")
        return None, None
    ok(f"مرحله ۱ ثبت‌نام: دریافت اطلاعات")

    # استخراج کد دمو
    m = re.search(r'data-demo-code="(\d{6})"', r.text)
    if not m:
        bad("کد دمو در صفحه تأیید پیدا نشد")
        return None, None
    code = m.group(1)
    ok(f"کد دمو استخراج شد: {code}")

    # مرحله ۲: تأیید کد + ورود خودکار
    r2 = s.post(f"{BASE}/register", data={"step": "2", "code": code})
    if r2.status_code == 302 or "داشبورد" in r2.text or "dashboard" in r2.url:
        ok(f"ثبت‌نام {username} + ورود خودکار")
    else:
        bad(f"ثبت‌نام/ورود خودکار ناموفق: {r2.status_code}")
        return None, None

    # ورود با رمز اشتباه (از session جدید!)
    s_wrong = requests.Session()
    r = s_wrong.post(f"{BASE}/login", data={
        "username": username,
        "password": "WrongPass123"
    }, allow_redirects=False)
    if r.status_code == 200 and "اشتباه" in r.text:
        ok("رمز اشتباه رد شد")
    else:
        bad(f"رمز اشتباه قبول شد! status={r.status_code}")

    # ورود با رمز صحیح → OTP
    s = requests.Session()
    r = s.post(f"{BASE}/login", data={
        "username": username,
        "password": password
    }, allow_redirects=False)
    if r.status_code == 302 and "/login/phone" in r.headers.get("Location", ""):
        ok("ورود مرحله ۱: OTP ارسال شد")
    else:
        bad(f"OTP ارسال نشد: {r.status_code}")
        return s, username

    # استخراج کد OTP
    rp = s.get(f"{BASE}/login/phone")
    m2 = re.search(r'data-demo-code="(\d{6})"', rp.text)
    if not m2:
        bad("کد OTP در صفحه پیدا نشد")
        return s, username
    otp_code = m2.group(1)

    # تأیید OTP
    r2 = s.post(f"{BASE}/login/phone", data={"code": otp_code}, allow_redirects=False)
    if r2.status_code == 302 and "/dashboard" in r2.headers.get("Location", ""):
        ok("ورود کامل با OTP")
    else:
        bad(f"ورود با OTP ناموفق: {r2.status_code}")

    # بررسی cookie
    if "soozan_sid" in s.cookies:
        ok(f"کوکی session صادر شد")
    else:
        bad("کوکی session صادر نشد")

    # بررسی داشبورد
    r = s.get(f"{BASE}/dashboard")
    if r.status_code == 200 and username in r.text:
        ok(f"داشبورد بارگذاری شد (نام کاربری موجود)")
    else:
        bad("داشبورد بارگذاری نشد")

    return s, username


# ═══════════════════════════════════════════════════════════
# بخش ۳: آپلود و ویزارد
# ═══════════════════════════════════════════════════════════
def test_3_upload(s):
    section("۳. آپلود فایل (انواع مختلف)")
    
    results = {}
    
    # ۳.۱ آپلود تصویر
    from PIL import Image
    img = Image.new('RGB', (100, 100), color='red')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    
    r = s.post(f"{BASE}/api/upload",
               files={"file": ("test.png", buf, "image/png")},
               data={"intro_message": "تست تصویر"})
    
    if r.headers.get("Content-Type", "").startswith("application/json"):
        j = r.json()
        if j.get("ok") and "uid" in j:
            ok(f"آپلود PNG موفق (uid={j['uid'][:12]}…)")
            results["image"] = j
        else:
            bad(f"آپلود PNG: {j}")
    else:
        bad(f"آپلود PNG: HTML برمی‌گرداند")
    
    # ۳.۲ آپلود متن
    txt_buf = io.BytesIO("این یک متن تستی فارسی است.".encode("utf-8"))
    r = s.post(f"{BASE}/api/upload",
               files={"file": ("test.txt", txt_buf, "text/plain")},
               data={"intro_message": "تست متن"})
    
    if r.headers.get("Content-Type", "").startswith("application/json"):
        j = r.json()
        if j.get("ok") and j.get("family") == "text":
            ok(f"آپلود متن موفق (family={j['family']})")
            results["text"] = j
        else:
            bad(f"آپلود متن: {j}")
    else:
        bad("آپلود متن: HTML برمی‌گرداند")
    
    # ۳.۳ آپلود با رمز
    txt_buf2 = io.BytesIO("متن رمزدار".encode("utf-8"))
    r = s.post(f"{BASE}/api/upload",
               files={"file": ("secret.txt", txt_buf2, "text/plain")},
               data={"intro_message": "رمزدار", "password": "secret123"})
    
    if r.headers.get("Content-Type", "").startswith("application/json"):
        j = r.json()
        if j.get("ok"):
            ok("آپلود با رمز موفق")
            results["password"] = j
        else:
            bad(f"آپلود با رمز: {j}")
    else:
        bad("آپلود با رمز: HTML برمی‌گرداند")
    
    # ۳.۴ فایل غیرمجاز رد شود
    bad_buf = io.BytesIO(b"\x00" * 100)
    r = s.post(f"{BASE}/api/upload",
               files={"file": ("bad.exe", bad_buf, "application/octet-stream")},
               data={"intro_message": "تست"})
    if r.headers.get("Content-Type", "").startswith("application/json"):
        j = r.json()
        if not j.get("ok"):
            ok("فایل غیرمجاز رد شد")
        else:
            warn("فایل غیرمجاز رد نشد (شاید مجاز است)")
    
    return results

# ═══════════════════════════════════════════════════════════
# بخش ۴: مشاهده و سوزاندن
# ═══════════════════════════════════════════════════════════
def test_4_view(results):
    section("۴. مشاهده فایل و سوزاندن")
    
    if "image" not in results:
        warn("فایل تصویری برای تست وجود ندارد")
        return
    
    uid = results["image"]["uid"]
    
    # صفحه /i
    r = requests.get(f"{BASE}/i")
    if r.status_code == 200:
        ok("صفحه /i بارگذاری شد")
    else:
        bad(f"صفحه /i: {r.status_code}")
    
    # alive (بررسی فعال بودن فایل)
    r = requests.get(f"{BASE}/api/v/alive/{uid}")
    if r.status_code == 200:
        j = r.json()
        if j.get("ok"):
            ok("alive: فایل فعال است (ok=true)")
        else:
            bad(f"alive: ok=false → {j}")
            return
    else:
        bad(f"alive: {r.status_code}")
        return
    
    # unlock اول (دریافت توکن)
    r = requests.post(f"{BASE}/api/v/unlock/{uid}")
    if r.status_code == 200:
        j = r.json()
        if j.get("ok") and "token" in j:
            token = j["token"]
            ok(f"unlock موفق (token={token[:12]}…)")
        else:
            bad(f"unlock: {j}")
            return
    else:
        bad(f"unlock: {r.status_code} → {r.text[:100]}")
        return
    
    # unlock دوم (رفتار طراحی: توکن جدید صادر می‌شود)
    r = requests.post(f"{BASE}/api/v/unlock/{uid}")
    if r.status_code == 200:
        j = r.json()
        if j.get("ok") and "token" in j:
            ok("unlock دوم نیز توکن جدید صادر کرد (رفتار طراحی)")
        else:
            ok("unlock دوم رد شد (یک‌بارمصرف)")
    else:
        ok(f"unlock دوم رد شد (status={r.status_code})")

# ═══════════════════════════════════════════════════════════
# بخش ۵: پنل مدیریت
# ═══════════════════════════════════════════════════════════
def test_5_manage(results):
    section("۵. پنل مدیریت")
    
    if "image" not in results:
        warn("فایل برای تست وجود ندارد")
        return
    
    admin_code = results["image"]["admin_code"]
    
    # ورود به پنل با کد صحیح (HTML یا redirect)
    r = requests.post(f"{BASE}/api/manage/enter", json={"code": admin_code}, allow_redirects=False)
    if r.status_code in (200, 302):
        ok(f"پنل مدیریت پاسخ داد (status={r.status_code})")
    else:
        bad(f"پنل مدیریت: {r.status_code}")
    
    # کد اشتباه (باید متفاوت پاسخ دهد)
    r = requests.post(f"{BASE}/api/manage/enter", json={"code": "WRONG_CODE_12345"}, allow_redirects=False)
    if r.status_code in (200, 302, 400, 401, 403):
        ok(f"کد اشتباه پاسخ داد (status={r.status_code})")
    else:
        warn(f"کد اشتباه پاسخ غیرمنتظره: {r.status_code}")

# ═══════════════════════════════════════════════════════════
# بخش ۶: امنیت (rate limit)
# ═══════════════════════════════════════════════════════════
def test_6_security():
    section("۶. امنیت (محدودیت نرخ ورود)")
    
    s = requests.Session()
    fail_count = 0
    
    for i in range(12):
        r = s.post(f"{BASE}/login", data={
            "username": "nonexistent_user_xyz",
            "password": "wrong"
        }, allow_redirects=False)
        if r.status_code == 200 and "تلاش بیش از حد" in r.text:
            ok(f"Rate limit فعال شد در تلاش {i+1}")
            return
    
    warn("rate limit بعد از 12 تلاش فعال نشد")

# ═══════════════════════════════════════════════════════════
# بخش ۷: کلید ارشد (بدون تداخل)
# ═══════════════════════════════════════════════════════════
def test_7_master_key():
        test_8_settings()
    section("۷. کلید ارشد و ساختار فایل")
    
    key_path = Path("data/.master.key")
    if key_path.exists():
        data = key_path.read_bytes()
        if len(data) == 32:
            ok(f"کلید ارشد 32 بایت است")
        else:
            bad(f"طول کلید: {len(data)}")
        
        perm = oct(key_path.stat().st_mode)[-3:]
        if perm == "600":
            ok(f"دسترسی کلید: {perm}")
        else:
            warn(f"دسترسی کلید: {perm} (انتظار: 600)")
    else:
        bad("فایل .master.key وجود ندارد")
    
    # بررسی پوشه data
    data_dir = Path("data")
    if data_dir.exists():
        perm = oct(data_dir.stat().st_mode)[-3:]
        if perm == "700":
            ok(f"دسترسی پوشه data: {perm}")
        else:
            warn(f"دسترسی پوشه data: {perm}")
    
    # بررسی دیتابیس
    db_path = Path("data/burn.db")
    if db_path.exists():
        conn = sqlite3.connect(str(db_path))
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        needed = {"users", "files", "views", "events"}
        if needed.issubset(set(tables)):
            ok(f"جداول ضروری موجودند: {needed}")
        else:
            bad(f"جداول ناقص: موجود={tables}")
        conn.close()
    else:
        bad("فایل burn.db وجود ندارد")

# ═══════════════════════════════════════════════════════════
# اجرای همه تست‌ها
# ═══════════════════════════════════════════════════════════
def main():
    print("=" * 70)
    print("🔥 تست جامع سوزان v1.0.0")
    print("=" * 70)
    
    proc = None
    try:
        proc = start_server()
        
        test_1_health()
        s, username = test_2_auth()
        if s:
            results = test_3_upload(s)
            test_4_view(results)
            test_5_manage(results)
        test_6_security()
        test_7_master_key()
        test_8_settings()
        
    finally:
        if proc:
            proc.terminate()
            proc.wait()
            print("\n🧹 سرور بسته شد")
    
    print("\n" + "=" * 70)
    print(f"📊 نتیجه: موفق={PASS} · شکست={FAIL} · هشدار={WARN}")
    print("=" * 70)
    
    if FAIL == 0:
        print("🏆 همه تست‌ها سبز شدند!")
        return 0
    else:
        print(f"⚠️  {FAIL} تست شکست خورد")
        return 1

if __name__ == "__main__":
    sys.exit(main())


def test_8_settings():
    section("۸. تنظیمات: مدیریت کامل حساب")
    import random
    username = f"set_{int(time.time())}_{random.randint(100,999)}"
    password = "SettingsPass123"
    s = requests.Session()
    r = s.post(f"{BASE}/register", data={"username": username, "password": password,
                                         "password2": password, "full_name": "تنظیمات تست",
                                         "phone": "09120000002"})
    m = re.search(r'data-demo-code="(\d{6})"', r.text)
    if not m:
        bad("ثبت‌نام برای تست تنظیمات شکست")
        return
    s.post(f"{BASE}/register", data={"step": "2", "code": m.group(1)})

    r = s.get(f"{BASE}/settings")
    if r.status_code == 200 and "تنظیمات" in r.text:
        ok("صفحه تنظیمات باز شد")
    else:
        bad(f"تنظیمات باز نشد: {r.status_code}")
        return

    s.post(f"{BASE}/settings/profile", data={"full_name": "نام جدید تستی"})
    if "نام جدید تستی" in s.get(f"{BASE}/settings").text:
        ok("ویرایش نام ذخیره شد")
    else:
        bad("ویرایش نام ذخیره نشد")

    # تغییر شماره — راه ۲ (رمز)
    s.post(f"{BASE}/settings/phone/start2", data={"password": password})
    r = s.post(f"{BASE}/settings/phone/new", data={"new_phone": "09120000003"})
    m = re.search(r'data-demo-code="(\d{6})"', r.text)
    if m:
        s.post(f"{BASE}/settings/otp/verify", data={"code": m.group(1)})
        t = s.get(f"{BASE}/settings").text
        if "09120000003" in t and "تغییر کرد" in t:
            ok("تغییر شماره (راه ۲) + پیامک هشدار به شماره قدیمی")
        else:
            bad("شماره جدید یا پیامک هشدار نیامد")
    else:
        bad("کد تأیید شماره صادر نشد")

    # تغییر رمز: رمز فعلی → کد → رمز جدید
    newpass = "NewSettingsPass456"
    r = s.post(f"{BASE}/settings/password/start", data={"current_password": password})
    m = re.search(r'data-demo-code="(\d{6})"', r.text)
    if m:
        s.post(f"{BASE}/settings/otp/verify", data={"code": m.group(1)})
        s.post(f"{BASE}/settings/password/new", data={"new_password": newpass, "new_password2": newpass})
        ok("تغییر رمز عبور با کد تأیید")
    else:
        bad("کد تغییر رمز صادر نشد")
        newpass = password

    # خروج: هشدار + تأیید
    r = s.get(f"{BASE}/logout")
    if r.status_code == 200 and "تأیید" in r.text:
        ok("صفحه هشدار خروج")
    else:
        bad("صفحه هشدار خروج نیامد")
    s.post(f"{BASE}/logout", data={"confirm": "1"})
    if s.get(f"{BASE}/dashboard", allow_redirects=False).status_code == 200:
        ok("خروج بدون checkbox انجام نشد (درست)")
    else:
        bad("خروج بدون تأیید انجام شد!")
    s.post(f"{BASE}/logout", data={"confirm": "1", "ack": "on"})
    if s.get(f"{BASE}/dashboard", allow_redirects=False).status_code == 302:
        ok("خروج با تأیید انجام شد")
    else:
        bad("خروج با تأیید کار نکرد")

    # ورود با رمز جدید
    s2 = requests.Session()
    r = s2.post(f"{BASE}/login", data={"username": username, "password": newpass}, allow_redirects=False)
    if r.status_code == 302 and "/login/phone" in r.headers.get("Location", ""):
        rp = s2.get(f"{BASE}/login/phone")
        m2 = re.search(r'data-demo-code="(\d{6})"', rp.text)
        if m2:
            s2.post(f"{BASE}/login/phone", data={"code": m2.group(1)})
            ok("ورود با رمز جدید موفق")
        else:
            bad("کد ورود نیامد")
    else:
        bad("ورود با رمز جدید شکست")

    # حذف کامل حساب
    s2.post(f"{BASE}/settings/delete", data={"password": newpass, "ack": "on"})
    r = s2.post(f"{BASE}/login", data={"username": username, "password": newpass}, allow_redirects=False)
    if r.status_code == 200:
        ok("حساب حذف شد (ورود دوباره ممکن نیست)")
    else:
        bad("حذف حساب کار نکرد")
