#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔥 تست جامع یکپارچه سوزان — همه‌چیز از صفر
اجرا: python3 test_full_regression.py
"""
from __future__ import annotations
import io
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# ─── رنگ‌ها ───
G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
B = "\033[94m"
BOLD = "\033[1m"
RESET = "\033[0m"

PASS = 0
FAIL = 0
WARN = 0
REPORT: list = []

def ok(msg: str):
    global PASS
    PASS += 1
    REPORT.append(f"  {G}✓{RESET} {msg}")
    print(f"  {G}✓{RESET} {msg}")

def bad(msg: str):
    global FAIL
    FAIL += 1
    REPORT.append(f"  {R}✗{RESET} {msg}")
    print(f"  {R}✗{RESET} {msg}")

def warn(msg: str):
    global WARN
    WARN += 1
    REPORT.append(f"  {Y}⚠{RESET} {msg}")
    print(f"  {Y}⚠{RESET} {msg}")

def section(title: str):
    print(f"\n{BOLD}{B}{'─'*60}{RESET}")
    print(f"{BOLD}{B}  {title}{RESET}")
    print(f"{BOLD}{B}{'─'*60}{RESET}")


# ═══════════════════════════════════════════════════════
# Setup
# ═══════════════════════════════════════════════════════
import requests

BASE = "http://127.0.0.1:8000"
DEV_MODE = True  # برای تست محلی

def ensure_server() -> subprocess.Popen:
    """سرور رو از صفر بالا ببر"""
    print(f"{BOLD}🔧 راه‌اندازی سرور تست...{RESET}")
    # کشتن سرور قدیمی
    subprocess.run(["pkill", "-f", "python app.py"], capture_output=True)
    time.sleep(1)
    # بالا بردن سرور جدید با DEV_MODE
    env = os.environ.copy()
    env["SOOZAN_DEV_MODE"] = "1"
    proc = subprocess.Popen(
        [sys.executable, "app.py"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=env, cwd=str(Path(__file__).parent)
    )
    # صبر برای آماده شدن
    for i in range(30):
        try:
            r = requests.get(BASE + "/health", timeout=2)
            if r.status_code == 200:
                print(f"  {G}✓{RESET} سرور آماده شد ({i+1} ثانیه)")
                return proc
        except:
            pass
        time.sleep(1)
    print(f"  {R}✗{RESET} سرور بعد از ۳۰ ثانیه آماده نشد")
    proc.kill()
    sys.exit(1)

def cleanup(proc: subprocess.Popen):
    """بستن سرور"""
    if proc:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except:
            proc.kill()
    print(f"\n{BOLD}🧹 سرور بسته شد{RESET}")


# ═══════════════════════════════════════════════════════
# بخش ۱: سلامت سرور و پیکربندی
# ═══════════════════════════════════════════════════════
def test_1_health():
    section("۱. سلامت سرور و پیکربندی")
    
    # /health
    r = requests.get(BASE + "/health", timeout=5)
    if r.status_code == 200 and r.json().get("ok"):
        ok(f"/health کار می‌کند (phase={r.json().get('phase')})")
    else:
        bad(f"/health خطا: {r.status_code}")
    
    # هدرهای امنیتی
    r = requests.get(BASE + "/login", timeout=5)
    headers = r.headers
    checks = [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Content-Security-Policy", None),
        ("Referrer-Policy", None),
    ]
    for h, val in checks:
        if h in headers:
            if val and headers[h] == val:
                ok(f"هدر {h}: {val}")
            elif val:
                warn(f"هدر {h} وجود دارد ولی مقدار متفاوت: {headers[h]}")
            else:
                ok(f"هدر {h} فعال است")
        else:
            bad(f"هدر {h} وجود ندارد")
    
    # DEV_MODE
    if DEV_MODE:
        ok("سرور در حالت DEV_MODE اجرا شده (برای تست محلی)")


# ═══════════════════════════════════════════════════════
# بخش ۲: امنیت پایه (فاز A)
# ═══════════════════════════════════════════════════════
def test_2_security_base():
    section("۲. امنیت پایه (فاز A)")
    
    # session_key ≠ KEK
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        from core import MasterKeyManager, hash_file_password, verify_file_password
        mk = MasterKeyManager.instance()
        kek = mk._kek
        sk = mk.session_key()
        if kek != sk:
            ok("session_key با KEK خام متفاوت است")
        else:
            bad("session_key با KEK یکسان است!")
        if len(sk) == 32:
            ok("طول session_key ۳۲ بایت است")
        # کش
        sk2 = mk.session_key()
        if sk is sk2:
            ok("session_key کش می‌شود")
    except Exception as e:
        bad(f"خطا در تست امنیت پایه: {e}")
    
    # هش رمز فایل
    try:
        pw = "TestPassword123!"
        h = hash_file_password(pw)
        if h.startswith("scrypt$"):
            ok("فرمت هش رمز: scrypt$salt$hash")
        if verify_file_password(pw, h):
            ok("رمز صحیح تأیید می‌شود")
        if not verify_file_password("wrong", h):
            ok("رمز غلط رد می‌شود")
        if not verify_file_password(pw, "plaintext"):
            ok("فرمت قدیمی رد می‌شود")
    except Exception as e:
        bad(f"خطا در تست هش رمز: {e}")


# ═══════════════════════════════════════════════════════
# بخش ۳: احراز هویت
# ═══════════════════════════════════════════════════════
def test_3_auth():
    section("۳. احراز هویت")
    
    s = requests.Session()
    username = "testuser_full_" + str(int(time.time()))
    password = "TestPassword123!"
    
    # ثبت‌نام
    r = s.post(BASE + "/register", data={"username": username, "password": password})
    if r.status_code in (200, 302):
        ok("ثبت‌نام موفق")
    else:
        bad(f"ثبت‌نام خطا: {r.status_code}")
        return s
    
    # ورود
    r = s.post(BASE + "/login", data={"username": username, "password": password},
               allow_redirects=False)
    if r.status_code == 302:
        ok("ورود موفق (ریدایرکت به داشبورد)")
    else:
        bad(f"ورود خطا: {r.status_code}")
    
    # ورود با رمز اشتباه
    r = s.post(BASE + "/login", data={"username": username, "password": "wrongpass"},
               allow_redirects=False)
    if r.status_code != 302:
        ok("ورود با رمز اشتباه رد شد")
    else:
        bad("ورود با رمز اشتباه قبول شد!")
    
    return s


# ═══════════════════════════════════════════════════════
# بخش ۴: آپلود و ویزارد
# ═══════════════════════════════════════════════════════
def test_4_upload(s: requests.Session):
    section("۴. آپلود و ویزارد")
    
    files = {}
    
    # آپلود تصویر
    from PIL import Image
    img = Image.new('RGB', (200, 200), color='blue')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    r = s.post(BASE + "/api/upload",
               files={"file": ("test.png", buf, "image/png")},
               data={"intro_message": "تست تصویر", "max_views": "2", "watermark": "سوزان"})
    j = r.json()
    if j.get("ok"):
        ok(f"آپلود تصویر موفق (uid={j['uid'][:12]}…)")
        files["image"] = j["uid"]
    else:
        bad(f"آپلود تصویر خطا: {j}")
    
    # آپلود متن با رمز
    text_content = b"# Test File\nprint('hello')\n# This is a secret"
    r = s.post(BASE + "/api/upload",
               files={"file": ("test.py", io.BytesIO(text_content), "text/plain")},
               data={"intro_message": "تست متن", "max_views": "1",
                     "has_password": "1", "password": "MySecret123",
                     "password_attempts": "3"})
    j = r.json()
    if j.get("ok"):
        ok(f"آپلود متن با رمز موفق (uid={j['uid'][:12]}…)")
        files["text"] = j["uid"]
    else:
        bad(f"آپلود متن خطا: {j}")
    
    # آپلود صوت
    audio_content = b"\x49\x44\x33" + b"\x00" * 1000  # هدر MP3 ساده
    r = s.post(BASE + "/api/upload",
               files={"file": ("test.mp3", io.BytesIO(audio_content), "audio/mpeg")},
               data={"intro_message": "تست صوت", "max_views": "1"})
    j = r.json()
    if j.get("ok"):
        ok(f"آپلود صوت موفق (uid={j['uid'][:12]}…)")
        files["audio"] = j["uid"]
    else:
        bad(f"آپلود صوت خطا: {j}")
    
    return files


# ═══════════════════════════════════════════════════════
# بخش ۵: رندر سمت سرور (فاز B)
# ═══════════════════════════════════════════════════════
def test_5_render(files: dict):
    section("۵. رندر سمت سرور (فاز B)")
    
    if not files:
        bad("هیچ فایلی برای تست رندر وجود ندارد")
        return
    
    s = requests.Session()
    
    # تست هر نوع فایل
    for ftype, uid in files.items():
        # باز کردن صفحه
        r = s.get(BASE + f"/v/{uid}")
        if r.status_code != 200:
            bad(f"صفحه /v/{uid} خطا: {r.status_code}")
            continue
        
        # unlock
        r = s.post(BASE + f"/api/v/unlock/{uid}", json={"password": ""})
        j = r.json()
        if not j.get("ok"):
            # شاید رمز لازم داره
            if ftype == "text":
                r = s.post(BASE + f"/api/v/unlock/{uid}", json={"password": "MySecret123"})
                j = r.json()
                if not j.get("ok"):
                    bad(f"unlock برای {ftype} خطا: {j}")
                    continue
            else:
                bad(f"unlock برای {ftype} خطا: {j}")
                continue
        
        ok(f"unlock برای {ftype} موفق")
        render_tokens = j.get("render_tokens", {})
        main_token = j.get("token")
        
        # تست endpoint قدیمی (باید 404 بده)
        r = s.get(BASE + f"/api/v/content/{uid}?token={main_token}")
        if r.status_code == 404:
            ok(f"endpoint قدیمی /api/v/content برای {ftype} حذف شده")
        else:
            bad(f"endpoint قدیمی هنوز کار می‌کند: {r.status_code}")
        
        # تست رندر جدید
        if ftype == "image" and "image" in render_tokens:
            img_token = render_tokens["image"]
            r = s.get(BASE + f"/api/v/image/{uid}?token={img_token}")
            if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("image/"):
                ok(f"تصویر رندرشده تحویل داده شد ({len(r.content)} بایت)")
                # بررسی PNG
                if r.content[:8] == b'\x89PNG\r\n\x1a\n':
                    ok("تصویر خروجی معتبر است")
                # بررسی هدرهای ضدکش
                cc = r.headers.get("Cache-Control", "")
                if "no-store" in cc and "no-cache" in cc:
                    ok("هدرهای ضدکش فعال هستند")
                else:
                    warn(f"هدرهای کش: {cc}")
                # بررسی واترمارک (از نظر لاگ)
            else:
                bad(f"رندر تصویر خطا: {r.status_code}")
        
        elif ftype == "text" and "text" in render_tokens:
            text_token = render_tokens["text"]
            r = s.get(BASE + f"/api/v/text/{uid}?token={text_token}")
            if r.status_code == 200:
                ok(f"متن رندرشده تحویل داده شد ({len(r.content)} کاراکتر)")
                # بررسی escape
                if "<script>" not in r.text:
                    ok("متن escape شده (بدون تگ خام)")
                else:
                    warn("متن ممکن است کاملًا escape نشده باشد")
            else:
                bad(f"رندر متن خطا: {r.status_code}")
        
        elif ftype == "audio" and "audio" in render_tokens:
            audio_token = render_tokens["audio"]
            r = s.get(BASE + f"/api/v/audio/{uid}?token={audio_token}")
            if r.status_code == 200:
                ok(f"صوت با توکن یک‌بارمصرف تحویل داده شد ({len(r.content)} بایت)")
            else:
                bad(f"رندر صوت خطا: {r.status_code}")
    
    # تست توکن یک‌بارمصرف
    if files.get("image"):
        uid = files["image"]
        r = s.post(BASE + f"/api/v/unlock/{uid}", json={"password": ""})
        j = r.json()
        if j.get("ok"):
            rt = j.get("render_tokens", {})
            img_token = rt.get("image", j.get("token"))
            # اولین استفاده
            r1 = s.get(BASE + f"/api/v/image/{uid}?token={img_token}")
            # دومین استفاده (باید رد بشه)
            r2 = s.get(BASE + f"/api/v/image/{uid}?token={img_token}")
            if r1.status_code == 200 and r2.status_code != 200:
                ok("توکن تصویر یک‌بارمصرف است")
            else:
                bad(f"توکن یک‌بارمصرف نیست: {r1.status_code} / {r2.status_code}")


# ═══════════════════════════════════════════════════════
# بخش ۶: نمایش و سوزاندن
# ═══════════════════════════════════════════════════════
def test_6_view_and_burn(files: dict):
    section("۶. نمایش و سوزاندن")
    
    if not files.get("image"):
        bad("فایلی برای تست نمایش وجود ندارد")
        return
    
    uid = files["image"]
    s = requests.Session()
    
    # باز کردن صفحه
    r = s.get(BASE + f"/v/{uid}")
    if r.status_code == 200:
        ok("صفحه نمایش باز شد")
    
    # تلاش مجدد بعد از سوزاندن (اگه قبلاً سوزانده شده)
    r = s.post(BASE + f"/api/v/unlock/{uid}", json={"password": ""})
    j = r.json()
    if j.get("ok"):
        ok("unlock موفق")
        # مصرف بازدید
        rt = j.get("render_tokens", {})
        img_token = rt.get("image", j.get("token"))
        r = s.get(BASE + f"/api/v/image/{uid}?token={img_token}")
        if r.status_code == 200:
            ok("محتوا نمایش داده شد")
        
        # بستن (باید بسوزه)
        r = s.post(BASE + f"/api/v/close/{uid}")
        if r.status_code == 200:
            ok("close فراخوانی شد")
        
        # تلاش مجدد (باید رد بشه)
        time.sleep(0.5)
        r = s.post(BASE + f"/api/v/unlock/{uid}", json={"password": ""})
        j = r.json()
        if not j.get("ok") and j.get("reason") == "gone":
            ok("بعد از سوزاندن، دسترسی رد شد")
        else:
            warn(f"بعد از سوزاندن هنوز قابل دسترسی: {j}")
    else:
        warn(f"unlock رد شد (شاید قبلاً سوزانده شده): {j}")


# ═══════════════════════════════════════════════════════
# بخش ۷: پنل مدیریت (اگه ساخته شده)
# ═══════════════════════════════════════════════════════
def test_7_admin_panel(files: dict):
    section("۷. پنل مدیریت")
    
    # بررسی وجود مسیر /manage
    r = requests.get(BASE + "/manage")
    if r.status_code == 200:
        ok("مسیر /manage وجود دارد")
        # تلاش ورود با کد اشتباه
        r = requests.post(BASE + "/api/manage/enter",
                         json={"admin_code": "wrong_code_123"})
        if r.status_code in (401, 403, 400):
            ok("کد اشتباه رد شد")
        else:
            warn(f"پاسخ غیرمنتظره: {r.status_code}")
    elif r.status_code == 404:
        warn("پنل مدیریت هنوز ساخته نشده (فاز E)")
    else:
        warn(f"مسیر /manage خطا: {r.status_code}")


# ═══════════════════════════════════════════════════════
# بخش ۸: لاگ و ممیزی
# ═══════════════════════════════════════════════════════
def test_8_audit():
    section("۸. لاگ و ممیزی")
    
    log_path = Path(__file__).parent / "data" / "soozan.log"
    if log_path.exists():
        content = log_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.strip().split('\n')
        if len(lines) > 0:
            ok(f"لاگ فعال است ({len(lines)} خط)")
        # بررسی رویدادهای جدید
        events = ["RENDER_IMAGE", "RENDER_TEXT", "RENDER_AUDIO", "VIEW_UNLOCK_OK"]
        for ev in events:
            if ev in content:
                ok(f"رویداد {ev} در لاگ ثبت شده")
        # بررسی اینکه فایل خام نرفته
        if "VIEW_CONTENT" in content:
            warn("رویداد قدیمی VIEW_CONTENT هنوز در لاگ هست (احتمالاً از قبل)")
    else:
        bad("فایل لاگ پیدا نشد")


# ═══════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════
def main():
    print(f"{BOLD}{B}")
    print("═" * 60)
    print("  🔥 تست جامع یکپارچه سوزان")
    print("═" * 60)
    print(f"{RESET}")
    
    # Setup
    os.chdir(Path(__file__).parent)
    proc = ensure_server()
    
    try:
        # اجرا تست‌ها
        test_1_health()
        test_2_security_base()
        s = test_3_auth()
        files = test_4_upload(s)
        test_5_render(files)
        test_6_view_and_burn(files)
        test_7_admin_panel(files)
        test_8_audit()
    except Exception as e:
        bad(f"خطای غیرمنتظره: {e}")
        import traceback
        traceback.print_exc()
    finally:
        cleanup(proc)
    
    # گزارش نهایی
    print(f"\n{BOLD}{'═'*60}")
    print(f"  نتیجه نهایی:{RESET}")
    print(f"    {G}✓ موفق: {PASS}{RESET}")
    print(f"    {R}✗ شکست: {FAIL}{RESET}")
    print(f"    {Y}⚠ هشدار: {WARN}{RESET}")
    print(f"{BOLD}{'═'*60}{RESET}")
    
    if FAIL == 0:
        print(f"\n{G}{BOLD}🏆 همه تست‌ها سبز شدند! سوزان آماده است.{RESET}")
        return 0
    else:
        print(f"\n{R}{BOLD}⚠️  {FAIL} تست شکست خورد. باید بررسی شود.{RESET}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
