#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🧪 آزمون فاز ۲ — ویزارد و داشبورد
"""

import sys
import time
import secrets
import requests
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"
GREEN = "\033[32m"; RED = "\033[31m"; BOLD = "\033[1m"; RESET = "\033[0m"

passed = failed = 0
def ok(m): global passed; passed += 1; print(f"  {GREEN}✓{RESET} {m}")
def bad(m): global failed; failed += 1; print(f"  {RED}✗{RESET} {m}")
def check(c, m):
    if c: ok(m)
    else: bad(m)
def section(t): print(f"\n{BOLD}── {t} ──{RESET}")

try:
    r = requests.get(f"{BASE_URL}/health", timeout=2)
    r.raise_for_status()
except:
    bad(f"سرور در دسترس نیست. ابتدا bash run.sh را اجرا کنید")
    sys.exit(1)

# ─── تست ۱: صفحات HTML ───
section("۱. صفحات HTML")
r = requests.get(f"{BASE_URL}/login")
check(r.status_code == 200, "/login پاسخ ۲۰۰")
check("ورود" in r.text or "login" in r.text, "صفحه ورود شامل کلمه «ورود»")
check("Vazirmatn" in r.text, "فونت وزیرمتن لود شده")

r = requests.get(f"{BASE_URL}/register")
check(r.status_code == 200, "/register پاسخ ۲۰۰")
check("ثبت‌نام" in r.text, "صفحه شامل «ثبت‌نام»")

# ─── تست ۲: محافظت از مسیرها ───
section("۲. محافظت از مسیرها")
r = requests.get(f"{BASE_URL}/dashboard", allow_redirects=False)
check(r.status_code == 302, "داشبورد بدون ورود ریدایرکت می‌شود")

r = requests.get(f"{BASE_URL}/wizard", allow_redirects=False)
check(r.status_code == 302, "ویزارد بدون ورود ریدایرکت می‌شود")

# ─── تست ۳: ثبت‌نام و ورود ───
section("۳. ثبت‌نام و ورود")
un = "phase2_80e122" + secrets.token_hex(3)
pw = "Test1234!Xyz"

s = requests.Session()
r = s.post(f"{BASE_URL}/register", data={"username": un, "password": pw})
check(r.status_code == 200, "ثبت‌نام از طریق فرم")
check("موفق" in r.text, "پیام موفقیت نمایش داده شد")

r = s.post(f"{BASE_URL}/login", data={"username": un, "password": pw},
           allow_redirects=False)
check(r.status_code == 302, "ورود موفق ریدایرکت می‌دهد")

r = s.get(f"{BASE_URL}/dashboard")
check(r.status_code == 200 and un in r.text, f"داشبورد با نام کاربری {un} بارگذاری شد")

r = s.get(f"{BASE_URL}/wizard")
check(r.status_code == 200, "ویزارد پس از ورود بارگذاری می‌شود")

# ─── تست ۴: آپلود فایل ───
section("۴. آپلود فایل")
sample_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 2000
r = s.post(f"{BASE_URL}/api/upload", files={"file": ("test.png", sample_png, "image/png")})
check(r.status_code == 200, "آپلود عکس تستی")
j = r.json()
check(j.get("ok") is True, "پاسخ ok=true")
check(len(j.get("uid", "")) == 64, f"آیدی ۶۴ کاراکتری (={len(j.get('uid', ''))})")
check(len(j.get("admin_code", "")) > 20, "کد مدیریت معتبر")
uid = j["uid"]

# تست آپلود با تنظیمات کامل
data = {
    "max_views": "5",
    "ip_once": "1",
    "timer_mode": "on_reveal",
    "timer_seconds": "60",
    "ttl_days": "7",
    "has_password": "1",
    "password": "Test@1234",
    "password_attempts": "3",
    "on_password_fail": "burn",
    "intro_message": "این یک سند تست است",
    "end_message": "سند پایان یافت",
    "image_zoom": "1",
    "image_rotate": "1",
    "image_pan": "1",
    "pdf_zoom": "1",
    "text_copy": "0",
    "audio_seek": "1",
    "watermark": "محرمانه",
    "auto_burn_violation": "1",
    "private_note": "تست فاز ۲",
}
sample_pdf = b"%PDF-1.4\n%" + b"\x00" * 500
r = s.post(f"{BASE_URL}/api/upload",
           files={"file": ("doc.pdf", sample_pdf, "application/pdf")},
           data=data)
check(r.status_code == 200, "آپلود PDF با تنظیمات کامل")
j2 = r.json()
check(j2.get("ok") and j2.get("family") == "pdf", "نوع فایل PDF تشخیص داده شد")

# ─── تست ۵: داشبورد با فایل‌ها ───
section("۵. داشبورد با فایل‌ها")
r = s.get(f"{BASE_URL}/dashboard")
check(r.status_code == 200, "داشبورد بارگذاری می‌شود")
check("test.png" in r.text, "نام فایل در داشبورد دیده می‌شود")
check("doc.pdf" in r.text, "فایل PDF هم نمایش داده می‌شود")
# آمار
check("۲" in r.text or "2" in r.text, "آمار تعداد فایل‌ها درست است")

# ─── تست ۶: اعتبارسنجی ───
section("۶. اعتبارسنجی")
# رمز کوتاه
r = s.post(f"{BASE_URL}/api/upload",
           files={"file": ("x.png", sample_png, "image/png")},
           data={"has_password": "1", "password": "ab"})
check(not r.json().get("ok"), "رمز کوتاه رد شد")

# فایل غیرمجاز
r = s.post(f"{BASE_URL}/api/upload",
           files={"file": ("hack.exe", b"\x00\x00\x00\x00", "application/octet-stream")})
check(not r.json().get("ok"), "فایل غیرمجاز رد شد")

# ─── تست ۷: هدرهای امنیتی ───
section("۷. هدرهای امنیتی")
r = s.get(f"{BASE_URL}/dashboard")
check("Content-Security-Policy" in r.headers, "CSP موجود است")
check("nosniff" in r.headers.get("X-Content-Type-Options", ""), "X-Content-Type-Options")
check("DENY" in r.headers.get("X-Frame-Options", ""), "X-Frame-Options")
check("nonce-" in r.headers.get("Content-Security-Policy", ""), "CSP شامل nonce است")

# ─── پایان ───
print(f"\n{'═'*50}")
print(f"  {GREEN}موفق: {passed}{RESET}  ·  {RED}شکست: {failed}{RESET}")
print(f"{'═'*50}")
sys.exit(0 if failed == 0 else 1)
