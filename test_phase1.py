#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🧪 آزمون جامع فاز ۱ — همه اجزای زیرساخت را تست می‌کند
این اسکریپت را اجرا کنید تا از صحت کامل فاز ۱ مطمئن شوید.
"""

import os
import sys
import time
import tempfile
import requests
import secrets
from pathlib import Path

BASE = Path(__file__).parent
sys.path.insert(0, str(BASE))

BASE_URL = "http://127.0.0.1:8000"

GREEN = "\033[32m"
RED = "\033[31m"
BOLD = "\033[1m"
RESET = "\033[0m"

passed = 0
failed = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  {GREEN}✓{RESET} {msg}")


def bad(msg):
    global failed
    failed += 1
    print(f"  {RED}✗{RESET} {msg}")


def section(title):
    print(f"\n{BOLD}── {title} ──{RESET}")


def check(cond, msg):
    if cond:
        ok(msg)
    else:
        bad(msg)
    return cond


# ───────────────────────────────────────────────────
section("۱. صحت فایل‌های هسته")
# ───────────────────────────────────────────────────
try:
    from core import (bootstrap, init_db, get_db, Auth, Security,
                      FileCrypto, MasterKeyManager, AuditLog,
                      sniff_mime, make_uid, make_admin_code, BASE_DIR, DATA_DIR, FILES_DIR,
                      MASTER_KEY, DB_PATH, LOG_PATH)
    ok("core.py به‌درستی import شد")
except Exception as e:
    bad(f"خطا در import core.py: {e}")
    sys.exit(1)

check(DATA_DIR.exists(), "پوشه data موجود است")
check(FILES_DIR.exists(), "پوشه data/files موجود است")
check((DATA_DIR.stat().st_mode & 0o777) == 0o700, "دسترسی data برابر ۷۰۰ است")

# ───────────────────────────────────────────────────
section("۲. کلید ارشد")
# ───────────────────────────────────────────────────
mk1 = MasterKeyManager.instance()
kek1 = mk1._kek
check(len(kek1) == 32, f"طول کلید ارشد ۳۲ بایت است (={len(kek1)})")
check(MASTER_KEY.exists(), "فایل .master.key موجود است")
check((MASTER_KEY.stat().st_mode & 0o777) == 0o600, "دسترسی کلید ارشد ۶۰۰ است")

mk2 = MasterKeyManager.instance()
check(mk2._kek == kek1, "Singleton بودن MasterKeyManager")

# ───────────────────────────────────────────────────
section("۳. رمزنگاری AES-256-GCM")
# ───────────────────────────────────────────────────
for label, payload in [
    ("خالی", b""),
    ("کوچک", b"Hello Soozan!"),
    ("متوسط", os.urandom(10_000)),
    ("بزرگ", os.urandom(500_000)),
]:
    ct, wrapped_dek = FileCrypto.encrypt_file(payload)
    check(len(wrapped_dek) == 12 + 32 + 16, f"[{label}] طول wrapped DEK صحیح است")
    pt = FileCrypto.decrypt_file(ct, wrapped_dek)
    check(pt == payload, f"[{label}] رمزگشایی دقیقاً برابر اصل است")
    # تست دستکاری (نباید رمزگشایی بشه)
    tampered = bytearray(ct)
    if len(tampered) > 13:
        tampered[15] ^= 0xff
        try:
            FileCrypto.decrypt_file(bytes(tampered), wrapped_dek)
            bad(f"[{label}] دستکاری تشخیص داده نشد!")
        except Exception:
            ok(f"[{label}] دستکاری در ciphertext به‌درستی رد شد")

# ───────────────────────────────────────────────────
section("۴. دیتابیس")
# ───────────────────────────────────────────────────
init_db()
with get_db() as conn:
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()]
expected = {"users", "files", "views", "events", "bans", "active_views"}
check(expected.issubset(set(tables)), f"همه جداول اصلی موجودند: {expected}")

# ───────────────────────────────────────────────────
section("۵. احراز هویت (scrypt)")
# ───────────────────────────────────────────────────
test_user = "testuser80e122" + secrets.token_hex(3)
test_pass = "SecurePass!123"

ok_r, msg = Auth.register(test_user, test_pass)
check(ok_r, f"ثبت‌نام: {msg}")

ok_r2, _ = Auth.register(test_user, test_pass)
check(not ok_r2, "ثبت‌نام تکراری رد شد")

ok_l, uid, _ = Auth.login(test_user, test_pass)
check(ok_l and uid is not None, "ورود با رمز صحیح")

ok_l2, _, _ = Auth.login(test_user, "wrong")
check(not ok_l2, "ورود با رمز اشتباه رد شد")

ok_l3, _, _ = Auth.login("ghost", test_pass)
check(not ok_l3, "ورود با کاربر ناموجود رد شد")

ok_c, msg = Auth.change_password(uid, test_pass, "NewPass!456")
check(ok_c, "تغییر رمز")

ok_l4, _, _ = Auth.login(test_user, "NewPass!456")
check(ok_l4, "ورود با رمز جدید")

ok_l5, _, _ = Auth.login(test_user, test_pass)
check(not ok_l5, "ورود با رمز قدیمی رد شد")

# ───────────────────────────────────────────────────
section("۶. شناسایی نوع فایل (magic bytes)")
# ───────────────────────────────────────────────────
samples = [
    (b"\xff\xd8\xff\xe0",                  "fake.jpg", "image/jpeg", "image"),
    (b"\x89PNG\r\n\x1a\n" + b"\x00" * 20, "fake.png", "image/png", "image"),
    (b"%PDF-1.4\n%",                        "fake.pdf", "application/pdf", "pdf"),
    (b"ID3\x04\x00\x00\x00",               "fake.mp3", "audio/mpeg", "audio"),
    (b"fLaC\x00\x00\x00\x22",              "fake.flac", "audio/flac", "audio"),
    (b"#!/usr/bin/env python\nprint('hi')", "test.py", "text/x-python", "text"),
    (b"def foo():\n    pass\n",             "x.py", "text/x-python", "text"),
]
for data, fn, expect_mime, expect_family in samples:
    mime, fam = sniff_mime(data, fn)
    check(mime == expect_mime, f"[{fn}] mime = {mime}")
    check(fam == expect_family, f"[{fn}] family = {fam}")

# ───────────────────────────────────────────────────
section("۷. تولید آیدی و کد مدیریت")
# ───────────────────────────────────────────────────
ids = {make_uid() for _ in range(1000)}
check(len(ids) == 1000, "۱۰۰۰ آیدی منحصر به فرد تولید شد")
check(all(len(u) == 64 for u in ids), "همه آیدی‌ها ۶۴ کاراکتر هستند")
codes = {make_admin_code() for _ in range(500)}
check(len(codes) == 500, "۵۰۰ کد مدیریت منحصر به فرد")

# ───────────────────────────────────────────────────
section("۸. امنیت (محدودیت نرخ + بن)")
# ───────────────────────────────────────────────────
fake_ip = "10.99.99.99"
Security.rate_check(fake_ip, "login")  # پاک‌سازی state قبلی
Security._rate_buckets.pop((fake_ip, "login"), None)
Security._violation_count.pop(fake_ip, None)
for i in range(5):
    Security.rate_check(fake_ip, "login")
check(Security.rate_check(fake_ip, "login") == False, "محدودیت نرخ login کار کرد")
Security._rate_buckets.pop((fake_ip, "login"), None)
# تست بن با ۱۰ تخلف
fake_ip2 = "10.88.88.88"
for i in range(10):
    Security.violation(fake_ip2, "test")
check(Security.is_banned(fake_ip2), "آی‌پی بعد از ۱۰ تخلف بن شد")

# ───────────────────────────────────────────────────
section("۹. امحای امن")
# ───────────────────────────────────────────────────
with tempfile.NamedTemporaryFile(delete=False) as tf:
    tf.write(os.urandom(1024))
    p = Path(tf.name)
check(p.exists(), "فایل تست ساخته شد")
check(FileCrypto.secure_delete(p), "امحای امن موفق بود")
check(not p.exists(), "فایل واقعاً حذف شد")

# ───────────────────────────────────────────────────
section("۱۰. ارتباط با سرور (اگر در حال اجرا باشد)")
# ───────────────────────────────────────────────────
try:
    r = requests.get(f"{BASE_URL}/health", timeout=2)
    if r.status_code == 200:
        ok(f"سرور در {BASE_URL} پاسخ می‌دهد")
        j = r.json()
        check(j.get("phase") == 1, "فاز سرور = ۱")

        # تست register
        un = "httptest_" + secrets.token_hex(3)
        r = requests.post(f"{BASE_URL}/api/register",
                          json={"username": un, "password": "Test1234!"})
        check(r.status_code == 200 and r.json().get("ok"), "ثبت‌نام از طریق API")

        # تست login با session
        s = requests.Session()
        r = s.post(f"{BASE_URL}/api/login",
                   json={"username": un, "password": "Test1234!"})
        check(r.json().get("ok"), "ورود از طریق API")

        # تست /api/me
        r = s.get(f"{BASE_URL}/api/me")
        check(r.json().get("user", {}).get("username") == un, "/api/me کاربر را برمی‌گرداند")

        # تست آمار
        r = s.get(f"{BASE_URL}/api/test/stats")
        check(r.json().get("ok") and r.json().get("users") >= 1, "آمار درست است")

        # تست رمزنگاری از طریق API
        r = s.post(f"{BASE_URL}/api/test/crypto", data="سلام سوزان!".encode("utf-8"))
        j = r.json()
        check(j.get("roundtrip") is True, "Roundtrip رمزنگاری از طریق API")

        # آپلود یک فایل واقعی
        sample_png = b"\x89PNG\r\n\x1a\n" + os.urandom(1000)
        r = s.post(f"{BASE_URL}/api/test/upload",
                   files={"file": ("test.png", sample_png, "image/png")})
        j = r.json()
        check(j.get("ok") and j.get("family") == "image", "آپلود عکس تستی")
        uid = j.get("uid")

        # verify
        r = s.get(f"{BASE_URL}/api/test/verify/{uid}")
        j = r.json()
        check(j.get("ok") and j.get("decrypted_size") == len(sample_png),
              "رمزگشایی از طریق API")
    else:
        bad(f"سرور پاسخ نادرست داد: {r.status_code}")
except requests.exceptions.ConnectionError:
    bad(f"سرور در {BASE_URL} در دسترس نیست — آن را اجرا کنید")
except Exception as e:
    bad(f"خطا در ارتباط با سرور: {e}")

# ───────────────────────────────────────────────────
print(f"\n{BOLD}{'═'*50}{RESET}")
print(f"  {GREEN}موفق: {passed}{RESET}  ·  {RED}شکست: {failed}{RESET}")
print(f"{'═'*50}")
sys.exit(0 if failed == 0 else 1)
