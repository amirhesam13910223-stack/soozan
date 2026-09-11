#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
تست‌های فاز A — امنیت پایه
- بخش ۲: session key ≠ KEK + کش + invalidation
- بخش ۳: هش رمز + constant-time
- بخش ۴: Secure cookie در non-DEV
- بخش ۷: رفع باگ تکرار خط
- یکپارچگی wizard + viewer
"""
from __future__ import annotations
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

PASS = 0
FAIL = 0


def check(cond: bool, msg: str) -> None:
    global PASS, FAIL
    if cond:
        print(f"  ✓ {msg}")
        PASS += 1
    else:
        print(f"  ✗ {msg}")
        FAIL += 1


def section(title: str) -> None:
    print(f"\n── {title} ──")


def main() -> int:
    # ─── بخش ۲: جداسازی کلید session ───
    section("۱. جداسازی کلید session")
    from core import MasterKeyManager
    mk = MasterKeyManager.instance()
    kek = mk._kek
    sk = mk.session_key()
    check(kek != sk, "session_key با KEK خام متفاوت است")
    check(len(sk) == 32, "session_key طول ۳۲ بایت دارد")
    check(len(kek) == 32, "KEK طول ۳۲ بایت دارد")
    # کش
    sk2 = mk.session_key()
    check(sk is sk2, "session_key کش می‌شود (همان شیء)")
    # چرخش: cache باید invalidate شود
    old_kek = mk._kek
    old_sk = sk
    mk._kek = os.urandom(32)
    try:
        mk.rotate_master([])
    except Exception:
        pass  # ممکن است wrapped_deks خالی باشد، فقط کش مهم است
    new_sk = mk.session_key()
    check(new_sk != old_sk, "بعد از چرخش، session_key تغییر می‌کند")
    # بازگرداندن
    mk._kek = old_kek
    mk._session_key_cache = None
    mk._session_key_kek = None

    # ─── بخش ۳: هش رمز + constant-time ───
    section("۲. هش رمز فایل")
    from core import hash_file_password, verify_file_password
    pw = "TestPassword123!"
    h = hash_file_password(pw)
    check(h.startswith("scrypt$"), "فرمت: scrypt$salt$hash")
    parts = h.split("$")
    check(len(parts) == 3, "ساختار سه‌بخشی")
    check(len(parts[1]) == 32, "salt ۱۶ بایت (hex)")
    check(len(parts[2]) == 64, "hash ۳۲ بایت (hex)")
    check(verify_file_password(pw, h), "رمز صحیح تأیید می‌شود")
    check(not verify_file_password("wrong", h), "رمز غلط رد می‌شود")
    check(not verify_file_password("", h), "رمز خالی رد می‌شود")
    check(not verify_file_password(pw, ""), "stored خالی رد می‌شود")
    check(not verify_file_password(pw, "plaintext"), "فرمت قدیمی plaintext رد می‌شود")
    check(not verify_file_password(pw, "scrypt$xx$yy"), "فرمت بد رد می‌شود")
    # salt منحصر به فرد
    h2 = hash_file_password(pw)
    check(h != h2, "salt منحصر به فرد در هر هش")
    # constant-time: زمان پاسخ باید تقریباً ثابت باشد
    def time_verify(pw_try: str, stored: str) -> float:
        t = time.perf_counter()
        for _ in range(500):
            verify_file_password(pw_try, stored)
        return time.perf_counter() - t
    t1 = time_verify(pw, h)
    t2 = time_verify("wrong_password_xxxxxxxxxxxxxxxxx", h)
    if min(t1, t2) > 0:
        ratio = max(t1, t2) / min(t1, t2)
        check(ratio < 2.0, f"زمان پاسخ نسبتاً ثابت (ratio={ratio:.2f})")

    # ─── بخش ۴: Secure cookie ───
    section("۳. Secure cookie")
    os.environ.pop("SOOZAN_DEV_MODE", None)
    # حذف ماژول app از cache اگر لود شده
    if "app" in sys.modules:
        del sys.modules["app"]
    from app import app
    with app.app_context():
        check(
            app.config["SESSION_COOKIE_SECURE"] is True,
            "در حالت غیر-DEV، cookie Secure=True",
        )
        check(app.config["SESSION_COOKIE_HTTPONLY"] is True, "HttpOnly فعال")
        check(app.config["SESSION_COOKIE_SAMESITE"] == "Strict", "SameSite=Strict")
        check(app.secret_key != mk._kek, "secret_key Flask با KEK متفاوت است")
        check(app.secret_key == mk.session_key(), "secret_key از session_key() مشتق شده")

    # ─── بخش ۷: رفع باگ تکرار خط ───
    section("۴. رفع باگ تکرار خط")
    viewer_src = Path("viewer.py").read_text(encoding="utf-8")
    dup = "st = _settings(row) if row else {}\n    st = _settings(row) if row else {}"
    check(dup not in viewer_src, "خط تکراری st = _settings حذف شده")

    # ─── یکپارچگی wizard + viewer ───
    section("۵. یکپارچگی wizard + viewer")
    from wizard import _parse_settings

    class FakeForm(dict):
        def get(self, k, d=None):  # type: ignore
            return dict.get(self, k, d)

    form = FakeForm({
        "max_views": "1",
        "ip_once": "1",
        "timer_mode": "none",
        "timer_seconds": "30",
        "ttl_days": "7",
        "has_password": "1",
        "password": "MySecret",
        "password_attempts": "5",
    })
    try:
        st = _parse_settings(form)
        pw_hashed = st.get("password")
        check(
            pw_hashed is not None and isinstance(pw_hashed, str)
            and pw_hashed.startswith("scrypt$"),
            "_parse_settings رمز را هش می‌کند",
        )
        check(
            verify_file_password("MySecret", pw_hashed),
            "هش شده با verify سازگار است",
        )
        check(
            not verify_file_password("wrong", pw_hashed),
            "رمز اشتباه رد می‌شود",
        )
    except Exception as e:
        check(False, f"_parse_settings خطا: {e}")

    # ─── گزارش ───
    print("\n" + "=" * 60)
    print(f"  موفق: {PASS}  ·  شکست: {FAIL}")
    print("=" * 60)
    if FAIL == 0:
        print("🏆 همه تست‌های فاز A سبز شدند")
    else:
        print(f"⚠️  {FAIL} تست شکست خورد")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
