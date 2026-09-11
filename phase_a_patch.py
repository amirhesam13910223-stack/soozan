#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
فاز A — اعمال پچ‌های امنیتی روی کد سوزان
- بخش ۲: جداسازی کلید session (HKDF + کش + invalidation)
- بخش ۳: هش رمز فایل + constant-time verify
- بخش ۴: Secure cookie + DEV_MODE flag
- بخش ۷: رفع باگ تکرار خط
"""
from __future__ import annotations
import sys
from pathlib import Path
from typing import List, Tuple

REPORT: List[str] = []

def ok(msg: str) -> None:
    REPORT.append(f"✅ {msg}")

def info(msg: str) -> None:
    REPORT.append(f"ℹ️  {msg}")

def fail(msg: str) -> None:
    REPORT.append(f"❌ {msg}")
    print_report()
    sys.exit(1)

def print_report() -> None:
    print("\n" + "=" * 60)
    print("🎯 گزارش اعمال فاز A")
    print("=" * 60)
    for r in REPORT:
        print(r)
    print("=" * 60)


# ═══════════════════════════════════════════════════════
# ۱) core.py
# ═══════════════════════════════════════════════════════
def patch_core() -> None:
    p = Path("core.py")
    if not p.exists():
        fail("core.py پیدا نشد")
    s = p.read_text(encoding="utf-8")
    original = s

    # ── ۱.۱) اضافه کردن imports لازم ──
    import_block = "\n".join([
        "from typing import Optional",
        "from cryptography.hazmat.primitives.kdf.hkdf import HKDF",
        "from cryptography.hazmat.primitives import hashes",
        "import hashlib",
        "import hmac",
    ])
    missing_imports = [
        line for line in import_block.split("\n")
        if line.strip() and line.strip() not in s
    ]
    if missing_imports:
        marker = "import threading"
        if marker not in s:
            # fallback: ابتدای فایل
            s = "\n".join(missing_imports) + "\n" + s
        else:
            s = s.replace(marker, marker + "\n" + "\n".join(missing_imports), 1)
        ok("import های HKDF/hmac/hashlib/typing اضافه شد")

    # ── ۱.۲) cache attrs در __init__ MasterKeyManager ──
    old_init = "    def __init__(self):\n        self._kek = self._load_or_create()"
    new_init = (
        "    def __init__(self):\n"
        "        self._kek = self._load_or_create()\n"
        "        # کش کلید session (جلوگیری از محاسبه مجدد در هر درخواست)\n"
        "        self._session_key_cache: Optional[bytes] = None\n"
        "        self._session_key_kek: Optional[bytes] = None"
    )
    if old_init in s and new_init not in s:
        s = s.replace(old_init, new_init, 1)
        ok("cache attrs به __init__ MasterKeyManager اضافه شد")
    elif new_init in s:
        info("cache attrs از قبل موجود بود")

    # ── ۱.۳) invalidation در rotate_master ──
    rotate_old = (
        "    def rotate_master(self, wrapped_deks: list):\n"
        "        \"\"\"چرخش کلید ارشد با حفظ قابلیت رمزگشایی فایل‌های قدیمی\"\"\"\n"
        "        new_kek = os.urandom(32)"
    )
    rotate_new = (
        "    def rotate_master(self, wrapped_deks: list):\n"
        "        \"\"\"چرخش کلید ارشد با حفظ قابلیت رمزگشایی فایل‌های قدیمی\"\"\"\n"
        "        new_kek = os.urandom(32)\n"
        "        # ابطال کش session key: سشن‌های فعال invalid می‌شوند (نه crash)\n"
        "        self._session_key_cache = None\n"
        "        self._session_key_kek = None"
    )
    if rotate_old in s and rotate_new not in s:
        s = s.replace(rotate_old, rotate_new, 1)
        ok("cache invalidation در rotate_master اضافه شد")
    elif rotate_new in s:
        info("rotate_master از قبل patched بود")

    # ── ۱.۴) متد session_key (داخل کلاس MasterKeyManager) ──
    session_key_method = '''
    def session_key(self) -> bytes:
        """
        کلید مستقل برای امضای session cookies — مشتق از KEK با HKDF.
        اصل جداسازی کلیدها: هرگز از KEK خام برای session استفاده نمی‌شود.
        کش برای جلوگیری از محاسبه مجدد در هر درخواست.
        """
        if self._session_key_cache is None or self._session_key_kek != self._kek:
            self._session_key_cache = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"soozan-session-salt-v1",
                info=b"soozan-session-key-v1",
            ).derive(self._kek)
            self._session_key_kek = self._kek
        return self._session_key_cache

'''
    class_file_crypto = "\nclass FileCrypto:"
    if "def session_key" in s:
        info("متد session_key از قبل موجود بود")
    elif class_file_crypto not in s:
        fail("class FileCrypto در core.py پیدا نشد")
    else:
        s = s.replace(class_file_crypto, session_key_method + class_file_crypto, 1)
        ok("متد session_key به MasterKeyManager اضافه شد")

    # ── ۱.۵) توابع hash_file_password و verify_file_password ──
    pw_funcs = '''

# ──── هش رمز فایل (بخش ۳ فاز A) ───────────────────────────
# فرمت ذخیره: "scrypt$<salt_hex>$<hash_hex>"
# پارامترهای سبک برای UX real-time (n=8192 ≈ ۵ms در CPU مدرن)

def hash_file_password(pw: str, salt: bytes = None) -> str:
    """هش رمز فایل با scrypt (پارامترهای سبک‌تر از رمز کاربر)"""
    if not pw:
        raise ValueError("رمز خالی مجاز نیست")
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.scrypt(
        pw.encode("utf-8"),
        salt=salt,
        n=8192, r=8, p=1, dklen=32,
    )
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_file_password(pw: str, stored: str) -> bool:
    """
    مقایسه constant-time رمز با هش ذخیره‌شده.
    فرمت قدیمی (plaintext) را رد می‌کند (نیاز به migration).
    """
    if not stored or not pw:
        return False
    if not stored.startswith("scrypt$"):
        # فرمت قدیمی — فقط migration می‌تواند استفاده کند
        return False
    parts = stored.split("$")
    if len(parts) != 3:
        return False
    try:
        salt = bytes.fromhex(parts[1])
        expected = bytes.fromhex(parts[2])
    except ValueError:
        return False
    try:
        dk = hashlib.scrypt(
            pw.encode("utf-8"),
            salt=salt,
            n=8192, r=8, p=1, dklen=32,
        )
    except Exception:
        return False
    return hmac.compare_digest(dk, expected)

'''
    if "def hash_file_password" in s:
        info("توابع هش رمز از قبل موجود بودند")
    else:
        if "def bootstrap" in s:
            s = s.replace("\ndef bootstrap", pw_funcs + "\ndef bootstrap", 1)
        else:
            s += pw_funcs
        ok("توابع hash_file_password و verify_file_password اضافه شد")

    if s != original:
        p.write_text(s, encoding="utf-8")
        ok("core.py با موفقیت نوشته شد")


# ═══════════════════════════════════════════════════════
# ۲) app.py
# ═══════════════════════════════════════════════════════
def patch_app() -> None:
    p = Path("app.py")
    if not p.exists():
        fail("app.py پیدا نشد")
    s = p.read_text(encoding="utf-8")
    original = s

    # ── ۲.۱) import os ──
    if "import os" not in s:
        s = s.replace("import sys", "import sys\nimport os", 1)

    # ── ۲.۲) secret_key با session_key() ──
    old_sk = "app.secret_key = MasterKeyManager.instance()._kek"
    new_sk = "app.secret_key = MasterKeyManager.instance().session_key()"
    if old_sk in s:
        s = s.replace(old_sk, new_sk, 1)
        ok("secret_key از session_key() مشتق می‌شود")
    elif new_sk in s:
        info("secret_key از قبل patched بود")
    else:
        fail("الگوی secret_key در app.py پیدا نشد")

    # ── ۲.۳) DEV_MODE + SESSION_COOKIE_SECURE ──
    dev_block = "\n# ── حالت توسعه (فقط تست محلی، بدون HTTPS) ──\nDEV_MODE = os.environ.get(\"SOOZAN_DEV_MODE\", \"0\") == \"1\"\n"
    if "DEV_MODE" not in s:
        marker = "app.config.update("
        if marker not in s:
            fail("app.config.update در app.py پیدا نشد")
        s = s.replace(marker, dev_block + "\n" + marker, 1)

    old_cfg = (
        "app.config.update(\n"
        "    SESSION_COOKIE_HTTPONLY=True,\n"
        "    SESSION_COOKIE_SAMESITE=\"Strict\",\n"
        "    SESSION_COOKIE_NAME=\"soozan_sid\",\n"
        ")"
    )
    new_cfg = (
        "app.config.update(\n"
        "    SESSION_COOKIE_HTTPONLY=True,\n"
        "    SESSION_COOKIE_SAMESITE=\"Strict\",\n"
        "    SESSION_COOKIE_NAME=\"soozan_sid\",\n"
        "    SESSION_COOKIE_SECURE=not DEV_MODE,\n"
        ")"
    )
    if old_cfg in s and new_cfg not in s:
        s = s.replace(old_cfg, new_cfg, 1)
        ok("SESSION_COOKIE_SECURE بر اساس DEV_MODE تنظیم شد")
    elif new_cfg in s:
        info("SESSION_COOKIE_SECURE از قبل موجود بود")

    # ── ۲.۴) هشدار DEV_MODE در بنر استارت ──
    old_banner = (
        "    print(\"=\" * 56)\n"
        "    print(\"  🔥 سوزان — فاز ۲ (ویزارد آپلود)\")"
    )
    new_banner = (
        "    if DEV_MODE:\n"
        "        print(\"!\" * 56)\n"
        "        print(\"  ⚠️  DEV_MODE فعال است — cookie ها Secure نیستند!\")\n"
        "        print(\"  ⚠️  فقط برای تست محلی استفاده شود\")\n"
        "        print(\"!\" * 56)\n"
        "    print(\"=\" * 56)\n"
        "    print(\"  🔥 سوزان — فاز ۲ (ویزارد آپلود)\")"
    )
    if old_banner in s and "DEV_MODE فعال است" not in s:
        s = s.replace(old_banner, new_banner, 1)
        ok("هشدار DEV_MODE به بنر استارت اضافه شد")

    if s != original:
        p.write_text(s, encoding="utf-8")
        ok("app.py با موفقیت نوشته شد")


# ═══════════════════════════════════════════════════════
# ۳) wizard.py
# ═══════════════════════════════════════════════════════
def patch_wizard() -> None:
    p = Path("wizard.py")
    if not p.exists():
        fail("wizard.py پیدا نشد")
    s = p.read_text(encoding="utf-8")
    original = s

    # ── ۳.۱) import hash_file_password ──
    if "hash_file_password" not in s:
        lines = s.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("from core import"):
                if "hash_file_password" not in line:
                    lines[i] = line.rstrip().rstrip(",") + ", hash_file_password"
                break
        s = "\n".join(lines)
        ok("hash_file_password به wizard.py ایمپورت شد")
    else:
        info("hash_file_password از قبل ایمپورت بود")

    # ── ۳.۲) هش کردن رمز در _parse_settings ──
    old_pw = (
        "    # رمز\n"
        "    if form.get(\"has_password\") == \"1\":\n"
        "        pw = (form.get(\"password\") or \"\").strip()\n"
        "        if len(pw) < 4:\n"
        "            raise ValueError(\"رمز باید حداقل ۴ کاراکتر باشد\")\n"
        "        settings[\"password\"] = pw"
    )
    new_pw = (
        "    # رمز (هش شده با scrypt — plaintext ذخیره نمی‌شود)\n"
        "    if form.get(\"has_password\") == \"1\":\n"
        "        pw = (form.get(\"password\") or \"\").strip()\n"
        "        if len(pw) < 4:\n"
        "            raise ValueError(\"رمز باید حداقل ۴ کاراکتر باشد\")\n"
        "        settings[\"password\"] = hash_file_password(pw)"
    )
    if old_pw in s:
        s = s.replace(old_pw, new_pw, 1)
        ok("رمز فایل در wizard.py حالا هش می‌شود")
    elif new_pw in s:
        info("wizard.py از قبل patched بود")
    else:
        fail("الگوی ذخیره password در wizard.py پیدا نشد")

    if s != original:
        p.write_text(s, encoding="utf-8")
        ok("wizard.py با موفقیت نوشته شد")


# ═══════════════════════════════════════════════════════
# ۴) viewer.py
# ═══════════════════════════════════════════════════════
def patch_viewer() -> None:
    p = Path("viewer.py")
    if not p.exists():
        fail("viewer.py پیدا نشد")
    s = p.read_text(encoding="utf-8")
    original = s

    # ── ۴.۱) import verify_file_password ──
    if "verify_file_password" not in s:
        lines = s.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("from core import"):
                if "verify_file_password" not in line:
                    lines[i] = line.rstrip().rstrip(",") + ", verify_file_password"
                break
        s = "\n".join(lines)
        ok("verify_file_password به viewer.py ایمپورت شد")
    else:
        info("verify_file_password از قبل ایمپورت بود")

    # ── ۴.۲) constant-time verify در unlock ──
    old_unlock = (
        "    st = _settings(row)\n"
        "    pw_needed = st.get(\"password\")\n"
        "    if pw_needed:\n"
        "        given = (request.get_json(silent=True) or {}).get(\"password\", \"\")\n"
        "        if given != pw_needed:\n"
        "            wrong = (row[\"wrong_pins\"] or 0) + 1"
    )
    new_unlock = (
        "    st = _settings(row)\n"
        "    pw_needed = st.get(\"password\")\n"
        "    if pw_needed:\n"
        "        given = (request.get_json(silent=True) or {}).get(\"password\", \"\")\n"
        "        # مقایسه constant-time — جلوگیری از timing attacks\n"
        "        if not verify_file_password(given, pw_needed):\n"
        "            wrong = (row[\"wrong_pins\"] or 0) + 1"
    )
    if old_unlock in s:
        s = s.replace(old_unlock, new_unlock, 1)
        ok("unlock در viewer.py حالا constant-time است")
    elif new_unlock in s:
        info("viewer.py از قبل patched بود")
    else:
        fail("الگوی مقایسه رمز در viewer.py پیدا نشد")

    # ── ۴.۳) رفع باگ تکرار خط ──
    dup_old = "    st = _settings(row) if row else {}\n    st = _settings(row) if row else {}\n"
    dup_new = "    st = _settings(row) if row else {}\n"
    if dup_old in s:
        count = s.count(dup_old)
        s = s.replace(dup_old, dup_new)
        ok(f"باگ تکرار خط رفع شد ({count} مورد)")
    else:
        info("باگ تکرار خط وجود نداشت (یا از قبل رفع شده بود)")

    if s != original:
        p.write_text(s, encoding="utf-8")
        ok("viewer.py با موفقیت نوشته شد")


# ═══════════════════════════════════════════════════════
# main
# ═══════════════════════════════════════════════════════
def main() -> None:
    import os
    os.chdir(Path(__file__).parent)
    print("🔧 شروع اعمال پچ‌های فاز A...")
    patch_core()
    patch_app()
    patch_wizard()
    patch_viewer()
    print_report()
    if any(r.startswith("❌") for r in REPORT):
        sys.exit(1)
    print("\n✅ همه پچ‌های کد با موفقیت اعمال شدند")
    print("مرحله بعدی: migration رمزهای plaintext موجود")


if __name__ == "__main__":
    main()
