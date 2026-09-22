import re
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔐 هسته‌ی سوزان — زیرساخت امنیتی و زیربنایی
رمزنگاری AES-256-GCM پاکتی · SQLite · scrypt · محدودیت نرخ · بن · لاگ
"""

import os
import io
import time
import json
import hmac
import sqlite3
import hashlib
import secrets
import threading
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pathlib import Path
from datetime import datetime
from flask import request
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import totp


# ═══════════════════════════════════════════════════════════════
#  پیکربندی
# ═══════════════════════════════════════════════════════════════

BASE_DIR   = Path(__file__).parent
DATA_DIR   = BASE_DIR / "data"
FILES_DIR  = DATA_DIR / "files"
DB_PATH    = DATA_DIR / "burn.db"
MASTER_KEY = DATA_DIR / ".master.key"
LOG_PATH   = DATA_DIR / "soozan.log"
LOG_RETENTION_DAYS = 180  # الزام قانونی ایران (حداقل ۶ ماه)

# اطمینان از وجود پوشه‌ها با دسترسی امن
DATA_DIR.mkdir(mode=0o700, exist_ok=True)
FILES_DIR.mkdir(mode=0o700, exist_ok=True)


# ═══════════════════════════════════════════════════════════════
#  ۱) لاگ امنیتی
# ═══════════════════════════════════════════════════════════════

class AuditLog:
    """لاگ امنیتی thread-safe با چرخش ساده"""
    MAX_SIZE = 5 * 1024 * 1024  # ۵ مگابایت
    _lock = threading.Lock()

    @classmethod
    def write(cls, event: str, ip: str = "-", detail: str = "", level: str = "INFO"):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = f"[{ts}] {level:5s} | {event:24s} | {ip:<15s} | {detail}\n"
        with cls._lock:
            try:
                if LOG_PATH.exists() and LOG_PATH.stat().st_size > cls.MAX_SIZE:
                    # چرخش: فایل قدیمی رو با پسوند .old ذخیره کن
                    old = LOG_PATH.with_suffix(".log.old")
                    if old.exists(): old.unlink()
                    LOG_PATH.rename(old)
                with open(LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(line)
            except OSError:
                pass

    @classmethod
    def read_last(cls, n: int = 50) -> list:
        if not LOG_PATH.exists():
            return []
        try:
            with open(LOG_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
            return lines[-n:]
        except OSError:
            return []

audit = AuditLog.write


# ═══════════════════════════════════════════════════════════════
#  ۲) موتور رمزنگاری AES-256-GCM پاکتی
# ═══════════════════════════════════════════════════════════════

class MasterKeyManager:
    """
    مدیریت کلید ارشد با الگوی KMS (Key Management System).
    - کلید ارشد: ۲۵۶ بیت، تولید یک‌بار، ذخیره با دسترسی ۶۰۰
    - هر فایل یک کلید تصادفی اختصاصی (DEK) می‌گیرد
    - DEK با کلید ارشد (KEK) رمزنگاری می‌شود و کنار فایل ذخیره می‌گردد
    - رمزگشایی فقط در حافظه، به‌صورت جریان‌دار
    """
    _instance = None
    _lock = threading.Lock()

    @classmethod
    def instance(cls) -> "MasterKeyManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._kek = self._load_or_create()
        # کش کلید session (جلوگیری از محاسبه مجدد در هر درخواست)
        self._session_key_cache: Optional[bytes] = None
        self._session_key_kek: Optional[bytes] = None

    def _load_or_create(self) -> bytes:
        if MASTER_KEY.exists():
            with open(MASTER_KEY, "rb") as f:
                key = f.read()  # بدون strip: بایت whitespace بخشی از کلید خام است
            if len(key) != 32:
                raise RuntimeError("کلید ارشد معتبر نیست")
            return key
        key = os.urandom(32)  # AES-256
        fd = os.open(str(MASTER_KEY), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(key)
        except:
            try: os.close(fd)
            except: pass
            raise
        os.chmod(MASTER_KEY, 0o600)
        audit("MASTER_KEY_CREATED", level="WARN")
        return key

    def wrap_dek(self, dek: bytes) -> bytes:
        """رمزنگاری کلید فایل (DEK) با کلید ارشد (KEK)"""
        aesgcm = AESGCM(self._kek)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, dek, None)
        return nonce + ct

    def unwrap_dek(self, wrapped: bytes) -> bytes:
        """رمزگشایی کلید فایل"""
        if len(wrapped) < 13:
            raise ValueError("کلید پیچیده‌شده نامعتبر است")
        nonce, ct = wrapped[:12], wrapped[12:]
        aesgcm = AESGCM(self._kek)
        return aesgcm.decrypt(nonce, ct, None)

    def rotate_master(self, wrapped_deks: list):
        """
        چرخش کلید ارشد — فقط در صورت لزوم، با رمزگشایی همه DEKها با KEK قدیم
        و رمزنگاری مجدد با KEK جدید.
        """
        audit("MASTER_KEY_ROTATION_START", level="WARN")
        new_kek = os.urandom(32)
        aesgcm_old = AESGCM(self._kek)
        aesgcm_new = AESGCM(new_kek)
        new_wrapped = []
        for w in wrapped_deks:
            nonce, ct = w[:12], w[12:]
            dek = aesgcm_old.decrypt(nonce, ct, None)
            new_nonce = os.urandom(12)
            new_ct = aesgcm_new.encrypt(new_nonce, dek, None)
            new_wrapped.append(new_nonce + new_ct)
        # جایگزینی کلید ارشد
        with open(MASTER_KEY, "wb") as f:
            f.write(new_kek)
        os.chmod(MASTER_KEY, 0o600)
        self._kek = new_kek
        audit("MASTER_KEY_ROTATED", detail=f"{len(new_wrapped)} DEK re-wrapped", level="WARN")
        return new_wrapped


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

    def kek(self) -> bytes:
        """دسترسی عمومی به KEK (برای رمزنگاری خارج از wrap/unwrap)"""
        return self._kek


class FileCrypto:
    """رمزنگاری/رمزگشایی فایل‌ها با AES-256-GCM"""

    @staticmethod
    def encrypt_file(plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        ورودی: داده خام فایل
        خروجی: (ciphertext با nonce و tag چسبیده, wrapped_dek)
        """
        dek = os.urandom(32)
        aesgcm = AESGCM(dek)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        wrapped = MasterKeyManager.instance().wrap_dek(dek)
        return nonce + ct, wrapped

    @staticmethod
    def decrypt_file(ciphertext: bytes, wrapped_dek: bytes) -> bytes:
        """
        ورودی: (ciphertext با nonce, wrapped_dek)
        خروجی: داده خام
        """
        dek = MasterKeyManager.instance().unwrap_dek(wrapped_dek)
        if len(ciphertext) < 13:
            raise ValueError("فایل رمزشده خیلی کوتاه است")
        nonce, ct = ciphertext[:12], ciphertext[12:]
        aesgcm = AESGCM(dek)
        return aesgcm.decrypt(nonce, ct, None)

    @staticmethod
    def secure_delete(path: Path) -> bool:
        """
        امحای امن: بازنویسی با داده تصادفی + fsync + حذف
        با راستی‌آزمایی حذف (مطمئن می‌شیم واقعاً حذف شده)
        """
        if not path.exists():
            return True
        try:
            size = path.stat().st_size
            # بازنویسی ۳ پاس با الگوهای متفاوت
            patterns = [b"\x00", b"\xff", os.urandom(1)]
            for p in patterns:
                with open(path, "r+b") as f:
                    chunk = p * min(65536, max(1, size))
                    while size > 0:
                        f.write(chunk[:size])
                        size -= len(chunk[:size])
                    f.flush()
                    os.fsync(f.fileno())
                size = path.stat().st_size
            path.unlink()
            # راستی‌آزمایی
            exists = path.exists()
            audit("SECURE_DELETE", detail=f"path={path.name} verified={not exists}")
            return not exists
        except OSError as e:
            audit("SECURE_DELETE_FAILED", detail=str(e), level="ERROR")
            return False


# ═══════════════════════════════════════════════════════════════
#  ۳) دیتابیس SQLite (Schema کامل)
# ═══════════════════════════════════════════════════════════════

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT    NOT NULL UNIQUE,
    pw_hash      BLOB    NOT NULL,
    salt         BLOB    NOT NULL,
    created_at   REAL    NOT NULL,
    last_login   REAL,
    disabled     INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

CREATE TABLE IF NOT EXISTS files (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    uid            TEXT    NOT NULL UNIQUE,        -- آیدی ۲۵۶ بیتی (۶۴ کاراکتر)
    owner_id       INTEGER NOT NULL REFERENCES users(id),
    filename       TEXT    NOT NULL,               -- نام اصلی (فقط برای نمایش به سازنده)
    mime           TEXT    NOT NULL,
    file_path      TEXT    NOT NULL,               -- مسیر فایل رمزشده
    dek_wrapped    BLOB    NOT NULL,               -- کلید فایل رمزنگاری‌شده با KEK
    settings       TEXT    NOT NULL DEFAULT '{}',  -- JSON تنظیمات
    admin_code     TEXT    NOT NULL UNIQUE,        -- کد مدیریت محرمانه
    status         TEXT    NOT NULL DEFAULT 'active',  -- active/paused/burned
    created_at     REAL    NOT NULL,
    first_viewed   REAL,                           -- زمان اولین نمایش
    views_count    INTEGER DEFAULT 0,
    expires_at     REAL                            -- زمان انقضای کلی (NULL = بدون)
);
CREATE INDEX IF NOT EXISTS idx_files_uid       ON files(uid);
CREATE INDEX IF NOT EXISTS idx_files_admin     ON files(admin_code);
CREATE INDEX IF NOT EXISTS idx_files_owner     ON files(owner_id);
CREATE INDEX IF NOT EXISTS idx_files_status    ON files(status);

CREATE TABLE IF NOT EXISTS views (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id     INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    ip          TEXT,
    user_agent  TEXT,
    viewed_at   REAL NOT NULL,
    duration    INTEGER,                           -- ثانیه (در پایان ثبت می‌شود)
    device      TEXT
);
CREATE INDEX IF NOT EXISTS idx_views_file ON views(file_id);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,                     -- login/upload/view/burn/...
    target      TEXT,                              -- uid یا username
    details     TEXT,
    ip          TEXT,
    at          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_at ON events(at);

CREATE TABLE IF NOT EXISTS bans (
    ip          TEXT PRIMARY KEY,
    until       REAL NOT NULL,
    reason      TEXT,
    created_at  REAL NOT NULL
);

-- برای نگهداری heartbeat «در حال مشاهده»
CREATE TABLE IF NOT EXISTS active_views (
    file_id     INTEGER PRIMARY KEY,
    user_id     INTEGER,
    started_at  REAL NOT NULL,
    last_ping   REAL NOT NULL
);
"""


def get_db() -> sqlite3.Connection:
    """دریافت اتصال به دیتابیس — هر فراخوانی یک اتصال جدید (thread-safe)"""
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA secure_delete=ON")
    return conn


def init_db():
    """ایجاد جداول در اولین اجرا — idempotent"""
    with get_db() as conn:
        conn.executescript(_SCHEMA)
    audit("DB_INITIALIZED")


# ═══════════════════════════════════════════════════════════════
#  ۴) احراز هویت (scrypt + نشست)
# ═══════════════════════════════════════════════════════════════

class Auth:
    """مدیریت کاربران و احراز هویت"""
    SCRYPT_N = 2**17        # ۱۳۱۰۷۲ — سختی مناسب برای موبایل
    SCRYPT_R = 8
    SCRYPT_P = 1
    SALT_LEN = 16

    @classmethod
    def _hash(cls, password: str, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32,
                     n=cls.SCRYPT_N, r=cls.SCRYPT_R, p=cls.SCRYPT_P,
                     backend=default_backend())
        return kdf.derive(password.encode("utf-8"))

    @classmethod
    def register(cls, username: str, password: str) -> Tuple[bool, str]:
        """ثبت‌نام کاربر جدید. خروجی: (موفقیت, پیام)"""
        username = (username or "").strip()
        if not (3 <= len(username) <= 32):
            return False, "نام کاربری باید بین ۳ تا ۳۲ کاراکتر باشد"
        if not all(c.isalnum() or c in "_-" for c in username):
            return False, "نام کاربری فقط می‌تواند شامل حروف، عدد، - و _ باشد"
        if len(password) < 8:
            return False, "رمز عبور باید حداقل ۸ کاراکتر باشد"

        salt = os.urandom(cls.SALT_LEN)
        pw_hash = cls._hash(password, salt)
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users(username, pw_hash, salt, created_at) VALUES (?,?,?,?)",
                    (username, pw_hash, salt, time.time())
                )
            audit("USER_REGISTER", detail=username)
            return True, "ثبت‌نام موفق"
        except sqlite3.IntegrityError:
            return False, "این نام کاربری قبلاً ثبت شده است"

    @classmethod
    def login(cls, username: str, password: str) -> Tuple[bool, Optional[int], str]:
        """ورود. خروجی: (موفقیت, user_id یا None, پیام)"""
        username = (username or "").strip()
        with get_db() as conn:
            row = conn.execute(
                "SELECT id, pw_hash, salt, disabled FROM users WHERE username=?",
                (username,)
            ).fetchone()
        if row is None:
            # برای جلوگیری از time-based enumeration، یک هش محاسبه کن
            cls._hash(password, os.urandom(cls.SALT_LEN))
            return False, None, "نام کاربری یا رمز اشتباه است"
        if row["disabled"]:
            return False, None, "حساب شما غیرفعال شده است"
        calc = cls._hash(password, row["salt"])
        if not hmac.compare_digest(calc, row["pw_hash"]):
            return False, None, "نام کاربری یا رمز اشتباه است"
        # به‌روزرسانی زمان آخرین ورود
        with get_db() as conn:
            conn.execute("UPDATE users SET last_login=? WHERE id=?", (time.time(), row["id"]))
        audit("LOGIN_OK", detail=username)
        return True, row["id"], "ورود موفق"

    @classmethod
    def change_password(cls, user_id: int, old_pw: str, new_pw: str) -> Tuple[bool, str]:
        if len(new_pw) < 8:
            return False, "رمز جدید باید حداقل ۸ کاراکتر باشد"
        with get_db() as conn:
            row = conn.execute("SELECT pw_hash, salt FROM users WHERE id=?", (user_id,)).fetchone()
            if row is None:
                return False, "کاربر یافت نشد"
            calc = cls._hash(old_pw, row["salt"])
            if not hmac.compare_digest(calc, row["pw_hash"]):
                return False, "رمز فعلی اشتباه است"
            salt = os.urandom(cls.SALT_LEN)
            new_hash = cls._hash(new_pw, salt)
            conn.execute("UPDATE users SET pw_hash=?, salt=? WHERE id=?", (new_hash, salt, user_id))
        audit("PASSWORD_CHANGED", detail=f"user_id={user_id}")
        return True, "رمز عبور تغییر کرد"

    @classmethod
    def get_user(cls, user_id: int) -> Optional[dict]:
        with get_db() as conn:
            row = conn.execute(
                "SELECT id, username, created_at, last_login FROM users WHERE id=?",
                (user_id,)
            ).fetchone()
            return dict(row) if row else None


# ═══════════════════════════════════════════════════════════════
#  ۵) امنیت عملیاتی: محدودیت نرخ + بن + هانی‌پات
# ═══════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════
    # 2FA (TOTP)
    # ═══════════════════════════════════════════════════════
    @classmethod
    def _encrypt_totp_secret(cls, secret_b32: str) -> bytes:
        """رمزنگاری secret با KEK (AES-256-GCM) — nonce 12 بایت + ciphertext"""
        from core import MasterKeyManager
        kek = MasterKeyManager.instance().kek()
        aesgcm = AESGCM(kek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, secret_b32.encode("utf-8"), None)
        return nonce + ciphertext  # 12 + len(ciphertext)

    @classmethod
    def _decrypt_totp_secret(cls, blob: bytes) -> str:
        """رمزگشایی secret با KEK"""
        from core import MasterKeyManager
        kek = MasterKeyManager.instance().kek()
        aesgcm = AESGCM(kek)
        nonce, ciphertext = blob[:12], blob[12:]
        return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

    @classmethod
    def _hash_backup_code(cls, code: str) -> str:
        """هش کد پشتیبان با scrypt (ساده‌تر از پسورد، چون کوتاه است)"""
        salt = os.urandom(8).hex()
        h = hashlib.scrypt(
            code.encode("utf-8"),
            salt=salt.encode("utf-8"),
            n=2**14, r=8, p=1, dklen=32
        ).hex()
        return f"{salt}${h}"

    @classmethod
    def _verify_backup_code(cls, stored: str, code: str) -> bool:
        if "$" not in stored:
            return False
        salt, h = stored.split("$", 1)
        try:
            calc = hashlib.scrypt(
                code.encode("utf-8"),
                salt=salt.encode("utf-8"),
                n=2**14, r=8, p=1, dklen=32
            ).hex()
            import hmac as _hmac
            return _hmac.compare_digest(calc, h)
        except Exception:
            return False

    @classmethod
    def is_totp_enabled(cls, user_id: int) -> bool:
        """آیا 2FA برای این کاربر فعال است؟"""
        with get_db() as conn:
            row = conn.execute(
                "SELECT totp_enabled FROM users WHERE id=?", (user_id,)
            ).fetchone()
            return row is not None and row["totp_enabled"] == 1

    @classmethod
    def setup_totp(cls, user_id: int) -> tuple:
        """
        شروع راه‌اندازی 2FA — secret و backup codes تولید می‌کند
        هنوز active نشده (user باید یک کد TOTP معتبر وارد کند)
        خروجی: (secret_b32, backup_codes_list)
        """
        secret_b32 = totp.generate_secret()
        backup_codes = totp.generate_backup_codes(8)

        # ذخیره موقت در session-like storage (در pending_2fa_setup)
        # برای سادگی، در users به‌صورت temporary ذخیره می‌کنیم
        # بعد از تأیید کد، totp_enabled=1 می‌شود
        
        # فعلاً secret را ذخیره می‌کنیم ولی totp_enabled=0 می‌ماند
        encrypted = cls._encrypt_totp_secret(secret_b32)
        hashed_backups = json.dumps([cls._hash_backup_code(c) for c in backup_codes])
        
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET totp_secret=?, backup_codes=? WHERE id=?",
                (encrypted, hashed_backups, user_id)
            )
        
        audit("TOTP_SETUP_STARTED", detail=f"user_id={user_id}")
        return secret_b32, backup_codes

    @classmethod
    def activate_totp(cls, user_id: int, code: str) -> tuple:
        """
        فعال‌سازی 2FA بعد از دریافت کد معتبر از کاربر
        خروجی: (success, message)
        """
        with get_db() as conn:
            row = conn.execute(
                "SELECT totp_secret, totp_enabled FROM users WHERE id=?",
                (user_id,)
            ).fetchone()
        
        if row is None:
            return False, "کاربر یافت نشد"
        if row["totp_enabled"] == 1:
            return False, "2FA قبلاً فعال است"
        if row["totp_secret"] is None:
            return False, "ابتدا باید setup شود"
        
        try:
            secret_b32 = cls._decrypt_totp_secret(row["totp_secret"])
        except Exception:
            return False, "خطا در رمزگشایی secret"
        
        if not totp.verify_code(secret_b32, code):
            Security.violation(client_ip(), "totp_setup_fail")
            return False, "کد نامعتبر است"
        
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET totp_enabled=1 WHERE id=?", (user_id,)
            )
        
        audit("TOTP_ACTIVATED", detail=f"user_id={user_id}")
        return True, "2FA فعال شد"

    @classmethod
    def verify_totp(cls, user_id: int, code: str) -> tuple:
        """
        بررسی کد TOTP در هنگام ورود
        خروجی: (success, message)
        """
        with get_db() as conn:
            row = conn.execute(
                "SELECT totp_secret, totp_enabled FROM users WHERE id=?",
                (user_id,)
            ).fetchone()
        
        if row is None or row["totp_enabled"] != 1:
            return False, "2FA فعال نیست"
        
        try:
            secret_b32 = cls._decrypt_totp_secret(row["totp_secret"])
        except Exception:
            return False, "خطا در رمزگشایی secret"
        
        if totp.verify_code(secret_b32, code):
            audit("TOTP_VERIFY_OK", detail=f"user_id={user_id}")
            return True, "معتبر"
        
        Security.violation(client_ip(), "totp_verify_fail")
        return False, "کد نامعتبر است"

    @classmethod
    def use_backup_code(cls, user_id: int, code: str) -> tuple:
        """
        استفاده از کد پشتیبان (یک‌بار مصرف)
        خروجی: (success, message)
        """
        with get_db() as conn:
            row = conn.execute(
                "SELECT backup_codes FROM users WHERE id=?", (user_id,)
            ).fetchone()
        
        if row is None or not row["backup_codes"]:
            return False, "کد پشتیبانی موجود نیست"
        
        try:
            hashes = json.loads(row["backup_codes"])
        except Exception:
            return False, "خطا در خواندن کدها"
        
        # پیدا کردن کد معتبر و حذف آن
        for i, stored_hash in enumerate(hashes):
            if cls._verify_backup_code(stored_hash, code):
                hashes.pop(i)  # حذف (یک‌بار مصرف)
                with get_db() as conn:
                    conn.execute(
                        "UPDATE users SET backup_codes=? WHERE id=?",
                        (json.dumps(hashes), user_id)
                    )
                audit("TOTP_BACKUP_USED", detail=f"user_id={user_id}, remaining={len(hashes)}")
                return True, f"معتبر ({len(hashes)} کد پشتیبان باقی‌مانده)"
        
        Security.violation(client_ip(), "totp_backup_fail")
        return False, "کد پشتیبان نامعتبر است"

    @classmethod
    def disable_totp(cls, user_id: int) -> tuple:
        """غیرفعال‌سازی 2FA"""
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET totp_secret=NULL, backup_codes=NULL, totp_enabled=0 WHERE id=?",
                (user_id,)
            )
        audit("TOTP_DISABLED", detail=f"user_id={user_id}")
        return True, "2FA غیرفعال شد"


class Security:
    """لایه‌ی دفاعی درون‌حافظه‌ای با پایداری در SQLite برای بن‌ها"""
    _lock = threading.Lock()
    _rate_buckets: Dict[Tuple[str, str], list] = {}

    # پیکربندی محدودیت‌ها: (حداکثر تلاش, پنجره زمانی ثانیه)
    LIMITS = {
        "login":     (5, 600),
        "register":  (10, 60),
        "upload":    (10, 600),
        "view":      (60, 60),
        "reveal":    (40, 60),
        "admin":     (30, 60),
        "manage_enter":  (5, 300),
        "manage_action": (20, 60),
    }
    BAN_AFTER = 10          # ۱۰ تخلف → بن
    BAN_SECONDS = 30 * 60   # ۳۰ دقیقه بن
    _violation_count: Dict[str, int] = {}

    @classmethod
    def is_banned(cls, ip: str) -> bool:
        """بررسی بن شدن آی‌پی (هم در حافظه، هم در دیتابیس)"""
        now = time.time()
        with get_db() as conn:
            row = conn.execute(
                "SELECT until FROM bans WHERE ip=?", (ip,)
            ).fetchone()
        if row and row["until"] > now:
            return True
        if row and row["until"] <= now:
            # بن منقضی شده — پاک کن
            with get_db() as conn:
                conn.execute("DELETE FROM bans WHERE ip=?", (ip,))
        return False

    @classmethod
    def _apply_ban(cls, ip: str, reason: str):
        until = time.time() + cls.BAN_SECONDS
        with get_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO bans(ip, until, reason, created_at) VALUES (?,?,?,?)",
                (ip, until, reason, time.time())
            )
        audit("IP_BANNED", ip, f"until={int(until)} reason={reason}", level="WARN")

    @classmethod
    def rate_check(cls, ip: str, action: str) -> bool:
        """
        بررسی محدودیت نرخ. خروجی: True = مجاز، False = رد شد
        اگر تعداد تخلف‌ها به BAN_AFTER رسید، آی‌پی بن می‌شود.
        """
        if cls.is_banned(ip):
            audit("BLOCKED_BANNED", ip, action)
            return False

        if action not in cls.LIMITS:
            return True
        max_n, window = cls.LIMITS[action]
        now = time.time()

        with cls._lock:
            bucket = cls._rate_buckets.setdefault((ip, action), [])
            bucket[:] = [t for t in bucket if now - t < window]
            allowed = len(bucket) < max_n
            if allowed:
                bucket.append(now)
            else:
                cls._violation_count[ip] = cls._violation_count.get(ip, 0) + 1
                audit("RATE_LIMIT_HIT", ip, f"action={action} violations={cls._violation_count[ip]}")
                if cls._violation_count[ip] >= cls.BAN_AFTER:
                    cls._apply_ban(ip, f"rate_limit:{action}")
                    cls._violation_count.pop(ip, None)

        return allowed

    @classmethod
    def violation(cls, ip: str, reason: str):
        """ثبت تخلف امنیتی — می‌تواند منجر به بن شود"""
        with cls._lock:
            cls._violation_count[ip] = cls._violation_count.get(ip, 0) + 1
            count = cls._violation_count[ip]
        audit("SECURITY_VIOLATION", ip, f"{reason} count={count}", level="WARN")
        if count >= cls.BAN_AFTER:
            cls._apply_ban(ip, reason)
            with cls._lock:
                cls._violation_count.pop(ip, None)


# ═══════════════════════════════════════════════════════════════
#  ۶) شناسایی نوع فایل (magic bytes واقعی)
# ═══════════════════════════════════════════════════════════════

# امضاهای باینری معتبر برای هر نوع فایل
_SIGNATURES = [
    # تصاویر
    (b"\xff\xd8\xff",                          "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n",                     "image/png"),
    (b"GIF87a",                                "image/gif"),
    (b"GIF89a",                                "image/gif"),
    (b"BM",                                    "image/bmp"),
    (b"RIFF____WEBP",                          "image/webp"),  # RIFF????WEBP
    # صوت
    (b"ID3",                                   "audio/mpeg"),  # mp3 with ID3
    (b"\xff\xfb",                              "audio/mpeg"),  # mp3 frame sync
    (b"\xff\xf3",                              "audio/mpeg"),
    (b"\xff\xf2",                              "audio/mpeg"),
    (b"fLaC",                                  "audio/flac"),
    (b"OggS",                                  "audio/ogg"),
    (b"FORM____AIFF",                          "audio/aiff"),
    # WAV (RIFF____WAVE)
    # M4A/AAC/MP4 (ftyp در offset 4)
    # PDF
    (b"%PDF",                                  "application/pdf"),
    # ZIP (ممکنه docx/xlsx یا فشرده باشه)
    (b"PK\x03\x04",                            "application/zip"),
    # متن/کد
    (b"\xef\xbb\xbf",                          "text/plain"),  # UTF-8 BOM
]


def sniff_mime(data: bytes, declared_filename: str = "") -> Tuple[Optional[str], str]:
    """
    شناسایی واقعی نوع فایل بر اساس امضای باینری + نام فایل
    خروجی: (mime یا None, family: 'image'|'audio'|'pdf'|'text'|'unknown')
    """
    if not data:
        return None, "unknown"

    # امضای باینری
    mime = None
    for sig, m in _SIGNATURES:
        if b"____" in sig:
            # امضای ترکیبی (مثل WEBP)
            parts = sig.split(b"____")
            if data[:len(parts[0])] == parts[0] and data[8:8+len(parts[1])] == parts[1]:
                mime = m
                break
        else:
            if data[:len(sig)] == sig:
                mime = m
                break

    # بررسی‌های خاص برای فرمت‌های با ساختار پیچیده‌تر
    if mime is None:
        # M4A/AAC/MP4: ftyp در byte 4
        if len(data) >= 12 and data[4:8] == b"ftyp":
            brand = data[8:12]
            if brand in (b"M4A ", b"M4B ", b"mp42", b"isom"):
                mime = "audio/mp4"
        # WAV
        if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE":
            mime = "audio/wav"
        # MP3 frame sync (0xff 0xe0-0xff mask)
        if data[:2] and data[0] == 0xff and (data[1] & 0xe0) == 0xe0:
            mime = "audio/mpeg"

    # اگر هیچ امضایی پیدا نشد، احتمال متن بودن
    if mime is None:
        try:
            sample = data[:4096]
            sample.decode("utf-8")
            # متن معتبر — تشخیص نوع بر اساس پسوند فایل
            ext = Path(declared_filename).suffix.lower()
            text_map = {
                ".txt": "text/plain", ".md": "text/markdown",
                ".py": "text/x-python", ".js": "text/javascript",
                ".ts": "text/typescript", ".html": "text/html",
                ".htm": "text/html", ".css": "text/css",
                ".json": "application/json", ".xml": "application/xml",
                ".yml": "text/yaml", ".yaml": "text/yaml",
                ".sh": "text/x-shellscript", ".bash": "text/x-shellscript",
                ".c": "text/x-c", ".cpp": "text/x-c++",
                ".h": "text/x-c", ".hpp": "text/x-c++",
                ".java": "text/x-java", ".rs": "text/x-rust",
                ".go": "text/x-go", ".rb": "text/x-ruby",
                ".php": "text/x-php", ".sql": "text/x-sql",
                ".ini": "text/plain", ".toml": "text/plain",
                ".log": "text/plain", ".csv": "text/csv",
            }
            mime = text_map.get(ext, "text/plain")
            # اعتبارسنجی بیشتر: اگر متن واقعاً خواناتر است
            if all(9 <= b <= 13 or 32 <= b < 127 or b >= 128 for b in sample):
                return mime, "text"
            return None, "unknown"
        except UnicodeDecodeError:
            return None, "unknown"

    # نگاشت family
    if mime.startswith("image/"):
        family = "image"
    elif mime.startswith("audio/"):
        family = "audio"
    elif mime == "application/pdf":
        family = "pdf"
    elif mime.startswith("text/") or "json" in mime or "xml" in mime:
        family = "text"
    else:
        family = "unknown"

    return mime, family


# ═══════════════════════════════════════════════════════════════
#  ۷) تولید آیدی امن و تنظیمات پیش‌فرض
# ═══════════════════════════════════════════════════════════════

def make_uid() -> str:
    """آیدی ۲۵۶ بیتی (۶۴ کاراکتر hex) — غیرقابل حدس"""
    return secrets.token_hex(32)


def make_admin_code() -> str:
    """کد مدیریت ۱۹۲ بیتی (۳۲ کاراکتر URL-safe)"""
    return secrets.token_urlsafe(24)


DEFAULT_SETTINGS = {
    # دسترسی
    "max_views":           1,              # 0 = نامحدود، 1 = یک‌بار، N = N بار
    "ip_once":             True,           # هر آی‌پی فقط یک بار
    "timer_mode":          "on_reveal",    # none | on_view | on_reveal
    "timer_seconds":       30,
    "global_ttl_days":     7,              # 0 = بدون انقضای کلی
    "global_deadline":     None,           # timestamp یا None
    # رمز
    "password":            None,           # رشته‌ی رمز یا None
    "password_attempts":   5,              # 1 تا 10
    "on_password_fail":    "burn",         # burn | lock
    # نمایش
    "intro_message":       "",             # پیام قبل از محتوا
    "end_message":         "",             # پیام پایان (به جای پیش‌فرض)
    "image_zoom":          True,
    "image_rotate":        True,
    "image_pan":           True,
    "pdf_zoom":            True,
    "text_copy":           False,
    "audio_seek":          True,
    "image_quality":       "original",     # original | optimized
    # امنیت
    "watermark":           "",             # متن واترمارک یا خالی
    "auto_burn_violation": True,
    # مدیریت
    "private_note":        "",
}


# ═══════════════════════════════════════════════════════════════
#  راه‌اندازی
# ═══════════════════════════════════════════════════════════════


# ──── هش رمز فایل (بخش ۳ فاز A) ───────────────────────────
# فرمت ذخیره: "scrypt$<salt_hex>$<hash_hex>"
# پارامترهای سبک برای UX real-time (n=8192 ≈ ۵ms در CPU مدرن)

def hash_file_password(pw: str, salt: bytes = None) -> str:
    """هش رمز فایل با scrypt (پارامترهای سبک‌تر از رمز کاربر)"""
    _ok, _msg = check_pw_rules(pw)
    if not _ok:
        raise ValueError(_msg)
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


def _migrate_users_2fa(conn):
    """Migration خودکار: افزودن ستون‌های 2FA به users اگر وجود ندارند"""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "totp_secret" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN totp_secret BLOB")
    if "totp_enabled" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0")
    if "backup_codes" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN backup_codes TEXT")
    conn.commit()


def _ensure_reports_table(conn):
    """ساخت جدول گزارش‌های محتوا (تیک‌داون)"""
    conn.execute("""CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uid TEXT NOT NULL,
        reason TEXT NOT NULL,
        contact TEXT,
        status TEXT DEFAULT 'open',
        created_at TEXT DEFAULT (datetime('now'))
    )""")
    conn.commit()


def purge_old_logs(retention_days: int = LOG_RETENTION_DAYS) -> int:
    """حذف فایل‌های لاگ قدیمی‌تر از retention_days (الزام قانونی نگهداری ۶ ماهه).
    برای هر فایل soozan.log*، timestamp آخرین خط را می‌خواند.
    برمی‌گرداند: تعداد فایل‌های حذف‌شده.
    """
    from datetime import datetime, timedelta
    cutoff = datetime.now() - timedelta(days=retention_days)
    removed = 0
    ts_pat = re.compile(r"^\[(\d{4}-\d{2}-\d{2}) ")

    candidates = [LOG_PATH] + list(DATA_DIR.glob("soozan.log.*"))
    for log_file in candidates:
        if not log_file.exists():
            continue
        try:
            # خواندن از انتهای فایل برای یافتن timestamp آخرین رویداد
            last_ts = None
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                # اگر فایل کوچک است، همه‌اش را بخوان
                content = f.read()
                for line in reversed(content.split("\n")):
                    m = ts_pat.match(line)
                    if m:
                        try:
                            last_ts = datetime.strptime(m.group(1), "%Y-%m-%d")
                            break
                        except ValueError:
                            continue

            if last_ts is None:
                # فایل خالی یا بدون timestamp معتبر — حذف امن است
                log_file.unlink(missing_ok=True)
                removed += 1
                continue

            if last_ts < cutoff:
                # امن‌تر از unlink: بازنویسی با صفر سپس حذف (shred-like)
                try:
                    with open(log_file, "wb") as f:
                        f.write(b"\x00" * 64)
                    log_file.unlink(missing_ok=True)
                    removed += 1
                except OSError:
                    pass
        except OSError:
            continue

    if removed > 0:
        audit("LOG_PURGE", detail=f"removed={removed}, retention={retention_days}d")
    return removed


def _migrate_burn_settings(conn):
    """Migration: فایل‌های قدیمی که burn_mode در settings ندارند،
    با پیش‌فرض 'both' (views + time) پر شوند."""
    rows = conn.execute("SELECT id, settings, views_count, expires_at, created_at FROM files").fetchall()
    updated = 0
    for r in rows:
        try:
            cfg = json.loads(r["settings"] or "{}")
        except Exception:
            cfg = {}
        if "burn_mode" not in cfg:
            # حدس از داده فعلی
            mv = cfg.get("max_views")
            ea = r["expires_at"]
            if mv is not None and ea is not None:
                cfg["burn_mode"] = "both"
                cfg["max_views"] = mv
                # تخمین ttl از expires_at - created_at
                try:
                    ttl_days = max(1, int((ea - r["created_at"]) / 86400))
                    cfg["ttl_days"] = ttl_days
                except Exception:
                    cfg["ttl_days"] = 7
            elif mv is not None:
                cfg["burn_mode"] = "views"
                cfg["max_views"] = mv
            elif ea is not None:
                cfg["burn_mode"] = "time"
                try:
                    cfg["ttl_days"] = max(1, int((ea - r["created_at"]) / 86400))
                except Exception:
                    cfg["ttl_days"] = 7
            else:
                cfg["burn_mode"] = "views"
                cfg["max_views"] = 1
            conn.execute("UPDATE files SET settings=? WHERE id=?",
                         (json.dumps(cfg, ensure_ascii=False), r["id"]))
            updated += 1
    if updated:
        conn.commit()


def bootstrap():
    """راه‌اندازی اولیه هسته"""
    init_db()
    # Migration خودکار ستون‌های 2FA
    with get_db() as _c:
        _migrate_users_2fa(_c)
        _ensure_reports_table(_c)
        _migrate_burn_settings(_c)

    # پاک‌سازی لاگ‌های قدیمی‌تر از ۱۸۰ روز (الزام قانونی)
    purge_old_logs()


    _ = MasterKeyManager.instance()  # تولید/بارگذاری کلید ارشد
    audit("CORE_BOOTSTRAPPED")


if __name__ == "__main__":
    bootstrap()
    print("✅ هسته‌ی سوزان آماده است")
    print(f"   دیتابیس: {DB_PATH}")
    print(f"   کلید ارشد: {MASTER_KEY}")
    print(f"   لاگ: {LOG_PATH}")


def client_ip() -> str:
    """استخراج IP واقعی کاربر (تحمل نبودن request context)"""
    try:
        from flask import request
    except ImportError:
        return "-"

    # دسترسی به headers خارج از request context RuntimeError می‌دهد
    try:
        hdrs = request.headers
    except RuntimeError:
        return "-"

    for hdr in ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"):
        val = (hdrs.get(hdr) or "").strip()
        if val:
            return val.split(",")[0].strip()

    try:
        return request.remote_addr or "-"
    except RuntimeError:
        return "-"


def real_status(rd, stg, disk_exists):
    """(کلید، badge سه‌گانه، گروه رنگ، جزئیات فارسی)"""
    import time as _tt
    vc = rd.get("views_count") or 0
    mv = int(stg.get("max_views") or 0)
    now = _tt.time()
    st = rd.get("status")
    if st in ("locked", "paused"):
        why = "قفل خودکار به دلیل رمز غلط بیش از حد" if st == "locked" else "مکث دستی از پنل مدیریت"
        return "locked", "مکث 🔒", "warn", f"{why} → فایل موقتاً در دسترس نیست."
    vs = rd.get("view_started_at")
    win = float(stg.get("timer_seconds") or 0) or 3600
    if vs and (now - float(vs)) < win + 60 and st == "active":
        return "viewing", "فعال 🟢", "ok", "بیننده در حال مشاهده فایل است."
    if mv and vc >= mv:
        return "done", "غیرفعال ⚫", "bad", f"تعداد دیدن‌ها تمام شده ({vc}/{mv}) → فایل غیرفعال شد."
    if st == "burned":
        return "burned", "غیرفعال ⚫", "bad", "فایل به صورت دستی از پنل مدیریت سوخته/حذف شده است."
    if not disk_exists:
        return "gone", "غیرفعال ⚫", "bad", "فایل روی دیسک موجود نیست → غیرفعال."
    if rd.get("expires_at") and now > float(rd["expires_at"]):
        return "expired", "غیرفعال ⚫", "bad", "زمان انقضا رسیده است → فایل غیرفعال شد."
    return "active", "فعال 🟢", "ok", f"فایل فعال و در انتظار مشاهده ({vc}/{mv if mv else '∞'} بازدید)."


def check_pw_rules(pw: str):
    """قوانین رمز فایل ویزارد. خروجی: (ok, پیام)"""
    import re as _re2
    if not pw or len(pw) < 8:
        return False, "رمز باید حداقل ۸ کاراکتر باشد"
    if _re2.search(r"[\u0600-\u06FF]", pw):
        return False, "رمز نباید حروف فارسی/عربی داشته باشد"
    if pw.isdigit():
        return False, "رمز نباید فقط عدد باشد"
    if not (_re2.search(r"[A-Za-z]", pw) and _re2.search(r"\d", pw)):
        return False, "رمز باید شامل حرف انگلیسی و عدد باشد"
    if " " in pw:
        return False, "رمز نباید فاصله داشته باشد"
    return True, ""
