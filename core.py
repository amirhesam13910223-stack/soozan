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

# ═══════════════════════════════════════════════════════════════
#  پیکربندی
# ═══════════════════════════════════════════════════════════════

BASE_DIR   = Path(__file__).parent
DATA_DIR   = BASE_DIR / "data"
FILES_DIR  = DATA_DIR / "files"
DB_PATH    = DATA_DIR / "burn.db"
MASTER_KEY = DATA_DIR / ".master.key"
LOG_PATH   = DATA_DIR / "soozan.log"

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
                key = f.read().strip()
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

class Security:
    """لایه‌ی دفاعی درون‌حافظه‌ای با پایداری در SQLite برای بن‌ها"""
    _lock = threading.Lock()
    _rate_buckets: Dict[Tuple[str, str], list] = {}

    # پیکربندی محدودیت‌ها: (حداکثر تلاش, پنجره زمانی ثانیه)
    LIMITS = {
        "login":     (5, 600),
        "register":  (3, 600),
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


def bootstrap():
    """راه‌اندازی اولیه هسته"""
    init_db()
    _ = MasterKeyManager.instance()  # تولید/بارگذاری کلید ارشد
    audit("CORE_BOOTSTRAPPED")


if __name__ == "__main__":
    bootstrap()
    print("✅ هسته‌ی سوزان آماده است")
    print(f"   دیتابیس: {DB_PATH}")
    print(f"   کلید ارشد: {MASTER_KEY}")
    print(f"   لاگ: {LOG_PATH}")


def client_ip():
    """استخراج آی‌پی واقعی کاربر.
    
    اولویت:
    1. X-Client-IP (برای تست محلی و reverse proxy های ساده)
    2. CF-Connecting-IP (Cloudflare — production)
    3. X-Real-IP (nginx)
    4. X-Forwarded-For (عمومی)
    5. request.remote_addr (fallback)
    """
    for hdr in ("X-Client-IP", "CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"):
        val = (request.headers.get(hdr) or "").strip()
        if val:
            first_ip = val.split(",")[0].strip()
            if first_ip and first_ip not in ("", "unknown", "127.0.0.1"):
                return first_ip
    
    return request.remote_addr or "unknown"
