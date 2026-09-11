#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🗄️ زیرساخت داده پنل مدیریت — فاز D

جداول جدید:
- password_attempts: ثبت هر تلاش رمز (موفق/ناموفق) با IP و زمان
- admin_actions: تاریخچه اکشن‌های مدیریتی
- notification_settings: تنظیمات اعلان (وبهوک)
"""
from __future__ import annotations
import time
from typing import Optional
from core import get_db


def migrate_admin_tables():
    """ساخت جداول جدید (idempotent)"""
    with get_db() as conn:
        # ── Migration برای ستون‌های جدید در جدول files ──
        # بررسی اینکه آیا ستون size_bytes وجود دارد
        cursor = conn.execute("PRAGMA table_info(files)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if "size_bytes" not in columns:
            conn.execute("ALTER TABLE files ADD COLUMN size_bytes INTEGER DEFAULT 0")
            # پر کردن size_bytes برای فایل‌های موجود
            rows = conn.execute("SELECT id, file_path FROM files WHERE file_path IS NOT NULL").fetchall()
            for row in rows:
                import os
                try:
                    size = os.path.getsize(row["file_path"]) if os.path.exists(row["file_path"]) else 0
                    conn.execute("UPDATE files SET size_bytes=? WHERE id=?", (size, row["id"]))
                except Exception:
                    pass
        # جدول تلاش‌های رمز عبور
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_attempts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id      INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                ip           TEXT,
                attempted_at REAL NOT NULL,
                success      INTEGER NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_pwattempts_file 
            ON password_attempts(file_id)
        """)
        
        # جدول اکشن‌های مدیریتی
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_actions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id     INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                action      TEXT NOT NULL,
                before_val  TEXT,
                after_val   TEXT,
                ip          TEXT,
                at          REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_adminactions_file 
            ON admin_actions(file_id)
        """)
        
        # جدول تنظیمات اعلان
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notification_settings (
                file_id              INTEGER PRIMARY KEY REFERENCES files(id) ON DELETE CASCADE,
                webhook_url          TEXT,
                notify_on_first_view INTEGER DEFAULT 0,
                notify_on_burn       INTEGER DEFAULT 0,
                notify_on_fail_spike INTEGER DEFAULT 0
            )
        """)


def record_password_attempt(file_id: int, ip: str, success: bool):
    """ثبت یک تلاش رمز عبور"""
    with get_db() as conn:
        conn.execute(
            "INSERT INTO password_attempts (file_id, ip, attempted_at, success) VALUES (?, ?, ?, ?)",
            (file_id, ip, time.time(), 1 if success else 0)
        )


def record_admin_action(file_id: int, action: str, before_val: str = None, 
                       after_val: str = None, ip: str = None):
    """ثبت یک اکشن مدیریتی"""
    with get_db() as conn:
        conn.execute(
            "INSERT INTO admin_actions (file_id, action, before_val, after_val, ip, at) VALUES (?, ?, ?, ?, ?, ?)",
            (file_id, action, before_val, after_val, ip, time.time())
        )


def get_password_attempts(file_id: int, limit: int = 100) -> list:
    """دریافت تلاش‌های رمز برای یک فایل"""
    with get_db() as conn:
        rows = conn.execute(
            """SELECT ip, attempted_at, success FROM password_attempts 
               WHERE file_id = ? ORDER BY attempted_at DESC LIMIT ?""",
            (file_id, limit)
        ).fetchall()
    return [dict(r) for r in rows]


def get_admin_actions(file_id: int, limit: int = 100) -> list:
    """دریافت اکشن‌های مدیریتی برای یک فایل"""
    with get_db() as conn:
        rows = conn.execute(
            """SELECT action, before_val, after_val, ip, at FROM admin_actions 
               WHERE file_id = ? ORDER BY at DESC LIMIT ?""",
            (file_id, limit)
        ).fetchall()
    return [dict(r) for r in rows]


# اجرای migration هنگام ایمپورت
migrate_admin_tables()
