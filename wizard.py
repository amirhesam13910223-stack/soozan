#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
📤 ویزارد آپلود سوزان
"""

import json
import time
import secrets
from pathlib import Path
from flask import Blueprint, request, session, jsonify
from core import (
    Security, FileCrypto, get_db, sniff_mime, make_uid, make_admin_code,
    DEFAULT_SETTINGS, FILES_DIR, audit, client_ip, hash_file_password
)
from scanner import scan_file, should_block_upload
from admin_infra import record_admin_action
from ui import render
from auth import require_auth

TEMPLATES = Path(__file__).parent / "templates"
bp = Blueprint("wizard", __name__)

MAX_UPLOAD = 100 * 1024 * 1024  # ۱۰۰ مگابایت

def _read(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


@bp.route("/wizard")
@require_auth
def wizard():
    return render(_read("wizard.html"))


def _parse_settings(form) -> dict:
    """تبدیل داده‌های فرم به دیکشنری تنظیمات با اعتبارسنجی کامل"""
    settings = {}

    # دسترسی
    try:
        mv = int(form.get("max_views", "1"))
    except ValueError:
        mv = 1
    if mv not in (0, 1, 2, 5, 10):
        mv = 1
    settings["max_views"] = mv

    settings["ip_once"] = form.get("ip_once") == "1"

    timer_mode = form.get("timer_mode", "on_reveal")
    if timer_mode not in ("none", "on_view", "on_reveal"):
        timer_mode = "on_reveal"
    settings["timer_mode"] = timer_mode

    try:
        ts = int(form.get("timer_seconds", "30"))
    except ValueError:
        ts = 30
    ts = max(5, min(3600, ts))
    settings["timer_seconds"] = ts

    try:
        ttl = int(form.get("ttl_days", "7"))
    except ValueError:
        ttl = 7
    if ttl < 0 or ttl > 365:
        ttl = 7
    settings["global_ttl_days"] = ttl
    settings["global_deadline"] = None

    # رمز (هش شده با scrypt — plaintext ذخیره نمی‌شود)
    if form.get("has_password") == "1":
        pw = (form.get("password") or "").strip()
        if len(pw) < 4:
            raise ValueError("رمز باید حداقل ۴ کاراکتر باشد")
        settings["password"] = hash_file_password(pw)
        try:
            pa = int(form.get("password_attempts", "5"))
        except ValueError:
            pa = 5
        pa = max(1, min(10, pa))
        settings["password_attempts"] = pa
        opa = form.get("on_password_fail", "burn")
        if opa not in ("burn", "lock"):
            opa = "burn"
        settings["on_password_fail"] = opa
    else:
        settings["password"] = None
        settings["password_attempts"] = 5
        settings["on_password_fail"] = "burn"

    # نمایش
    settings["intro_message"] = (form.get("intro_message") or "")[:500]
    settings["end_message"] = (form.get("end_message") or "")[:500]
    settings["image_zoom"] = form.get("image_zoom") == "1"
    settings["image_rotate"] = form.get("image_rotate") == "1"
    settings["image_pan"] = form.get("image_pan") == "1"
    settings["pdf_zoom"] = form.get("pdf_zoom") == "1"
    settings["text_copy"] = form.get("text_copy") == "1"
    settings["audio_seek"] = form.get("audio_seek") == "1"
    settings["image_quality"] = "original"

    # امنیت
    settings["watermark"] = (form.get("watermark") or "")[:200]
    settings["auto_burn_violation"] = form.get("auto_burn_violation") == "1"

    # مدیریت
    settings["private_note"] = (form.get("private_note") or "")[:1000]

    return settings


@bp.route("/api/upload", methods=["POST"])
@require_auth
def api_upload():
    ip = client_ip()
    if not Security.rate_check(ip, "upload"):
        return jsonify(ok=False, error="تلاش بیش از حد"), 429

    user_id = session.get("user_id")
    f = request.files.get("file")
    if not f:
        return jsonify(ok=False, error="فایلی ارسال نشده"), 400

    data = f.read()
    if not data:
        return jsonify(ok=False, error="فایل خالی است"), 400
    if len(data) > MAX_UPLOAD:
        return jsonify(ok=False, error="فایل بیش از ۱۰۰ مگابایت است"), 413

    filename = (f.filename or "unnamed").strip()[:200]
    mime, family = sniff_mime(data, filename)
    if mime is None or family == "unknown":
        audit("UPLOAD_BAD_TYPE", ip, f"filename={filename}")
        return jsonify(ok=False, error="نوع فایل پشتیبانی نمی‌شود"), 415

    # اعتبارسنجی تنظیمات
    try:
        settings = _parse_settings(request.form)
    except ValueError as e:
        return jsonify(ok=False, error=str(e)), 400

    # رمزنگاری
    ct, wrapped_dek = FileCrypto.encrypt_file(data)
    del data  # آزادسازی حافظه

    uid_token = make_uid()
    admin_code = make_admin_code()
    disk_name = secrets.token_hex(16) + ".enc"
    disk_path = FILES_DIR / disk_name

    with open(disk_path, "wb") as out:
        out.write(ct)
    del ct

    # محاسبه زمان انقضا
    now = time.time()
    ttl_days = settings["global_ttl_days"]
    expires = now + (ttl_days * 86400) if ttl_days > 0 else None

    # ذخیره در دیتابیس
    with get_db() as conn:
        conn.execute(
            """INSERT INTO files
               (uid, owner_id, filename, mime, file_path, dek_wrapped,
                settings, admin_code, created_at, expires_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (uid_token, user_id, filename, mime, str(disk_path),
             wrapped_dek, json.dumps(settings, ensure_ascii=False),
             admin_code, now, expires)
        )

    audit("FILE_UPLOADED", ip, f"uid={uid_token[:16]}… family={family} size={disk_path.stat().st_size}")

    return jsonify(
        ok=True,
        uid=uid_token,
        admin_code=admin_code,
        mime=mime,
        family=family,
    )
