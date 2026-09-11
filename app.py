#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
سوزان — سرور اصلی Flask (فاز ۲)
"""

import sys
import os
import secrets
from pathlib import Path
from flask import Flask, g, request

sys.path.insert(0, str(Path(__file__).parent))
from core import bootstrap, MasterKeyManager, Security, audit, LOG_PATH, DB_PATH, client_ip
from ui import harden_response, serve_asset

PORT = 8000

bootstrap()

# ── زیرساخت پنل مدیریت (فاز D) ──
import admin_infra  # migration خودکار اجرا می‌شود

app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
app.secret_key = MasterKeyManager.instance().session_key()

# ── حالت توسعه (فقط تست محلی، بدون HTTPS) ──
DEV_MODE = os.environ.get("SOOZAN_DEV_MODE", "0") == "1"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_NAME="soozan_sid",
    SESSION_COOKIE_SECURE=not DEV_MODE,
)


# ── دروازه امنیتی: نانس + بررسی بن ──
@app.before_request
def gate():
    g.nonce = secrets.token_urlsafe(16)
    ip = client_ip()
    if Security.is_banned(ip):
        audit("BLOCKED_BANNED", ip, request.path)
        return "403 Forbidden", 403


# ── هدرهای امنیتی روی همه پاسخ‌ها ──
@app.after_request
def harden(resp):
    return harden_response(resp)


# ── دارایی‌های لوکال (فونت، pdf.js، هایلایتر) ──
@app.route("/assets/<path:path>")
def assets(path):
    return serve_asset(path)


# ── سلامت سرور ──
@app.get("/health")
def health():
    return {"ok": True, "phase": 2}


# ── ثبت بلوپرینت‌ها ──
from auth import bp as auth_bp
from wizard import bp as wizard_bp
from dashboard import bp as dashboard_bp
from viewer import bp as viewer_bp
from admin_panel import bp as admin_panel_bp

app.register_blueprint(auth_bp)
app.register_blueprint(wizard_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(viewer_bp)
app.register_blueprint(admin_panel_bp)




@app.route("/")
def index():
    """صفحه اصلی هوشمند:
    - اگر کاربر login است → داشبورد
    - اگر login نیست → صفحه ورود
    """
    from flask import session, redirect
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")


if __name__ == "__main__":
    if DEV_MODE:
        print("!" * 56)
        print("  ⚠️  DEV_MODE فعال است — cookie ها Secure نیستند!")
        print("  ⚠️  فقط برای تست محلی استفاده شود")
        print("!" * 56)
    print("=" * 56)
    print("  🔥 سوزان — فاز ۲ (ویزارد آپلود)")
    print(f"  →  http://127.0.0.1:{PORT}/")
    print(f"  📜 لاگ: {LOG_PATH}")
    print(f"  🗄️ دیتابیس: {DB_PATH}")
    print("=" * 56)
    try:
        from waitress import serve
        serve(app, host="0.0.0.0", port=PORT, threads=8)
    except ImportError:
        app.run(host="0.0.0.0", port=PORT, threaded=True, debug=False)
