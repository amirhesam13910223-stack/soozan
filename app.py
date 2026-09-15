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
SOOZAN_VERSION = "1.1.0-phase2"
SOOZAN_PHASE = "۲ (زیرساخت)"
SOOZAN_BOOT = __import__("time").time()


@app.route("/api/disk-usage")
def api_disk_usage():
    """API عمومی برای دریافت درصد استفاده دیسک (JSON)"""
    import shutil
    from flask import jsonify
    from core import DATA_DIR
    
    try:
        du = shutil.disk_usage(str(DATA_DIR))
        pct = du.used / du.total * 100
        return jsonify({
            "ok": True,
            "usage_percent": round(pct, 1),
            "used_gb": round(du.used / (1024**3), 2),
            "total_gb": round(du.total / (1024**3), 2),
            "free_gb": round(du.free / (1024**3), 2),
            "status": "ok" if pct < 80 else ("warn" if pct < 90 else "critical")
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/status")
def status():
    """صفحه وضعیت عمومی — بدون داده حساس"""
    from flask import render_template
    import secrets, shutil, time
    from pathlib import Path as _P
    from core import DATA_DIR, LOG_RETENTION_DAYS, get_db

    # ۱) پایگاه داده
    try:
        with get_db() as conn:
            conn.execute("SELECT 1").fetchone()
        db_cls, db_txt = "ok", "سالم"
    except Exception:
        db_cls, db_txt = "bad", "خطا"

    # ۲) دیسک
    try:
        du = shutil.disk_usage(str(DATA_DIR))
        pct = du.used / du.total * 100
        if pct < 70:
            disk_cls, disk_txt = "ok", f"{pct:.0f}٪ استفاده"
        elif pct < 85:
            disk_cls, disk_txt = "warn", f"{pct:.0f}٪ استفاده"
        else:
            disk_cls, disk_txt = "bad", f"{pct:.0f}٪ استفاده — بحرانی"
    except Exception:
        disk_cls, disk_txt, pct = "warn", "نامشخص", -1

    # ۳) آخرین بک‌آپ
    try:
        backups = sorted(_P("backups").glob("soozan_backup_*.tar.gz"),
                         key=lambda f: f.stat().st_mtime, reverse=True)
        if backups:
            age_h = (time.time() - backups[0].stat().st_mtime) / 3600
            if age_h < 36:
                bak_cls, bak_txt = "ok", f"{age_h:.0f} ساعت پیش"
            elif age_h < 72:
                bak_cls, bak_txt = "warn", f"{age_h:.0f} ساعت پیش"
            else:
                bak_cls, bak_txt = "bad", f"{age_h:.0f} ساعت پیش — قدیمی"
        else:
            bak_cls, bak_txt = "bad", "وجود ندارد"
    except Exception:
        bak_cls, bak_txt = "warn", "نامشخص"

    # ۴) uptime
    up = int(time.time() - SOOZAN_BOOT)
    d, rem = divmod(up, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    uptime_txt = f"{d} روز و {h} ساعت و {m} دقیقه" if d else f"{h} ساعت و {m} دقیقه"

    return render_template("status.html",
                           nonce=secrets.token_urlsafe(24),
                           version=SOOZAN_VERSION, phase=SOOZAN_PHASE,
                           db_cls=db_cls, db_txt=db_txt,
                           disk_cls=disk_cls, disk_txt=disk_txt,
                           bak_cls=bak_cls, bak_txt=bak_txt,
                           uptime_txt=uptime_txt,
                           retention=LOG_RETENTION_DAYS)


@app.route("/content-policy")
def content_policy():
    """سیاست محتوا و تیک‌داون (عمومی)"""
    from flask import render_template
    import secrets
    return render_template("content.html", nonce=secrets.token_urlsafe(24))


@app.route("/report", methods=["GET", "POST"])
def report():
    """فرم گزارش محتوا (عمومی، rate-limited)"""
    from flask import render_template, request
    from core import Security, get_db, audit, client_ip
    import secrets
    nonce = secrets.token_urlsafe(24)

    if request.method == "POST":
        ip = client_ip()
        if not Security.rate_check(ip, "report"):
            return render_template("report.html", nonce=nonce,
                                   error="تعداد گزارش‌ها بیش از حد است؛ بعداً تلاش کنید.")
        uid = (request.form.get("uid") or "").strip()
        reason = (request.form.get("reason") or "").strip()
        contact = (request.form.get("contact") or "").strip()

        if not uid or not reason:
            return render_template("report.html", nonce=nonce,
                                   error="شناسه فایل و دلیل گزارش الزامی است.")

        with get_db() as conn:
            exists = conn.execute("SELECT COUNT(*) FROM files WHERE uid=?", (uid,)).fetchone()[0]
            if not exists:
                return render_template("report.html", nonce=nonce,
                                       error="فایلی با این شناسه یافت نشد (احتمالاً امحا شده).")
            conn.execute("INSERT INTO reports(uid, reason, contact) VALUES (?,?,?)",
                         (uid, reason, contact))
        audit("CONTENT_REPORT", ip, f"uid={uid[:12]}")
        return render_template("report.html", nonce=nonce, ok=True)

    return render_template("report.html", nonce=nonce)


@app.route("/terms")
def terms():
    """صفحه شرایط استفاده (عمومی)"""
    from flask import render_template
    import secrets
    nonce = secrets.token_urlsafe(24)
    return render_template("terms.html", nonce=nonce)


@app.route("/privacy")
def privacy():
    """صفحه سیاست حریم خصوصی (عمومی)"""
    from flask import render_template
    import secrets
    nonce = secrets.token_urlsafe(24)
    return render_template("privacy.html", nonce=nonce)


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
        serve(
            app,
            host="0.0.0.0",
            port=PORT,
            threads=8,                    # = تعداد هسته CPU
            connection_limit=100,         # حداکثر اتصال هم‌زمان
            channel_timeout=120,          # 2 دقیقه timeout اتصال idle
            cleanup_interval=30,          # پاک‌سازی هر 30 ثانیه
            recv_bytes=16384,             # بافر دریافت (16KB)
            send_bytes=18000,             # بافر ارسال
            max_request_header_size=16384,
            max_request_body_size=52428800,  # 50MB (مطابق محدودیت آپلود)
            expose_tracebacks=False,      # امنیتی: stack trace در production نشت نکند
        )
    except ImportError:
        app.run(host="0.0.0.0", port=PORT, threaded=True, debug=False)
