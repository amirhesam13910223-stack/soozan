#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
سوزان — سرور اصلی Flask (فاز ۲)
"""

import sys
import os
import secrets
from pathlib import Path
from flask import Flask, g, request, session

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
    SESSION_COOKIE_SAMESITE="Lax",  # Lax: کوکی در top-level navigation (حتی از ایتا/اپ دیگر) ارسال می‌شود
    SESSION_COOKIE_NAME="soozan_sid",
    SESSION_COOKIE_SECURE=not DEV_MODE,
    PERMANENT_SESSION_LIFETIME=__import__("datetime").timedelta(days=30),
)


# ── دروازه امنیتی: نانس + بررسی بن ──
@app.before_request
def gate():
    g.nonce = secrets.token_urlsafe(16)
    ip = client_ip()
    # پاک کردن session زامبی: user_id در session هست ولی در دیتابیس نیست
    if "user_id" in session:
        try:
            from core import get_db
            with get_db() as c:
                u = c.execute("SELECT id FROM users WHERE id=?", (session["user_id"],)).fetchone()
                if not u:
                    session.clear()
        except Exception:
            pass
    if Security.is_banned(ip):
        audit("BLOCKED_BANNED", ip, request.path)
        return "403 Forbidden", 403


# ── هدرهای امنیتی روی همه پاسخ‌ها ──
@app.after_request
def harden(resp):
    return harden_response(resp)


# ── دارایی‌های لوکال (فونت، pdf.js، هایلایتر) ──
@app.context_processor
def _inject_nav_user():
    """تزریق username برای ناوبری"""
    from flask import session
    uid = session.get("user_id") or session.get("uid")
    username = None
    if uid:
        try:
            from core import get_db
            with get_db() as conn:
                u = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
                username = u["username"] if u else None
        except Exception:
            pass
    return {"nav_username": username}


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


@app.route("/settings")
def settings():
    """صفحه تنظیمات حساب و امنیت"""
    from flask import session, redirect
    from ui import render as _render
    from pathlib import Path as _P
    from core import get_db
    _uid = session.get("user_id") or session.get("uid")
    if not _uid:
        return redirect("/login")
    with get_db() as conn:
        u = conn.execute("SELECT * FROM users WHERE id=?", (_uid,)).fetchone()
    if not u:
        return redirect("/login")
    two_fa = False
    for col in ("totp_secret", "totp_enc", "totp"):
        try:
            two_fa = bool(u[col])
            break
        except Exception:
            continue
    tpl = (_P(__file__).parent / "templates" / "settings.html").read_text(encoding="utf-8")
    return _render(tpl, username=u["username"],
                   full_name=(u["full_name"] or "") if "full_name" in u.keys() else "",
                   phone=(u["phone"] or "") if "phone" in u.keys() else "",
                   two_fa=two_fa,
                   setup_route="", disable_route="")


# ─── تنظیمات: مدیریت کامل حساب ───
def _set_user():
    from flask import session
    from core import get_db
    _uid = session.get("user_id") or session.get("uid")
    if not _uid:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (_uid,)).fetchone()

def _set_render(tpl_name, **kw):
    from ui import render as _render
    from pathlib import Path as _P
    tpl = (_P(__file__).parent / "templates" / tpl_name).read_text(encoding="utf-8")
    return _render(tpl, **kw)

def _set_otp(purpose, phone, desc, new_phone=None):
    import secrets as _sec, time as _t
    from flask import session
    code = f"{_sec.randbelow(1000000):06d}"
    session["set_otp"] = {"purpose": purpose, "code": code, "exp": _t.time() + 120,
                          "tries": 0, "phone": phone, "new_phone": new_phone, "desc": desc}
    return _set_render("settings_otp.html", demo_code=code, desc=desc, phone=_mask_phone(phone))

def _mask_phone(ph):
    return (ph[:4] + "***" + ph[-2:]) if ph and len(ph) >= 7 else (ph or "")

@app.route("/settings")

@app.route("/settings/profile", methods=["POST"])
def settings_profile():
    from flask import session, redirect
    from core import get_db
    u = _set_user()
    if not u:
        return redirect("/login")
    fn = request.form.get("full_name", "").strip()
    if len(fn) >= 3:
        with get_db() as c:
            c.execute("UPDATE users SET full_name=? WHERE id=?", (fn, u["id"]))
        session["demo_sms"] = None
    return redirect("/settings")

@app.route("/settings/phone/start1", methods=["POST"])
def settings_phone_start1():
    """راه ۱: کد به شماره قدیمی"""
    from flask import session, redirect
    u = _set_user()
    if not u:
        return redirect("/login")
    return _set_otp("phone_old", u["phone"], "تغییر شماره — تأیید شماره فعلی")

@app.route("/settings/phone/start2", methods=["POST"])
def settings_phone_start2():
    """راه ۲: تأیید با رمز حساب"""
    import time as _t
    from flask import session, redirect
    from core import Auth, get_db
    u = _set_user()
    if not u:
        return redirect("/login")
    ok, _, _msg = Auth.login(u["username"], request.form.get("password", ""))
    if not ok:
        session["demo_sms"] = "❌ رمز حساب اشتباه بود"
        return redirect("/settings")
    session["phone_pw_ok"] = _t.time() + 300
    return redirect("/settings")

@app.route("/settings/phone/new", methods=["POST"])
def settings_phone_new():
    """ثبت شماره جدید + کد به شماره جدید"""
    import re as _re, time as _t
    from flask import session, redirect
    u = _set_user()
    if not u:
        return redirect("/login")
    if not (_t.time() < max(session.get("phone_old_ok", 0), session.get("phone_pw_ok", 0))):
        session["demo_sms"] = "❌ اول یکی از دو راه تأیید را انجام بده"
        return redirect("/settings")
    np = request.form.get("new_phone", "").strip()
    if not _re.match(r"^09\d{9}$", np):
        session["demo_sms"] = "❌ شماره جدید معتبر نیست"
        return redirect("/settings")
    return _set_otp("phone_new", np, "تغییر شماره — تأیید شماره جدید", new_phone=np)

@app.route("/settings/password/start", methods=["POST"])
def settings_password_start():
    """تغییر رمز: اول رمز قدیمی، بعد کد به شماره"""
    from flask import redirect
    from core import Auth
    u = _set_user()
    if not u:
        return redirect("/login")
    ok, _, _m = Auth.login(u["username"], request.form.get("current_password", ""))
    if not ok:
        from flask import session as _s
        _s["demo_sms"] = "❌ رمز فعلی اشتباه است"
        return redirect("/settings")
    return _set_otp("pw_change", u["phone"], "تغییر رمز عبور — تأیید با کد")

@app.route("/settings/otp/verify", methods=["POST"])
def settings_otp_verify():
    import time as _t
    from flask import session, redirect
    from core import get_db
    pend = session.get("set_otp")
    if not pend or _t.time() > pend.get("exp", 0):
        session.pop("set_otp", None)
        session["demo_sms"] = "❌ کد منقضی شد"
        return redirect("/settings")
    code = request.form.get("code", "").strip()
    if pend.get("tries", 0) >= 4:
        session.pop("set_otp", None)
        session["demo_sms"] = "❌ تلاش بیش از حد؛ کد باطل شد"
        return redirect("/settings")
    if code != pend.get("code"):
        pend["tries"] = pend.get("tries", 0) + 1
        session["set_otp"] = pend
        return _set_render("settings_otp.html", demo_code=pend["code"], desc=pend["desc"],
                           phone=_mask_phone(pend["phone"]), error="کد نادرست است")
    purpose = pend.get("purpose")
    session.pop("set_otp", None)
    u = _set_user()
    if purpose == "phone_old":
        session["phone_old_ok"] = _t.time() + 300
        return redirect("/settings")
    if purpose == "phone_new" and u:
        np = pend.get("new_phone")
        with get_db() as c:
            c.execute("UPDATE users SET phone=?, phone_verified=1 WHERE id=?", (np, u["id"]))
        session.pop("phone_old_ok", None); session.pop("phone_pw_ok", None)
        session["demo_sms"] = f"📨 پیامک به شماره قدیمی {_mask_phone(u['phone'])}: شماره موبایل حساب سوزان شما به {np} تغییر کرد."
        return redirect("/settings")
    if purpose == "pw_change":
        session["pw_ok_until"] = _t.time() + 300
        return redirect("/settings")
    return redirect("/settings")

@app.route("/settings/password/new", methods=["POST"])
def settings_password_new():
    import os, time as _t
    from flask import session, redirect
    from core import Auth, get_db
    u = _set_user()
    if not u or not (_t.time() < session.get("pw_ok_until", 0)):
        session["demo_sms"] = "❌ ابتدا کد تأیید را وارد کن"
        return redirect("/settings")
    p1 = request.form.get("new_password", "")
    p2 = request.form.get("new_password2", "")
    if len(p1) < 8 or p1 != p2:
        session["demo_sms"] = "❌ رمز جدید معتبر نیست یا تکرارش متفاوت است"
        return redirect("/settings")
    salt = os.urandom(Auth.SALT_LEN)
    pw_hash = Auth._hash(p1, salt)
    with get_db() as c:
        c.execute("UPDATE users SET pw_hash=?, salt=? WHERE id=?", (pw_hash, salt, u["id"]))
    session.pop("pw_ok_until", None)
    session["demo_sms"] = f"📨 پیامک: رمز حساب سوزان شما در ساعت {_t.strftime('%H:%M')} تاریخ {_t.strftime('%Y/%m/%d')} تغییر یافت."
    return redirect("/settings")

@app.route("/settings/delete", methods=["POST"])
def settings_delete():
    from flask import session, redirect
    from core import Auth, get_db
    u = _set_user()
    if not u:
        return redirect("/login")
    if request.form.get("ack") != "on":
        session["demo_sms"] = "❌ تأیید حذف را علامت بزن"
        return redirect("/settings")
    ok, _, _m = Auth.login(u["username"], request.form.get("password", ""))
    if not ok:
        session["demo_sms"] = "❌ رمز اشتباه است"
        return redirect("/settings")
    with get_db() as c:
        paths = [r["file_path"] for r in c.execute("SELECT file_path FROM files WHERE owner_id=? AND file_path!=''", (u["id"],))]
        c.execute("DELETE FROM views WHERE file_id IN (SELECT id FROM files WHERE owner_id=?)", (u["id"],))
        c.execute("DELETE FROM files WHERE owner_id=?", (u["id"],))
        c.execute("DELETE FROM users WHERE id=?", (u["id"],))
    for pp in [x[0] for x in paths]:
        try: os.remove(pp)
        except Exception: pass
    session.clear()
    return redirect("/login")


@app.route("/profile")
def profile():
    """صفحه پروفایل سازنده"""
    from flask import render_template, session, redirect
    import secrets, time as _t
    from core import get_db
    _uid = session.get("user_id") or session.get("uid")
    if not _uid:
        return redirect("/login")
    with get_db() as conn:
        u = conn.execute("SELECT * FROM users WHERE id=?", (_uid,)).fetchone()
        if not u:
            return redirect("/login")
        n_files = conn.execute("SELECT COUNT(*) FROM files WHERE owner_id=? AND status='active'", (u["id"],)).fetchone()[0]
        n_views = conn.execute("SELECT COALESCE(SUM(views_count),0) FROM files WHERE owner_id=?", (u["id"],)).fetchone()[0]
    two_fa = False
    for col in ("totp_secret", "totp_enc", "totp"):
        try:
            two_fa = bool(u[col])
            break
        except Exception:
            continue
    joined = _t.strftime("%Y/%m/%d", _t.localtime(u["created_at"])) if u["created_at"] else "-"
    from ui import render as _render
    from pathlib import Path as _P
    _tpl = (_P(__file__).parent / "templates" / "profile.html").read_text(encoding="utf-8")
    return _render(_tpl,
                           username=u["username"], joined=joined,
                           n_files=n_files, n_views=n_views, two_fa=two_fa,
                           full_name=(u["full_name"] or "") if "full_name" in u.keys() else "",
                           phone=(u["phone"] or "") if "phone" in u.keys() else "")


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



# ─── تست: پاک کردن ban (فقط DEV_MODE) ───
@app.route("/test/clear-ban")
def test_clear_ban():
    import os as _os
    if _os.environ.get("SOOZAN_DEV_MODE", "") not in ("1", "true", "yes"):
        return "forbidden", 403
    from core import Security
    for _attr in ("_rate_buckets", "_violation_count"):
        if hasattr(Security, _attr):
            getattr(Security, _attr).clear()
    return "ok"

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
