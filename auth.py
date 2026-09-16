#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔐 مسیرهای احراز هویت سوزان
"""

from flask import Blueprint, request, session, redirect, url_for
from core import Auth, Security, audit, client_ip, get_db
import totp
from ui import render
from pathlib import Path

TEMPLATES = Path(__file__).parent / "templates"

bp = Blueprint("auth", __name__)


def _read(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


# ── migration: اطلاعات واقعی کاربران ──
def _migrate_users():
    from core import get_db
    with get_db() as c:
        cols = [r["name"] for r in c.execute("PRAGMA table_info(users)")]
        for name, ddl in [
            ("full_name", "ALTER TABLE users ADD COLUMN full_name TEXT DEFAULT ''"),
            ("phone", "ALTER TABLE users ADD COLUMN phone TEXT DEFAULT ''"),
            ("phone_verified", "ALTER TABLE users ADD COLUMN phone_verified INTEGER DEFAULT 0"),
        ]:
            if name not in cols:
                c.execute(ddl)

_migrate_users()


def _mask(phone):
    return (phone[:4] + "***" + phone[-2:]) if phone and len(phone) >= 7 else (phone or "")


@bp.route("/login", methods=["GET", "POST"])
def login():
    # اگر کاربر قبلاً login است، به داشبورد برود
    if "user_id" in session:
        return redirect("/dashboard")
    
    if request.method == "POST":
        ip = client_ip()
        if not Security.rate_check(ip, "login"):
            return render(_read("auth.html"), mode="login",
                         error="تلاش بیش از حد. چند دقیقه صبر کنید.")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ok, user_id, msg = Auth.login(username, password)
        if not ok:
            Security.violation(ip, "login_fail")
            return render(_read("auth.html"), mode="login", error=msg, username=username)
        # اگر 2FA فعال است، به مرحله دوم برو
        if Auth.is_totp_enabled(user_id):
            session["pending_2fa_user_id"] = user_id
            audit("LOGIN_2FA_PENDING", ip, f"user={username}")
            return redirect("/login/totp")
        
        # OTP پیامکی (دمو): اگر شماره ثبت‌شده دارد
        import secrets as _sec
        import time as _t2
        from core import get_db
        with get_db() as c:
            urow = c.execute("SELECT id, phone FROM users WHERE id=?", (user_id,)).fetchone()
        if urow and urow["phone"]:
            code = f"{_sec.randbelow(1000000):06d}"
            session.clear()
            session["login_pending"] = {"user_id": user_id, "code": code,
                                        "exp": _t2.time() + 300, "tries": 0,
                                        "phone": urow["phone"]}
            audit("LOGIN_OTP_SENT", ip, f"user={username} (دمو)")
            return redirect("/login/phone")
        # Session regeneration برای جلوگیری از Session Fixation
        session.clear()
        session.permanent = True
        session.modified = True
        session["user_id"] = user_id
        audit("LOGIN_OK", ip, f"user={username}")
        return redirect("/dashboard")
    return render(_read("auth.html"), mode="login")


@bp.route("/register", methods=["GET", "POST"])
def register():
    """ثبت‌نام دومرحله‌ای: اطلاعات → کد تأیید (دمو) → ساخت حساب"""
    import re as _re
    import time as _time
    import secrets as _sec
    from core import get_db
    if "user_id" in session:
        return redirect("/dashboard")

    if request.method == "POST":
        ip = client_ip()
        if not Security.rate_check(ip, "register"):
            return render(_read("auth_register.html"),
                          error="تلاش بیش از حد. چند دقیقه صبر کنید.")
        # مرحله ۲: تأیید کد
        if request.form.get("step") == "2":
            pend = session.get("reg_pending")
            code = request.form.get("code", "").strip()
            if not pend or _time.time() > pend.get("exp", 0):
                session.pop("reg_pending", None)
                return render(_read("auth_register.html"), error="جلسه منقضی شد؛ دوباره شروع کنید.")
            if pend.get("tries", 0) >= 5:
                session.pop("reg_pending", None)
                return render(_read("auth_register.html"), error="تلاش بیش از حد؛ از ابتدا ثبت‌نام کنید.")
            if code != pend.get("code"):
                pend["tries"] = pend.get("tries", 0) + 1
                session["reg_pending"] = pend
                return render(_read("auth_verify.html"), demo_code=pend["code"],
                              phone=pend["phone"], error="کد نادرست است.")
            ok, msg = Auth.register(pend["username"], pend["password"])
            if not ok:
                session.pop("reg_pending", None)
                return render(_read("auth_register.html"), error=msg, username=pend["username"])
            with get_db() as c:
                c.execute("UPDATE users SET full_name=?, phone=?, phone_verified=1 WHERE username=?",
                          (pend["full_name"], pend["phone"], pend["username"]))
            session.pop("reg_pending", None)
            audit("REGISTER_OK", ip, f"user={pend['username']} phone={_mask(pend['phone'])}")
            return render(_read("auth.html"), mode="login",
                          success="ثبت‌نام موفق. حالا وارد شوید.", username=pend["username"])
        # مرحله ۱: دریافت اطلاعات
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        full_name = request.form.get("full_name", "").strip()
        phone = request.form.get("phone", "").strip()
        if len(full_name) < 3:
            return render(_read("auth_register.html"), error="نام و نام خانوادگی را کامل وارد کنید.",
                          username=username, full_name=full_name, phone=phone)
        if not _re.match(r"^09\d{9}$", phone):
            return render(_read("auth_register.html"), error="شماره موبایل معتبر نیست (مثال: 09123456789).",
                          username=username, full_name=full_name, phone=phone)
        code = f"{_sec.randbelow(1000000):06d}"
        session["reg_pending"] = {"username": username, "password": password,
                                  "full_name": full_name, "phone": phone,
                                  "code": code, "exp": _time.time() + 300, "tries": 0}
        audit("REGISTER_CODE", ip, f"user={username} (دمو)")
        return render(_read("auth_verify.html"), demo_code=code, phone=phone)
    return render(_read("auth_register.html"))




@bp.route("/login/phone", methods=["GET", "POST"])
def login_phone():
    """مرحله دوم ورود: کد یک‌بار مصرف (فعلاً دمو)"""
    import time as _time
    pend = session.get("login_pending")
    if not pend or _time.time() > pend.get("exp", 0):
        session.pop("login_pending", None)
        return redirect("/login")
    if request.method == "POST":
        ip = client_ip()
        code = request.form.get("code", "").strip()
        if pend.get("tries", 0) >= 5:
            session.pop("login_pending", None)
            return render(_read("auth.html"), mode="login", error="تلاش بیش از حد؛ دوباره وارد شوید.")
        if code != pend.get("code"):
            pend["tries"] = pend.get("tries", 0) + 1
            session["login_pending"] = pend
            return render(_read("auth_otp.html"), demo_code=pend["code"],
                          phone_mask=_mask(pend["phone"]), error="کد نادرست است.")
        user_id = pend["user_id"]
        session.pop("login_pending", None)
        if Auth.is_totp_enabled(user_id):
            session["pending_2fa_user_id"] = user_id
            return redirect("/login/totp")
        session.clear()
        session.permanent = True
        session.modified = True
        session["user_id"] = user_id
        audit("LOGIN_OK", ip, f"user_id={user_id} (otp)")
        return redirect("/dashboard")
    return render(_read("auth_otp.html"), demo_code=pend["code"], phone_mask=_mask(pend["phone"]))

@bp.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


def require_auth(fn):
    """دکوراتور: کاربر باید وارد شده باشد"""
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper

# ═══════════════════════════════════════════════════════════
# 2FA (TOTP) — ورود دومرحله‌ای و مدیریت
# ═══════════════════════════════════════════════════════════
@bp.route("/login/totp", methods=["GET", "POST"])
def login_totp():
    """مرحله دوم ورود: دریافت کد TOTP یا کد پشتیبان"""
    pending_id = session.get("pending_2fa_user_id")
    if pending_id is None:
        return redirect("/login")
    
    if request.method == "POST":
        ip = client_ip()
        if not Security.rate_check(ip, "totp"):
            return render(_read("totp.html"), mode="login",
                         error="تلاش بیش از حد. چند دقیقه صبر کنید.")
        
        code = request.form.get("code", "").strip()
        
        # اول TOTP، بعد backup code
        ok, msg = Auth.verify_totp(pending_id, code)
        if not ok:
            ok, msg = Auth.use_backup_code(pending_id, code)
        
        if not ok:
            Security.violation(ip, "totp_login_fail")
            return render(_read("totp.html"), mode="login", error=msg)
        
        # ورود کامل
        session.pop("pending_2fa_user_id", None)
        session["user_id"] = pending_id
        audit("LOGIN_2FA_OK", ip, f"user_id={pending_id}")
        return redirect("/dashboard")
    
    return render(_read("totp.html"), mode="login")


@bp.route("/account/2fa", methods=["GET"])
@require_auth
def account_2fa():
    """صفحه مدیریت 2FA"""
    user_id = session["user_id"]
    enabled = Auth.is_totp_enabled(user_id)
    return render(_read("totp.html"), mode="manage", enabled=enabled)


@bp.route("/account/2fa/setup", methods=["POST"])
@require_auth
def account_2fa_setup():
    """شروع راه‌اندازی 2FA — نمایش QR و کدهای پشتیبان"""
    user_id = session["user_id"]
    
    if Auth.is_totp_enabled(user_id):
        return redirect("/account/2fa")
    
    secret_b32, backup_codes = Auth.setup_totp(user_id)
    
    # ذخیره موقت در session برای مرحله activate
    session["totp_setup_secret"] = secret_b32
    session["totp_setup_backups"] = backup_codes
    
    # ساخت URI و QR
    with get_db() as conn:
        row = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    username = row["username"] if row else "user"
    
    uri = totp.build_provisioning_uri("Soozan", username, secret_b32)
    qr_svg = totp.generate_qr_svg(uri)
    
    return render(_read("totp.html"), mode="setup",
                 secret=secret_b32, backup_codes=backup_codes,
                 qr_svg=qr_svg, uri=uri)


@bp.route("/account/2fa/activate", methods=["POST"])
@require_auth
def account_2fa_activate():
    """فعال‌سازی 2FA بعد از تأیید کد"""
    user_id = session["user_id"]
    code = request.form.get("code", "").strip()
    
    ok, msg = Auth.activate_totp(user_id, code)
    if not ok:
        return render(_read("totp.html"), mode="setup_error", error=msg)
    
    # پاک کردن session موقت
    session.pop("totp_setup_secret", None)
    session.pop("totp_setup_backups", None)
    
    return redirect("/account/2fa")


@bp.route("/account/2fa/disable", methods=["POST"])
@require_auth
def account_2fa_disable():
    """غیرفعال‌سازی 2FA"""
    user_id = session["user_id"]
    ok, msg = Auth.disable_totp(user_id)
    return redirect("/account/2fa")
