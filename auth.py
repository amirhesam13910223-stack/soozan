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
        
        # Session regeneration برای جلوگیری از Session Fixation
        session.clear()
        session.permanent = True  # قبل از modified تا عمر اعمال شود
        session.modified = True  # اجبار Flask به ارسال Set-Cookie جدید با Max-Age
        session["user_id"] = user_id
        audit("LOGIN_OK", ip, f"user={username}")
        return redirect("/dashboard")
    return render(_read("auth.html"), mode="login")


@bp.route("/register", methods=["GET", "POST"])
def register():
    # اگر کاربر قبلاً login است، به داشبورد برود
    if "user_id" in session:
        return redirect("/dashboard")
    
    if request.method == "POST":
        ip = client_ip()
        if not Security.rate_check(ip, "register"):
            return render(_read("auth.html"), mode="register",
                         error="تلاش بیش از حد. چند دقیقه صبر کنید.")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ok, msg = Auth.register(username, password)
        if not ok:
            return render(_read("auth.html"), mode="register", error=msg, username=username)
        return render(_read("auth.html"), mode="register",
                     success="ثبت‌نام موفق. حالا وارد شوید.", username=username)
    return render(_read("auth.html"), mode="register")


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
