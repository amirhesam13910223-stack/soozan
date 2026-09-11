#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔐 مسیرهای احراز هویت سوزان
"""

from flask import Blueprint, request, session, redirect, url_for
from core import Auth, Security, audit, client_ip
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
