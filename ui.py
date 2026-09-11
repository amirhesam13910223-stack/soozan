#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""🎨 توابع کمکی رابط کاربری سوزان"""

from flask import render_template_string, g, send_from_directory
from pathlib import Path
import secrets

BASE_DIR = Path(__file__).parent
ASSETS_DIR = BASE_DIR / "assets"


def render(template_str: str, **context):
    nonce = getattr(g, "nonce", secrets.token_urlsafe(16))
    context.setdefault("nonce", nonce)
    context["ASSETS"] = "/assets"
    return render_template_string(template_str, **context)


def harden_response(resp):
    nonce = getattr(g, "nonce", None)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if nonce:
        resp.headers["Content-Security-Policy"] = (
            f"default-src 'none'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"style-src 'self' 'nonce-{nonce}'; "
            f"style-src-attr 'unsafe-inline'; "
            f"img-src 'self' data:; "
            f"font-src 'self'; "
            f"connect-src 'self'; "
            f"frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
    return resp


def serve_asset(path: str):
    resp = send_from_directory(ASSETS_DIR, path)
    resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return resp
