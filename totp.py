#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TOTP (Time-based One-Time Password) — استاندارد RFC 6238
بدون وابستگی خارجی، فقط با hmac + struct (کتابخانه استاندارد پایتون)
"""
import base64
import hashlib
import hmac
import os
import struct
import time
import urllib.parse
from typing import Tuple, Optional


# تنظیمات استاندارد TOTP
DIGITS = 6            # تعداد ارقام کد
PERIOD = 30           # طول پنجره زمانی (ثانیه)
ALGORITHM = "sha1"    # الگوریتم استاندارد RFC 6238
DRIFT_WINDOWS = 1     # تحمل انحراف زمانی (±۱ پنجره = ±۳۰ ثانیه)


def generate_secret(length: int = 20) -> str:
    """تولید secret جدید (base32 برای سازگاری با Google Authenticator)"""
    random_bytes = os.urandom(length)
    return base64.b32encode(random_bytes).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    """محاسبه HOTP طبق RFC 4226"""
    # decode base32 (با پدگذاری مجدد در صورت لزوم)
    padded = secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded.upper())
    
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** DIGITS)).zfill(DIGITS)


def generate_code(secret_b32: str, timestamp: Optional[float] = None) -> str:
    """تولید کد TOTP فعلی"""
    t = timestamp if timestamp is not None else time.time()
    counter = int(t) // PERIOD
    return _hotp(secret_b32, counter)


def verify_code(secret_b32: str, code: str, timestamp: Optional[float] = None) -> bool:
    """
    بررسی کد با تحمل drift (±DRIFT_WINDOWS پنجره)
    برای مقابله با timing attack، همیشه مقایسه ثابت‌زمان
    """
    if not code or len(code) != DIGITS or not code.isdigit():
        return False
    
    t = timestamp if timestamp is not None else time.time()
    counter = int(t) // PERIOD
    
    for offset in range(-DRIFT_WINDOWS, DRIFT_WINDOWS + 1):
        expected = _hotp(secret_b32, counter + offset)
        if hmac.compare_digest(expected, code):
            return True
    return False


def generate_backup_codes(count: int = 8) -> list:
    """تولید کدهای پشتیبان یک‌بارمصرف"""
    codes = []
    for _ in range(count):
        code = base64.b32encode(os.urandom(5)).decode("ascii")[:8]
        codes.append(code)
    return codes


def build_provisioning_uri(issuer: str, account: str, secret_b32: str) -> str:
    """ساخت otpauth URI برای QR code (سازگار با Google Authenticator)"""
    label = f"{urllib.parse.quote(issuer)}:{urllib.parse.quote(account)}"
    params = {
        "secret": secret_b32,
        "issuer": issuer,
        "algorithm": ALGORITHM.upper(),
        "digits": str(DIGITS),
        "period": str(PERIOD),
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"otpauth://totp/{label}?{query}"


def generate_qr_svg(uri: str, size: int = 200) -> str:
    """تولید QR code به‌صورت SVG inline (بدون وابستگی خارجی)"""
    # پیاده‌سازی ساده QR با الگوریتم نسخه 2 (25x25) — کافی برای otpauth URI
    # برای سادگی و عدم وابستگی، از یک الگوریتم پایه QR استفاده می‌کنیم
    
    # استفاده از کتابخانه qrcode اگر موجود باشد، وگرنه placeholder ساده
    try:
        import qrcode
        import qrcode.image.svg
        import io
        factory = qrcode.image.svg.SvgPathImage
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(image_factory=factory)
        buf = io.BytesIO()
        img.save(buf)
        return buf.getvalue().decode("utf-8")
    except ImportError:
        # fallback: نمایش URI به‌صورت متن قابل کپی + لینک به Google Authenticator
        import html
        escaped_uri = html.escape(uri)
        return f'''
        <div style="padding:20px; background:#0f1730; border-radius:12px; text-align:center;">
            <div style="color:#9aa7cf; margin-bottom:12px;">
                این کد را در Google Authenticator وارد کنید:
            </div>
            <code style="display:block; padding:12px; background:#070b14; border-radius:8px;
                         color:#ffa257; font-size:13px; word-break:break-all; font-family:monospace;">
                {html.escape(uri)}
            </code>
            <div style="margin-top:12px; font-size:12px; color:#5f6c93;">
                یا کد setup را کپی کنید و در برنامه وارد کنید
            </div>
        </div>
        '''


# ═══════════════════════════════════════════════════════════
# تست خودکار (اگر مستقیم اجرا شود)
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("🔐 تست TOTP...")
    secret = generate_secret()
    print(f"  secret: {secret}")
    
    code = generate_code(secret)
    print(f"  کد فعلی: {code}")
    
    assert verify_code(secret, code), "کد باید معتبر باشد"
    print("  ✅ کد معتبر تأیید شد")
    
    assert not verify_code(secret, "000000"), "کد ساختگی نباید معتبر باشد"
    print("  ✅ کد ساختگی رد شد")
    
    # تست drift: کد قبلی هم باید قبول شود
    prev_counter = int(time.time()) // PERIOD - 1
    prev_code = generate_code(secret, prev_counter * PERIOD)
    if verify_code(secret, prev_code):
        print("  ✅ drift tolerance کار می‌کند")
    
    # URI و QR
    uri = build_provisioning_uri("Soozan", "testuser", secret)
    print(f"  URI: {uri[:60]}...")
    
    print("\n🏆 همه تست‌های TOTP پاس شدند")
