#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
رندر سمت سرور — فایل خام هرگز به مرورگر نمی‌رسد
"""
from __future__ import annotations
import io
import os
import secrets
import threading
import time
from typing import Optional, Tuple

try:
    from PIL import Image, ImageDraw, ImageFont
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import fitz  # PyMuPDF
    HAS_PDF = True
except ImportError:
    HAS_PDF = False

# ─── مدیریت توکن‌های رندر (یک‌بارمصرف، کوتاه‌مدت، مقید به IP) ───
_LOCK = threading.Lock()
_RENDER_TOKENS: dict = {}

def issue_token(uid: str, ip: str, kind: str, ttl: float = 30.0, extra: dict = None) -> str:
    """صدور توکن یک‌بارمصرف رندر"""
    token = secrets.token_urlsafe(24)
    with _LOCK:
        _RENDER_TOKENS[token] = {
            "uid": uid, "ip": ip, "kind": kind,
            "exp": time.time() + ttl, "extra": extra or {},
        }
    return token

def pop_token(token: str, uid: str, ip: str, kind: str) -> Optional[dict]:
    """اعتبارسنجی و مصرف توکن"""
    with _LOCK:
        t = _RENDER_TOKENS.pop(token, None)
    if not t:
        return None
    if t["uid"] != uid or t["ip"] != ip or t["kind"] != kind:
        return None
    if time.time() > t["exp"]:
        return None
    return t

# ─── رندر تصویر ───
def render_image(data: bytes, watermark: str = "") -> Tuple[bytes, str]:
    """
    تصویر را در حافظه باز، متادیتا را حذف، واترمارک را در پیکسل‌ها می‌سوزاند.
    خروجی: (بایت‌های PNG جدید، mimetype)
    """
    if not HAS_PIL:
        raise RuntimeError("Pillow نصب نیست")
    img = Image.open(io.BytesIO(data))
    img = img.convert("RGB") if img.mode != "RGB" else img
    if watermark:
        draw = ImageDraw.Draw(img)
        w, h = img.size
        font_size = max(16, min(w, h) // 20)
        try:
            font = ImageFont.load_default(size=font_size)
        except Exception:
            font = ImageFont.load_default()
        bbox = draw.textbbox((0, 0), watermark, font=font)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x, y = (w - tw) // 2, (h - th) // 2
        draw.text((x + 1, y + 1), watermark, font=font, fill=(0, 0, 0, 128))
        draw.text((x, y), watermark, font=font, fill=(255, 255, 255, 200))
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue(), "image/png"

# ─── رندر PDF (صفحه‌به‌صفحه) ───
def render_pdf_page(data: bytes, page_num: int, watermark: str = "") -> Tuple[bytes, str]:
    """
    رندر یک صفحه از PDF به تصویر PNG.
    اگر PyMuPDF نصب نباشد، RuntimeError می‌دهد (caller باید fallback داشته باشد).
    """
    if not HAS_PDF:
        raise RuntimeError("PyMuPDF نصب نیست")
    doc = fitz.open(stream=data, filetype="pdf")
    if page_num < 1 or page_num > len(doc):
        doc.close()
        raise ValueError("شماره صفحه نامعتبر")
    page = doc[page_num - 1]
    # رندر با DPI مناسب
    mat = fitz.Matrix(2.0, 2.0)  # 2x zoom
    pix = page.get_pixmap(matrix=mat)
    img_data = pix.tobytes("png")
    doc.close()
    # واترمارک
    if watermark and HAS_PIL:
        img = Image.open(io.BytesIO(img_data))
        draw = ImageDraw.Draw(img)
        w, h = img.size
        font_size = max(16, min(w, h) // 20)
        try:
            font = ImageFont.load_default(size=font_size)
        except Exception:
            font = ImageFont.load_default()
        bbox = draw.textbbox((0, 0), watermark, font=font)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x, y = (w - tw) // 2, (h - th) // 2
        draw.text((x + 1, y + 1), watermark, font=font, fill=(0, 0, 0, 128))
        draw.text((x, y), watermark, font=font, fill=(255, 255, 255, 200))
        out = io.BytesIO()
        img.save(out, format="PNG")
        img_data = out.getvalue()
    return img_data, "image/png"

# ─── رندر متن ───
def render_text(data: bytes) -> str:
    """متن را به‌صورت امن برمی‌گرداند (برای تزریق در DOM)"""
    return data.decode("utf-8", errors="replace")
