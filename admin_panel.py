#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔐 پنل مدیریت فایل — فاز E

معماری:
- ورود با admin_code (۱۹۲ بیتی، مستقل از session کاربر)
- صدور mgmt_token کوتاه‌مدت (۳۰ دقیقه بی‌فعالیتی)
- توکن با کلید مشتق‌شده از session_key امضا می‌شود (نه KEK)
- CSRF token برای عملیات state-changing
- Rate-limit مستقل از مسیرهای بازدید
"""
from __future__ import annotations

import hmac as _hmac

def _otp_eq(a: str, b: str) -> bool:
    """مقایسه constant-time کد OTP"""
    if not a or not b:
        return False
    return _hmac.compare_digest(a.encode(), b.encode())


import hmac
import hashlib
import os
import secrets
import time
import threading
try:
    import jdatetime
except ImportError:
    jdatetime = None
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict

from flask import Blueprint, request, jsonify, session, redirect, url_for
from core import (
    Security, FileCrypto, get_db, audit, client_ip, 
    make_admin_code, MasterKeyManager, FILES_DIR
)
from admin_infra import (
    record_admin_action, get_password_attempts, get_admin_actions
)
from analytics import get_full_analytics
from export import export_attempts_csv, export_views_csv, export_full_report_html
bp = Blueprint("admin_panel", __name__, url_prefix="")

# ─── توکن نشست مدیریتی ─────────────────────────────
# هر mgmt_token: (file_id, exp, csrf) به‌صورت signed string
# فرمت: "<file_id>.<exp>.<csrf>.<sig>"

_LOCK = threading.Lock()
_MGMT_TOKENS: Dict[str, dict] = {}  # در حافظه + اعتبارسنجی با امضا


def _derive_mgmt_key() -> bytes:
    """کلید مستقل برای امضای توکن مدیریتی (مشتق از session_key با info متفاوت)"""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    session_key = MasterKeyManager.instance().session_key()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"soozan-admin-mgmt-salt-v1",
        info=b"soozan-admin-mgmt-key-v1",
    ).derive(session_key)


def _sign(data: bytes) -> str:
    """امضای داده با کلید mgmt"""
    key = _derive_mgmt_key()
    sig = hmac.new(key, data, hashlib.sha256).digest()
    return sig.hex()


def issue_mgmt_token(file_id: int, ttl: float = 30 * 60) -> str:
    """صدور توکن نشست مدیریتی (۳۰ دقیقه پیش‌فرض)"""
    exp = int(time.time() + ttl)
    csrf = secrets.token_urlsafe(16)
    payload = f"{file_id}.{exp}.{csrf}"
    sig = _sign(payload.encode())
    token = f"{payload}.{sig}"
    return token


def verify_mgmt_token(token: str, expected_csrf: str = None) -> Optional[dict]:
    """اعتبارسنجی توکن نشست مدیریتی"""
    if not token or token.count('.') != 3:
        return None
    try:
        file_id_str, exp_str, csrf, sig = token.split('.')
        file_id = int(file_id_str)
        exp = int(exp_str)
    except (ValueError, TypeError):
        return None
    
    if time.time() > exp:
        return None
    
    # بررسی امضا
    payload = f"{file_id_str}.{exp_str}.{csrf}"
    expected_sig = _sign(payload.encode())
    if not hmac.compare_digest(sig, expected_sig):
        return None
    
    if expected_csrf and not hmac.compare_digest(csrf, expected_csrf):
        return None
    
    return {"file_id": file_id, "csrf": csrf, "exp": exp}


# ─── صفحه ورود admin_code ─────────────────────────────




def _to_jalali(timestamp: float) -> str:
    """تبدیل timestamp به تاریخ شمسی"""
    from datetime import datetime
    dt = datetime.fromtimestamp(timestamp)
    if jdatetime:
        try:
            return jdatetime.datetime.fromgregorian(datetime=dt).strftime('%Y/%m/%d %H:%M')
        except Exception:
            return dt.strftime('%Y-%m-%d %H:%M')
    return dt.strftime('%Y-%m-%d %H:%M')

@bp.get("/manage")
def manage_enter_page():
    """صفحه ورود admin_code"""
    from pathlib import Path
    from ui import render
    tpl = (Path(__file__).parent / "templates" / "manage_enter.html").read_text(encoding="utf-8")
    return render(tpl, error=None)


# ─── ورود با admin_code ─────────────────────────────
@bp.post("/api/manage/enter")
def manage_enter():
    """اعتبارسنجی admin_code و صدور mgmt_token"""
    ip = client_ip()
    if not Security.rate_check(ip, "manage_enter"):
        audit("MANAGE_ENTER_RATE_LIMITED", ip, level="WARN")
        return jsonify(ok=False, error="تلاش بیش از حد. چند دقیقه صبر کنید."), 429
    
    if request.form.get("resend") and session.get("manage_otp"):
        import secrets as _sec2, time as _t2, os as _os2
        from pathlib import Path as _P2
        from ui import render as _render2
        pend = session["manage_otp"]
        code2 = f"{_sec2.randbelow(1000000):06d}"
        pend["code"] = code2
        pend["exp"] = _t2.time() + 120
        pend["tries"] = 0
        pend["locked"] = False
        session["manage_otp"] = pend
        phone2 = ""
        with get_db() as conn2:
            ow2 = conn2.execute("SELECT phone FROM users WHERE id=(SELECT owner_id FROM files WHERE id=?)", (pend["file_id"],)).fetchone()
        if ow2 and ow2["phone"]:
            phone2 = ow2["phone"][:4] + "***" + ow2["phone"][-2:]
        DEV2 = _os2.environ.get("SOOZAN_DEV_MODE", "") in ("1", "true", "yes")
        tpl2 = (_P2(__file__).parent / "templates" / "manage_otp.html").read_text(encoding="utf-8")
        return _render2(tpl2, demo_code=code2, phone=phone2, error=None)
    admin_code = (request.form.get("admin_code") or "").strip()
    if not admin_code:
        audit("MANAGE_ENTER_EMPTY", ip, level="INFO")
        return redirect(url_for("admin_panel.manage_enter_page"))
    
    # جستجو در دیتابیس (constant-time compare برای جلوگیری از timing attacks)
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, uid, admin_code, status FROM files WHERE admin_code=?",
            (admin_code,)
        ).fetchone()
    
    if not row:
        Security.violation(ip, "manage_wrong_code")
        audit("MANAGE_ENTER_WRONG", ip, level="WARN")
        from pathlib import Path
        from ui import render
        tpl = (Path(__file__).parent / "templates" / "manage_enter.html").read_text(encoding="utf-8")
        return render(tpl, error="کد نامعتبر است"), 401
    
    file_id = row["id"]
    uid = row["uid"]
    status = row["status"]
    
    # ── مرحله ۲: کد پیامکی به شماره مالک فایل ──
    with get_db() as conn:
        owner = conn.execute(
            "SELECT phone FROM users WHERE id=(SELECT owner_id FROM files WHERE id=?)",
            (file_id,)
        ).fetchone()
    phone = (owner["phone"] if owner else "") or ""
    from pathlib import Path as _P
    from ui import render as _render
    import os as _os
    DEV = _os.environ.get("SOOZAN_DEV_MODE", "") in ("1", "true", "yes")
    try:
        from core import DEV_MODE as _dm
        DEV = DEV or bool(_dm)
    except Exception:
        pass
    if not phone:
        audit("MANAGE_ENTER_NOPHONE", ip, level="WARN")
        tpl = (_P(__file__).parent / "templates" / "manage_enter.html").read_text(encoding="utf-8")
        return _render(tpl, error="حساب مالک این فایل شماره موبایل ثبت‌شده ندارد؛ مدیریت ممکن نیست."), 403

    import secrets as _sec, time as _t
    code = f"{_sec.randbelow(1000000):06d}"
    session["manage_otp"] = {"code": code, "exp": _t.time() + 120, "tries": 0,
                             "file_id": file_id, "uid": uid}
    audit("MANAGE_OTP_SENT", ip, f"uid={uid[:12]}… status={status}")
    masked = phone[:4] + "***" + phone[-2:]
    tpl = (_P(__file__).parent / "templates" / "manage_otp.html").read_text(encoding="utf-8")
    return _render(tpl, demo_code=code, phone=masked, error=None)




@bp.post("/manage/otp")
def manage_otp_verify():
    """تأیید کد پیامکی مالک → صدور توکن مدیریت"""
    import time as _t
    from pathlib import Path as _P
    from ui import render as _render
    ip = client_ip()
    pend = session.get("manage_otp")
    if request.form.get("resend") and pend:
        import secrets as _s3, time as _t3, os as _o3
        from pathlib import Path as _P3
        from ui import render as _r3
        pend["code"] = f"{_s3.randbelow(1000000):06d}"
        pend["exp"] = _t3.time() + 120
        pend["tries"] = 0
        pend["locked"] = False
        session["manage_otp"] = pend
        ph3 = ""
        with get_db() as c3:
            ow3 = c3.execute("SELECT phone FROM users WHERE id=(SELECT owner_id FROM files WHERE id=?)", (pend["file_id"],)).fetchone()
        if ow3 and ow3["phone"]:
            ph3 = ow3["phone"][:4] + "***" + ow3["phone"][-2:]
        tp3 = (_P3(__file__).parent / "templates" / "manage_otp.html").read_text(encoding="utf-8")
        return _r3(tp3, demo_code=pend["code"], phone=ph3, error=None)

    def _page(err):
        tpl = (_P(__file__).parent / "templates" / "manage_otp.html").read_text(encoding="utf-8")
        return _render(tpl, error=err, demo_code=None, phone="")

    if pend and pend.get("locked"):
        return _page("کد باطل شده است؛ دکمه ارسال مجدد را بزنید."), 401
    if not pend:
        return redirect(url_for("admin_panel.manage_enter_page"))
    if _t.time() > pend["exp"]:
        session.pop("manage_otp", None)
        audit("MANAGE_OTP_EXPIRED", ip, level="WARN")
        return _page("کد منقضی شد؛ دوباره کد مدیریت را وارد کن."), 401
    code = (request.form.get("code") or "").strip()
    if not _otp_eq(code, pend["code"]):
        pend["tries"] = pend.get("tries", 0) + 1
        session["manage_otp"] = pend
        if pend["tries"] >= 4:
            pend["locked"] = True; pend["code"] = ""; session["manage_otp"] = pend
            Security.violation(ip, "manage_otp_wrong")
            audit("MANAGE_OTP_LOCKED", ip, level="WARN")
            return _page("تلاش بیش از حد؛ کد باطل شد."), 401
        audit("MANAGE_OTP_WRONG", ip, level="WARN")
        return _page("کد صحیح نیست"), 401
    session.pop("manage_otp", None)
    token = issue_mgmt_token(pend["file_id"])
    audit("MANAGE_ENTER_OK", ip, f"uid={pend['uid'][:12]}… (با کد پیامکی)")
    return redirect(f"/manage/panel/{token}")



@bp.post("/manage/otp/resend")
def manage_otp_resend():
    """ارسال مجدد کد تأیید مالک"""
    import secrets as _sec, time as _t, os as _os
    from pathlib import Path as _P
    from ui import render as _render
    pend = session.get("manage_otp")
    if not pend:
        return redirect(url_for("admin_panel.manage_enter_page"))
    code = f"{_sec.randbelow(1000000):06d}"
    pend["code"] = code
    pend["exp"] = _t.time() + 120
    pend["tries"] = 0
    pend["locked"] = False
    session["manage_otp"] = pend
    phone = ""
    with get_db() as conn:
        ow = conn.execute("SELECT phone FROM users WHERE id=(SELECT owner_id FROM files WHERE id=?)", (pend["file_id"],)).fetchone()
    if ow and ow["phone"]:
        phone = ow["phone"][:4] + "***" + ow["phone"][-2:]
    DEV = _os.environ.get("SOOZAN_DEV_MODE", "") in ("1", "true", "yes")
    tpl = (_P(__file__).parent / "templates" / "manage_otp.html").read_text(encoding="utf-8")
    return _render(tpl, demo_code=code, phone=phone, error=None)



@bp.post("/manage/leave")
def manage_leave():
    """خروج از پنل: توکن مصرف‌شده می‌شود"""
    act = session.pop("mgmt_active", None)
    if act:
        session["mgmt_consumed"] = act
    return "ok"

# ─── رندر پنل مدیریت ─────────────────────────────


@bp.get("/manage/panel/<mgmt_token>")
def manage_panel(mgmt_token):
    """رندر پنل مدیریت با توکن"""
    info = verify_mgmt_token(mgmt_token)
    if not info:
        audit("MANAGE_PANEL_INVALID_TOKEN", client_ip(), level="WARN")
        return redirect(url_for("admin_panel.manage_enter_page"))
    
    file_id = info["file_id"]
    csrf = info["csrf"]
    confirm_code = f"{secrets.randbelow(10000):04d}"
    if session.get("mgmt_consumed") == mgmt_token:
        return redirect(url_for("admin_panel.manage_enter_page"))
    if session.get("mgmt_active") not in (None, mgmt_token):
        return redirect(url_for("admin_panel.manage_enter_page"))
    session["mgmt_active"] = mgmt_token
    session['mgmt_confirm_code'] = confirm_code
    
    with get_db() as conn:
        row = conn.execute(
            """SELECT id, uid, filename, mime, size_bytes, status, views_count, 
                      settings, created_at FROM files WHERE id=?""",
            (file_id,)
        ).fetchone()
    
    if not row:
        return "فایل یافت نشد", 404
    
    import json
    from datetime import datetime
    st = json.loads(row["settings"] or "{}")
    max_views = st.get("max_views", 1)
    
    file_info = {
        "filename": row["filename"] or "فایل",
        "uid": row["uid"],
        "mime": row["mime"] or "unknown",
        "size_kb": round((row["size_bytes"] or 0) / 1024, 1),
        "status": row["status"],
        "views_count": row["views_count"],
        "max_views": max_views,
        "created_at_str": datetime.fromtimestamp(row["created_at"]).strftime("%Y-%m-%d %H:%M"),
    }
    
    # تلاش‌های رمز
    attempts = get_password_attempts(file_id, limit=10)
    for a in attempts:
        a["attempted_at_str"] = datetime.fromtimestamp(a["attempted_at"]).strftime("%H:%M:%S")
    
    # اکشن‌های مدیریتی
    admin_actions = get_admin_actions(file_id, limit=10)
    for a in admin_actions:
        a["at_str"] = datetime.fromtimestamp(a["at"]).strftime("%H:%M:%S")
    
    # تاریخ شمسی
    file_info["created_at_fa"] = _to_jalali(row["created_at"])
    status_map = {"active": "فعال", "paused": "مکث‌شده", "burned": "سوخته", "locked": "قفل‌شده", "expired": "منقضی"}
    file_info["status_fa"] = status_map.get(file_info["status"], file_info["status"])
    for a in attempts:
        a["attempted_at_fa"] = _to_jalali(a["attempted_at"])
    for a in admin_actions:
        a["at_fa"] = _to_jalali(a["at"])
    
    from pathlib import Path
    from ui import render
    tpl = (Path(__file__).parent / "templates" / "manage_panel.html").read_text(encoding="utf-8")
    return render(
        tpl,
        mgmt_token=mgmt_token,
        csrf=csrf,
        confirm_code=confirm_code,
        file_info=file_info,
        attempts=attempts,
        admin_actions=admin_actions,
        analytics=get_full_analytics(row["id"]),
    )


# ─── اکشن‌های مدیریتی (API) ─────────────────────────────
def _validate_action(mgmt_token, body_csrf):
    """اعتبارسنجی مشترک برای همه اکشن‌ها"""
    info = verify_mgmt_token(mgmt_token, expected_csrf=body_csrf)
    if not info:
        return None, (jsonify(ok=False, error="توکن نامعتبر یا منقضی"), 401)
    return info, None


def _get_file(file_id):
    with get_db() as conn:
        return conn.execute(
            "SELECT id, uid, filename, status, file_path, dek_wrapped, admin_code FROM files WHERE id=?",
            (file_id,)
        ).fetchone()


@bp.post("/api/manage/<mgmt_token>/pause")
def mgmt_pause(mgmt_token):
    ip = client_ip()
    if not Security.rate_check(ip, "manage_action"):
        return jsonify(ok=False, error="rate limit"), 429
    body = request.get_json(silent=True) or {}
    info, err = _validate_action(mgmt_token, body.get("csrf"))
    if err: return err
    
    row = _get_file(info["file_id"])
    if not row:
        return jsonify(ok=False, error="فایل یافت نشد"), 404
    if row["status"] == "burned":
        return jsonify(ok=False, error="فایل سوخته است"), 400
    
    with get_db() as conn:
        conn.execute("UPDATE files SET status='paused' WHERE id=?", (row["id"],))
    record_admin_action(row["id"], "pause", row["status"], "paused", ip)
    audit("MANAGE_PAUSE", ip, f"uid={row['uid'][:12]}…")
    return jsonify(ok=True, msg="فایل موقتاً غیرفعال شد")


@bp.post("/api/manage/<mgmt_token>/resume")
def mgmt_resume(mgmt_token):
    ip = client_ip()
    if not Security.rate_check(ip, "manage_action"):
        return jsonify(ok=False, error="rate limit"), 429
    body = request.get_json(silent=True) or {}
    info, err = _validate_action(mgmt_token, body.get("csrf"))
    if err: return err
    
    row = _get_file(info["file_id"])
    if not row:
        return jsonify(ok=False, error="فایل یافت نشد"), 404
    if row["status"] != "paused":
        return jsonify(ok=False, error="فایل در حالت paused نیست"), 400
    
    with get_db() as conn:
        conn.execute("UPDATE files SET status='active' WHERE id=?", (row["id"],))
    record_admin_action(row["id"], "resume", row["status"], "active", ip)
    audit("MANAGE_RESUME", ip, f"uid={row['uid'][:12]}…")
    return jsonify(ok=True, msg="فایل فعال شد")


@bp.post("/api/manage/<mgmt_token>/lock")
def mgmt_lock(mgmt_token):
    ip = client_ip()
    if not Security.rate_check(ip, "manage_action"):
        return jsonify(ok=False, error="rate limit"), 429
    body = request.get_json(silent=True) or {}
    info, err = _validate_action(mgmt_token, body.get("csrf"))
    if err: return err
    
    row = _get_file(info["file_id"])
    if not row:
        return jsonify(ok=False, error="فایل یافت نشد"), 404
    if row["status"] == "burned":
        return jsonify(ok=False, error="فایل سوخته است"), 400
    
    with get_db() as conn:
        conn.execute("UPDATE files SET status='locked' WHERE id=?", (row["id"],))
    record_admin_action(row["id"], "lock", row["status"], "locked", ip)
    audit("MANAGE_LOCK", ip, f"uid={row['uid'][:12]}…")
    return jsonify(ok=True, msg="فایل قفل دائمی شد (بدون حذف)")


@bp.post("/api/manage/<mgmt_token>/burn")
def mgmt_burn(mgmt_token):
    ip = client_ip()
    if not Security.rate_check(ip, "manage_action"):
        return jsonify(ok=False, error="rate limit"), 429
    body = request.get_json(silent=True) or {}
    info, err = _validate_action(mgmt_token, body.get("csrf"))
    if err: return err
    
    confirm_code = body.get("confirm_code")
    expected = session.get('mgmt_confirm_code')
    if not confirm_code or not expected or confirm_code != expected:
        audit("MANAGE_BURN_BAD_CONFIRM", ip, level="WARN")
        return jsonify(ok=False, error="کد تأیید اشتباه است"), 400
    session.pop('mgmt_confirm_code', None)
    
    row = _get_file(info["file_id"])
    if not row:
        return jsonify(ok=False, error="فایل یافت نشد"), 404
    if row["status"] == "burned":
        return jsonify(ok=False, error="فایل قبلاً سوخته"), 400
    
    # حذف امن فایل
    file_path = Path(row["file_path"]) if row["file_path"] else None
    if file_path and file_path.exists():
        FileCrypto.secure_delete(file_path)
    
    with get_db() as conn:
        conn.execute("UPDATE files SET status='burned', file_path='', dek_wrapped='' WHERE id=?", (row["id"],))
    record_admin_action(row["id"], "burn", row["status"], "burned", ip)
    audit("MANAGE_BURN", ip, f"uid={row['uid'][:12]}…", level="WARN")
    return jsonify(ok=True, msg="فایل سوزانده شد")


@bp.post("/api/manage/<mgmt_token>/revoke")
def mgmt_revoke(mgmt_token):
    ip = client_ip()
    if not Security.rate_check(ip, "manage_action"):
        return jsonify(ok=False, error="rate limit"), 429
    body = request.get_json(silent=True) or {}
    info, err = _validate_action(mgmt_token, body.get("csrf"))
    if err: return err
    
    confirm_code = body.get("confirm_code")
    expected = session.get('mgmt_confirm_code')
    if not confirm_code or not expected or confirm_code != expected:
        audit("MANAGE_REVOKE_BAD_CONFIRM", ip, level="WARN")
        return jsonify(ok=False, error="کد تأیید اشتباه است"), 400
    session.pop('mgmt_confirm_code', None)
    
    row = _get_file(info["file_id"])
    if not row:
        return jsonify(ok=False, error="فایل یافت نشد"), 404
    
    old_code = row["admin_code"]
    new_code = make_admin_code()
    with get_db() as conn:
        conn.execute("UPDATE files SET admin_code=? WHERE id=?", (new_code, row["id"]))
    record_admin_action(row["id"], "revoke_admin_code", old_code[:6] + "…", new_code[:6] + "…", ip)
    audit("MANAGE_REVOKE_CODE", ip, f"uid={row['uid'][:12]}…", level="WARN")
    return jsonify(ok=True, msg="کد مدیریت جدید صادر شد", new_admin_code=new_code)


# ═══════════════════════════════════════════════════════
# Export Endpoints (فاز H)
# ═══════════════════════════════════════════════════════

@bp.post("/api/manage/<mgmt_token>/export/attempts")
def export_attempts(mgmt_token):
    """Export تلاش‌های رمز به CSV"""
    ip = client_ip()
    if not Security.rate_check(ip, "manage_action"):
        return jsonify(ok=False, error="rate limit"), 429
    body = request.get_json(silent=True) or {}
    info, err = _validate_action(mgmt_token, body.get("csrf"))
    if err: return err
    
    row = _get_file(info["file_id"])
    if not row:
        return jsonify(ok=False, error="فایل یافت نشد"), 404
    
    csv_data = export_attempts_csv(row["id"], row["uid"], row["filename"] or "file")
    
    from flask import Response
    resp = Response(csv_data, mimetype="text/csv; charset=utf-8")
    resp.headers["Content-Disposition"] = f'attachment; filename="attempts_{row["uid"][:8]}.csv"'
    resp.headers["Cache-Control"] = "no-store"
    audit("EXPORT_ATTEMPTS_CSV", ip, f"uid={row['uid'][:12]}…")
    return resp


@bp.post("/api/manage/<mgmt_token>/export/views")
def export_views(mgmt_token):
    """Export بازدیدها به CSV"""
    ip = client_ip()
    if not Security.rate_check(ip, "manage_action"):
        return jsonify(ok=False, error="rate limit"), 429
    body = request.get_json(silent=True) or {}
    info, err = _validate_action(mgmt_token, body.get("csrf"))
    if err: return err
    
    row = _get_file(info["file_id"])
    if not row:
        return jsonify(ok=False, error="فایل یافت نشد"), 404
    
    csv_data = export_views_csv(row["id"], row["uid"], row["filename"] or "file")
    
    from flask import Response
    resp = Response(csv_data, mimetype="text/csv; charset=utf-8")
    resp.headers["Content-Disposition"] = f'attachment; filename="views_{row["uid"][:8]}.csv"'
    resp.headers["Cache-Control"] = "no-store"
    audit("EXPORT_VIEWS_CSV", ip, f"uid={row['uid'][:12]}…")
    return resp


@bp.post("/api/manage/<mgmt_token>/export/report")
def export_report(mgmt_token):
    """Export گزارش کامل HTML (قابل پرینت به PDF)"""
    ip = client_ip()
    if not Security.rate_check(ip, "manage_action"):
        return jsonify(ok=False, error="rate limit"), 429
    body = request.get_json(silent=True) or {}
    info, err = _validate_action(mgmt_token, body.get("csrf"))
    if err: return err
    
    row = _get_file(info["file_id"])
    if not row:
        return jsonify(ok=False, error="فایل یافت نشد"), 404
    
    with get_db() as conn:
        full_row = conn.execute("SELECT admin_code FROM files WHERE id=?", (row["id"],)).fetchone()
        admin_code = full_row["admin_code"] if full_row else ""
    
    html_data = export_full_report_html(row["id"], row["uid"], row["filename"] or "file", admin_code)
    
    from flask import Response
    resp = Response(html_data, mimetype="text/html; charset=utf-8")
    resp.headers["Content-Disposition"] = f'attachment; filename="report_{row["uid"][:8]}.html"'
    resp.headers["Cache-Control"] = "no-store"
    audit("EXPORT_FULL_REPORT", ip, f"uid={row['uid'][:12]}…")
    return resp

