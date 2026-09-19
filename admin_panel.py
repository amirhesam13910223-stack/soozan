from __future__ import annotations
import hmac as _hmac
import hashlib as _hash
import secrets as _sec
import time as _t
import os as _os
from pathlib import Path
from typing import Optional
from flask import Blueprint, request, redirect, url_for, session, jsonify
from core import get_db, audit, client_ip, Security
from ui import render as _render

bp = Blueprint("admin_panel", __name__)


# ════════════════════════════════════════════════════════════════
# توکن‌سازی و CSRF
# ════════════════════════════════════════════════════════════════
def _derive_mgmt_key() -> bytes:
    key_path = Path(__file__).parent / "data" / "mgmt.key"
    if key_path.exists():
        return key_path.read_bytes()
    key = _sec.token_bytes(32)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key)
    _os.chmod(key_path, 0o600)
    return key


def issue_mgmt_token(file_id: int, ttl: float = 30 * 60) -> str:
    """صدور توکن مدیریت: file_id + exp امضاشده"""
    exp = _t.time() + ttl
    payload = f"{file_id}|{int(exp)}"
    sig = _hmac.new(_derive_mgmt_key(), payload.encode(), "sha256").hexdigest()[:24]
    return f"{payload}|{sig}"


def verify_mgmt_token(token: str) -> Optional[dict]:
    """اعتبارسنجی توکن و بازگرداندن {file_id, exp}"""
    try:
        fid_s, exp_s, sig = token.split("|")
        payload = f"{fid_s}|{exp_s}"
        expected = _hmac.new(_derive_mgmt_key(), payload.encode(), "sha256").hexdigest()[:24]
        if not _hmac.compare_digest(sig, expected):
            return None
        exp = float(exp_s)
        if _t.time() > exp:
            return None
        return {"file_id": int(fid_s), "exp": exp,
                "csrf": _hmac.new(_derive_mgmt_key(), token.encode(), "sha256").hexdigest()[:16]}
    except Exception:
        return None


def _otp_eq(a: str, b: str) -> bool:
    if not a or not b:
        return False
    return _hmac.compare_digest(str(a).encode(), str(b).encode())


# ════════════════════════════════════════════════════════════════
# صفحه ورود کد مدیریت
# ════════════════════════════════════════════════════════════════
@bp.route("/manage", methods=["GET", "POST"])
def manage_enter():
    ip = client_ip()
    tpl = (Path(__file__).parent / "templates" / "manage_enter.html").read_text(encoding="utf-8")

    if request.method == "GET":
        return _render(tpl, error=None, seconds_left=120)

    if not Security.rate_check(ip, "manage_enter"):
        audit("MANAGE_ENTER_RATE_LIMITED", ip, level="WARN")
        return _render(tpl, error="تلاش بیش از حد. چند دقیقه صبر کنید.", seconds_left=120), 429

    admin_code = (request.form.get("admin_code") or "").strip()
    if not admin_code:
        return redirect(url_for("admin_panel.manage_enter"))

    with get_db() as conn:
        row = conn.execute(
            "SELECT id, uid, admin_code, status FROM files WHERE admin_code=?",
            (admin_code,)
        ).fetchone()

    if not row:
        Security.violation(ip, "manage_wrong_code")
        audit("MANAGE_ENTER_WRONG", ip, level="WARN")
        return _render(tpl, error="کد نامعتبر است"), 401

    file_id = row["id"]
    uid = row["uid"]
    status = row["status"]

    # مرحله ۲: OTP به شماره مالک
    with get_db() as conn:
        ow = conn.execute(
            "SELECT phone FROM users WHERE id=(SELECT owner_id FROM files WHERE id=?)",
            (file_id,)
        ).fetchone()
    phone = (ow["phone"] if ow else "") or ""

    if not phone:
        audit("MANAGE_ENTER_NOPHONE", ip, level="WARN")
        return _render(tpl, error="حساب مالک این فایل شماره موبایل ثبت‌شده ندارد."), 403

    code = f"{_sec.randbelow(1000000):06d}"
    session["manage_otp"] = {
        "code": code, "exp": _t.time() + 120, "tries": 0,
        "file_id": file_id, "uid": uid,
    }
    audit("MANAGE_OTP_SENT", ip, f"uid={uid[:12]}… status={status}")
    masked = phone[:4] + "***" + phone[-2:]
    otp_tpl = (Path(__file__).parent / "templates" / "manage_otp.html").read_text(encoding="utf-8")
    DEV = _os.environ.get("SOOZAN_DEV_MODE", "") in ("1", "true", "yes")
    return _render(otp_tpl, demo_code=code if DEV else None, phone=masked,
                   error=None, seconds_left=120)


# ════════════════════════════════════════════════════════════════
# تأیید کد ۶ رقمی
# ════════════════════════════════════════════════════════════════
@bp.post("/manage/otp")
def manage_otp_verify():
    ip = client_ip()
    otp_tpl = (Path(__file__).parent / "templates" / "manage_otp.html").read_text(encoding="utf-8")
    DEV = _os.environ.get("SOOZAN_DEV_MODE", "") in ("1", "true", "yes")
    pend = session.get("manage_otp")

    def page(err, demo=None, phone="", sec=0):
        return _render(otp_tpl, demo_code=demo, phone=phone, error=err, seconds_left=sec)

    if not pend:
        return redirect(url_for("admin_panel.manage_enter"))

    remaining = max(0, int(pend["exp"] - _t.time()))
    if remaining <= 0:
        session.pop("manage_otp", None)
        audit("MANAGE_OTP_EXPIRED", ip, level="WARN")
        return page("کد منقضی شد؛ دوباره کد مدیریت را وارد کن."), 401

    # resend: کد جدید + reload (seconds_left تازه)
    if request.form.get("resend"):
        new_code = f"{_sec.randbelow(1000000):06d}"
        pend["code"] = new_code
        pend["exp"] = _t.time() + 120
        pend["tries"] = 0
        session["manage_otp"] = pend
        phone = ""
        with get_db() as conn:
            ow = conn.execute("SELECT phone FROM users WHERE id=(SELECT owner_id FROM files WHERE id=?)",
                              (pend["file_id"],)).fetchone()
        if ow and ow["phone"]:
            phone = ow["phone"][:4] + "***" + ow["phone"][-2:]
        audit("MANAGE_OTP_RESENT", ip)
        return page(None, demo=new_code if DEV else None, phone=phone, sec=120)

    # قفل: فقط resend
    if pend.get("locked"):
        return page("کد باطل شده است؛ دکمه ارسال مجدد را بزنید.",
                    phone="", sec=0), 401

    code = (request.form.get("code") or "").strip()
    if not _otp_eq(code, pend["code"]):
        pend["tries"] = pend.get("tries", 0) + 1
        if pend["tries"] >= 4:
            pend["locked"] = True
            pend["code"] = ""
            session["manage_otp"] = pend
            Security.violation(ip, "manage_otp_wrong")
            audit("MANAGE_OTP_LOCKED", ip, level="WARN")
            return page("تلاش بیش از حد؛ کد باطل شد. ارسال مجدد بزنید.", sec=0), 401
        session["manage_otp"] = pend
        audit("MANAGE_OTP_WRONG", ip, level="WARN")
        # reload صفحه → seconds_left تازه از سرور
        phone = ""
        with get_db() as conn:
            ow = conn.execute("SELECT phone FROM users WHERE id=(SELECT owner_id FROM files WHERE id=?)",
                              (pend["file_id"],)).fetchone()
        if ow and ow["phone"]:
            phone = ow["phone"][:4] + "***" + ow["phone"][-2:]
        return page("کد صحیح نیست", demo=pend["code"] if DEV else None,
                    phone=phone, sec=remaining), 401

    # موفق
    session.pop("manage_otp", None)
    token = issue_mgmt_token(pend["file_id"])
    audit("MANAGE_ENTER_OK", ip, f"uid={pend['uid'][:12]}…")
    return redirect(f"/manage/panel/{token}")


# ════════════════════════════════════════════════════════════════
# پنل مدیریت
# ════════════════════════════════════════════════════════════════
@bp.get("/manage/panel/<mgmt_token>")
def manage_panel(mgmt_token):
    info = verify_mgmt_token(mgmt_token)
    if not info:
        return redirect(url_for("admin_panel.manage_enter"))

    with get_db() as conn:
        row = conn.execute(
            "SELECT f.id, f.uid, f.filename, f.status, f.mime, f.size_bytes, f.admin_code "
            "FROM files f WHERE f.id=?", (info["file_id"],)
        ).fetchone()
    if not row:
        return redirect(url_for("admin_panel.manage_enter"))

    STATUS_FA = {"active": "فعال", "paused": "متوقف", "locked": "قفل‌شده",
                 "burned": "سوخته", "revoked": "باطل‌شده"}
    file_info = {
        "uid": row["uid"],
        "uid_short": row["uid"][:5] + "…",
        "filename": row["filename"],
        "status": row["status"],
        "status_fa": STATUS_FA.get(row["status"], row["status"]),
        "mime": row["mime"] or "—",
        "size_kb": round((row["size_bytes"] or 0) / 1024, 1),
    }
    tpl = (Path(__file__).parent / "templates" / "manage_panel.html").read_text(encoding="utf-8")
    return _render(tpl, file_info=file_info, mgmt_token=mgmt_token,
                   confirm_code=info["csrf"])


# ════════════════════════════════════════════════════════════════
# اکشن‌های پنل (با step-up OTP برای همه ۵ مورد)
# ════════════════════════════════════════════════════════════════
def _stepup_flow(action: str, mgmt_token: str):
    """جریان دو مرحله‌ای: issue کد → verify کد + اجرای اکشن"""
    mode = request.headers.get("X-Mgmt-Stepup", "")
    info = verify_mgmt_token(mgmt_token)
    if not info:
        return jsonify(ok=False, error="توکن نامعتبر"), 403
    file_id = info["file_id"]

    # تأیید CSRF برای verify
    if mode == "verify":
        form_csrf = request.form.get("confirm_code")
        if form_csrf != info["csrf"]:
            return jsonify(ok=False, error="توکن جلسه نامعتبر"), 403

    if mode == "issue":
        phone = ""
        with get_db() as c:
            ow = c.execute("SELECT phone FROM users WHERE id=(SELECT owner_id FROM files WHERE id=?)",
                           (file_id,)).fetchone()
        if ow and ow["phone"]:
            phone = ow["phone"]
        if not phone:
            return jsonify(ok=False, error="شماره مالک یافت نشد"), 403
        code = f"{_sec.randbelow(1000000):06d}"
        session["mgmt_stepup"] = {
            "token": mgmt_token, "action": action,
            "code": code, "exp": _t.time() + 120, "tries": 0,
        }
        audit("MGMT_STEPUP_SENT", client_ip(), f"action={action}")
        DEV = _os.environ.get("SOOZAN_DEV_MODE", "") in ("1", "true", "yes")
        return jsonify(ok=True, demo=code if DEV else None)

    if mode != "verify":
        return jsonify(ok=False, error="تأیید پله‌ای لازم است"), 403

    st = session.get("mgmt_stepup")
    if not st or st["token"] != mgmt_token or st["action"] != action:
        return jsonify(ok=False, error="اول کد را درخواست کن"), 403
    if _t.time() > st["exp"]:
        session.pop("mgmt_stepup", None)
        return jsonify(ok=False, error="کد منقضی شد"), 401
    code = (request.form.get("code") or "").strip()
    if not _otp_eq(code, st["code"]):
        st["tries"] = st.get("tries", 0) + 1
        if st["tries"] >= 4:
            session.pop("mgmt_stepup", None)
            return jsonify(ok=False, error="کد باطل شد"), 401
        session["mgmt_stepup"] = st
        return jsonify(ok=False, error="کد صحیح نیست"), 401
    session.pop("mgmt_stepup", None)
    return None  # OK — caller proceeds


def _run_action(action: str, file_id: int):
    """اجرای واقعی اکشن روی فایل"""
    with get_db() as conn:
        row = conn.execute("SELECT status, file_path FROM files WHERE id=?", (file_id,)).fetchone()
        if not row:
            return jsonify(ok=False, error="فایل یافت نشد"), 404
        st = row["status"]
        if action == "pause":
            if st != "active":
                return jsonify(ok=False, error="فایل فعال نیست"), 400
            conn.execute("UPDATE files SET status='paused' WHERE id=?", (file_id,))
        elif action == "resume":
            if st not in ("paused", "locked"):
                return jsonify(ok=False, error="فایل متوقف/قفل نیست"), 400
            conn.execute("UPDATE files SET status='active' WHERE id=?", (file_id,))
        elif action == "burn":
            try:
                if row["file_path"] and Path(row["file_path"]).exists():
                    Path(row["file_path"]).unlink()
            except Exception:
                pass
            conn.execute("UPDATE files SET status='burned' WHERE id=?", (file_id,))
        elif action == "revoke":
            conn.execute("UPDATE files SET status='revoked', admin_code=NULL WHERE id=?", (file_id,))
        elif action == "copy_id":
            uid = conn.execute("SELECT uid FROM files WHERE id=?", (file_id,)).fetchone()["uid"]
            audit("MGMT_COPY_ID", client_ip())
            return jsonify(ok=True, uid=uid, link=f"/i/{uid}")
    audit(f"MGMT_{action.upper()}", client_ip(), f"file_id={file_id}")
    return jsonify(ok=True)


@bp.post("/api/manage/<mgmt_token>/<action>")
def mgmt_action(mgmt_token, action):
    if action not in ("pause", "resume", "burn", "revoke", "copy_id"):
        return jsonify(ok=False, error="اکشن ناشناخته"), 404
    deny = _stepup_flow(action, mgmt_token)
    if deny:
        return deny
    info = verify_mgmt_token(mgmt_token)
    return _run_action(action, info["file_id"])


def register(app):
    app.register_blueprint(bp)
