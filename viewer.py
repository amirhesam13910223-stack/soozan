#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
👁️ موتور نمایش سوزان — قوانین سکوت، درگاه رمز، توکن یک‌بارمصرف محتوا
"""

import json
import time
import secrets
import threading
from pathlib import Path
from flask import Blueprint, request, jsonify, Response
from core import get_db, Security, FileCrypto, audit, client_ip, verify_file_password
from admin_infra import record_password_attempt
from renderer import issue_token, pop_token, render_image, render_text

bp = Blueprint("viewer", __name__)
TEMPLATES = Path(__file__).parent / "templates"

DEFAULT_END_MESSAGE = "این محتوا دیگر در دسترس نیست."

_LOCK = threading.Lock()
_VIEW_TOKENS = {}   # token -> {uid, ip, exp}


# ── مهاجرست دیتابیس (ستون‌های جدید فاز ۳) ──────────────
def _migrate():
    with get_db() as c:
        cols = {r["name"] for r in c.execute("PRAGMA table_info(files)").fetchall()}
        for col, ddl in [
            ("entered_at",  "ALTER TABLE files ADD COLUMN entered_at REAL"),
            ("revealed_at", "ALTER TABLE files ADD COLUMN revealed_at REAL"),
            ("view_started_at", "ALTER TABLE files ADD COLUMN view_started_at REAL"),
            ("viewer_ip",   "ALTER TABLE files ADD COLUMN viewer_ip TEXT"),
            ("wrong_pins",  "ALTER TABLE files ADD COLUMN wrong_pins INTEGER DEFAULT 0"),
        ]:
            if col not in cols:
                c.execute(ddl)
_migrate()


def _row(uid):
    with get_db() as c:
        return c.execute("SELECT * FROM files WHERE uid=?", (uid,)).fetchone()



def _record_view(uid: str, file_id: int, ip: str, user_agent: str, now: float):
    """ثبت بازدید در جدول views"""
    device = "mobile" if "Mobile" in user_agent else "desktop"
    with get_db() as c:
        c.execute(
            "UPDATE files SET revealed_at=COALESCE(revealed_at,?), "
            "views_count=views_count+1, viewer_ip=COALESCE(viewer_ip,?) WHERE uid=?",
            (now, ip, uid)
        )
        r2 = c.execute("SELECT settings FROM files WHERE uid=?", (uid,)).fetchone()
        try:
            st2 = json.loads(r2["settings"] or "{}")
        except Exception:
            st2 = {}
        if st2.get("timer_mode") == "on_reveal":
            c.execute("UPDATE files SET view_started_at=? WHERE uid=?", (now, uid))
        c.execute(
            "INSERT INTO views(file_id, ip, user_agent, viewed_at, device) VALUES (?,?,?,?,?)",
            (file_id, ip, user_agent[:200], now, device)
        )


def _settings(row):
    try:
        return json.loads(row["settings"] or "{}")
    except Exception:
        return {}


def viewer_state(row, now, ip):
    """وضعیت از دید بیننده — فقط open یعنی قابل شروع"""
    if row is None:
        return "unknown"
    if row["status"] in ("burned", "paused", "locked"):
        return "gone"
    if not row["file_path"]:
        return "expired"
    if row["expires_at"] and now > row["expires_at"]:
        return "expired"
    st = _settings(row)
    # تایمر نمایش فقط حین نمایش قطع می‌کند (alive_state)؛
    # مانع ورود دوباره نمی‌شود. ورود دوباره فقط با سهمیه مشاهده و انقضای جهانی محدود است.
    mv = st.get("max_views", 1)
    if mv and row["views_count"] >= mv:
        return "expired"
    if st.get("ip_once") and row["viewer_ip"] and row["viewer_ip"] != ip:
        return "gone"
    return "open"


def alive_state(row, now):
    """برای نظرسنجی حین نمایش — تایمر/انقضا قطع می‌کند، سهمیه نه"""
    if row is None or row["status"] in ("burned", "paused", "locked"):
        return "gone"
    if row["expires_at"] and now > row["expires_at"]:
        return "gone"
    st = _settings(row)
    tm = st.get("timer_mode", "none")
    if tm != "none":
        try:
            start = row["view_started_at"]
        except Exception:
            start = None
        if start and now > start + st.get("timer_seconds", 30):
            return "gone"
    return "ok"


def _end_msg(row):
    if row is None:
        return DEFAULT_END_MESSAGE
    st = _settings(row)
    return (st.get("end_message") or "").strip() or DEFAULT_END_MESSAGE


# ── صفحه ورود آیدی ────────────────────────────────────
@bp.get("/v/<uid>")
def view_page(uid):
    ip = client_ip()
    if not Security.rate_check(ip, "view"):
        return Response("429", status=429)
    now = time.time()
    row = _row(uid)
    state = viewer_state(row, now, ip)
    st = _settings(row) if row else {}

    # شروع تایمر on_view هنگام ورود آیدی
    if state == "open" and st.get("timer_mode") == "on_view":
        with get_db() as c:
            c.execute("UPDATE files SET entered_at=COALESCE(entered_at,?), view_started_at=? WHERE uid=?",
                      (now, now, uid))
        row = _row(uid)
        st = _settings(row)
    if state == "open":
        boot_state = "gate" if st.get("password") else "ready"
    else:
        boot_state = "gone"

    boot = {
        "state": boot_state,
        "uid": uid,
        "msg": DEFAULT_END_MESSAGE if state == "unknown" else _end_msg(row),
        "intro": st.get("intro_message", "") if state == "open" else "",
        "family": row["mime"] and (
            "image" if row["mime"].startswith("image/") else
            "audio" if row["mime"].startswith("audio/") else
            "pdf" if row["mime"] == "application/pdf" else "text"
        ) if row else "text",
        "mime": row["mime"] if row else "",
        "view": {
            "zoom": st.get("image_zoom", True), "rotate": st.get("image_rotate", True),
            "pan": st.get("image_pan", True), "pdfzoom": st.get("pdf_zoom", True),
            "seek": st.get("audio_seek", True), "copy": st.get("text_copy", False),
        },
        "wm": st.get("watermark", ""),

    }
    boot_json = json.dumps(boot, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    audit("VIEW_RESOLVE", ip, f"state={boot_state} known={row is not None}")
    tpl = (TEMPLATES / "viewer.html").read_text(encoding="utf-8")
    from ui import render
    return render(tpl, boot=boot_json)


# ── درگاه رمز / صدور توکن ─────────────────────────────
@bp.post("/api/v/unlock/<uid>")
def unlock(uid):
    ip = client_ip()
    if not Security.rate_check(ip, "reveal"):
        return jsonify(ok=False, reason="gone"), 429
    now = time.time()
    row = _row(uid)
    if viewer_state(row, now, ip) != "open":
        return jsonify(ok=False, reason="gone", msg=_end_msg(row)), 410

    st = _settings(row)
    pw_needed = st.get("password")
    if pw_needed:
        given = (request.get_json(silent=True) or {}).get("password", "")
        # مقایسه constant-time — جلوگیری از timing attacks
        if not verify_file_password(given, pw_needed):
            wrong = (row["wrong_pins"] or 0) + 1
            limit = max(1, min(10, int(st.get("password_attempts", 5))))
            if wrong >= limit:
                action = st.get("on_password_fail", "burn")
                new_status = "burned" if action == "burn" else "locked"
                with get_db() as c:
                    c.execute("UPDATE files SET wrong_pins=?, status=? WHERE uid=?",
                              (wrong, new_status, uid))
                audit("VIEW_LOCKED_BURNED", ip, f"action={action}")
                return jsonify(ok=False, reason="locked", msg=_end_msg(row)), 410
            with get_db() as c:
                c.execute("UPDATE files SET wrong_pins=? WHERE uid=?", (wrong, uid))
            Security.violation(ip, "viewer_wrong_pw")
            record_password_attempt(row["id"], ip, success=False)
            return jsonify(ok=False, reason="wrongpin", left=limit - wrong), 403

    token = secrets.token_urlsafe(24)
    with _LOCK:
        _VIEW_TOKENS[token] = {"uid": uid, "ip": ip, "exp": now + 90}
    audit("VIEW_UNLOCK_OK", ip)
    record_password_attempt(row["id"], ip, success=True)
    # صدور توکن‌های رندر برای هر نوع محتوا
    render_tokens = {}
    family = row["mime"] and (
        "image" if row["mime"].startswith("image/") else
        "audio" if row["mime"].startswith("audio/") else
        "pdf" if row["mime"] == "application/pdf" else "text"
    )
    if family == "image":
        render_tokens["image"] = issue_token(uid, ip, "image", ttl=60)
    elif family == "text":
        render_tokens["text"] = issue_token(uid, ip, "text", ttl=60)
    elif family == "audio":
        render_tokens["audio"] = issue_token(uid, ip, "audio", ttl=120)
    # PDF فعلاً با روش قدیمی (تا نصب PyMuPDF)
    return jsonify(ok=True, token=token, render_tokens=render_tokens)


# ── رندر تصویر (فایل خام هرگز ارسال نمی‌شود) ───
@bp.get("/api/v/image/<uid>")
def image_render(uid):
    """رندر تصویر سمت سرور با حذف متادیتا و افزودن واترمارک پیکسلی"""
    ip = client_ip()
    token = request.args.get("token", "")
    t = pop_token(token, uid, ip, "image")
    if not t:
        audit("RENDER_BAD_TOKEN", ip, level="WARN")
        return jsonify(ok=False, reason="gone"), 410
    row = _row(uid)
    if not row or not row["file_path"]:
        return jsonify(ok=False, reason="gone"), 410
    try:
        with open(row["file_path"], "rb") as f:
            ct = f.read()
        plain = FileCrypto.decrypt_file(ct, row["dek_wrapped"])
    except Exception:
        return jsonify(ok=False, reason="gone"), 410
    st = _settings(row)
    wm = st.get("watermark", "")
    try:
        img_bytes, mime = render_image(plain, wm)
    except Exception as e:
        audit("RENDER_FAIL", ip, f"image error: {e}", level="ERROR")
        return jsonify(ok=False, reason="error"), 500
    
    # ثبت بازدید (اولین بار)
    now = time.time()
    first = row["revealed_at"] is None
    _record_view(uid, row["id"], ip, request.headers.get("User-Agent", ""), now)
    audit("RENDER_IMAGE", ip, f"uid={uid[:12]}… first={first}")
    resp = Response(img_bytes, mimetype=mime)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

# ── رندر متن (HTML escape شده، غیرقابل‌دانلود) ───
@bp.get("/api/v/text/<uid>")
def text_render(uid):
    """رندر متن با escape امن، تحویل به‌صورت HTML"""
    ip = client_ip()
    token = request.args.get("token", "")
    t = pop_token(token, uid, ip, "text")
    if not t:
        audit("RENDER_BAD_TOKEN", ip, level="WARN")
        return jsonify(ok=False, reason="gone"), 410
    row = _row(uid)
    if not row or not row["file_path"]:
        return jsonify(ok=False, reason="gone"), 410
    try:
        with open(row["file_path"], "rb") as f:
            ct = f.read()
        plain = FileCrypto.decrypt_file(ct, row["dek_wrapped"])
    except Exception:
        return jsonify(ok=False, reason="gone"), 410
    text = render_text(plain)
    import html
    escaped = html.escape(text, quote=True)
    
    # ثبت بازدید
    now = time.time()
    first = row["revealed_at"] is None
    _record_view(uid, row["id"], ip, request.headers.get("User-Agent", ""), now)
    audit("RENDER_TEXT", ip, f"uid={uid[:12]}… first={first}")
    resp = Response(escaped, mimetype="text/plain; charset=utf-8")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

# ── streaming صوت (فایل یکجا در حافظه، ولی با توکن یک‌بارمصرف) ───
@bp.get("/api/v/audio/<uid>")
def audio_stream(uid):
    """پخش صوت با توکن یک‌بارمصرف"""
    ip = client_ip()
    token = request.args.get("token", "")
    t = pop_token(token, uid, ip, "audio")
    if not t:
        audit("RENDER_BAD_TOKEN", ip, level="WARN")
        return jsonify(ok=False, reason="gone"), 410
    row = _row(uid)
    if not row or not row["file_path"]:
        return jsonify(ok=False, reason="gone"), 410
    try:
        with open(row["file_path"], "rb") as f:
            ct = f.read()
        plain = FileCrypto.decrypt_file(ct, row["dek_wrapped"])
    except Exception:
        return jsonify(ok=False, reason="gone"), 410
    # ثبت بازدید
    now = time.time()
    first = row["revealed_at"] is None
    _record_view(uid, row["id"], ip, request.headers.get("User-Agent", ""), now)
    audit("RENDER_AUDIO", ip, f"uid={uid[:12]}… first={first}")
    resp = Response(plain, mimetype=row["mime"])
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Content-Disposition"] = "inline"
    return resp





# ── نظرسنجی زنده + ضربان + پایان ─────────────────────
@bp.get("/api/v/alive/<uid>")
def alive(uid):
    now = time.time()
    row = _row(uid)
    if alive_state(row, now) != "ok":
        return jsonify(ok=False, msg=_end_msg(row))
    return jsonify(ok=True)


@bp.post("/api/v/ping/<uid>")
def ping(uid):
    row = _row(uid)
    if not row:
        return jsonify(ok=False), 404
    now = time.time()
    with get_db() as c:
        c.execute("INSERT INTO active_views(file_id, user_id, started_at, last_ping) "
                  "VALUES (?,?,?,?) ON CONFLICT(file_id) DO UPDATE SET last_ping=?",
                  (row["id"], 0, now, now, now))
    return jsonify(ok=True)


@bp.post("/api/v/close/<uid>")
def close(uid):
    row = _row(uid)
    if not row:
        return jsonify(ok=False), 404
    now = time.time()
    with get_db() as c:
        c.execute("DELETE FROM active_views WHERE file_id=?", (row["id"],))
        c.execute("UPDATE views SET duration=? WHERE file_id=? AND duration IS NULL",
                  (int(now - (row["revealed_at"] or now)), row["id"]))
    return jsonify(ok=True)


# ── صفحه ورود آیدی (خانه اپلیکیشن) ─────────────────
@bp.get("/i")
def enter_id():
    """صفحه ورود آیدی فایل (بدون منو)"""
    from ui import render
    tpl = (TEMPLATES / "enter.html").read_text(encoding="utf-8")
    return render(tpl)


# ── پاک‌ساز: امحای واقعی فایل‌های مرده ────────────────
def _cleaner():
    while True:
        time.sleep(3)
        now = time.time()
        with get_db() as c:
            rows = c.execute("SELECT id,file_path,status,expires_at,entered_at,revealed_at,"
                             "views_count,settings FROM files WHERE file_path!=''").fetchall()
        for r in rows:
            st = {}
            try:
                st = json.loads(r["settings"] or "{}")
            except Exception:
                pass
            dead = r["status"] == "burned"
            if not dead and r["expires_at"] and now > r["expires_at"]:
                dead = True
            mv = st.get("max_views", 1)
            if not dead and r["revealed_at"] and mv and r["views_count"] >= mv:
                dead = True
            # تایمر نمایش هرگز فایل را امحا نمی‌کند؛
            # امحا فقط با: status burned / انقضای جهانی / اتمام سهمیه مشاهده
            if dead:
                FileCrypto.secure_delete(Path(r["file_path"]))
                with get_db() as c:
                    c.execute("UPDATE files SET file_path='' WHERE id=?", (r["id"],))
                audit("VIEW_CLEANED", detail=f"id={r['id']}")

threading.Thread(target=_cleaner, daemon=True).start()


# ── PDF موقت (تا نصب PyMuPDF برای رندر کامل) ───
@bp.get("/api/v/pdf/<uid>")
def pdf_temp(uid):
    """PDF با توکن یک‌بارمصرف (موقت تا رندر کامل)"""
    ip = client_ip()
    token = request.args.get("token", "")
    now = time.time()
    with _LOCK:
        t = _VIEW_TOKENS.pop(token, None)
    if not t or t["uid"] != uid or t["ip"] != ip or now > t["exp"]:
        audit("PDF_BAD_TOKEN", ip, level="WARN")
        return jsonify(ok=False, reason="gone"), 410
    row = _row(uid)
    if not row or not row["file_path"]:
        return jsonify(ok=False, reason="gone"), 410
    try:
        with open(row["file_path"], "rb") as f:
            ct = f.read()
        plain = FileCrypto.decrypt_file(ct, row["dek_wrapped"])
    except Exception:
        return jsonify(ok=False, reason="gone"), 410
    audit("RENDER_PDF_TEMP", ip, f"uid={uid[:12]}…")
    resp = Response(plain, mimetype="application/pdf")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Content-Disposition"] = "inline"
    return resp

