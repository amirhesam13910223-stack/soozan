from __future__ import annotations
import hmac as _hmac
import hashlib as _hash
import secrets as _sec
import time as _t
import os as _os
import re
from pathlib import Path
from typing import Optional
from flask import Blueprint, request, redirect, url_for, session, jsonify
from core import get_db, audit, client_ip, Security, real_status
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
        rev = _meta_get("mgmt_revoke_ts")
        if rev and (exp - 1800) < float(rev):
            return None
        return {"file_id": int(fid_s), "exp": exp,
                "csrf": _hmac.new(_derive_mgmt_key(), token.encode(), "sha256").hexdigest()[:16]}
    except Exception:
        return None


def _to_jalali(ts) -> str:
    """تبديل timestamp به شمسی: YYYY/MM/DD HH:MM"""
    if not ts:
        return "—"
    import datetime as _dt
    d = _dt.datetime.fromtimestamp(float(ts))
    gy, gm, gd = d.year, d.month, d.day
    g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    gy2 = gy - 1600
    g_day_no = 365 * gy2 + (gy2 + 3) // 4 - (gy2 + 99) // 100 + (gy2 + 399) // 400 + g_d_m[gm - 1] + gd - 1
    j_day_no = g_day_no - 79
    j_np = j_day_no // 12053
    j_day_no %= 12053
    jy = 979 + 33 * j_np + 4 * (j_day_no // 1461)
    j_day_no %= 1461
    if j_day_no >= 366:
        jy += (j_day_no - 1) // 365
        j_day_no = (j_day_no - 1) % 365
    if j_day_no < 186:
        jm = 1 + j_day_no // 31
        jd = 1 + j_day_no % 31
    else:
        jm = 7 + (j_day_no - 186) // 30
        jd = 1 + (j_day_no - 186) % 30
    return f"{jy:04d}/{jm:02d}/{jd:02d}  {d.hour:02d}:{d.minute:02d}"






def _meta_get(k):
    with get_db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, val TEXT)")
        r = c.execute("SELECT val FROM meta WHERE key=?", (k,)).fetchone()
        return r["val"] if r else None


def _meta_set(k, v):
    with get_db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, val TEXT)")
        c.execute("INSERT OR REPLACE INTO meta(key,val) VALUES(?,?)", (k, str(v)))


TRASH = Path(__file__).parent / "data" / "trash"


def _purge_trash():
    import json as _jp
    if not TRASH.exists():
        return
    for mp in TRASH.glob("*.meta.json"):
        try:
            m = _jp.loads(mp.read_text(encoding="utf-8"))
            if _t.time() > m.get("until", 0):
                fp = TRASH / (m["uid"] + ".enc")
                if fp.exists():
                    fp.unlink()
                mp.unlink()
        except Exception:
            try:
                mp.unlink()
            except Exception:
                pass


def _trash_info(uid):
    import json as _jp
    mp = TRASH / (uid + ".meta.json")
    if not mp.exists():
        return None
    try:
        m = _jp.loads(mp.read_text(encoding="utf-8"))
        if _t.time() > m.get("until", 0):
            return None
        m["left_min"] = max(1, int((m["until"] - _t.time()) // 60))
        return m
    except Exception:
        return None

def _restore_left(rd, trash):
    """دقیقه باقی‌مانده پنجره ۱ ساعته بازیابی پس از غیرفعال‌شدن"""
    if _meta_get("restore_used_" + str(rd.get("uid"))):
        return None
    if trash:
        return trash.get("left_min")
    now = _t.time()
    st = rd.get("status")
    vc = rd.get("views_count") or 0
    try:
        stg = __import__("json").loads(rd.get("settings") or "{}")
    except Exception:
        stg = {}
    mv = int(stg.get("max_views") or 0)
    if st == "burned":
        return None
    if mv and vc >= mv:
        with get_db() as c:
            r = c.execute("SELECT MAX(viewed_at) AS t FROM views WHERE file_id=?", (rd["id"],)).fetchone()
        last = r["t"] if r and r["t"] else None
        if last:
            left = (float(last) + 3600 - now) / 60
            return max(1, int(left)) if left > 0 else None
        return None
    if rd.get("expires_at") and now > float(rd["expires_at"]):
        left = (float(rd["expires_at"]) + 3600 - now) / 60
        return max(1, int(left)) if left > 0 else None
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
        from flask import make_response
        _resp = make_response(_render(tpl, error=None, seconds_left=120))
        _resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
        _resp.headers["Pragma"] = "no-cache"
        _resp.headers["Expires"] = "0"
        return _resp

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
    DEV = _os.environ.get("SOOZAN_DEV_MODE", "") in ("1", "true", "yes") or client_ip() in ("127.0.0.1", "::1", "localhost")
    session["manage_otp_phone"] = masked
    return redirect(url_for("admin_panel.manage_otp_page"))


# ════════════════════════════════════════════════════════════════
# تأیید کد ۶ رقمی
# ════════════════════════════════════════════════════════════════
@bp.post("/manage/otp")
def manage_otp_verify():
    ip = client_ip()
    otp_tpl = (Path(__file__).parent / "templates" / "manage_otp.html").read_text(encoding="utf-8")
    DEV = _os.environ.get("SOOZAN_DEV_MODE", "") in ("1", "true", "yes") or client_ip() in ("127.0.0.1", "::1", "localhost")
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
        pend["locked"] = False
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
            "SELECT f.*, (SELECT COUNT(*) FROM views v WHERE v.file_id=f.id) AS vc, (SELECT MIN(v.viewed_at) FROM views v WHERE v.file_id=f.id) AS fts, (SELECT MAX(v.viewed_at) FROM views v WHERE v.file_id=f.id) AS lts FROM files f WHERE f.id=?", (info["file_id"],)
        ).fetchone()
        devs = conn.execute(
            "SELECT device, COUNT(*) AS c FROM views v WHERE v.file_id=? GROUP BY device ORDER BY c DESC",
            (info["file_id"],)
        ).fetchall()
    if not row:
        return redirect(url_for("admin_panel.manage_enter"))

    STATUS_FA = {"active": "فعال", "paused": "متوقف", "locked": "قفل‌شده",
                 "burned": "سوخته", "revoked": "باطل‌شده"}
    rd = dict(row)
    import json as _js, os as _osx
    try:
        stg = _js.loads(rd.get("settings") or "{}")
    except Exception:
        stg = {}
    ow = None
    if rd.get("owner_id"):
        with get_db() as c2:
            ow = c2.execute("SELECT full_name AS un, phone AS ph FROM users WHERE id=?", (rd["owner_id"],)).fetchone()
    fp = rd.get("file_path")
    disk_exists = bool(fp and _osx.path.exists(fp))
    if disk_exists:
        disk_fa = f"{_osx.path.getsize(fp) / 1024:.1f} KB"
    elif rd["status"] == "burned":
        disk_fa = "سوخته 🔥"
    else:
        disk_fa = "حذف‌شده"
    mv = int(stg.get("max_views") or 0)
    vc = rd.get("views_count") or 0
    pw_val = next((stg[k] for k in ('password', 'pw', 'pass', 'pin', 'passcode', 'file_password') if stg.get(k)), None)
    has_pw = bool(pw_val)
    pw_is_hash = bool(pw_val) and re.fullmatch(r"[0-9a-fA-F]{32,128}", str(pw_val)) is not None
    lock_n = next((int(stg[k]) for k in ('lock_after_wrong', 'max_wrong', 'wrong_limit', 'lock_after', 'lock_tries', 'max_wrong_pins', 'lock_after_tries') if stg.get(k)), 0)
    _sz = rd.get("size_bytes") or 0
    if not _sz:
        _fp = rd.get("file_path")
        _cand = Path(_fp) if (_fp and Path(_fp).exists()) else (TRASH / (rd["uid"] + ".enc"))
        if _cand.exists():
            _sz = max(0, _cand.stat().st_size - 28)
            with get_db() as _cs:
                _cs.execute("UPDATE files SET size_bytes=? WHERE id=?", (_sz, rd["id"]))
        rd["size_bytes"] = _sz
    st_real, st_badge, st_group, st_detail = real_status(rd, stg, disk_exists)
    dev_fa = "، ".join(((d["device"] or "نامشخص")[:24] + " ×" + str(d["c"])) for d in devs) or "—"
    file_info = {
        "uid": rd["uid"],
        "uid_short": rd["uid"][:5] + "…",
        "filename": rd["filename"],
        "status": rd["status"],
        "status_real": st_real,
        "status_group": st_group,
        "status_fa": st_badge,
        "status_detail": st_detail,
        "mime": rd.get("mime") or "—",
        "size_kb": round((rd.get("size_bytes") or 0) / 1024, 1),
        "views": vc,
        "max_views": mv,
        "views_left": (mv - vc) if mv else "∞",
        "created_fa": _to_jalali(rd.get("created_at")),
        "first_fa": _to_jalali(rd.get("first_viewed")),
        "last_fa": _to_jalali(rd.get("lts")),
        "owner_fa": (ow["un"] + " · " + ow["ph"][:4] + "***" + ow["ph"][-2:]) if (ow and ow["ph"]) else (ow["un"] if ow else "—"),
        "disk_fa": disk_fa,
        "disk_exists": disk_exists,
        "has_pw": has_pw,
        "pw_recoverable": has_pw and not pw_is_hash,
        "pw_fa": ("دارد 🔒" if has_pw else "ندارد") + ("" if (not has_pw or not pw_is_hash) else " (هش — غیرقابل بازیابی)"),
        "ok_count": vc,
        "bad_count": rd.get("wrong_pins") or 0,
        "lock_fa": f"بعد از {lock_n} رمز غلط" if lock_n else "خاموش",
        "exp_fa": _to_jalali(rd.get("expires_at")) if rd.get("expires_at") else "—",
        "dev_fa": dev_fa,
        "note": stg.get("private_note") or "",
        "intro": stg.get("intro_message") or "",
        "endm": stg.get("end_message") or "",
        "exp_ts": rd.get("expires_at") or 0,
        "now_ts": _t.time(),
        "created_ts": rd.get("created_at") or 0,
        "trash": _trash_info(rd["uid"]),
        "restore_left": _restore_left(rd, _trash_info(rd["uid"])),
    }
    _purge_trash()
    with get_db() as c4:
        vrows = c4.execute("SELECT ip, device, duration, viewed_at FROM views WHERE file_id=? ORDER BY viewed_at DESC LIMIT 20", (info["file_id"],)).fetchall()
    views_rows = [{"ts_fa": _to_jalali(v["viewed_at"]), "ip": v["ip"] or "—", "dev": (v["device"] or "نامشخص")[:24], "dur": f"{int(v['duration'] or 0)} ثانیه"} for v in vrows]
    recent_wrong = None
    try:
        with get_db() as c5:
            ecol = {r["name"] for r in c5.execute("PRAGMA table_info(events)")}
            tcol = next((x for x in ("ts", "created_at", "time") if x in ecol), None)
            acol = next((x for x in ("action", "type", "name", "event") if x in ecol), None)
            icol = next((x for x in ("ip", "client_ip", "addr") if x in ecol), None)
            dcol = next((x for x in ("detail", "msg", "message", "extra") if x in ecol), None)
            if tcol and acol:
                uidq = rd["uid"][:12]
                cnt = 0
                ips = set()
                for er in c5.execute(f"SELECT * FROM events WHERE {tcol} > ? ORDER BY {tcol} DESC LIMIT 30", (_t.time() - 600,)).fetchall():
                    act = str(er[acol] or "")
                    det = str(er[dcol] or "") if dcol else ""
                    if ("WRONG" in act or "FAIL" in act) and (uidq in det or uidq in act):
                        cnt += 1
                        if icol:
                            ips.add(str(er[icol]))
                if cnt:
                    recent_wrong = {"count": cnt, "ips": "، ".join(sorted(ips)) or "—"}
    except Exception:
        recent_wrong = None
    tpl = (Path(__file__).parent / "templates" / "manage_panel.html").read_text(encoding="utf-8")
    return _render(tpl, file_info=file_info, mgmt_token=mgmt_token,
                   confirm_code=info["csrf"],
                   copy_result=session.pop("stepup_result", None),
                   stepup_error=session.pop("stepup_error", None),
                   stepup_msg=session.pop("stepup_msg", None),
                   views_rows=views_rows, recent_wrong=recent_wrong)


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
        DEV = _os.environ.get("SOOZAN_DEV_MODE", "") in ("1", "true", "yes") or client_ip() in ("127.0.0.1", "::1", "localhost")
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
        row = conn.execute("SELECT status, file_path, uid FROM files WHERE id=?", (file_id,)).fetchone()
        if not row:
            return jsonify(ok=False, error="فایل یافت نشد"), 404
        st = row["status"]
        from core import real_status as _rs2
        import json as _js3
        try:
            _stg3 = _js3.loads(row["settings"] or "{}")
        except Exception:
            _stg3 = {}
        _k3, _f3, _g3, _d3 = _rs2(dict(row), _stg3, bool(row["file_path"] and Path(row["file_path"]).exists()))
        if _g3 == "bad" and action not in ("revoke_sessions",):
            return jsonify(ok=False, error="این فایل دیگر موجود نیست"), 409
        if action == "pause":
            if st != "active":
                return jsonify(ok=False, error="فایل فعال نیست"), 400
            conn.execute("UPDATE files SET status='paused' WHERE id=?", (file_id,))
        elif action == "resume":
            if st not in ("paused", "locked"):
                return jsonify(ok=False, error="فایل متوقف/قفل نیست"), 400
            conn.execute("UPDATE files SET status='active' WHERE id=?", (file_id,))
        elif action == "burn":
            _purge_trash()
            import shutil as _sh, json as _jm, os as _osm
            TRASH.mkdir(parents=True, exist_ok=True)
            _osm.chmod(TRASH, 0o700)
            src = row["file_path"]
            if src and Path(src).exists():
                _sh.move(src, str(TRASH / (row["uid"] + ".enc")))
                (TRASH / (row["uid"] + ".meta.json")).write_text(
                    _jm.dumps({"uid": row["uid"], "until": _t.time() + 3600, "orig": src}), encoding="utf-8")
            conn.execute("UPDATE files SET status='burned' WHERE id=?", (file_id,))
        elif action == "revoke":
            conn.execute("UPDATE files SET status='revoked', admin_code=NULL WHERE id=?", (file_id,))
        elif action == "revoke_sessions":
            _meta_set("mgmt_revoke_ts", _t.time())
            audit("MGMT_REVOKE_ALL", client_ip())
            return jsonify(ok=True)
        elif action == "copy_id":
            uid = conn.execute("SELECT uid FROM files WHERE id=?", (file_id,)).fetchone()["uid"]
            audit("MGMT_COPY_ID", client_ip())
            return jsonify(ok=True, uid=uid, link=f"/i/{uid}")
    audit(f"MGMT_{action.upper()}", client_ip(), f"file_id={file_id}")
    return jsonify(ok=True)


@bp.post("/api/manage/<mgmt_token>/<action>")
def mgmt_action(mgmt_token, action):
    if action not in ("pause", "resume", "burn", "revoke", "copy_id", "restore", "revoke_sessions", "edit_capacity", "edit_expiry", "edit_note", "edit_intro", "edit_end"):
        return jsonify(ok=False, error="اکشن ناشناخته"), 404
    deny = _stepup_flow(action, mgmt_token)
    if deny:
        return deny
    info = verify_mgmt_token(mgmt_token)
    return _run_action(action, info["file_id"])


@bp.route("/manage/stepup/<mgmt_token>/<action>", methods=["GET", "POST"])
def manage_stepup(mgmt_token, action):
    """صفحه کد ۶ رقمی برای عملیات‌ها — دقیقاً همان صفحه ورود پنل"""
    if action not in ("pause", "resume", "burn", "copy_id", "restore", "revoke_sessions", "edit_capacity", "edit_expiry", "edit_note", "edit_intro", "edit_end"):
        return redirect(url_for("admin_panel.manage_enter"))
    info = verify_mgmt_token(mgmt_token)
    if not info:
        return redirect(url_for("admin_panel.manage_enter"))
    fid = info["file_id"]
    DEV = _os.environ.get("SOOZAN_DEV_MODE", "") in ("1", "true", "yes") or client_ip() in ("127.0.0.1", "::1", "localhost")
    tpl = (Path(__file__).parent / "templates" / "manage_otp.html").read_text(encoding="utf-8")
    DESCS = {
        "pause": "⏸ درخواست مکث موقت فایل",
        "resume": "▶ درخواست ادامه دسترسی فایل",
        "burn": "🔥 درخواست سوزاندن فایل — فایل رمزنگاری‌شده تا ۱ ساعت در سطل بازیافت می‌ماند و قابل بازگشت است",
        "copy_id": "📋 درخواست کپی مجدد آیدی فایل",
        "restore": "📥 درخواست بازیابی و دانلود فایل از سطل بازیافت",
        "revoke_sessions": "🚪 درخواست خروج از همه نشست‌های مدیریت",
        "edit_capacity": "✏️ درخواست تغییر ظرفیت بازدید",
        "edit_expiry": "⏳ درخواست تغییر زمان انقضا",
        "edit_note": "📝 درخواست ویرایش یادداشت خصوصی",
        "edit_intro": "💬 درخواست ویرایش پیام خوش‌آمد",
        "edit_end": "💬 درخواست ویرایش پیام پس از سوختن",
    }
    kw = {"otp_action": request.path, "otp_desc": DESCS[action], "otp_submit": "اجرای عملیات ←"}

    def page(err=None, demo=None, phone="", sec=0, code=None):
        from ui import render as _r2
        if code is None:
            code = 401 if err else 200
        from flask import make_response
        _resp = make_response(_r2(tpl, demo_code=demo, phone=phone, error=err, seconds_left=sec, **kw), code)
        _resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        _resp.headers["Pragma"] = "no-cache"
        return _resp

    phone_full = ""
    with get_db() as c:
        ow = c.execute("SELECT phone FROM users WHERE id=(SELECT owner_id FROM files WHERE id=?)", (fid,)).fetchone()
    if ow and ow["phone"]:
        phone_full = ow["phone"]
    masked = phone_full[:4] + "***" + phone_full[-2:] if phone_full else ""

    if request.method == "GET":
        done = session.get("stepup_done")
        if done and done["token"] == mgmt_token and done["action"] == action and _t.time() < done["exp"]:
            return redirect(f"/manage/panel/{mgmt_token}")
        st0 = session.get("mgmt_stepup")
        if st0 and st0["token"] == mgmt_token and st0["action"] == action and _t.time() < st0["exp"]:
            rem0 = max(0, int(st0["exp"] - _t.time()))
            return page(None, demo=st0["code"] if DEV else None, phone=masked, sec=rem0)
        if not phone_full:
            return page("شماره مالک یافت نشد", sec=0)
        code = f"{_sec.randbelow(1000000):06d}"
        session["mgmt_stepup"] = {"token": mgmt_token, "action": action, "code": code, "exp": _t.time() + 120, "tries": 0}
        audit("MGMT_STEPUP_SENT", client_ip(), f"action={action}")
        return page(None, demo=code if DEV else None, phone=masked, sec=120)

    st = session.get("mgmt_stepup")
    if not st or st["token"] != mgmt_token or st["action"] != action:
        return redirect(request.path)
    remaining = max(0, int(st["exp"] - _t.time()))
    if request.form.get("resend"):
        code = f"{_sec.randbelow(1000000):06d}"
        st.update(code=code, exp=_t.time() + 120, tries=0, locked=False)
        session["mgmt_stepup"] = st
        audit("MGMT_STEPUP_RESENT", client_ip(), f"action={action}")
        return page(None, demo=code if DEV else None, phone=masked, sec=120)
    if remaining <= 0:
        session.pop("mgmt_stepup", None)
        return page("کد منقضی شد؛ دوباره درخواست بده.", sec=0)
    if st.get("locked"):
        return page("کد باطل شده است؛ ارسال مجدد بزنید.", sec=0)
    code = (request.form.get("code") or "").strip()
    if not _otp_eq(code, st["code"]):
        st["tries"] = st.get("tries", 0) + 1
        if st["tries"] >= 4:
            st["locked"] = True
            st["code"] = ""
            session["mgmt_stepup"] = st
            audit("MGMT_STEPUP_LOCKED", client_ip(), level="WARN") if "level" in audit.__code__.co_varnames else audit("MGMT_STEPUP_LOCKED", client_ip())
            return page("تلاش بیش از حد؛ کد باطل شد. ارسال مجدد بزنید.", sec=0)
        session["mgmt_stepup"] = st
        return page("کد صحیح نیست", demo=st["code"] if DEV else None, phone=masked, sec=remaining)
    session.pop("mgmt_stepup", None)
    session["stepup_done"] = {"token": mgmt_token, "action": action, "exp": _t.time() + 90}
    if action.startswith("edit_"):
        session["stepup_form"] = {"token": mgmt_token, "action": action, "exp": _t.time() + 180}
        return redirect(f"/manage/editform/{mgmt_token}/{action}")
    if action == "restore":
        pwok = session.get("restore_pw_ok")
        if not pwok or pwok["token"] != mgmt_token or _t.time() > pwok["exp"]:
            return redirect(f"/manage/restore/{mgmt_token}")
        session.pop("restore_pw_ok", None)
        session["restore_dl"] = {"token": mgmt_token, "exp": _t.time() + 120}
        return redirect(f"/manage/restore_dl_page/{mgmt_token}")
    if action == "burn":
        pwok = session.get("burn_pw_ok")
        if not pwok or pwok["token"] != mgmt_token or _t.time() > pwok["exp"]:
            return redirect(f"/manage/burn_pw/{mgmt_token}")
        session.pop("burn_pw_ok", None)
    rv = _run_action(action, fid)
    err = None
    if isinstance(rv, tuple):
        err = (rv[0].get_json() or {}).get("error")
    else:
        data = rv.get_json() or {}
        if not data.get("ok"):
            err = data.get("error")
        elif action == "copy_id":
            uid_v = data.get("uid", "")
            session["pw_pickup"] = {"value": uid_v, "exp": _t.time() + 120}
            session["stepup_result"] = {"label": "📋 آیدی کامل فایل:", "value": "", "masked": (uid_v[:5] + "••••••" + uid_v[-4:]) if len(uid_v) > 9 else "•" * len(uid_v), "pickup": True}
        else:
            session["stepup_msg"] = {"pause": "فایل موقتاً متوقف شد", "resume": "دسترسی فایل ادامه یافت", "burn": "فایل سوخته شد و تا ۱ ساعت در سطل بازیافت است"}.get(action, "عملیات انجام شد")
    if err:
        session["stepup_error"] = err
        return redirect(f"/manage/panel/{mgmt_token}")
    if action == "revoke_sessions":
        session.pop("mgmt_token_note", None)
        return redirect(url_for("admin_panel.manage_enter"))
    return redirect(f"/manage/panel/{mgmt_token}")



@bp.post("/manage/pickup")
def manage_pickup():
    """رمز را یک‌بار از session می‌دهد (هرگز در HTML نمی‌آید)"""
    pk = session.pop("pw_pickup", None)
    if not pk or _t.time() > pk["exp"]:
        return jsonify(ok=False, error="منقضی شد"), 401
    audit("MGMT_PW_PICKUP", client_ip())
    return jsonify(ok=True, value=pk["value"])


def _find_pw_verifier():
    """پیدا کردن تابع بررسی رمز عبور (scrypt) از auth/core"""
    for mod in ("auth", "core"):
        pf = Path(__file__).parent / (mod + ".py")
        if not pf.exists():
            continue
        src = pf.read_text(encoding="utf-8")
        for m in re.finditer(r"def (\w+)\(([^)]*)\):", src):
            body = src[m.end():m.end() + 700]
            if "scrypt" in body:
                return mod, m.group(1)
    return None, None


def _discover_verifiers():
    """کشف خودکار تابع بررسی رمز خود اپلیکیشن (auth/core)"""
    out = []
    for mod in ("auth", "core"):
        pf = Path(__file__).parent / (mod + ".py")
        if not pf.exists():
            continue
        src = pf.read_text(encoding="utf-8")
        for m in re.finditer(r"def (\w+)\(([^)]*)\):", src):
            body = src[m.end():m.end() + 800]
            if "scrypt" not in body:
                continue
            args = [a.strip().split("=")[0].strip() for a in m.group(2).split(",") if a.strip()]
            out.append((mod, m.group(1), args))
    return out


_VERIFIERS = _discover_verifiers()


def _check_account_pw(user_row, password):
    """بررسی رمز حساب: دقیقاً مثل Auth.login — با Scrypt رسمی core"""
    import hmac as _hmc
    from core import Auth
    ph = user_row["pw_hash"]
    sa = user_row["salt"]
    if not ph or not sa:
        return False
    try:
        calc = Auth._hash(password, bytes(sa))
        return _hmc.compare_digest(calc, bytes(ph))
    except Exception:
        return False

@bp.route("/manage/restore/<mgmt_token>", methods=["GET", "POST"])
def manage_restore_pw(mgmt_token):
    info = verify_mgmt_token(mgmt_token)
    if not info:
        return redirect(url_for("admin_panel.manage_enter"))
    with get_db() as c:
        row = c.execute("SELECT id, uid, owner_id, status, views_count, settings, expires_at, file_path FROM files WHERE id=?", (info["file_id"],)).fetchone()
    if not row:
        return redirect(url_for("admin_panel.manage_enter"))
    rd = dict(row)
    left = _restore_left(rd, _trash_info(rd["uid"]))
    if not left:
        return redirect(f"/manage/panel/{mgmt_token}")
    tpl = (Path(__file__).parent / "templates" / "manage_restore_pw.html").read_text(encoding="utf-8")
    if request.method == "GET":
        return _render(tpl, mgmt_token=mgmt_token, pw_error=None)
    pw = request.form.get("password") or ""
    with get_db() as c:
        u = c.execute("SELECT pw_hash, salt FROM users WHERE id=?", (rd["owner_id"],)).fetchone()
    rl = session.get("restore_rl") or {"n": 0, "until": 0, "uid": ""}
    if rl.get("uid") == rd["uid"] and _t.time() < rl["until"]:
        audit("RESTORE_PW_LOCKED", client_ip())
        return _render(tpl, mgmt_token=mgmt_token, pw_error="۵ تلاش غلط؛ بازیابی این فایل ۱ دقیقه قفل است"), 429
    if not u or not _check_account_pw(u, pw):
        if rl.get("uid") != rd["uid"]:
            rl = {"n": 0, "until": 0, "uid": rd["uid"]}
        rl["n"] = rl.get("n", 0) + 1
        if rl["n"] >= 5:
            rl = {"n": 0, "until": _t.time() + 60, "uid": rd["uid"]}
        session["restore_rl"] = rl
        audit("RESTORE_PW_WRONG", client_ip())
        return _render(tpl, mgmt_token=mgmt_token, pw_error="رمز عبور حساب صحیح نیست"), 401
    session.pop("restore_rl", None)
    session["restore_pw_ok"] = {"token": mgmt_token, "exp": _t.time() + 120}
    audit("RESTORE_PW_OK", client_ip())
    return redirect(f"/manage/stepup/{mgmt_token}/restore")


@bp.get("/manage/restore_dl_page/<mgmt_token>")
def manage_restore_page(mgmt_token):
    info = verify_mgmt_token(mgmt_token)
    dl = session.get("restore_dl")
    if not info or not dl or dl["token"] != mgmt_token or _t.time() > dl["exp"]:
        return redirect(f"/manage/panel/{mgmt_token}")
    tpl = (Path(__file__).parent / "templates" / "manage_restore_dl.html").read_text(encoding="utf-8")
    return _render(tpl, mgmt_token=mgmt_token)


@bp.get("/manage/restore_dl/<mgmt_token>")
def manage_restore_dl(mgmt_token):
    import traceback
    from flask import send_file
    import io as _io
    try:
        info = verify_mgmt_token(mgmt_token)
        if not info:
            return redirect(url_for("admin_panel.manage_enter"))
        dl = session.pop("restore_dl", None)
        if not dl or dl["token"] != mgmt_token or _t.time() > dl["exp"]:
            return redirect(f"/manage/panel/{mgmt_token}")
        with get_db() as c:
            row = c.execute("SELECT uid, filename, mime, dek_wrapped AS dw FROM files WHERE id=?", (info["file_id"],)).fetchone()
        if not row or _meta_get("restore_used_" + str(row["uid"])):
            return redirect(f"/manage/panel/{mgmt_token}")
        src = TRASH / (row["uid"] + ".enc")
        if not src.exists():
            with get_db() as c2:
                fp = c2.execute("SELECT file_path FROM files WHERE id=?", (info["file_id"],)).fetchone()
            src = Path(fp["file_path"]) if (fp and fp["file_path"] and Path(fp["file_path"]).exists()) else None
        if not src:
            return redirect(f"/manage/panel/{mgmt_token}")
        plain = None
        try:
            import core as _core, inspect as _insp
            _df = getattr(_core, "decrypt_file", None)
            if _df is None:
                for _nm in dir(_core):
                    _ob = getattr(_core, _nm)
                    if _insp.isclass(_ob) and hasattr(_ob, "decrypt_file"):
                        _df = _ob.decrypt_file
                        break
            if _df and row["dw"]:
                plain = _df(src.read_bytes(), bytes(row["dw"]))
        except Exception:
            traceback.print_exc()
            plain = None
        if plain:
            resp = send_file(_io.BytesIO(plain), mimetype=(row["mime"] or "application/octet-stream"),
                             as_attachment=True, download_name=row["filename"])
        else:
            resp = send_file(str(src), as_attachment=True, download_name=row["filename"] + ".enc")
        audit("MGMT_RESTORE_DOWNLOAD", client_ip(), f"file_id={info['file_id']} decrypted={bool(plain)}")
        _meta_set("restore_used_" + str(row["uid"]), _t.time())
        tf = TRASH / (row["uid"] + ".enc")
        if tf.exists():
            tf.unlink()
        tm = TRASH / (row["uid"] + ".meta.json")
        if tm.exists():
            tm.unlink()
        return resp
    except Exception:
        traceback.print_exc()
        return "خطای سرور در دانلود بازیابی", 500

@bp.route("/manage/editform/<mgmt_token>/<action>", methods=["GET", "POST"])
def manage_editform(mgmt_token, action):
    info = verify_mgmt_token(mgmt_token)
    st = session.get("stepup_form")
    if not info:
        return redirect(url_for("admin_panel.manage_enter"))
    if not st or st["token"] != mgmt_token or st["action"] != action or _t.time() > st["exp"] or action not in FORMS:
        return redirect(f"/manage/panel/{mgmt_token}")
    title, ftype, key = FORMS[action]
    import json as _jf
    with get_db() as c:
        row = c.execute("SELECT settings, expires_at FROM files WHERE id=?", (info["file_id"],)).fetchone()
    try:
        stg = _jf.loads(row["settings"] or "{}")
    except Exception:
        stg = {}
    tpl = (Path(__file__).parent / "templates" / "manage_editform.html").read_text(encoding="utf-8")
    if request.method == "GET":
        cur = stg.get(key, "") if ftype == "textarea" else (stg.get("max_views", "") if key == "max_views" else "")
        return _render(tpl, form_title=title, form_type=ftype, form_cur=cur, mgmt_token=mgmt_token, form_error=None)
    val = (request.form.get("value") or "").strip()
    err = None
    if key == "max_views":
        try:
            n = int(val)
            if not (1 <= n <= 10000):
                err = "عدد باید بین ۱ تا ۱۰۰۰ باشد"
        except Exception:
            err = "عدد نامعتبر"
        if not err:
            stg["max_views"] = n
    elif key == "expires":
        unit = request.form.get("unit") or "hour"
        mult = {"min": 60, "hour": 3600, "day": 86400}.get(unit, 3600)
        try:
            h = float(val)
            if h < 0:
                err = "عدد منفی نامعتبر"
        except Exception:
            err = "عدد نامعتبر"
        if not err:
            with get_db() as c:
                c.execute("UPDATE files SET expires_at=? WHERE id=?", (None if h <= 0 else _t.time() + h * mult, info["file_id"]))
    else:
        if len(val) > 500:
            err = "حداکثر ۵۰۰ نویسه"
        else:
            stg[key] = val
    if err:
        return _render(tpl, form_title=title, form_type=ftype, form_cur=val, mgmt_token=mgmt_token, form_error=err), 400
    if key != "expires":
        with get_db() as c:
            c.execute("UPDATE files SET settings=? WHERE id=?", (_jf.dumps(stg, ensure_ascii=False), info["file_id"]))
    session.pop("stepup_form", None)
    session["stepup_msg"] = f"{title} اعمال شد"
    audit("MGMT_EDIT_" + action.upper(), client_ip(), f"file_id={info['file_id']}")
    return redirect(f"/manage/panel/{mgmt_token}")


@bp.post("/manage/stepup_issue/<mgmt_token>/<action>")
def manage_stepup_issue(mgmt_token, action):
    if action not in ("pause", "resume", "burn", "copy_id", "restore", "revoke_sessions", "edit_capacity", "edit_expiry", "edit_note", "edit_intro", "edit_end"):
        return jsonify(ok=False, error="اکشن نامعتبر"), 400
    info = verify_mgmt_token(mgmt_token)
    if not info:
        return jsonify(ok=False, error="نشست نامعتبر"), 401
    DEV = _os.environ.get("SOOZAN_DEV_MODE", "") in ("1", "true", "yes") or client_ip() in ("127.0.0.1", "::1", "localhost")
    with get_db() as c:
        ow = c.execute("SELECT phone FROM users WHERE id=(SELECT owner_id FROM files WHERE id=?)", (info["file_id"],)).fetchone()
    if not ow or not ow["phone"]:
        return jsonify(ok=False, error="شماره مالک یافت نشد"), 404
    code = f"{_sec.randbelow(1000000):06d}"
    session["mgmt_stepup"] = {"token": mgmt_token, "action": action, "code": code, "exp": _t.time() + 120, "tries": 0}
    audit("MGMT_STEPUP_SENT", client_ip(), f"action={action}")
    return jsonify(ok=True, demo=code if DEV else None,
                   phone=ow["phone"][:4] + "***" + ow["phone"][-2:], seconds=120)


@bp.post("/manage/stepup_verify/<mgmt_token>/<action>")
def manage_stepup_verify(mgmt_token, action):
    info = verify_mgmt_token(mgmt_token)
    if not info:
        return jsonify(ok=False, error="نشست نامعتبر"), 401
    st = session.get("mgmt_stepup")
    if not st or st["token"] != mgmt_token or st["action"] != action:
        return jsonify(ok=False, error="اول درخواست کد بده"), 400
    remaining = max(0, int(st["exp"] - _t.time()))
    if remaining <= 0:
        session.pop("mgmt_stepup", None)
        return jsonify(ok=False, error="کد منقضی شد؛ دکمه ارسال مجدد را بزن"), 401
    if st.get("locked"):
        return jsonify(ok=False, error="کد باطل شده؛ ارسال مجدد را بزن"), 401
    code = (request.form.get("code") or "").strip()
    if not _otp_eq(code, st["code"]):
        st["tries"] = st.get("tries", 0) + 1
        if st["tries"] >= 4:
            st["locked"] = True
            st["code"] = ""
        session["mgmt_stepup"] = st
        audit("MGMT_STEPUP_WRONG", client_ip())
        return jsonify(ok=False, error="کد صحیح نیست", seconds=remaining)
    session.pop("mgmt_stepup", None)
    fid = info["file_id"]
    if action.startswith("edit_"):
        session["stepup_form"] = {"token": mgmt_token, "action": action, "exp": _t.time() + 180}
        return jsonify(ok=True, redirect=f"/manage/editform/{mgmt_token}/{action}")
    if action == "restore":
        pwok = session.get("restore_pw_ok")
        if not pwok or pwok["token"] != mgmt_token or _t.time() > pwok["exp"]:
            return jsonify(ok=False, error="اول رمز حساب را وارد کن"), 401
        session.pop("restore_pw_ok", None)
        session["restore_dl"] = {"token": mgmt_token, "exp": _t.time() + 120}
        return jsonify(ok=True, redirect=f"/manage/restore_dl_page/{mgmt_token}")
    rv = _run_action(action, fid)
    if isinstance(rv, tuple):
        return jsonify(ok=False, error=(rv[0].get_json() or {}).get("error", "خطا"))
    data = rv.get_json() or {}
    if not data.get("ok"):
        return jsonify(ok=False, error=data.get("error", "خطا"))
    if action == "copy_id":
        uid_v = data.get("uid", "")
        session["pw_pickup"] = {"value": uid_v, "exp": _t.time() + 120}
        session["stepup_result"] = {"label": "📋 آیدی کامل فایل:", "value": "", "masked": (uid_v[:5] + "••••••" + uid_v[-4:]) if len(uid_v) > 9 else "•" * len(uid_v), "pickup": True}
        return jsonify(ok=True, redirect=f"/manage/panel/{mgmt_token}")
    if action == "revoke_sessions":
        return jsonify(ok=True, redirect=url_for("admin_panel.manage_enter"))
    session["stepup_msg"] = {"pause": "فایل موقتاً متوقف شد", "resume": "دسترسی فایل ادامه یافت", "burn": "فایل سوخته شد و تا ۱ ساعت در سطل بازیافت است"}.get(action, "عملیات انجام شد")
    return jsonify(ok=True, redirect=f"/manage/panel/{mgmt_token}")


@bp.post("/manage/restore_pw_json/<mgmt_token>")
def manage_restore_pw_json(mgmt_token):
    info = verify_mgmt_token(mgmt_token)
    if not info:
        return jsonify(ok=False, error="نشست نامعتبر"), 401
    with get_db() as c:
        row = c.execute("SELECT uid, owner_id FROM files WHERE id=?", (info["file_id"],)).fetchone()
    if not row or not _trash_info(row["uid"]):
        return jsonify(ok=False, error="سطل بازیافت خالی است"), 404
    pw = request.form.get("password") or ""
    with get_db() as c:
        u = c.execute("SELECT pw_hash, salt FROM users WHERE id=?", (row["owner_id"],)).fetchone()
    if not u or not _check_account_pw(u, pw):
        audit("RESTORE_PW_WRONG", client_ip())
        return jsonify(ok=False, error="رمز عبور حساب صحیح نیست"), 401
    session["restore_pw_ok"] = {"token": mgmt_token, "exp": _t.time() + 120}
    audit("RESTORE_PW_OK", client_ip())
    return jsonify(ok=True)


@bp.get("/manage/otp")
def manage_otp_page():
    st = session.get("manage_otp")
    if not st:
        return redirect(url_for("admin_panel.manage_enter"))
    DEV = _os.environ.get("SOOZAN_DEV_MODE", "") in ("1", "true", "yes") or client_ip() in ("127.0.0.1", "::1", "localhost")
    tpl = (Path(__file__).parent / "templates" / "manage_otp.html").read_text(encoding="utf-8")
    remaining = max(0, int(st["exp"] - _t.time()))
    from flask import make_response
    r = make_response(_render(tpl, demo_code=st["code"] if DEV else None,
                              phone=session.get("manage_otp_phone", ""), error=None, seconds_left=remaining))
    r.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    r.headers["Pragma"] = "no-cache"
    return r


@bp.route("/manage/burn_pw/<mgmt_token>", methods=["GET", "POST"])
def manage_burn_pw(mgmt_token):
    info = verify_mgmt_token(mgmt_token)
    if not info:
        return redirect(url_for("admin_panel.manage_enter"))
    with get_db() as c:
        row = c.execute("SELECT id, uid, owner_id, status, views_count, settings, expires_at FROM files WHERE id=?", (info["file_id"],)).fetchone()
    if not row:
        return redirect(url_for("admin_panel.manage_enter"))
    rd = dict(row)
    import json as _jx
    try:
        _stg = _jx.loads(rd.get("settings") or "{}")
    except Exception:
        _stg = {}
    from core import real_status as _rsx
    _k, _f, _g, _d = _rsx(rd, _stg, bool(rd.get("file_path") and Path(rd["file_path"]).exists()))
    if _g == "bad":
        return redirect(f"/manage/panel/{mgmt_token}")
    tpl = (Path(__file__).parent / "templates" / "manage_burn_pw.html").read_text(encoding="utf-8")
    if request.method == "GET":
        return _render(tpl, mgmt_token=mgmt_token, pw_error=None)
    pw = request.form.get("password") or ""
    rl = session.get("burn_rl") or {"n": 0, "until": 0, "uid": ""}
    if rl.get("uid") == rd["uid"] and _t.time() < rl["until"]:
        audit("BURN_PW_LOCKED", client_ip())
        return _render(tpl, mgmt_token=mgmt_token, pw_error="۵ تلاش غلط؛ سوزاندن این فایل ۳ دقیقه قفل است"), 429
    with get_db() as c:
        u = c.execute("SELECT pw_hash, salt FROM users WHERE id=?", (rd["owner_id"],)).fetchone()
    if not u or not _check_account_pw(u, pw):
        if rl.get("uid") != rd["uid"]:
            rl = {"n": 0, "until": 0, "uid": rd["uid"]}
        rl["n"] = rl.get("n", 0) + 1
        if rl["n"] >= 5:
            rl = {"n": 0, "until": _t.time() + 180, "uid": rd["uid"]}
        session["burn_rl"] = rl
        audit("BURN_PW_WRONG", client_ip())
        return _render(tpl, mgmt_token=mgmt_token, pw_error="رمز عبور حساب صحیح نیست"), 401
    session.pop("burn_rl", None)
    session["burn_pw_ok"] = {"token": mgmt_token, "exp": _t.time() + 120}
    audit("BURN_PW_OK", client_ip())
    return redirect(f"/manage/stepup/{mgmt_token}/burn")


def register(app):
    app.register_blueprint(bp)
