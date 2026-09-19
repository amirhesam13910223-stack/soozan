#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
📊 داشبورد سوزان
"""

import time
from pathlib import Path
from flask import Blueprint, session
from core import get_db
from ui import render
from auth import require_auth

TEMPLATES = Path(__file__).parent / "templates"
bp = Blueprint("dashboard", __name__)


def _read(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


def _persian_time(ts):
    """تبدیل timestamp به تاریخ و ساعت فارسی ساده"""
    if not ts:
        return "—"
    try:
        from datetime import datetime
        dt = datetime.fromtimestamp(ts)
        # تبدیل ساده — در فازهای بعد با jalaali کامل می‌شود
        return f"{dt.year:04d}/{dt.month:02d}/{dt.day:02d} {dt.hour:02d}:{dt.minute:02d}"
    except:
        return "—"


@bp.route("/dashboard")
@require_auth
def dashboard():
    user_id = session.get("user_id")
    with get_db() as conn:
        # آمار
        row = conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN status IN ('burned','expired') THEN 1 ELSE 0 END) as burned,
                SUM(views_count) as total_views
            FROM files WHERE owner_id=?
        """, (user_id,)).fetchone()

        stats = {
            "total_files": row["total"] or 0,
            "active_files": row["active"] or 0,
            "burned_files": row["burned"] or 0,
            "total_views": row["total_views"] or 0,
        }

        # لیست فایل‌ها
        files = conn.execute("""
            SELECT uid, filename, mime, status, views_count, created_at
            FROM files WHERE owner_id=?
            ORDER BY created_at DESC LIMIT 100
        """, (user_id,)).fetchall()

        files_list = []
        for f in files:
            mime = f["mime"] or ""
            if mime.startswith("image/"):
                family = "عکس"
            elif mime.startswith("audio/"):
                family = "صوت"
            elif mime == "application/pdf":
                family = "PDF"
            else:
                family = "متن"

            files_list.append({
                "uid": f["uid"],
                "filename": f["filename"],
                "family": family,
                "status": f["status"],
                "views_count": f["views_count"] or 0,
                "created_persian": _persian_time(f["created_at"]),
            })

    # نام کاربری
    with get_db() as conn:
        u = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
        username = u["username"] if u else "کاربر"

    import os as _osd, json as _jsd
    from core import real_status as _rs
    with get_db() as _cd:
        _rows = _cd.execute("SELECT * FROM files WHERE owner_id=? ORDER BY id DESC", (session.get("user_id"),)).fetchall()
    _fl = []
    _stats = {"total": 0, "active": 0, "viewing": 0, "done": 0, "locked": 0, "paused": 0, "expired": 0, "burned": 0, "gone": 0, "views": 0}
    for _x in _rows:
        _r = dict(_x)
        try:
            _stg = _jsd.loads(_r.get("settings") or "{}")
        except Exception:
            _stg = {}
        _de = bool(_r.get("file_path") and _osd.path.exists(_r["file_path"]))
        _k, _fa, _grp, _det = _rs(_r, _stg, _de)
        _r["status_fa_real"] = _fa
        _r["status_group_real"] = _grp
        _r["status_detail"] = _det
        _r["status_key_real"] = _k
        try:
            _r["created_persian"] = _persian_time(_r["created_at"]) if _r.get("created_at") else "—"
        except Exception:
            _r["created_persian"] = "—"
        _fl.append(_r)
        _stats["total"] += 1
        _stats[_k] = _stats.get(_k, 0) + 1
        _stats["views"] += _r.get("views_count") or 0
    return render(_read("dashboard.html"),
                 username=username,
                 **stats, files=_fl, stats=_stats)
