#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""📊 آنالیتیکس و گزارش‌دهی پیشرفته — فاز G"""
from __future__ import annotations
import time, math
from collections import Counter
from datetime import datetime, timedelta
from typing import List, Dict, Any
from core import get_db

try:
    import jdatetime
    HAS_JALALI = True
except ImportError:
    HAS_JALALI = False

def _to_jalali(ts: float) -> str:
    try:
        dt = datetime.fromtimestamp(ts)
        if HAS_JALALI:
            return jdatetime.datetime.fromgregorian(datetime=dt).strftime('%Y/%m/%d %H:%M')
        return dt.strftime('%Y-%m-%d %H:%M')
    except Exception:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')

def get_views_data(file_id: int, days: int = 30) -> List[Dict]:
    since = time.time() - days * 86400
    with get_db() as conn:
        rows = conn.execute(
            "SELECT viewed_at, ip, user_agent, device FROM views WHERE file_id = ? AND viewed_at >= ? ORDER BY viewed_at ASC",
            (file_id, since)).fetchall()
    return [dict(r) for r in rows]

def get_attempts_data(file_id: int, days: int = 30) -> List[Dict]:
    since = time.time() - days * 86400
    with get_db() as conn:
        rows = conn.execute(
            "SELECT attempted_at, ip, success FROM password_attempts WHERE file_id = ? AND attempted_at >= ? ORDER BY attempted_at ASC",
            (file_id, since)).fetchall()
    return [dict(r) for r in rows]

def _empty_chart_svg(message: str) -> str:
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 220" style="width:100%;max-width:600px">
  <rect width="600" height="220" fill="#0a102266" rx="12"/>
  <text x="300" y="115" fill="#5f6c93" font-size="14" text-anchor="middle">{message}</text>
</svg>'''

def generate_time_chart_svg(views: List[Dict], days: int = 14) -> str:
    if not views:
        return _empty_chart_svg("هنوز بازدیدی ثبت نشده")
    daily = Counter()
    for v in views:
        dt = datetime.fromtimestamp(v["viewed_at"])
        daily[dt.strftime("%m/%d")] += 1
    all_days = []
    now = datetime.now()
    for i in range(days - 1, -1, -1):
        d = now - timedelta(days=i)
        key = d.strftime("%m/%d")
        all_days.append((key, daily.get(key, 0)))
    max_val = max((v for _, v in all_days), default=0) or 1
    width, height, padding = 600, 220, 40
    chart_w, chart_h = width - padding * 2, height - padding * 2
    bar_w = chart_w / len(all_days) * 0.7
    gap = chart_w / len(all_days) * 0.3
    bars, labels = [], []
    for i, (day, count) in enumerate(all_days):
        x = padding + i * (bar_w + gap)
        bar_h = (count / max_val) * chart_h if count > 0 else 0
        y = padding + chart_h - bar_h
        bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" fill="url(#barGrad)" rx="3"/>')
        if count > 0:
            bars.append(f'<text x="{x + bar_w/2:.1f}" y="{y - 4:.1f}" fill="#ff6b35" font-size="10" text-anchor="middle" font-weight="600">{count}</text>')
        if i % max(1, len(all_days) // 10) == 0:
            labels.append(f'<text x="{x + bar_w/2:.1f}" y="{height - 8:.1f}" fill="#9aa7cf" font-size="9" text-anchor="middle" font-family="monospace">{day}</text>')
    total = sum(c for _, c in all_days)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" style="width:100%;max-width:600px">
  <defs><linearGradient id="barGrad" x1="0%" y1="0%" x2="0%" y2="100%">
    <stop offset="0%" stop-color="#ff6b35"/><stop offset="100%" stop-color="#ffa257" stop-opacity="0.5"/>
  </linearGradient></defs>
  <line x1="{padding}" y1="{padding}" x2="{padding}" y2="{height-padding}" stroke="#1d2a4d"/>
  <line x1="{padding}" y1="{height-padding}" x2="{width-padding}" y2="{height-padding}" stroke="#1d2a4d"/>
  {"".join(bars)}{"".join(labels)}
  <text x="{width-10}" y="20" fill="#9aa7cf" font-size="11" text-anchor="end" font-family="monospace">مجموع {days} روز: {total}</text>
</svg>'''

def generate_device_chart_svg(views: List[Dict]) -> str:
    if not views:
        return _empty_chart_svg("داده‌ای نیست")
    devices = Counter(v.get("device", "desktop") for v in views)
    mobile, desktop = devices.get("mobile", 0), devices.get("desktop", 0)
    total = mobile + desktop
    if total == 0:
        return _empty_chart_svg("داده‌ای نیست")
    size = 200
    cx, cy, r = size/2, size/2, 70
    def arc_path(sa, ea, color):
        if ea - sa >= 2 * math.pi:
            return f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{color}"/>'
        x1, y1 = cx + r * math.cos(sa), cy + r * math.sin(sa)
        x2, y2 = cx + r * math.cos(ea), cy + r * math.sin(ea)
        la = 1 if (ea - sa) > math.pi else 0
        return f'<path d="M {cx} {cy} L {x1:.2f} {y1:.2f} A {r} {r} 0 {la} 1 {x2:.2f} {y2:.2f} Z" fill="{color}"/>'
    parts, angle = [], -math.pi / 2
    slices = [("mobile", mobile, "#ff6b35", "موبایل"), ("desktop", desktop, "#3b5bdb", "دسکتاپ")]
    for key, count, color, label in slices:
        if count == 0: continue
        frac = count / total
        ea = angle + 2 * math.pi * frac
        parts.append(arc_path(angle, ea, color))
        mid = (angle + ea) / 2
        lx, ly = cx + r * 0.6 * math.cos(mid), cy + r * 0.6 * math.sin(mid)
        pct = int(frac * 100)
        if pct >= 5:
            parts.append(f'<text x="{lx:.1f}" y="{ly:.1f}" fill="#fff" font-size="11" text-anchor="middle" dominant-baseline="middle" font-weight="700">{pct}%</text>')
        angle = ea
    legend_y, legend_parts = 20, []
    for key, count, color, label in slices:
        pct = int(count / total * 100) if total > 0 else 0
        legend_parts.append(f'<rect x="10" y="{legend_y}" width="12" height="12" fill="{color}" rx="2"/><text x="28" y="{legend_y + 10}" fill="#eef2ff" font-size="11">{label}: {count} ({pct}%)</text>')
        legend_y += 22
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 300 200" style="width:100%;max-width:300px">
  <g transform="translate(50, 0)">{"".join(parts)}</g>
  <g transform="translate(200, 40)">{"".join(legend_parts)}</g>
</svg>'''

def detect_anomalies(file_id: int, hours: int = 24) -> List[Dict[str, Any]]:
    anomalies = []
    since = time.time() - hours * 3600
    with get_db() as conn:
        views = conn.execute("SELECT ip, viewed_at FROM views WHERE file_id = ? AND viewed_at >= ?", (file_id, since)).fetchall()
        view_ips = set(v["ip"] for v in views)
        attempts = conn.execute("SELECT ip, attempted_at, success FROM password_attempts WHERE file_id = ? AND attempted_at >= ?", (file_id, since)).fetchall()
        attempt_ips = set(a["ip"] for a in attempts)
        failed = [a for a in attempts if not a["success"]]
        all_ips = view_ips | attempt_ips
        if len(failed) >= 3:
            anomalies.append({"level": "bad", "icon": "🔓", "title": "تلاش‌های رمز مشکوک", "detail": f"{len(failed)} تلاش ناموفق رمز در {hours} ساعت"})
        if len(all_ips) >= 3:
            anomalies.append({"level": "warn", "icon": "🌐", "title": "IP های متعدد", "detail": f"{len(all_ips)} IP متفاوت در {hours} ساعت گذشته"})
        if len(views) >= 2:
            times = sorted([v["viewed_at"] for v in views])
            rapid = sum(1 for i in range(1, len(times)) if times[i] - times[i-1] < 5)
            if rapid >= 1:
                anomalies.append({"level": "warn", "icon": "⚡", "title": "بازدید سریع متوالی", "detail": f"{rapid + 1} بازدید در فاصله کمتر از ۵ ثانیه"})
    return anomalies

def get_live_viewers(file_id: int, timeout_seconds: int = 120) -> List[Dict]:
    since = time.time() - timeout_seconds
    with get_db() as conn:
        rows = conn.execute("SELECT ip, viewed_at FROM views WHERE file_id = ? AND viewed_at >= ? ORDER BY viewed_at DESC", (file_id, since)).fetchall()
        return [dict(r) for r in rows]

def get_full_analytics(file_id: int) -> Dict[str, Any]:
    views = get_views_data(file_id, days=30)
    attempts = get_attempts_data(file_id, days=30)
    total_views = len(views)
    successful_attempts = sum(1 for a in attempts if a["success"])
    failed_attempts = sum(1 for a in attempts if not a["success"])
    time_chart_7d = generate_time_chart_svg(get_views_data(file_id, days=7), days=7)
    time_chart_30d = generate_time_chart_svg(views, days=30)
    device_chart = generate_device_chart_svg(views)
    anomalies = detect_anomalies(file_id, hours=24)
    live = get_live_viewers(file_id)
    first_view_fa = _to_jalali(views[0]["viewed_at"]) if views else None
    last_view_fa = _to_jalali(views[-1]["viewed_at"]) if views else None
    return {
        "total_views": total_views,
        "successful_attempts": successful_attempts,
        "failed_attempts": failed_attempts,
        "time_chart_7d": time_chart_7d,
        "time_chart_30d": time_chart_30d,
        "device_chart": device_chart,
        "anomalies": anomalies,
        "live_viewers": live,
        "live_count": len(live),
        "first_view_fa": first_view_fa,
        "last_view_fa": last_view_fa,
    }
