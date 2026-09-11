#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
📤 Export گزارش‌ها — فاز H

- CSV: تلاش‌های رمز، بازدیدها
- HTML: گزارش کامل (قابل پرینت به PDF)
- همه با تاریخ شمسی و RTL-aware
"""
from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import List, Dict
from core import get_db

try:
    import jdatetime
    HAS_JALALI = True
except ImportError:
    HAS_JALALI = False


def _to_jalali(ts: float) -> str:
    """تبدیل timestamp به تاریخ شمسی"""
    try:
        dt = datetime.fromtimestamp(ts)
        if HAS_JALALI:
            return jdatetime.datetime.fromgregorian(datetime=dt).strftime('%Y/%m/%d %H:%M:%S')
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


# ═══════════════════════════════════════════════════════
# ۱) Export تلاش‌های رمز به CSV
# ═══════════════════════════════════════════════════════
def export_attempts_csv(file_id: int, uid: str, filename: str) -> str:
    """تولید CSV از تلاش‌های رمز"""
    with get_db() as conn:
        rows = conn.execute(
            """SELECT attempted_at, ip, success 
               FROM password_attempts 
               WHERE file_id = ? 
               ORDER BY attempted_at DESC""",
            (file_id,)
        ).fetchall()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header (فارسی)
    writer.writerow(["زمان (شمسی)", "IP", "نتیجه"])
    
    # Data rows
    for row in rows:
        writer.writerow([
            _to_jalali(row["attempted_at"]),
            row["ip"],
            "موفق" if row["success"] else "ناموفق"
        ])
    
    return output.getvalue()


# ═══════════════════════════════════════════════════════
# ۲) Export بازدیدها به CSV
# ═══════════════════════════════════════════════════════
def export_views_csv(file_id: int, uid: str, filename: str) -> str:
    """تولید CSV از بازدیدها"""
    with get_db() as conn:
        rows = conn.execute(
            """SELECT viewed_at, ip, user_agent, device 
               FROM views 
               WHERE file_id = ? 
               ORDER BY viewed_at DESC""",
            (file_id,)
        ).fetchall()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["زمان (شمسی)", "IP", "دستگاه", "User-Agent"])
    
    # Data rows
    for row in rows:
        writer.writerow([
            _to_jalali(row["viewed_at"]),
            row["ip"],
            "موبایل" if row["device"] == "mobile" else "دسکتاپ",
            (row["user_agent"] or "")[:100]  # truncate
        ])
    
    return output.getvalue()


# ═══════════════════════════════════════════════════════
# ۳) Export گزارش کامل HTML (قابل پرینت به PDF)
# ═══════════════════════════════════════════════════════
def export_full_report_html(file_id: int, uid: str, filename: str, admin_code: str) -> str:
    """تولید HTML کامل با همه اطلاعات (قابل پرینت به PDF با Ctrl+P)"""
    
    # دریافت اطلاعات فایل
    with get_db() as conn:
        file_row = conn.execute(
            "SELECT uid, filename, mime, size_bytes, status, views_count, created_at FROM files WHERE id=?",
            (file_id,)
        ).fetchone()
        
        attempts = conn.execute(
            "SELECT attempted_at, ip, success FROM password_attempts WHERE file_id=? ORDER BY attempted_at DESC",
            (file_id,)
        ).fetchall()
        
        views = conn.execute(
            "SELECT viewed_at, ip, device FROM views WHERE file_id=? ORDER BY viewed_at DESC",
            (file_id,)
        ).fetchall()
    
    # محاسبات
    total_attempts = len(attempts)
    successful_attempts = sum(1 for a in attempts if a["success"])
    failed_attempts = total_attempts - successful_attempts
    
    total_views = len(views)
    unique_ips = len(set(v["ip"] for v in views))
    
    # تولید HTML
    html = f'''<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<title>گزارش کامل — {filename}</title>
<style>
  @page {{ margin: 2cm; size: A4; }}
  body {{ font-family: Tahoma, Arial, sans-serif; line-height: 1.8; color: #333; }}
  .header {{ text-align: center; border-bottom: 3px solid #ff6b35; padding-bottom: 20px; margin-bottom: 30px; }}
  .header h1 {{ color: #ff6b35; font-size: 28px; margin: 0; }}
  .header .subtitle {{ color: #666; font-size: 14px; margin-top: 10px; }}
  .section {{ margin-bottom: 30px; page-break-inside: avoid; }}
  .section h2 {{ color: #333; font-size: 20px; border-right: 4px solid #ff6b35; padding-right: 12px; }}
  .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; background: #f5f5f5; padding: 16px; border-radius: 8px; }}
  .info-item {{ display: flex; justify-content: space-between; }}
  .info-label {{ font-weight: bold; color: #666; }}
  .info-value {{ font-family: monospace; direction: ltr; }}
  .stats-boxes {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }}
  .stat-box {{ background: #ff6b3522; border: 2px solid #ff6b35; border-radius: 8px; padding: 16px; text-align: center; }}
  .stat-value {{ font-size: 32px; font-weight: bold; color: #ff6b35; }}
  .stat-label {{ font-size: 12px; color: #666; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
  th {{ background: #ff6b35; color: white; padding: 10px; text-align: right; }}
  td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
  .success {{ color: #10b981; font-weight: bold; }}
  .fail {{ color: #ef4444; font-weight: bold; }}
  .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #999; font-size: 11px; }}
  @media print {{
    body {{ font-size: 11pt; }}
    .section {{ page-break-inside: avoid; }}
    th {{ background: #ff6b35 !important; -webkit-print-color-adjust: exact; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>🔥 سوزان — گزارش کامل فایل</h1>
  <div class="subtitle">تولید شده در {_to_jalali(datetime.now().timestamp())}</div>
</div>

<div class="section">
  <h2>📋 اطلاعات فایل</h2>
  <div class="info-grid">
    <div class="info-item"><span class="info-label">نام فایل:</span> <span class="info-value">{filename}</span></div>
    <div class="info-item"><span class="info-label">UID:</span> <span class="info-value">{uid[:20]}…</span></div>
    <div class="info-item"><span class="info-label">نوع MIME:</span> <span class="info-value">{file_row["mime"] or "نامشخص"}</span></div>
    <div class="info-item"><span class="info-label">حجم:</span> <span class="info-value">{round((file_row["size_bytes"] or 0) / 1024, 1)} KB</span></div>
    <div class="info-item"><span class="info-label">وضعیت:</span> <span class="info-value">{file_row["status"]}</span></div>
    <div class="info-item"><span class="info-label">تاریخ آپلود:</span> <span class="info-value">{_to_jalali(file_row["created_at"])}</span></div>
    <div class="info-item"><span class="info-label">کد مدیریت:</span> <span class="info-value">{admin_code[:12]}…</span></div>
  </div>
</div>

<div class="section">
  <h2>📊 آمار کلی</h2>
  <div class="stats-boxes">
    <div class="stat-box">
      <div class="stat-value">{total_views}</div>
      <div class="stat-label">کل بازدید</div>
    </div>
    <div class="stat-box">
      <div class="stat-value">{unique_ips}</div>
      <div class="stat-label">IP منحصر به فرد</div>
    </div>
    <div class="stat-box">
      <div class="stat-value">{successful_attempts}</div>
      <div class="stat-label">رمز موفق</div>
    </div>
    <div class="stat-box">
      <div class="stat-value">{failed_attempts}</div>
      <div class="stat-label">رمز ناموفق</div>
    </div>
  </div>
</div>

<div class="section">
  <h2>🔑 تلاش‌های رمز ({total_attempts} مورد)</h2>
  <table>
    <thead>
      <tr><th>زمان (شمسی)</th><th>IP</th><th>نتیجه</th></tr>
    </thead>
    <tbody>
'''
    
    # تلاش‌های رمز
    for a in attempts[:50]:  # حداکثر ۵۰ مورد برای جلوگیری از PDF خیلی طولانی
        status_class = "success" if a["success"] else "fail"
        status_text = "موفق" if a["success"] else "ناموفق"
        html += f'''      <tr>
        <td>{_to_jalali(a["attempted_at"])}</td>
        <td style="direction:ltr;text-align:right">{a["ip"]}</td>
        <td class="{status_class}">{status_text}</td>
      </tr>
'''
    
    html += '''    </tbody>
  </table>
</div>

<div class="section">
  <h2>👁️ بازدیدها ({total} مورد)</h2>
  <table>
    <thead>
      <tr><th>زمان (شمسی)</th><th>IP</th><th>دستگاه</th></tr>
    </thead>
    <tbody>
'''.format(total=total_views)
    
    # بازدیدها
    for v in views[:50]:
        device = "موبایل" if v["device"] == "mobile" else "دسکتاپ"
        html += f'''      <tr>
        <td>{_to_jalali(v["viewed_at"])}</td>
        <td style="direction:ltr;text-align:right">{v["ip"]}</td>
        <td>{device}</td>
      </tr>
'''
    
    html += f'''    </tbody>
  </table>
</div>

<div class="footer">
  <p>این گزارش توسط سیستم سوزان تولید شده است</p>
  <p>برای ذخیره به عنوان PDF: Ctrl+P (یا Cmd+P در Mac) → "Save as PDF"</p>
</div>

</body>
</html>'''
    
    return html

