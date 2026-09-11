#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""🧪 آزمون جامع فاز ۳ — موتور نمایش و قوانین سکوت"""

import os, sys, time, secrets, sqlite3, requests
from pathlib import Path

BASE = Path(__file__).parent
BASE_URL = "http://127.0.0.1:8000"
DB = BASE / "data" / "burn.db"
GREEN = "\033[32m"; RED = "\033[31m"; BOLD = "\033[1m"; RESET = "\033[0m"
passed = failed = 0
def ok(m): global passed; passed += 1; print(f"  {GREEN}✓{RESET} {m}")
def bad(m): global failed; failed += 1; print(f"  {RED}✗{RESET} {m}")
def check(c, m): (ok if c else bad)(m); return c
def section(t): print(f"\n{BOLD}── {t} ──{RESET}")

PNG = b"\x89PNG\r\n\x1a\n" + os.urandom(800)

try:
    requests.get(BASE_URL + "/health", timeout=2)
except Exception:
    bad("سرور در دسترس نیست"); sys.exit(1)

s = requests.Session()
un = "v3_" + secrets.token_hex(3)
s.post(BASE_URL + "/register", data={"username": un, "password": "Test1234!"})
s.post(BASE_URL + "/login", data={"username": un, "password": "Test1234!"})

def upload(data, name, extra=None):
    d = extra or {}
    r = s.post(BASE_URL + "/api/upload", files={"file": (name, data)}, data=d)
    return r.json()

def resolve(uid):
    return requests.get(BASE_URL + "/v/" + uid)

def unlock(uid, pw=""):
    return requests.post(BASE_URL + "/api/v/unlock/" + uid, json={"password": pw})

def fetch_content(uid, tok):
    return requests.get(BASE_URL + "/api/v/content/" + uid + "?token=" + tok)

# ─── ۱. سکوت و عدم نشت ───
section("۱. قوانین سکوت و عدم نشت")
fake = secrets.token_hex(32)
r = resolve(fake)
check("این محتوا دیگر در دسترس نیست." in r.text, "آیدی ناشناخته → پیام پیش‌فرض")
j = upload(PNG, "a.png")
uid1 = j["uid"]
r = resolve(uid1)
check('"state":"ready"' in r.text.replace(" ", ""), "آیدی تازه → حالت ready")
check("یک‌بار" not in r.text and "ثانیه مانده" not in r.text, "هیچ اشاره‌ای به یک‌بارمصرفی/تایمر نیست")

# ─── ۲. جریان کامل نمایش ───
section("۲. جریان کامل نمایش")
tok = unlock(uid1).json()["token"]
r = fetch_content(uid1, tok)
check(r.status_code == 200 and r.content == PNG, "محتوا دقیقاً برابر اصل است")
check("no-store" in r.headers.get("Cache-Control", ""), "هدر no-store روی محتوا")
check(r.headers.get("X-Content-Type-Options") == "nosniff", "nosniff روی محتوا")
r2 = fetch_content(uid1, tok)
check(r2.status_code == 410, "توکن یک‌بارمصرف است (بار دوم رد شد)")

# ─── ۳. یک‌بارمصرفی ───
section("۳. یک‌بارمصرفی")
r = resolve(uid1)
check('"state":"gone"' in r.text.replace(" ", ""), "بعد از نمایش، resolve → gone")
check("این محتوا دیگر در دسترس نیست." in r.text, "پیام پایان پیش‌فرض نمایش داده شد")

# ─── . پیام پایان سفارشی ───
section("۴. پیام پایان سفارسی")
j = upload(PNG, "b.png", {"end_message": "خداحافظ دوست من"})
uid2 = j["uid"]
tok = unlock(uid2).json()["token"]
fetch_content(uid2, tok)
r = resolve(uid2)
check("خداحافظ دوست من" in r.text, "پیام سفارشی برای آیدی واقعی")
r = resolve(fake)
check("خداحافظ دوست من" not in r.text, "پیام سفارشی برای آیدی ناشناخته نشت نمی‌کند")

# ─── ۵. درگاه رمز ───
section("۵. درگاه رمز")
j = upload(PNG, "c.png", {"has_password": "1", "password": "S@1x", "password_attempts": "3"})
uid3 = j["uid"]
r = resolve(uid3)
check('"state":"gate"' in r.text.replace(" ", ""), "فایل رمزدار → حالت gate")
r = unlock(uid3, "wrong")
check(r.status_code == 403 and r.json().get("left") == 2, "رمز اشتباه → ۲ فرصت مانده")
r = unlock(uid3, "S@1x")
check(r.json().get("ok"), "رمز درست → توکن")
check(fetch_content(uid3, r.json()["token"]).content == PNG, "محتوا بعد از رمز درست")

# ─── . سوختن با رمز اشتباه ───
section("۶. رفتار پس از اتمام تلاش‌ها")
j = upload(PNG, "d.png", {"has_password": "1", "password": "S@2x", "password_attempts": "1", "on_password_fail": "burn"})
uid4 = j["uid"]
unlock(uid4, "nope")
r = resolve(uid4)
check('"state":"gone"' in r.text.replace(" ", ""), "burn: فایل سوخت")
j = upload(PNG, "e.png", {"has_password": "1", "password": "S@3x", "password_attempts": "1", "on_password_fail": "lock"})
uid5 = j["uid"]
unlock(uid5, "nope")
with sqlite3.connect(DB) as c:
    st = c.execute("SELECT status FROM files WHERE uid=?", (uid5,)).fetchone()[0]
check(st == "locked", "lock: وضعیت قفل شد")

# ─── ۷. تایمر on_view ───
section("۷. تایمر از لحظه ورود")
j = upload(PNG, "f.png", {"timer_mode": "on_view", "timer_seconds": "5"})
uid6 = j["uid"]
resolve(uid6)  # شروع تایمر
tok = unlock(uid6).json()["token"]
check(fetch_content(uid6, tok).status_code == 200, "قبل از انقضا محتوا می‌آید")
check(requests.get(BASE_URL + "/api/v/alive/" + uid6).json().get("ok"), "alive قبل از انقضا")
time.sleep(6)
check(not requests.get(BASE_URL + "/api/v/alive/" + uid6).json().get("ok"), "alive بعد از ۵ ثانیه → gone")
check('"state":"gone"' in resolve(uid6).text.replace(" ", ""), "صفحه بعد از تایمر → gone")

# ─── . سهمیه بازدید ──
section("۸. سهمیه N بار")
j = upload(PNG, "g.png", {"max_views": "2"})
uid7 = j["uid"]
for i in range(2):
    t = unlock(uid7).json()["token"]
    check(fetch_content(uid7, t).status_code == 200, f"بازدید {i+1} موفق")
r = unlock(uid7)
check(r.status_code == 410, "بازدید سوم رد شد")

# ─── ۹. محدودیت آی‌پی ───
section("۹. هر آی‌پی یک‌بار")
j = upload(PNG, "h.png", {"ip_once": "1"})
uid8 = j["uid"]
t = unlock(uid8).json()["token"]
fetch_content(uid8, t)
with sqlite3.connect(DB) as c:
    c.execute("UPDATE files SET viewer_ip='9.9.9.9' WHERE uid=?", (uid8,))
r = resolve(uid8)
check('"state":"gone"' in r.text.replace(" ", ""), "آی‌پی متفاوت → مسدود")

# ─── ۰. ضربان و امحا ───
section("۱۰. ضربان + امحای واقعی")
j = upload(PNG, "i.png", {"timer_mode": "on_reveal", "timer_seconds": "5"})
uid9 = j["uid"]
t = unlock(uid9).json()["token"]
fetch_content(uid9, t)
requests.post(BASE_URL + "/api/v/ping/" + uid9)
with sqlite3.connect(DB) as c:
    n = c.execute("SELECT COUNT(*) FROM active_views").fetchone()[0]
check(n >= 1, "ضربان در active_views ثبت شد")
requests.post(BASE_URL + "/api/v/close/" + uid9)
with sqlite3.connect(DB) as c:
    n = c.execute("SELECT COUNT(*) FROM active_views").fetchone()[0]
check(n == 0, "close ردیف ضربان را پاک کرد")
time.sleep(10)  # صبر برای پاک‌ساز
with sqlite3.connect(DB) as c:
    fp = c.execute("SELECT file_path FROM files WHERE uid=?", (uid9,)).fetchone()[0]
check(fp == "", "پاک‌ساز فایل منقضی را امحا کرد")
import glob as _g
with sqlite3.connect(DB) as c:
    dead = c.execute("SELECT COUNT(*) FROM files WHERE file_path != '' AND status NOT IN ('locked','paused')").fetchone()[0]
    live = {r[0] for r in c.execute("SELECT file_path FROM files WHERE file_path != ''")}
check(dead == 0, "هیچ فایل مرده‌ای روی دیسک نمانده")
check(set(_g.glob(str(BASE / "data" / "files" / "*.enc"))) == live, "دیسک دقیقاً برابر فایل‌های زنده است")

print(f"\n{'═'*50}")
print(f"  {GREEN}موفق: {passed}{RESET}  ·  {RED}شکست: {failed}{RESET}")
print(f"{'═'*50}")
sys.exit(0 if failed == 0 else 1)
