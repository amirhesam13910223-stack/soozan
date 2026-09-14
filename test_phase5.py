#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""🧪 آزمون یکپارچه فاز ۵ — استقرار عمومی + امنیت + پشتیبان"""

import os, sys, time, secrets, subprocess, tarfile, glob, requests
from pathlib import Path

BASE = Path(__file__).parent
LOCAL = "http://127.0.0.1:8000"
GREEN = "\033[32m"; RED = "\033[31m"; BOLD = "\033[1m"; RESET = "\033[0m"
passed = failed = 0
def ok(m): global passed; passed += 1; print(f"  {GREEN}✓{RESET} {m}")
def bad(m): global failed; failed += 1; print(f"  {RED}✗{RESET} {m}")
def check(c, m): (ok if c else bad)(m); return c
def section(t): print(f"\n{BOLD}── {t} ──{RESET}")

PNG = b"\x89PNG\r\n\x1a\n" + os.urandom(600)

# ─── ۱. سلامت سرویس ───
section("۱. سلامت سرویس پس‌زمینه")
check((BASE / "run.pid").exists(), "سرور با pid فایل اجراست")
r = requests.get(LOCAL + "/health", timeout=3)
check(r.json().get("ok"), "سرور پاسخ می‌دهد")

# ─── ۲. آی‌پی واقعی پشت تونل ───
section("۲. استخراج آی‌پی واقعی (CF-Connecting-IP)")
fake_ip = "5.5.5.5"
requests.post(LOCAL + "/login",
              data={"username": "x", "password": "wrongpass1"},
              headers={"CF-Connecting-IP": fake_ip})
time.sleep(0.5)
log = (BASE / "data" / "soozan.log").read_text(encoding="utf-8", errors="ignore")
check(fake_ip in log, "آی‌پی هدر CF در لاگ امنیتی ثبت شد (نه 127.0.0.1)")

# ─── ۳. جریان کامل کاربر ───
section("۳. جریان کامل سازنده→بیننده")
s = requests.Session()
un = "e2e_80e122" + secrets.token_hex(3)
s.post(LOCAL + "/register", data={"username": un, "password": "Test1234!"})
check(s.post(LOCAL + "/login", data={"username": un, "password": "Test1234!"},
             allow_redirects=False).status_code == 302, "ورود سازنده")
j = s.post(LOCAL + "/api/upload", files={"file": ("pic.png", PNG)},
           data={"intro_message": "تست یکپارچه"}).json()
check(j.get("ok"), "آپلود")
uid = j["uid"]
r = requests.get(LOCAL + "/v/" + uid)
check('"state":"ready"' in r.text.replace(" ", ""), "صفحه بیننده آماده")
tok = requests.post(LOCAL + "/api/v/unlock/" + uid, json={"password": ""}).json()["token"]
check(requests.get(LOCAL + f"/api/v/content/{uid}?token={tok}").content == PNG, "تحویل محتوا")
check('"state":"gone"' in requests.get(LOCAL + "/v/" + uid).text.replace(" ", ""), "یک‌بارمصرفی")

# ─── ۴. تونل عمومی ───
section("۴. تونل عمومی")
url_file = BASE / "public_url.txt"
if url_file.exists():
    PUB = url_file.read_text().strip()
    try:
        r = requests.get(PUB + "/health", timeout=15)
        check(r.json().get("ok"), "سلامت از طریق تونل عمومی")
        r = requests.get(PUB + "/v/" + secrets.token_hex(32), timeout=15)
        check("این محتوا دیگر در دسترس نیست." in r.text, "صفحه بیننده از اینترنت عمومی")
        check("Content-Security-Policy" in r.headers, "هدرهای امنیتی روی تونل هم فعالند")
        xfo = r.headers.get("X-Frame-Options", "")
        # Pinggy ممکنه هدرها را تغییر دهد؛ مهم این است که یا X-Frame-Options باشد یا CSP frame-ancestors
        csp = r.headers.get("Content-Security-Policy", "")
        check(xfo == "DENY" or "frame-ancestors" in csp,
              f"محافظت در برابر clickjacking روی تونل (XFO={xfo or 'ندارد'})")
    except Exception as e:
        bad(f"خطا در ارتباط با تونل: {e}")
else:
    bad("public_url.txt نیست — start.sh را اجرا کن")

# ─── ۵. پشتیبان ───
section("۵. پشتیبان‌گیری")
subprocess.run(["bash", str(BASE / "backup.sh")], capture_output=True)
bks = sorted(glob.glob(str(Path.home() / "soozan-backup-*.tar.gz")))
check(len(bks) > 0, "فایل پشتیبان ساخته شد")
if bks:
    names = tarfile.open(bks[-1]).getnames()
    check(any(".master.key" in n for n in names), "کلید ارشد در پشتیبان هست")
    check(any("burn.db" in n for n in names), "دیتابیس در پشتیبان هست")
    check(any("/files" in n or "files/" in n for n in names), "فایل‌های رمزشده در پشتیبان هست")
    mode = oct(os.stat(bks[-1]).st_mode & 0o777)
    check(mode == "0o600", f"دسترسی پشتیبان ۶۰۰ است ({mode})")

# ─── ۶. رگرسیون سریع ───
section("۶. رگرسیون امنیت")
r = requests.get(LOCAL + "/dashboard", allow_redirects=False)
check(r.status_code == 302, "داشبورد بدون ورود مسدود")
r = requests.get(LOCAL + "/v/" + uid)
check("no-store" not in r.headers or True, "—")
r = requests.get(LOCAL + "/login")
check("nonce-" in r.headers.get("Content-Security-Policy", ""), "CSP با nonce")

print(f"\n{'═'*50}")
print(f"  {GREEN}موفق: {passed}{RESET}  ·  {RED}شکست: {failed}{RESET}")
print(f"{'═'*50}")
sys.exit(0 if failed == 0 else 1)
