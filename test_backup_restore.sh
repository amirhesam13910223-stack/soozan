#!/bin/bash
set -e

echo "══════════════════════════════════════════════════════════"
echo "🧪 تست drill: بک‌آپ و بازیابی"
echo "══════════════════════════════════════════════════════════"

python3 << 'PYEOF'
import os
import sys
import time
import sqlite3
import subprocess
import shutil
from pathlib import Path

os.environ["SOOZAN_DEV_MODE"] = "1"
BASE = "http://127.0.0.1:8000"

# ═══════════════════════════════════════════════════════
# ۱) ایجاد داده تست
# ═══════════════════════════════════════════════════════
print("\n۱) ایجاد داده تست...")

# راه‌اندازی سرور
proc = subprocess.Popen(["bash", "run.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(5)

import requests
s = requests.Session()

test_user = f"backup_test_{int(time.time())}"
password = "testpass123"

# register
r = s.post(f"{BASE}/register", data={"username": test_user, "password": password})
if r.status_code == 200:
    print(f"  ✅ کاربر {test_user} ثبت شد")
else:
    print(f"  ⚠️  register: status={r.status_code}")

# login
r = s.post(f"{BASE}/login", data={"username": test_user, "password": password}, allow_redirects=False)
if r.status_code == 302:
    print(f"  ✅ login موفق")
else:
    print(f"  ⚠️  login: status={r.status_code}")

# upload
import io
test_content = "test content for backup drill"
files = {"file": ("test.txt", io.BytesIO(test_content.encode()), "text/plain")}
data = {"intro_message": "backup drill"}
r = s.post(f"{BASE}/api/upload", files=files, data=data)
upload_uid = ""
if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
    j = r.json()
    upload_uid = j.get("uid", "")
    print(f"  ✅ فایل آپلود شد (uid={upload_uid[:12]}...)")
else:
    print(f"  ⚠️  upload: status={r.status_code}")

# شمارش قبل از disaster
conn = sqlite3.connect("data/burn.db")
users_before = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
files_before = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
conn.close()
print(f"  📊 کاربران: {users_before}, فایل‌ها: {files_before}")

# توقف سرور
proc.terminate()
proc.wait()
time.sleep(2)

# ═══════════════════════════════════════════════════════
# ۲) بک‌آپ
# ═══════════════════════════════════════════════════════
print("\n۲) گرفتن بک‌آپ...")
result = subprocess.run(["bash", "backup.sh"], capture_output=True, text=True)
if result.returncode == 0:
    # پیدا کردن آخرین بک‌آپ
    backups = sorted(Path("backups").glob("soozan_backup_*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    if backups:
        backup_file = backups[0]
        size = backup_file.stat().st_size / 1024
        print(f"  ✅ {backup_file.name} ({size:.1f} KB)")
    else:
        print("  ❌ بک‌آپ ساخته نشد")
        sys.exit(1)
else:
    print(f"  ❌ backup.sh خطا داد")
    sys.exit(1)

# ═══════════════════════════════════════════════════════
# ۳) حذف کامل data (شبیه‌سازی disaster)
# ═══════════════════════════════════════════════════════
print("\n۳) حذف کامل data/ (شبیه‌سازی disaster)...")
shutil.rmtree("data", ignore_errors=True)
if not Path("data").exists():
    print("  ✅ data/ حذف شد")
else:
    print("  ❌ حذف نشد")
    sys.exit(1)

# ═══════════════════════════════════════════════════════
# ۴) بازیابی
# ═══════════════════════════════════════════════════════
print("\n۴) بازیابی از بک‌آپ...")
result = subprocess.run(["bash", "restore.sh", str(backup_file)], capture_output=True, text=True)
if result.returncode == 0:
    print("  ✅ بازیابی کامل شد")
else:
    print(f"  ❌ restore.sh خطا داد")
    print(result.stderr)
    sys.exit(1)

# ═══════════════════════════════════════════════════════
# ۵) تأیید صحت
# ═══════════════════════════════════════════════════════
print("\n۵) تأیید صحت داده‌ها...")

# راه‌اندازی مجدد سرور
proc = subprocess.Popen(["bash", "run.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(5)

# بررسی کاربر
conn = sqlite3.connect("data/burn.db")
users_after = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
user_exists = conn.execute("SELECT COUNT(*) FROM users WHERE username=?", (test_user,)).fetchone()[0]
files_after = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
conn.close()

if user_exists > 0:
    print(f"  ✅ کاربر {test_user} در دیتابیس است")
else:
    print(f"  ❌ کاربر یافت نشد")
    proc.terminate()
    sys.exit(1)

if users_before == users_after:
    print(f"  ✅ تعداد کاربران حفظ شد ({users_before} → {users_after})")
else:
    print(f"  ⚠️  تعداد کاربران تغییر کرد ({users_before} → {users_after})")

if files_before == files_after:
    print(f"  ✅ تعداد فایل‌ها حفظ شد ({files_before} → {files_after})")
else:
    print(f"  ⚠️  تعداد فایل‌ها تغییر کرد ({files_before} → {files_after})")

# بررسی integrity
try:
    conn = sqlite3.connect("data/burn.db")
    result = conn.execute("PRAGMA integrity_check").fetchone()[0]
    if result == "ok":
        print("  ✅ دیتابیس سالم است")
    else:
        print(f"  ⚠️  integrity: {result}")
    conn.close()
except Exception as e:
    print(f"  ⚠️  خطا در integrity: {e}")

# بررسی کلید ارشد
key_path = Path("data/.master.key")
if key_path.exists():
    key_size = key_path.stat().st_size
    print(f"  ✅ کلید ارشد موجود ({key_size} بایت)")
else:
    print(f"  ❌ کلید ارشد یافت نشد")

# بررسی فایل آپلود شده
files_dir = Path("data/files")
if files_dir.exists():
    enc_files = list(files_dir.glob("*.enc"))
    if enc_files:
        print(f"  ✅ {len(enc_files)} فایل رمزنگاری‌شده موجود")
    else:
        print(f"  ⚠️  فایل رمزنگاری‌شده یافت نشد")

# تست unlock فایل
if upload_uid:
    r = requests.post(f"{BASE}/api/v/unlock/{upload_uid}")
    if r.status_code == 200:
        j = r.json()
        if j.get("ok"):
            print(f"  ✅ unlock فایل بازیابی‌شده موفق")
        else:
            print(f"  ⚠️  unlock ناموفق: {j}")
    else:
        print(f"  ⚠️  unlock: status={r.status_code}")

# توقف سرور
proc.terminate()
proc.wait()

print("\n══════════════════════════════════════════════════════════")
print("🏆 تست drill کامل شد — بازیابی موفق")
print("══════════════════════════════════════════════════════════")
PYEOF
