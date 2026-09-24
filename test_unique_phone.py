#!/usr/bin/env python3
import requests, time, re, secrets

BASE = "http://127.0.0.1:8000"
s = requests.Session()

def register_user(username, phone):
    # ثبت‌نام
    r = s.post(f"{BASE}/register", data={
        "username": username,
        "password": "Pass1234",
        "password2": "Pass1234",
        "full_name": "تست",
        "phone": phone,
    })
    # استخراج کد دمو
    m = re.search(r'data-demo-code="(\d{6})"', r.text)
    if not m:
        return False, r.text[:500]
    code = m.group(1)
    r = s.post(f"{BASE}/register", data={"code": code, "step": "2"})
    return r.status_code == 200 or "dashboard" in r.url, r.url

# ۱) ثبت کاربر A با شماره 09121111111
ok, url = register_user("user_a_" + str(int(time.time())), "09121111111")
print(f"✅ ثبت کاربر A: {ok}")

# ۲) خارج شدن
s.get(f"{BASE}/logout")
s.post(f"{BASE}/logout", data={"confirm": "1", "ack": "on"})

# ۳) ثبت کاربر B با شماره متفاوت
ok, _ = register_user("user_b_" + str(int(time.time())), "09122222222")
print(f"✅ ثبت کاربر B: {ok}")

# ۴) تلاش برای تغییر شماره کاربر B به شماره کاربر A
r = s.post(f"{BASE}/settings/phone/start")  # شروع فرآیند
print(f"POST /settings/phone/start: {r.status_code}")

# کد به شماره فعلی B (09122222222)
m = re.search(r'data-demo-code="(\d{6})"', r.text)
if m:
    r = s.post(f"{BASE}/settings/otp/verify", data={"code": m.group(1)})
    print(f"تأیید شماره فعلی B: {r.status_code} → {r.url}")
    
    # حالا تلاش برای شماره جدید = 09121111111 (متعلق به A)
    r = s.post(f"{BASE}/settings/phone/new", data={"new_phone": "09121111111"})
    print(f"تلاش تغییر شماره B به شماره A: {r.status_code}")
    print(f"پیام: {'✅ جلوگیری شد' if 'قبلاً برای حساب دیگری' in s.cookies.get('session', '') or 'قبلاً' in str(r.headers) else '❌ نشت!'}")

# ۵) تست register با شماره تکراری
s2 = requests.Session()
r = s2.post(f"{BASE}/register", data={
    "username": "user_c_" + str(int(time.time())),
    "password": "Pass1234",
    "password2": "Pass1234",
    "full_name": "تست",
    "phone": "09121111111",  # تکراری
})
print(f"ثبت‌نام با شماره تکراری: {r.status_code}")
print(f"جلوگیری شد: {'✅' if 'قبلاً ثبت شده' in r.text else '❌ نشت!'}")
