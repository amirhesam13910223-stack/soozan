"""تست جامع سناریوهای مدیریت — واحد + یکپارچه"""
import os, sys, time, sqlite3, tempfile, shutil
from pathlib import Path
sys.path.insert(0, ".")
os.environ.setdefault("SOOZAN_DEV_MODE", "1")

PASS = FAIL = 0
def ck(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  ✓ {name}")
    else: FAIL += 1; print(f"  ✗ {name}")

print("═══ بخش ۱: واحد ═══")
import admin_panel as ap
import core

# ۱) کشف decrypt_file داخل کلاس
df = getattr(core, "decrypt_file", None)
if df is None:
    import inspect
    for nm in dir(core):
        ob = getattr(core, nm)
        if inspect.isclass(ob) and hasattr(ob, "decrypt_file"):
            df = ob.decrypt_file; break
ck("decrypt_file در core موجود است", df is not None)

# ۲) بررسی رمز غلط → False بدون exception
con = sqlite3.connect("data/burn.db"); con.row_factory = sqlite3.Row
u = con.execute("SELECT pw_hash, salt FROM users LIMIT 1").fetchone(); con.close()
try:
    r = ap._check_account_pw(u, "قطعاً_غلط_999")
    ck("رمز غلط → False", r is False)
except Exception as e:
    ck(f"رمز غلط بدون exception ({e})", False)

# ۳) متا یک‌بارمصرف
ap._meta_set("t_v2", "1")
ck("متا set/get", ap._meta_get("t_v2") == "1")
con = sqlite3.connect("data/burn.db"); con.execute("DELETE FROM meta WHERE key='t_v2'"); con.commit(); con.close()

# ۴) پاک‌سازی سطل منقضی
ap.TRASH.mkdir(parents=True, exist_ok=True)
mf = ap.TRASH / "v2test.meta.json"; ef = ap.TRASH / "v2test.enc"
mf.write_text('{"uid":"v2test","until":1,"orig":"x"}'); ef.write_bytes(b"x")
ap._purge_trash()
ck("سطل منقضی پاک شد", not mf.exists() and not ef.exists())

# ۵) پنجره بازیابی: فایل سوخته بدون سطل → None
rd = {"id": -1, "uid": "v2none", "status": "burned", "views_count": 0, "settings": "{}", "expires_at": None}
ck("سوخته بدون سطل → بدون بازیابی", ap._restore_left(rd, None) is None)

# ۶) پنجره بازیابی: منقضی تازه → دقیقه مثبت
rd2 = {"id": -2, "uid": "v2exp", "status": "active", "views_count": 0, "settings": "{}", "expires_at": time.time() - 600}
ck("منقضی ≤۱ ساعت → بازیابی فعال", (ap._restore_left(rd2, None) or 0) > 0)

# ۷) پرچم مصرف‌شده → None
ap._meta_set("restore_used_v2x", "1")
rd3 = {"id": -3, "uid": "v2x", "status": "active", "views_count": 0, "settings": "{}", "expires_at": time.time() - 60}
ck("پرچم مصرف → بدون بازیابی", ap._restore_left(rd3, None) is None)
con = sqlite3.connect("data/burn.db"); con.execute("DELETE FROM meta WHERE key='restore_used_v2x'"); con.commit(); con.close()

print("═══ بخش ۲: یکپارچه (test_client — بدون نیاز به سرور) ═══")
from app import app as _flask_app
_flask_app.config["TESTING"] = True
_c = _flask_app.test_client()

# ۸) OTP بدون نشست → ریدایرکت به ورود (PRG گارد)
r = _c.get("/manage/otp")
ck("GET /manage/otp بدون نشست → 302", r.status_code == 302)

# ۹) توکن نامعتبر → ورود
r = _c.get("/manage/panel/999|1|bad")
ck("توکن نامعتبر → ریدایرکت", r.status_code in (301, 302))

# ۱۰) هدر no-store روی صفحه ورود مدیریت
r = _c.get("/manage")
ck("هدر no-store روی /manage", "no-store" in r.headers.get("Cache-Control", ""))

# ۱۱) اکشن فایل مرده → 409 (اگر فایل سوخته موجود باشد)
con = sqlite3.connect("data/burn.db"); con.row_factory = sqlite3.Row
dead = con.execute("SELECT id FROM files WHERE status='burned' LIMIT 1").fetchone(); con.close()
if dead:
    try:
        from app import app as _flask_app
        with _flask_app.app_context(), _flask_app.test_request_context():
            rv = ap._run_action("pause", dead["id"])
        if isinstance(rv, tuple):
            code = rv[1]
            ck("اکشن روی فایل مرده → 409", code == 409)
        else:
            ck("اکشن روی فایل مرده → tuple", False)
    except Exception as e:
        ck(f"اکشن روی فایل مرده بدون exception ({type(e).__name__})", False)
else:
    print("  - (فایل سوخته برای تست نیست)")

# ۱۲) ابطال نشست: توکن قدیمی پس از revoke رد می‌شود
ap._meta_set("mgmt_revoke_ts", time.time())
tok = f"1|{int(time.time()) + 600}|x"
ck("توکن پس از revoke → None", ap.verify_mgmt_token(tok) is None)
con = sqlite3.connect("data/burn.db"); con.execute("DELETE FROM meta WHERE key='mgmt_revoke_ts'"); con.commit(); con.close()

print("=" * 50)
print(f"📊 موفق={PASS} · شکست={FAIL}")
print("🏆 همه سبز!" if FAIL == 0 else "⚠️ شکست داریم")
sys.exit(0 if FAIL == 0 else 1)
