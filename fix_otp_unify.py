from pathlib import Path

ch = []

# ═══ ۱) بدنه مشترک OTP (کپی دقیق پنل) ═══
Path("templates/otp_shared.html").write_text('''{% set otp_dead = error and ("باطل" in error or "منقضی" in error) %}
<div class="ot-wrap">
  <div class="ot-card">
    <div class="ot-icon">🛡️</div>
    <h1 class="ot-title">{{ otp_title|default("تأیید دومرحله‌ای") }}</h1>
    <p class="ot-sub">{{ otp_desc|default("کد مدیریت معتبر بود ✔") }}<br>کد ۶ رقمی ارسال‌شده به شماره <span class="ot-phone">{{ phone|default(phone_mask|default("—")) }}</span> را وارد کنید</p>
    {% if demo_code %}
    <div class="ot-demo">
      <div class="ot-demo-label">📨 کد پیامک دمو</div>
      <div class="ot-demo-code" data-demo-code="{{ demo_code }}">{{ demo_code }}</div>
    </div>
    {% endif %}
    {% if not otp_no_timer and not otp_dead %}
    <div class="ot-timer">زمان باقی‌مانده: <b id="ot-time">{{ "%02d:%02d"|format((seconds_left|default(120))//60, (seconds_left|default(120))%60) }}</b></div>
    <div class="ot-progress"><div class="ot-progress-bar" id="ot-bar" style="width:{{ ((seconds_left|default(120)) / 120 * 100)|round }}%"></div></div>
    {% endif %}
    {% if error %}<div class="ot-alert">⚠️ {{ error }}</div>{% endif %}
    <form method="post" action="{{ otp_action|default('/manage/otp') }}" id="ot-form">
      <div class="ot-boxes" id="ot-boxes">
        {% for i in range(6) %}<input class="ot-box" type="text" inputmode="numeric" maxlength="1" data-idx="{{ i }}">{% endfor %}
      </div>
      <input type="hidden" name="code" id="ot-code">
      <button class="ot-btn" type="submit" id="ot-submit" disabled>{{ otp_submit|default("ورود به پنل مدیریت ←") }}</button>
    </form>
    {% if not otp_no_resend %}
    <form method="post" action="{{ otp_resend_url|default(otp_action|default('/manage/otp')) }}" id="ot-resend-form">
      <input type="hidden" name="resend" value="1">
      <button class="ot-resend" type="submit" id="ot-resend" {% if not otp_dead %}disabled{% endif %}>
        🔄 ارسال مجدد کد{% if not otp_dead %} (بعد از پایان زمان){% endif %}
      </button>
    </form>
    {% endif %}
    {% if otp_cancel_url|default("/manage") %}
    <a href="{{ otp_cancel_url|default('/manage') }}" class="ot-cancel">انصراف و بازگشت</a>
    {% endif %}
  </div>
</div>
<script nonce="{{ nonce }}">
(function(){
  var boxes = document.querySelectorAll(".ot-box");
  var codeEl = document.getElementById("ot-code");
  var submit = document.getElementById("ot-submit");
  var left = {{ seconds_left|default(120) }};
  var totalTime = 120;
  var timeEl = document.getElementById("ot-time");
  var barEl = document.getElementById("ot-bar");
  var resend = document.getElementById("ot-resend");
  function collect(){
    var v = "";
    boxes.forEach(function(b){ v += b.value; });
    codeEl.value = v;
    submit.disabled = v.length !== 6;
    boxes.forEach(function(b){ b.classList.toggle("filled", b.value !== ""); });
  }
  boxes.forEach(function(b, i){
    b.addEventListener("input", function(e){
      var v = e.target.value.replace(/\\D/g, "").slice(-1);
      e.target.value = v;
      if(v && i < boxes.length - 1) boxes[i+1].focus();
      collect();
    });
    b.addEventListener("keydown", function(e){
      if(e.key === "Backspace" && !e.target.value && i > 0){
        boxes[i-1].focus();
        boxes[i-1].value = "";
        collect();
      }
    });
    b.addEventListener("paste", function(e){
      e.preventDefault();
      var txt = (e.clipboardData || window.clipboardData).getData("text").replace(/\\D/g, "").slice(0, 6);
      for(var j=0; j<txt.length; j++){ boxes[j].value = txt[j]; }
      if(txt.length > 0) boxes[Math.min(txt.length, 5)].focus();
      collect();
    });
  });
  if(boxes[0]) boxes[0].focus();
  function tick(){
    if(!timeEl && !barEl) return;
    if(left <= 0){
      if(timeEl) timeEl.textContent = "00:00";
      if(barEl) barEl.style.width = "0%";
      if(resend){
        resend.disabled = false;
        resend.innerHTML = "🔄 ارسال مجدد کد";
      }
      if(submit) submit.disabled = true;
      return;
    }
    if(timeEl){
      timeEl.textContent = String(Math.floor(left/60)).padStart(2,"0") + ":" + String(left%60).padStart(2,"0");
    }
    if(barEl){
      barEl.style.width = ((left / totalTime) * 100) + "%";
    }
    left -= 1;
    setTimeout(tick, 1000);
  }
  tick();
})();
</script>
''', encoding="utf-8")
ch.append("otp_shared.html ساخته شد")

WRAP = '''{% extends "app.html" %}
{% block head %}<link rel="stylesheet" href="/static/mgmt.css">{% endblock %}
{% block title %}سوزان — تأیید کد{% endblock %}
{% block app_content %}
{% include "otp_shared.html" %}
{% endblock %}
'''
Path("templates/manage_otp.html").write_text(WRAP, encoding="utf-8")
Path("templates/auth_otp.html").write_text(WRAP, encoding="utf-8")
Path("templates/auth_verify.html").write_text(WRAP, encoding="utf-8")
Path("templates/totp_login.html").write_text(WRAP, encoding="utf-8")
ch.append("چهار template → wrapper مشترک")

# ═══ ) auth.py: منطق یکسان + متغیرهای هر صفحه ═══
p = Path("auth.py")
s = p.read_text(encoding="utf-8")

reps = [
    # ثبت‌نام: تشخیص مرحله ۲ بدون فیلد step
    ('if request.form.get("step") == "2":',
     'if session.get("reg_pending") and request.form.get("code") is not None:'),
    # ثبت‌نام: کد غلط → زمان باقی‌مانده
    ('return render(_read("auth_verify.html"), demo_code=pend["code"],\n                                                    phone=pend["phone"], error="کد نادرست است.")',
     'return render(_read("auth_verify.html"), demo_code=pend["code"],\n                                                    phone=pend["phone"], error="کد نادرست است.",\n                                                    seconds_left=max(0, int(pend.get("exp", 0) - _time.time())),\n                                                    otp_action="/register", otp_submit="ثبت‌نام ←", otp_desc="کد تأیید ثبت‌نام", otp_resend_url="/register/resend", otp_cancel_url="/")'),
    # ثبت‌نام: قفل → صفحه مرده با ارسال مجدد
    ('return render(_read("auth_register.html"), error="تلاش بیش از حد؛ از ابتدا ثبت‌نام کنید.")',
     'return render(_read("auth_verify.html"), phone=pend["phone"], error="کد باطل شد؛ ارسال مجدد را بزن.",\n                                            otp_action="/register", otp_submit="ثبت‌نام ←", otp_desc="کد تأیید ثبت‌نام", otp_resend_url="/register/resend", otp_cancel_url="/")'),
    # ثبت‌نام GET: اگر pending هست → صفحه کد
    ('    return render(_read("auth_register.html"))\n\n\n@bp.route("/login/phone", methods=["GET", "POST"])',
     '''    if session.get("reg_pending"):
        pend = session["reg_pending"]
        rem = max(0, int(pend.get("exp", 0) - _time.time()))
        return render(_read("auth_verify.html"), demo_code=pend.get("code") or None, phone=pend["phone"],
                      seconds_left=rem, error=None if rem else "کد منقضی شد؛ ارسال مجدد را بزن.",
                      otp_action="/register", otp_submit="ثبت‌نام ←", otp_desc="کد تأیید ثبت‌نام",
                      otp_resend_url="/register/resend", otp_cancel_url="/")
    return render(_read("auth_register.html"))


@bp.route("/login/phone", methods=["GET", "POST"])'''),
    # ورود: انقضی → صفحه مرده (نه ریدایرکت)
    ('    pend = session.get("login_pending")\n    if not pend or _time.time() > pend.get("exp", 0):\n        session.pop("login_pending", None)\n        return redirect("/login")',
     '''    pend = session.get("login_pending")
    if not pend:
        return redirect("/login")
    if _time.time() > pend.get("exp", 0):
        return render(_read("auth_otp.html"), phone_mask=_mask(pend["phone"]),
                      error="کد منقضی شد؛ ارسال مجدد را بزن.",
                      otp_action="/login/phone", otp_submit="ورود ←", otp_desc="کد یک‌بار مصرف ورود",
                      otp_resend_url="/login/phone/resend", otp_cancel_url="/login")'''),
    # ورود: قفل → صفحه مرده
    ('return render(_read("auth.html"), mode="login", error="تلاش بیش از حد؛ دوباره وارد شوید.")',
     'return render(_read("auth_otp.html"), phone_mask=_mask(pend["phone"]), error="کد باطل شد؛ ارسال مجدد را بزن.",\n                                            otp_action="/login/phone", otp_submit="ورود ←", otp_desc="کد یک‌بار مصرف ورود",\n                                            otp_resend_url="/login/phone/resend", otp_cancel_url="/login")'),
    # ورود: کد غلط → زمان باقی‌مانده
    ('return render(_read("auth_otp.html"), demo_code=pend["code"],\n                                                    phone_mask=_mask(pend["phone"]), error="کد نادرست است.")',
     'return render(_read("auth_otp.html"), demo_code=pend["code"],\n                                                    phone_mask=_mask(pend["phone"]), error="کد نادرست است.",\n                                                    seconds_left=max(0, int(pend.get("exp", 0) - _time.time())),\n                                                    otp_action="/login/phone", otp_submit="ورود ←", otp_desc="کد یک‌بار مصرف ورود",\n                                                    otp_resend_url="/login/phone/resend", otp_cancel_url="/login")'),
    # ورود GET: زمان باقی‌مانده
    ('    return render(_read("auth_otp.html"), demo_code=pend["code"], phone_mask=_mask(pend["phone"]))',
     '    return render(_read("auth_otp.html"), demo_code=pend["code"], phone_mask=_mask(pend["phone"]),\n                    seconds_left=max(0, int(pend.get("exp", 0) - _time.time())),\n                    otp_action="/login/phone", otp_submit="ورود ←", otp_desc="کد یک‌بار مصرف ورود",\n                    otp_resend_url="/login/phone/resend", otp_cancel_url="/login")'),
    # TOTP ورود → template مشترک بدون تایمر
    ('return render(_read("totp.html"), mode="login",\n                                                                     error="تلاش بیش از حد. چند دقیقه صبر کنید.")',
     'return render(_read("totp_login.html"), error="تلاش بیش از حد. چند دقیقه صبر کنید.",\n                                                otp_action="/login/totp", otp_submit="تأیید ←", otp_desc="کد برنامه authenticator یا کد پشتیبان",\n                                                otp_no_timer=True, otp_no_resend=True, otp_cancel_url="/login")'),
    ('return render(_read("totp.html"), mode="login", error=msg)',
     'return render(_read("totp_login.html"), error=msg,\n                                            otp_action="/login/totp", otp_submit="تأیید ←", otp_desc="کد برنامه authenticator یا کد پشتیبان",\n                                            otp_no_timer=True, otp_no_resend=True, otp_cancel_url="/login")'),
    ('    return render(_read("totp.html"), mode="login")',
     '    return render(_read("totp_login.html"), otp_action="/login/totp", otp_submit="تأیید ←",\n                        otp_desc="کد برنامه authenticator یا کد پشتیبان",\n                        otp_no_timer=True, otp_no_resend=True, otp_cancel_url="/login")'),
]
n = 0
for old, new in reps:
    if old in s:
        s = s.replace(old, new, 1)
        n += 1
    else:
        print("⚠ پیدا نشد:", old[:60].replace("\n", " "))
p.write_text(s, encoding="utf-8")
ch.append(f"{n} جایگزینی منطق auth")

for x in ch:
    print(f"✅ {x}")
import py_compile
py_compile.compile("auth.py", doraise=True)
print("✅ syntax auth سالم")
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader("templates"))
for t in ["manage_otp.html", "auth_otp.html", "auth_verify.html", "totp_login.html"]:
    env.get_template(t)
    print(f"✅ Jinja {t}")
