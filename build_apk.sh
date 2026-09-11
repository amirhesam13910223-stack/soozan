#!/data/data/com.termux/files/usr/bin/bash
# ═══════════════════════════════════════════════════════════
#  🔥 سوزان — فاز ۴: ساخت و امضای APK واقعی در ترموکس (نهایی)
#  اولین صفحه اپ = ورود آیدی · FLAG_SECURE · بدون دانلود
# ═══════════════════════════════════════════════════════════
set -u
BASE="$HOME/soozan"
WORK="$BASE/apkbuild"
JAR="$WORK/android.jar"
FR=(⠋  ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
DPKG_OPTS=(-o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef")

if [ -t 1 ]; then
  R=$'\e[31m' G=$'\e[32m' Y=$'\e[33m' C=$'\e[36m' B=$'\e[1m' D=$'\e[2m' N=$'\e[0m'
else R="" G="" Y="" C="" B="" D="" N=""; fi

ok(){ printf "  %s\n" "${G}✅ $1${N}"; }
info(){ printf "  %s\n" "${C}ℹ $1${N}"; }
warn(){ printf "  %s\n" "${Y}⚠ $1${N}"; }
step(){ printf "\n%s\n" "${B}── $1 ──${N}"; }
err(){ printf "\n%s\n" "${R}❌ خطا: $1${N}"; exit 1; }
confirm(){ local a; printf "  %s" "${B}$1 [y/n]:${N} "; read -r a;
  case "$a" in y|Y|بله|آره|بلی) return 0;; *) return 1;; esac; }
hsize(){ local b=$1; if [ "$b" -ge 1048576 ]; then printf "%d.%d MB" $((b/1048576)) $(((b%1048576)*10/1048576));
  elif [ "$b" -ge 1024 ]; then printf "%d KB" $((b/1024)); else printf "%d B" "$b"; fi; }

spinner(){ local msg=$1; shift; local tmp pid rc t0=$SECONDS i=0
  tmp=$(mktemp) || return 1; "$@" >"$tmp" 2>&1 & pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    i=$(( (i+1) % ${#FR[@]} ))
    printf "\r  %s %s ${D}(%d ثانیه)${N}      " "${FR[i]}" "$msg" $((SECONDS-t0)); sleep .15
  done
  wait "$pid"; rc=$?
  printf "\r%s\n" "                                                                    "
  [ $rc -ne 0 ] && tail -6 "$tmp" | sed 's/^/     /'
  rm -f "$tmp"; return $rc; }

bar_show(){ local cur=$1 total=$2 label=$3 pct=0 fill i b=""
  [ "$total" -gt 0 ] && pct=$(( cur*100/total )); [ "$pct" -gt 100 ] && pct=100
  fill=$(( pct*24/100 ))
  for ((i=0;i<24;i++)); do [ "$i" -lt "$fill" ] && b+="█" || b+="░"; done
  printf "\r   [%s] %3d%% %s ${D}%s/%s${N}   " "$b" "$pct" "$label" "$(hsize "$cur")" "$(hsize "$total")"; }

dl(){ local url=$1 dest=$2 min_kb=$3 total=${4:-0} name pid rc cur
  name=$(basename "$dest")
  if [ -f "$dest" ] && [ $(( $(stat -c%s "$dest") / 1024 )) -ge "$min_kb" ]; then
    printf "   %s\n" "${D}✔ $name — موجود است${N}"; return 0; fi
  [ "$total" -gt 0 ] || total=$(curl -fsIL --connect-timeout 15 "$url" 2>/dev/null \
    | grep -i '^content-length:' | tail -1 | tr -dc '0-9'); total=${total:-0}
  curl -fL --retry 3 --connect-timeout 25 -s -o "$dest" "$url" & pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    cur=$(stat -c%s "$dest" 2>/dev/null || echo 0); bar_show "$cur" "$total" "$name"; sleep .2
  done
  wait "$pid"; rc=$?
  printf "\r%s\n" "                                                                        "
  [ $rc -ne 0 ] && return 1
  [ $(( $(stat -c%s "$dest") / 1024 )) -ge "$min_kb" ] || return 1
  printf "   %s\n" "${G}⬇ $name — $(hsize "$(stat -c%s "$dest")")${N}"; }

main(){
  local t0=$SECONDS
  printf "%s\n" "${B}"
  printf "   🔥 سوزان — فاز ۴: ساخت اپلیکیشن Viewer\n"
  printf "   %s${N}\n" "──────────────────────────────────────────────────"

  step "بررسی‌های اولیه"
  case "${PREFIX:-}" in *com.termux*) ok "ترموکس شناسایی شد";; *) err "فقط در ترموکس اجرا می‌شود";; esac
  [ -f "$BASE/viewer.py" ] || err "پروژه سوزان پیدا نشد"
  local fs blocks used av pct mp
  read -r fs blocks used av pct mp <<<"$(df -Pk "$HOME" | tail -1)"
  [ "$av" -ge $((600*1024)) ] || err "فضای کافی نیست (حداقل ۶۰۰ مگابایت آزاد لازم است)"
  ok "فضای آزاد: $(hsize $((av*1024)))"

  step "برنامه"
  printf "   ۱) نصب زنجیره ابزار ساخت APK (OpenJDK · ecj · dx · aapt · apksigner)\n"
  printf "   ۲) دانلود android.jar (کلاس‌های فریم‌ورک اندروید)\n"
  printf "   ۳) تولید سورس اپ + آیکون اختصاصی سوزان\n"
  printf "   ۴) کامپایل → DEX → بسته‌بندی → امضای دیجیتال → راستی‌آزمایی\n"
  confirm "ادامه می‌دهید؟" || err "لغو شد"

  step "نصب ابزارها"
  spinner "نصب OpenJDK و ابزارها…" pkg install -y openjdk-17 ecj aapt apksigner "${DPKG_OPTS[@]}" \
    || err "نصب ابزارها ناموفق بود"
  pkg install -y dx "${DPKG_OPTS[@]}" >/dev/null 2>&1
  local DEX=d8; command -v dx >/dev/null 2>&1 && DEX=dx
  ok "ابزارها آماده‌اند (dex با: $DEX)"

  step "دانلود android.jar"
  mkdir -p "$WORK"
  dl "https://repo1.maven.org/maven2/com/google/android/android/4.1.1.4/android-4.1.1.4.jar" \
     "$JAR" 3000 || err "دانلود android.jar ناموفق بود"

  step "تولید سورس‌ها"
  rm -rf "$WORK/gen" "$WORK/obj" "$WORK/bin"
  mkdir -p "$WORK/src/com/soozan/viewer" "$WORK/gen" "$WORK/obj" "$WORK/bin" "$WORK/res/drawable"

  cat > "$WORK/AndroidManifest.xml" <<'MANIFEST'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.soozan.viewer" android:versionCode="1" android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="27" />
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:label="سوزان" android:icon="@drawable/icon"
        android:theme="@android:style/Theme.DeviceDefault.NoActionBar">
        <activity android:name=".MainActivity" android:exported="true"
            android:configChanges="orientation|screenSize|keyboardHidden">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
MANIFEST

  cat > "$WORK/src/com/soozan/viewer/MainActivity.java" <<'JAVA'
package com.soozan.viewer;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager;
import android.webkit.DownloadListener;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Toast;

public class MainActivity extends Activity {
    private WebView web;
    private SharedPreferences prefs;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        // 🛡️ مسدودسازی اسکرین‌شات و ضبط صفحه در سطح اندروید
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                             WindowManager.LayoutParams.FLAG_SECURE);
        prefs = getSharedPreferences("soozan", MODE_PRIVATE);
        // اولین صفحه = ورود آیدی (سرور پیش‌فرض لوکال)
        startWeb(prefs.getString("server", "http://127.0.0.1:8000"));
    }

    private void showSetup() {
        LinearLayout lay = new LinearLayout(this);
        lay.setOrientation(LinearLayout.VERTICAL);
        lay.setBackgroundColor(0xFF070B14);
        lay.setPadding(70, 140, 70, 70);
        final EditText et = new EditText(this);
        et.setHint("http://127.0.0.1:8000");
        et.setText(prefs.getString("server", ""));
        et.setTextColor(0xFFEEF2FF);
        et.setHintTextColor(0xFF5F6C93);
        et.setBackgroundColor(0xFF0F1730);
        et.setPadding(30, 30, 30, 30);
        Button btn = new Button(this);
        btn.setText("اتصال به سوزان 🔥");
        btn.setBackgroundColor(0xFFFF6B35);
        btn.setTextColor(0xFFFFFFFF);
        btn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String u = et.getText().toString().trim();
                if (u.isEmpty()) return;
                if (!u.startsWith("http")) u = "http://" + u;
                prefs.edit().putString("server", u).apply();
                startWeb(u);
            }
        });
        lay.addView(et); lay.addView(btn);
        setContentView(lay);
    }

    private void showError() {
        LinearLayout lay = new LinearLayout(this);
        lay.setOrientation(LinearLayout.VERTICAL);
        lay.setBackgroundColor(0xFF070B14);
        lay.setPadding(70, 200, 70, 70);
        android.widget.TextView tv = new android.widget.TextView(this);
        tv.setText("🔌 اتصال به سرور برقرار نشد");
        tv.setTextColor(0xFFEEF2FF);
        tv.setTextSize(18);
        tv.setGravity(android.view.Gravity.CENTER);
        Button retry = new Button(this);
        retry.setText("تلاش مجدد");
        retry.setBackgroundColor(0xFFFF6B35);
        retry.setTextColor(0xFFFFFFFF);
        retry.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                startWeb(prefs.getString("server", "http://127.0.0.1:8000"));
            }
        });
        Button cfg = new Button(this);
        cfg.setText("تنظیم سرور");
        cfg.setBackgroundColor(0xFF0F1730);
        cfg.setTextColor(0xFFEEF2FF);
        cfg.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { showSetup(); }
        });
        lay.addView(tv); lay.addView(retry); lay.addView(cfg);
        setContentView(lay);
    }

    private void startWeb(String url) {
        if (url.endsWith("/")) url = url.substring(0, url.length() - 1);
        web = new WebView(this);
        web.setBackgroundColor(0xFF070B14);
        WebSettings ws = web.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setCacheMode(WebSettings.LOAD_NO_CACHE);
        // 🛡️ سخت‌سازی امنیتی وب‌ویو
        ws.setAllowFileAccess(false);
        ws.setAllowContentAccess(false);
        ws.setAllowFileAccessFromFileURLs(false);
        ws.setAllowUniversalAccessFromFileURLs(false);
        web.setLongClickable(false);
        web.setOnLongClickListener(new View.OnLongClickListener() {
            @Override public boolean onLongClick(View v) { return true; }
        });
        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String u) {
                String host = prefs.getString("server", "");
                if (u.startsWith(host) || u.startsWith("http://127.0.0.1")
                    || u.startsWith("http://localhost")) return false;
                Toast.makeText(MainActivity.this,
                    "دسترسی به آدرس‌های خارجی مسدود است", Toast.LENGTH_SHORT).show();
                return true;
            }

            @Override
            public void onReceivedError(WebView view, int code, String desc, String failingUrl) {
                showError();
            }
        });
        // 🛡️ مسدودسازی کامل دانلود
        web.setDownloadListener(new DownloadListener() {
            @Override public void onDownloadStart(String u, String ua, String cd, String mt, long len) {
                Toast.makeText(MainActivity.this,
                    "دریافت فایل در سوزان غیرفعال است", Toast.LENGTH_SHORT).show();
            }
        });
        setContentView(web);
        web.loadUrl(url + "/i");
    }

    @Override
    public void onBackPressed() {
        if (web != null && web.canGoBack()) web.goBack(); else super.onBackPressed();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu m) {
        m.add(0, 1, 0, "تغییر سرور");
        m.add(0, 2, 0, "خروج");
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem i) {
        if (i.getItemId() == 1) { showSetup(); return true; }
        if (i.getItemId() == 2) { finish(); return true; }
        return super.onOptionsItemSelected(i);
    }
}
JAVA
  ok "سورس‌ها نوشته شد"

  step "تولید آیکون اختصاصی"
  python3 - "$WORK/res/drawable/icon.png" <<'PY'
import sys, zlib, struct
W = H = 96
def flame(x, y):
    if 20 <= y <= 84:
        if y <= 40: w = (y - 16) * 22 // 24
        else:
            dy = (y - 58) / 26.0
            w = int(22 * (1 - dy * dy) ** 0.5) if abs(dy) < 1 else 0
        if abs(x - 48) <= w: return True
    return False
raw = bytearray()
for y in range(H):
    raw.append(0)
    for x in range(W):
        raw += bytes((255, 255, 255)) if flame(x, y) else bytes((255, 107, 53))
def chunk(t, d):
    c = struct.pack(">I", len(d)) + t + d
    return c + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
png = (b"\x89PNG\r\n\x1a\n"
       + chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
       + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
       + chunk(b"IEND", b""))
open(sys.argv[1], "wb").write(png)
print("     آیکون شعله ۹۶×۹۶ ساخته شد")
PY
  [ -f "$WORK/res/drawable/icon.png" ] || err "تولید آیکون ناموفق بود"
  ok "آیکون سوزان آماده است"

  step "تولید R.java"
  spinner "aapt package…" aapt package -f -m -J "$WORK/gen" -M "$WORK/AndroidManifest.xml" \
    -S "$WORK/res" -I "$JAR" || err "aapt (R.java) ناموفق بود"
  ok "R.java ساخته شد"

  step "کامپایل جاوا"
  spinner "ecj compile…" ecj -nowarn -classpath "$JAR" \
    -d "$WORK/obj" $(find "$WORK/src" "$WORK/gen" -name '*.java') || err "کامپایل ناموفق بود"
  ok "کامپایل موفق"

  step "تبدیل به DEX"
  if [ "$DEX" = dx ]; then
    spinner "dx --dex…" dx --dex --output="$WORK/bin/classes.dex" "$WORK/obj" || err "dex ناموفق بود"
  else
    spinner "d8…" d8 --output "$WORK/bin" $(find "$WORK/obj" -name '*.class') || err "dex ناموفق بود"
  fi
  ok "classes.dex ساخته شد"

  step "بسته‌بندی APK"
  spinner "aapt package…" aapt package -f -M "$WORK/AndroidManifest.xml" -S "$WORK/res" \
    -I "$JAR" -F "$WORK/bin/app-unsigned.apk" || err "بسته‌بندی ناموفق بود"
  ( cd "$WORK/bin" && aapt add -f app-unsigned.apk classes.dex >/dev/null ) || err "افزودن dex ناموفق بود"
  ok "APK خام بسته‌بندی شد"

  step "امضای دیجیتال"
  if [ ! -f "$WORK/soozan.keystore" ]; then
    spinner "ساخت keystore…" keytool -genkeypair -keystore "$WORK/soozan.keystore" -alias soozan \
      -keyalg RSA -keysize 2048 -validity 10000 -storepass soozan123 -keypass soozan123 \
      -dname "CN=Soozan, O=Soozan, C=IR" || err "ساخت keystore ناموفق بود"
  fi
  spinner "apksigner sign…" apksigner sign --ks "$WORK/soozan.keystore" \
    --ks-pass pass:soozan123 --key-pass pass:soozan123 \
    --out "$BASE/soozan-viewer.apk" "$WORK/bin/app-unsigned.apk" || err "امضا ناموفق بود"
  ok "APK امضا شد"

  step "راستی‌آزمایی امضا"
  spinner "apksigner verify…" apksigner verify "$BASE/soozan-viewer.apk" || err "امضا معتبر نیست!"
  ok "امضا دیجیتال معتبر است ✔"

  step "گزارش پایانی"
  ls -lh "$BASE/soozan-viewer.apk" | sed 's/^/   /'
  printf "\n"
  ok "فاز ۴ کامل شد — زمان: $(((SECONDS-t0)/60)) دقیقه و $(((SECONDS-t0)%60)) ثانیه 🎉"
  info "ادامه: نصب و تست (دستورهای زیر)"
}

main "$@" 2>&1 | tee "$HOME/soozan-apk-build.log"
exit "${PIPESTATUS[0]}"
