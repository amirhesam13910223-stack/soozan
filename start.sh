#!/data/data/com.termux/files/usr/bin/bash
# 🔥 سوزان — شروع سرویس (سرور + تونل Pinggy) در پس‌زمینه
cd "$(dirname "$0")" || exit 1
termux-wake-lock 2>/dev/null

command -v ssh >/dev/null 2>&1 || {
  echo "⏳ نصب openssh…"
  pkg install -y openssh || { echo "❌ نصب openssh ناموفق"; exit 1; }
}

# ── سرور ──
if [ -f run.pid ] && kill -0 "$(cat run.pid)" 2>/dev/null; then
  echo "ℹ سرور از قبل اجراست (pid $(cat run.pid))"
else
  nohup python app.py > server.log 2>&1 &
  echo $! > run.pid
  echo "✅ سرور شروع شد (pid $(cat run.pid))"
fi

# ── تونل Pinggy ──
if [ -f tunnel.pid ] && kill -0 "$(cat tunnel.pid)" 2>/dev/null; then
  echo "ℹ تونل از قبل اجراست (pid $(cat tunnel.pid))"
  cat public_url.txt 2>/dev/null
else
  rm -f tunnel.log
  nohup ssh -o StrictHostKeyChecking=no \
            -o ServerAliveInterval=30 \
            -o ServerAliveCountMax=3 \
            -R 80:localhost:8000 a.pinggy.io > tunnel.log 2>&1 &
  echo $! > tunnel.pid
  echo "⏳ گرفتن لینک عمومی از Pinggy (تا ~۳۰ ثانیه)…"
  url=""
  for i in $(seq 1 30); do
    # Pinggy لینک را در قالب "https://xxxxx.pinggy.link" چاپ می‌کند
    url=$(grep -oE "https://[a-zA-Z0-9-]+\.pinggy\.link" tunnel.log | head -1)
    [ -n "$url" ] && break
    sleep 1
  done
  if [ -n "$url" ]; then
    echo "$url" > public_url.txt
    echo ""
    echo "   🌍 لینک عمومی: $url"
    echo "   📱 در اپ: منوی ⋮ → تغییر سرور → همین آدرس"
    echo "   ⚠ لینک‌های رایگان Pinggy هر چند ساعت عوض می‌شوند"
    echo ""
  else
    echo "❌ لینک گرفته نشد. log کامل:"
    echo "────────────────────────"
    cat tunnel.log
    echo "────────────────────────"
  fi
fi
