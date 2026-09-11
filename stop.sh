#!/data/data/com.termux/files/usr/bin/bash
cd "$(dirname "$0")" || exit 1
[ -f tunnel.pid ] && kill "$(cat tunnel.pid)" 2>/dev/null && rm -f tunnel.pid && echo "✅ تونل متوقف شد"
[ -f run.pid ] && kill "$(cat run.pid)" 2>/dev/null && rm -f run.pid && echo "✅ سرور متوقف شد"
termux-wake-unlock 2>/dev/null
