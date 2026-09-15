#!/bin/bash
# ═══════════════════════════════════════════════════════════
# 🛡️ watchdog — پایش سلامت و ری‌استارت خودکار سرور
# ═══════════════════════════════════════════════════════════
cd "$(dirname "$0")" || exit 1

LOG="data/watchdog.log"
INTERVAL=${WATCHDOG_INTERVAL:-30}   # ثانیه بین بررسی‌ها
MAX_FAILS=3                          # آستانه ری‌استارت
mkdir -p data

echo "── $(date '+%Y-%m-%d %H:%M:%S') watchdog شروع شد (interval=${INTERVAL}s) ──" >> "$LOG"

FAILS=0
while true; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:8000/health 2>/dev/null)

    if [ "$CODE" = "200" ]; then
        FAILS=0
    else
        FAILS=$((FAILS + 1))
        echo "$(date '+%Y-%m-%d %H:%M:%S') WARN health=$CODE fails=$FAILS" >> "$LOG"

        if [ $FAILS -ge $MAX_FAILS ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') RESTART سرور مرده بود — ری‌استارت" >> "$LOG"
            pkill -9 -f "python.*app.py" 2>/dev/null
            sleep 2
            nohup bash run.sh >> "$LOG" 2>&1 &
            FAILS=0
            sleep 10
            # چرخش لاگ watchdog
            tail -200 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
        fi
    fi

    sleep "$INTERVAL"
done
