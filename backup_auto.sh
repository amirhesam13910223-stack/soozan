#!/bin/bash
# ═══════════════════════════════════════════════════════════
# 💾 بک‌آپ خودکار زمان‌بندی‌شده (برای cron)
# ═══════════════════════════════════════════════════════════
cd "$(dirname "$0")" || exit 1

LOG="data/backup_auto.log"
mkdir -p data

echo "── $(date '+%Y-%m-%d %H:%M:%S') شروع بک‌آپ خودکار ──" >> "$LOG"
bash backup.sh >> "$LOG" 2>&1
STATUS=$?

if [ $STATUS -eq 0 ]; then
    echo "✅ موفق" >> "$LOG"
else
    echo "❌ شکست با کد $STATUS" >> "$LOG"
fi

# چرخش لاگ خودِ بک‌آپ (نگه‌داشتن ۲۰۰ خط آخر)
if [ -f "$LOG" ]; then
    tail -200 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi

exit $STATUS
