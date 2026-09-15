#!/bin/bash
# ═══════════════════════════════════════════════════════════
# 💿 مانیتورینگ دیسک + هشدار خودکار
# ═══════════════════════════════════════════════════════════
cd "$(dirname "$0")" || exit 1

LOG="data/disk_alerts.log"
WARN_THRESHOLD=${DISK_WARN_THRESHOLD:-80}   # درصد هشدار
CRIT_THRESHOLD=${DISK_CRIT_THRESHOLD:-90}   # درصد بحرانی
mkdir -p data

# گرفتن درصد استفاده از پارتیشن data
USAGE=$(df -h data/ | awk 'NR==2 {print $5}' | sed 's/%//')

if [ -z "$USAGE" ]; then
    echo "❌ خطا: نمی‌توان درصد استفاده دیسک را خواند" >&2
    exit 1
fi

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

if [ "$USAGE" -ge "$CRIT_THRESHOLD" ]; then
    echo "[$TIMESTAMP] 🔴 CRITICAL: دیسک $USAGE٪ پر است (آستانه بحرانی: $CRIT_THRESHOLD٪)" >> "$LOG"
    echo "🔴 CRITICAL: دیسک $USAGE٪ پر است"
elif [ "$USAGE" -ge "$WARN_THRESHOLD" ]; then
    echo "[$TIMESTAMP] ⚠️  WARNING: دیسک $USAGE٪ پر است (آستانه هشدار: $WARN_THRESHOLD٪)" >> "$LOG"
    echo "⚠️  WARNING: دیسک $USAGE٪ پر است"
else
    # فقط در حالت verbose لاگ کن
    if [ "${VERBOSE:-0}" = "1" ]; then
        echo "[$TIMESTAMP] ✅ دیسک $USAGE٪ استفاده (سالم)" >> "$LOG"
    fi
fi

# چرخش لاگ هشدارها (حفظ ۵۰۰ خط آخر)
if [ -f "$LOG" ] && [ "$(wc -l < "$LOG")" -gt 500 ]; then
    tail -500 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi

# خروجی عددی برای استفاده در script های دیگر
echo "$USAGE"
