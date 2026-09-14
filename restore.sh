#!/bin/bash
# ═══════════════════════════════════════════════════════════
# 🔄 بازیابی سوزان از بک‌آپ
# ═══════════════════════════════════════════════════════════
set -e

if [ -z "$1" ]; then
    echo "استفاده: bash restore.sh <path/to/backup.tar.gz>"
    echo ""
    echo "بک‌آپ‌های موجود:"
    ls -lh backups/soozan_backup_*.tar.gz 2>/dev/null | tail -5
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "❌ فایل یافت نشد: $BACKUP_FILE"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "══════════════════════════════════════════════════════════"
echo "🔄 بازیابی سوزان"
echo "══════════════════════════════════════════════════════════"
echo "📦 فایل: $BACKUP_FILE"
echo ""

# ۱) تأیید checksum (از داخل دایرکتوری بک‌آپ)
BACKUP_DIR_PATH=$(dirname "$BACKUP_FILE")
BACKUP_BASE=$(basename "$BACKUP_FILE")
if [ -f "${BACKUP_FILE}.sha256" ]; then
    echo "۱) بررسی checksum..."
    if (cd "$BACKUP_DIR_PATH" && sha256sum -c "${BACKUP_BASE}.sha256") > /dev/null 2>&1; then
        echo "  ✅ checksum معتبر"
    else
        echo "  ❌ checksum نامعتبر — بک‌آپ دستکاری شده"
        exit 1
    fi
else
    echo "  ⚠️  checksum یافت نشد — ادامه بدون بررسی"
fi

# ۲) توقف سرور (اگر در حال اجراست)
echo "۲) توقف سرور..."
pkill -9 -f "python.*app.py" 2>/dev/null || true
pkill -9 -f "bash.*run.sh" 2>/dev/null || true
sleep 1
echo "  ✅ سرور متوقف شد"

# ۳) بک‌آپ از وضعیت فعلی (احتیاط)
echo "۳) بک‌آپ از وضعیت فعلی..."
PRE_RESTORE="data/pre_restore_$(date +%Y%m%d_%H%M%S).tar.gz"
if [ -d "data" ]; then
    tar -czf "$PRE_RESTORE" data/ 2>/dev/null || true
    echo "  ✅ $PRE_RESTORE"
fi

# ۴) استخراج بک‌آپ
echo "۴) استخراج بک‌آپ..."
tar -xzf "$BACKUP_FILE"
echo "  ✅ استخراج کامل شد"

# ۵) بررسی صحت فایل‌های حیاتی
echo "۵) بررسی صحت..."
ERRORS=0

if [ ! -f "data/.master.key" ]; then
    echo "  ❌ data/.master.key یافت نشد"
    ERRORS=$((ERRORS+1))
else
    echo "  ✅ data/.master.key موجود"
fi

if [ ! -f "data/burn.db" ]; then
    echo "  ❌ data/burn.db یافت نشد"
    ERRORS=$((ERRORS+1))
else
    echo "  ✅ data/burn.db موجود"
    
    # بررسی integrity
    if sqlite3 data/burn.db "PRAGMA integrity_check;" 2>/dev/null | grep -q "ok"; then
        echo "  ✅ burn.db سالم است"
    else
        echo "  ⚠️  burn.db ممکن است مشکل داشته باشد"
    fi
fi

if [ $ERRORS -gt 0 ]; then
    echo ""
    echo "⚠️  $ERRORS فایل حیاتی یافت نشد"
    exit 1
fi

echo ""
echo "══════════════════════════════════════════════════════════"
echo "✅ بازیابی کامل شد"
echo "══════════════════════════════════════════════════════════"
echo ""
echo "🚀 برای راه‌اندازی سرور:"
echo "   bash run.sh"
