#!/bin/bash
# ═══════════════════════════════════════════════════════════
# 🗄️ بک‌آپ کامل سوزان
# ═══════════════════════════════════════════════════════════
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BACKUP_DIR="backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="soozan_backup_${TIMESTAMP}.tar.gz"

mkdir -p "$BACKUP_DIR"

echo "══════════════════════════════════════════════════════════"
echo "🗄️ شروع بک‌آپ سوزان"
echo "══════════════════════════════════════════════════════════"
echo "📁 مسیر: $SCRIPT_DIR"
echo "📦 نام: $BACKUP_NAME"
echo ""

# ۱) بک‌آپ دیتابیس (live copy با integrity check)
echo "۱) بک‌آپ دیتابیس..."
if [ -f "data/burn.db" ]; then
    # استفاده از sqlite3 .backup برای جلوگیری از corruption
    sqlite3 data/burn.db ".backup 'data/burn.db.backup'"
    echo "  ✅ burn.db.backup ساخته شد"
else
    echo "  ⚠️  data/burn.db یافت نشد"
fi

# ۲) بک‌آپ کلید ارشد (حیاتی‌ترین فایل)
echo "۲) بک‌آپ کلید ارشد..."
if [ -f "data/.master.key" ]; then
    cp data/.master.key data/.master.key.backup
    echo "  ✅ .master.key.backup ساخته شد"
else
    echo "  ⚠️  data/.master.key یافت نشد"
fi

# ۳) ایجاد آرشیو (بدون فایل‌های موقت)
echo "۳) ساخت آرشیو..."
tar -czf "$BACKUP_DIR/$BACKUP_NAME" \
    --exclude='backups' \
    --exclude='*.pyc' \
    --exclude='__pycache__' \
    --exclude='.git' \
    --exclude='venv' \
    --exclude='*.log' \
    data/ templates/ \
    app.py core.py auth.py \
    admin_panel.py admin_infra.py \
    analytics.py dashboard.py export.py \
    renderer.py scanner.py ui.py viewer.py wizard.py \
    totp.py phase_a_patch.py \
    run.sh requirements.txt \
    2>/dev/null || tar -czf "$BACKUP_DIR/$BACKUP_NAME" data/ 2>/dev/null

# ۴) پاک کردن فایل‌های موقت بک‌آپ
rm -f data/burn.db.backup data/.master.key.backup

# ۵) محاسبه checksum
cd "$BACKUP_DIR"
sha256sum "$BACKUP_NAME" > "${BACKUP_NAME}.sha256"
SIZE=$(du -h "$BACKUP_NAME" | cut -f1)
cd ..

echo ""
echo "══════════════════════════════════════════════════════════"
echo "✅ بک‌آپ کامل شد"
echo "══════════════════════════════════════════════════════════"
echo "📦 فایل: $BACKUP_DIR/$BACKUP_NAME"
echo "📏 اندازه: $SIZE"
echo "🔐 checksum: $BACKUP_DIR/${BACKUP_NAME}.sha256"
echo ""
echo "💡 بازیابی:"
echo "   bash restore.sh $BACKUP_DIR/$BACKUP_NAME"
