#!/data/data/com.termux/files/usr/bin/bash
# 🗄 پشتیبان کامل سوزان (دیتابیس + کلید ارشد + فایل‌های رمزشده)
cd ~/soozan || exit 1
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="$HOME/soozan-backup-$STAMP.tar.gz"
tar -czf "$OUT" -C "$HOME" soozan/data
chmod 600 "$OUT"
ls -lh "$OUT" | sed 's/^/   /'
echo "✅ پشتیبان ساخته شد"
echo "⚠️  این فایل شامل کلید ارشد است — جای امن نگهش دار"
