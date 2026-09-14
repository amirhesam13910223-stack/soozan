export SOOZAN_DEV_MODE=1
#!/data/data/com.termux/files/usr/bin/bash
cd "$(dirname "$0")"
echo "🔥 اجرای سوزان…"
exec python app.py
