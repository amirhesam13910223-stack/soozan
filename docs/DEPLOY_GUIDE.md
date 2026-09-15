# 🚀 راهنمای استقرار production سوزان

**هدف:** VPS ایران + nginx + HTTPS + systemd
**مخاطب:** اپراتور سوزان · نسخه ۱.۰ · شهریور ۱۴۰۵

---

## ۰. پیش‌نیازها

- [ ] دامنه `.ir` ثبت‌شده به نام شما + کد ساماندهی (مطابق LEGAL_GUIDE)
- [ ] VPS داخل ایران: Ubuntu 22.04/24.04، حداقل ۲ هسته / ۲GB RAM / ۲۰GB دیسک
- [ ] دسترسی root با کلید SSH (رمز غیرفعال)

---

## ۱. آماده‌سازی سرور

```bash
# کاربر اختصاصی
adduser soozan --disabled-password
usermod -aG sudo soozan

# فایروال
ufw default deny incoming
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp
ufw enable

# ابزارها
apt update && apt upgrade -y
apt install -y python3 python3-venv python3-pip git nginx certbot python3-certbot-nginx fail2ban
```

## ۲. استقرار کد

```bash
su - soozan
git clone https://github.com/amirhesam13910223-stack/soozan.git   # یا deploy با کلید خصوصی
cd soozan
git checkout main && git pull
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

# bootstrap اولیه (ساخت کلید ارشد + دیتابیس)
./venv/bin/python -c "from core import bootstrap; bootstrap()"
ls -la data/   # باید: .master.key با دسترسی 600 و پوشه data با 700
```

> 🔐 **هرگز** `SOOZAN_DEV_MODE=1` را در production ست نکنید.

## ۳. سرویس systemd

`/etc/systemd/system/soozan.service`:

```ini
[Unit]
Description=Soozan burn-after-read service
After=network.target

[Service]
User=soozan
WorkingDirectory=/home/soozan/soozan
ExecStart=/home/soozan/soozan/venv/bin/python app.py
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/home/soozan/soozan/data

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now soozan
systemctl status soozan --no-pager
```

> 💡 با systemd، `Restart=always` نقش watchdog را هم پوشش می‌دهد؛ watchdog.sh برای محیط Termux بماند.

## ۴. nginx + HTTPS

`/etc/nginx/sites-available/soozan`:

```nginx
server {
    listen 80;
    server_name soozan.ir www.soozan.ir;

    client_max_body_size 50m;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
```

```bash
ln -s /etc/nginx/sites-available/soozan /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# صدور گواهی Let's Encrypt + تنظیم خودکار HTTPS
certbot --nginx -d soozan.ir -d www.soozan.ir
certbot renew --dry-run   # تأیید تمدید خودکار
```

## ۵. cron های production

```bash
crontab -e   # به‌عنوان کاربر soozan
```
```cron
# بک‌آپ روزانه ساعت ۳
0 3 * * * cd /home/soozan/soozan && bash backup_auto.sh
# پاک‌سازی لاگ بک‌آپ
0 4 * * 0 cd /home/soozan/soozan && tail -200 data/backup_auto.log > data/.bal.tmp && mv data/.bal.tmp data/backup_auto.log
```

## ۶. چک‌لیست smoke test پس از استقرار

- [ ] `curl -I https://soozan.ir/health` → 200 + هدرهای امنیتی
- [ ] `https://soozan.ir/status` → نشانگرها سبز
- [ ] ثبت‌نام + آپلود + مشاهده + امحا (e2e دستی)
- [ ] فعال‌سازی 2FA برای حساب اپراتور
- [ ] `bash backup.sh` + یک drill بازیابی در مسیر موقت
- [ ] `fail2ban-client status` فعال
- [ ] بررسی `systemctl is-enabled soozan` = enabled

## ۷. بازگشت به عقب (Rollback)

```bash
systemctl stop soozan
bash restore.sh backups/<آخرین_بک‌آپ_معتبر>.tar.gz
systemctl start soozan
curl -s https://soozan.ir/health
```

## ۸. نگهداری مستمر

| اقدام | بازه |
|---|---|
| بک‌آپ خودکار | روزانه (cron) |
| بررسی /status | روزانه (خودتان یا uptime monitor) |
| `apt upgrade` + `pip-audit` | ماهانه |
| تمرین بازیابی (drill) | فصلی |
| بازبینی اسناد حقوقی | سالانه |

---

*نکته پایانی: این راهنما برای استقرار بتای خصوصی کافی است؛ پیش از راه‌اندازی عمومی، چک‌لیست حقوقی LEGAL_GUIDE باید کامل شده باشد.*
