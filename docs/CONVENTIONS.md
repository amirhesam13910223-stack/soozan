# Soozan Engineering Conventions (v1.0.0)

## شاخه‌ها
- `main` : همیشه قابل استقرار — سرور فقط از اینجا pull می‌کند
- `dev`  : یکپارچه‌سازی — فقط وقتی CI سبز است به main ادغام می‌شود
- `feature/*` و `fix/*` : برای تغییرات پرریسک → ادغام به dev

## کامیت‌ها
فرمت: `type(scope): subject`
انواع: feat | fix | sec | ui | docs | test | chore | perf
مثال: `feat(billing): add invoice model`
مثال: `sec(auth): enforce otp rate limit`

## قوانین
- هر push باید CI را سبز کند
- اسرار (master key، توکن‌ها) هرگز وارد git نمی‌شوند
- از فاز ۱ به بعد: push مستقیم به main ممنوع (فقط merge از dev)

## جریان ادغام
git checkout main && git pull
git merge dev && git push
# سپس در سرور: git pull + Reload
