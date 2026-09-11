#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
مهاجرت رمزهای plaintext فایل‌ها به هش scrypt.
ایمن (idempotent): فایل‌های از قبل هش‌شده را رد می‌کند.
در صورت خطا، تراکنش را rollback می‌کند.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from core import get_db, hash_file_password, audit, bootstrap


def main() -> int:
    bootstrap()
    migrated = 0
    skipped_no_pw = 0
    skipped_already_hashed = 0
    errors = 0

    try:
        with get_db() as c:
            # فعال‌سازی foreign keys
            c.execute("PRAGMA foreign_keys = ON")
            rows = c.execute("SELECT id, settings FROM files").fetchall()
            print(f"📊 {len(rows)} فایل در دیتابیس یافت شد")

            for row in rows:
                fid = row["id"]
                raw = row["settings"] or "{}"
                try:
                    st = json.loads(raw)
                except json.JSONDecodeError as e:
                    print(f"  ⚠️  فایل {fid}: JSON نامعتبر ({e})")
                    errors += 1
                    continue

                pw = st.get("password")
                if not pw:
                    skipped_no_pw += 1
                    continue

                # از قبل هش شده؟
                if isinstance(pw, str) and pw.startswith("scrypt$"):
                    skipped_already_hashed += 1
                    continue

                # هش کردن
                try:
                    st["password"] = hash_file_password(pw)
                    c.execute(
                        "UPDATE files SET settings=? WHERE id=?",
                        (json.dumps(st, ensure_ascii=False), fid),
                    )
                    migrated += 1
                except Exception as e:
                    errors += 1
                    print(f"  ❌ خطا در فایل {fid}: {e}")
    except Exception as e:
        print(f"❌ خطای بحرانی: {e}")
        return 1

    try:
        audit(
            "PHASE_A_MIGRATION",
            detail=f"migrated={migrated} no_pw={skipped_no_pw} "
                   f"already_hashed={skipped_already_hashed} errors={errors}",
            level="INFO",
        )
    except Exception:
        pass  # audit نباید مهاجرت را خراب کند

    print("\n✅ مهاجرت کامل شد:")
    print(f"   🔄 هش‌شده: {migrated}")
    print(f"   ⏭ بدون رمز: {skipped_no_pw}")
    print(f"   ⏭ از قبل هش‌شده: {skipped_already_hashed}")
    print(f"   ❌ خطا: {errors}")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
