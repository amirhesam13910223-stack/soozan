#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🛡️ اسکن بدافزار برای فایل‌های text/code — فاز C

طراحی plug-in/قابل‌تعویض:
- اینترفیس ساده `MalwareScanner`
- پیاده‌سازی پیش‌فرض: `PatternScanner` (بدون وابستگی خارجی)
- پیاده‌سازی اختیاری: `ClamAVScanner` (اگر clamscan نصب باشد)
- رفتار در صورت خطا/عدم‌دسترسی: قابل‌تنظیم با `MALWARE_FAIL_MODE`
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Protocol


# ─── ساختار نتیجه اسکن ───
@dataclass
class ScanResult:
    """نتیجه‌ی اسکن یک فایل"""
    safe: bool
    scanner_name: str = ""
    threats: List[str] = field(default_factory=list)
    detail: str = ""


# ─── اینترفیس اسکنر ───
class MalwareScanner(Protocol):
    """
    اینترفیس اسکن بدافزار.
    هر پیاده‌سازی باید متد `scan` را داشته باشد.
    """
    def scan(self, data: bytes, filename: str = "") -> ScanResult: ...


# ─── الگوهای خطرناک برای فایل‌های کد ───
# این الگوها برای تشخیص کدهای مشکوک در فایل‌های متنی/کد هستند
DANGEROUS_PATTERNS: List[tuple] = [
    # ── Shell / Command Injection ──
    (r'\bos\.system\s*\(', "os.system() call"),
    (r'\bsubprocess\.\w+\s*\(', "subprocess call"),
    (r'\beval\s*\(', "eval() call"),
    (r'\bexec\s*\(', "exec() call"),
    (r'\bcompile\s*\(', "compile() call"),
    (r'\b__import__\s*\(', "__import__() call"),
    # ── File system manipulation ──
    (r'\bshutil\.rmtree\s*\(', "shutil.rmtree() call"),
    (r'\bos\.remove\s*\(', "os.remove() call"),
    (r'\bos\.unlink\s*\(', "os.unlink() call"),
    (r'\bos\.rmdir\s*\(', "os.rmdir() call"),
    # ── Network exfiltration ──
    (r'\brequests\.(get|post|put|delete)\s*\(', "HTTP request call"),
    (r'\burllib\.\w+\s*\(', "urllib call"),
    (r'\bsocket\.\w+\s*\(', "socket call"),
    (r'\bftplib\.\w+\s*\(', "FTP call"),
    # ── Obfuscation / Encoding ──
    (r'\bbase64\.(b64decode|decodebytes)\s*\(', "base64 decode"),
    (r'\bcodecs\.decode\s*\(', "codecs decode"),
    (r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}', "hex-encoded string chain"),
    # ── Credential harvesting ──
    (r'\bos\.environ\s*(\[|\.get)', "environment variable access"),
    (r'\bgetpass\s*\(', "getpass() call"),
    (r'\.ssh/|id_rsa|\.gnupg', "credential file path"),
    # ── Persistence ──
    (r'\bcrontab\b', "crontab reference"),
    (r'\.bashrc|\.bash_profile|\.profile', "shell profile modification"),
    (r'/etc/passwd|/etc/shadow', "system credential file"),
    # ── Web shell patterns ──
    (r'<%.*exec.*%>', "web shell pattern (JSP/ASP)"),
    (r'php://input|php://filter', "PHP wrapper"),
    (r'\bsystem\s*\(\s*\$', "PHP system() call"),
    (r'\bpassthru\s*\(', "PHP passthru() call"),
    # ── Reverse shell ──
    (r'/bin/(ba)?sh\s+-i', "interactive shell"),
    (r'nc\s+-e\s+/bin', "netcat reverse shell"),
    (r'\bpty\.spawn\b', "pty spawn"),
    # ── Privilege escalation ──
    (r'\bchmod\s+[0-7]*777\b', "chmod 777"),
    (r'\bsudo\b.*\bNOPASSWD\b', "sudo NOPASSWD"),
    # ── Data destruction ──
    (r'\bdd\s+if=.*of=/dev/', "dd to device"),
    (r'\bmkfs\b', "filesystem format"),
    (r'\bshred\s+\-', "secure deletion tool"),
    # ── Crypto mining indicators ──
    (r'stratum\+tcp://', "mining pool URL"),
    (r'\bminerd\b|\bcpuminer\b|\bxmrig\b', "crypto miner binary"),
    # ── JavaScript dangerous ──
    (r'\bdocument\.write\s*\(', "document.write()"),
    (r'\bwindow\.location\s*=', "location redirect"),
    (r'\.innerHTML\s*=.*\+', "innerHTML concatenation"),
]

# فایل‌هایی که نباید اسکن شوند (تصویر، صوت، PDF)
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg', '.ico',
    '.mp3', '.wav', '.ogg', '.flac', '.m4a', '.aac',
    '.pdf',
}


class PatternScanner:
    """
    اسکنر مبتنی بر الگو (بدون وابستگی خارجی).
    فایل‌های متنی را با مجموعه‌ای از الگوهای خطرناک مقایسه می‌کند.
    """

    def __init__(self, patterns: List[tuple] = None, threshold: int = 1):
        """
        :param patterns: لیست (regex, توضیح) الگوهای خطرناک
        :param threshold: حداقل تعداد الگوی منطبق برای تشخیص آلودگی
        """
        self._patterns = [(re.compile(p, re.IGNORECASE), desc) for p, desc in (patterns or DANGEROUS_PATTERNS)]
        self._threshold = threshold

    def scan(self, data: bytes, filename: str = "") -> ScanResult:
        # بررسی پسوند فایل — اگر تصویر/صوت/PDF باشد، اسکن نمی‌شود
        ext = Path(filename).suffix.lower()
        if ext in SKIP_EXTENSIONS:
            return ScanResult(safe=True, scanner_name="PatternScanner", detail="skipped (non-text)")

        # تلاش برای decode به‌عنوان متن
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = data.decode("latin-1")
            except Exception:
                return ScanResult(safe=True, scanner_name="PatternScanner", detail="skipped (binary)")

        threats = []
        for pattern, description in self._patterns:
            if pattern.search(text):
                threats.append(description)

        if len(threats) >= self._threshold:
            return ScanResult(
                safe=False,
                scanner_name="PatternScanner",
                threats=threats,
                detail=f"{len(threats)} dangerous pattern(s) detected",
            )
        return ScanResult(safe=True, scanner_name="PatternScanner")


class ClamAVScanner:
    """
    اسکنر ClamAV (اختیاری).
    اگر `clamscan` در سیستم موجود باشد استفاده می‌شود.
    """

    def __init__(self):
        self._clamscan = shutil.which("clamscan")

    @property
    def available(self) -> bool:
        return self._clamscan is not None

    def scan(self, data: bytes, filename: str = "") -> ScanResult:
        if not self.available:
            return ScanResult(safe=True, scanner_name="ClamAVScanner", detail="clamscan not installed")

        # نوشتن به فایل موقت امن
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(suffix=Path(filename).suffix or ".tmp")
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
            # اجرای clamscan
            result = subprocess.run(
                [self._clamscan, "--no-summary", tmp_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                return ScanResult(safe=True, scanner_name="ClamAVScanner")
            elif result.returncode == 1:
                threats = [line.strip() for line in result.stdout.split('\n') if 'FOUND' in line]
                return ScanResult(safe=False, scanner_name="ClamAVScanner", threats=threats, detail="virus detected")
            else:
                return ScanResult(safe=True, scanner_name="ClamAVScanner", detail=f"scan error (rc={result.returncode})")
        except subprocess.TimeoutExpired:
            return ScanResult(safe=True, scanner_name="ClamAVScanner", detail="scan timeout")
        except Exception as e:
            return ScanResult(safe=True, scanner_name="ClamAVScanner", detail=f"scan error: {e}")
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass


# ─── مدیریت تنظیمات و اجرای اسکن ───
# رفتار در صورت عدم‌دسترسی اسکنر یا خطا:
#   "fail-closed" → آپلود مسدود شود (پیشنهادی برای امنیت بالا)
#   "fail-open"   → با هشدار عبور کند
MALWARE_FAIL_MODE: str = os.environ.get("SOOZAN_MALWARE_MODE", "fail-closed")

# اسکنر پیش‌فرض
_DEFAULT_SCANNER: Optional[MalwareScanner] = None


def get_scanner() -> MalwareScanner:
    """دریافت اسکنر فعال (ترتیب اولویت: ClamAV > Pattern)"""
    global _DEFAULT_SCANNER
    if _DEFAULT_SCANNER is None:
        clamav = ClamAVScanner()
        if clamav.available:
            _DEFAULT_SCANNER = clamav
        else:
            _DEFAULT_SCANNER = PatternScanner()
    return _DEFAULT_SCANNER


def scan_file(data: bytes, filename: str = "", family: str = "text") -> ScanResult:
    """
    اسکن یک فایل برای بدافزار.
    فقط فایل‌های خانواده‌ی text اسکن می‌شوند.

    :param data: محتوای فایل
    :param filename: نام فایل
    :param family: خانواده فایل (image/audio/pdf/text)
    :return: نتیجه اسکن
    """
    # فقط فایل‌های متنی/کد اسکن می‌شوند
    if family not in ("text",):
        return ScanResult(safe=True, scanner_name="skip", detail=f"family={family} skipped")

    # بررسی پسوند هم به‌عنوان لایه اضافی
    ext = Path(filename).suffix.lower()
    if ext in SKIP_EXTENSIONS:
        return ScanResult(safe=True, scanner_name="skip", detail=f"extension={ext} skipped")

    scanner = get_scanner()
    return scanner.scan(data, filename)


def should_block_upload(scan_result: ScanResult) -> bool:
    """
    آیا آپلود باید مسدود شود؟
    بر اساس نتیجه اسکن و تنظیمات `MALWARE_FAIL_MODE` تصمیم می‌گیرد.
    """
    if scan_result.safe:
        return False
    # فایل آلوده شناسایی شده
    return True
