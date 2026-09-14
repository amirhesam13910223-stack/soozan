#!/usr/bin/env python3
"""Soozan Phase 0 audit: inventory + routes + security scan -> docs/audit/phase0_audit.md"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = ROOT / "docs" / "audit"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

py_files = [p for p in sorted(ROOT.rglob("*.py"))
            if not any(x in p.parts for x in ("venv", ".git", "apkbuild", "__pycache__"))]

out = []
add = out.append
add("# Soozan Phase 0 Audit Report")
add("")

# 1) LOC inventory
add("## 1) Code inventory (LOC)")
total = 0
for p in py_files:
    n = len(p.read_text(encoding="utf-8", errors="replace").splitlines())
    total += n
    add(f"- `{p.relative_to(ROOT)}`: {n} lines")
add(f"- **TOTAL**: {total} lines")
add("")

# 2) Routes
add("## 2) Routes")
route_re = re.compile(r"@([\w\.]+)\.route\(\s*['\"]([^'\"]+)['\"]([^\)]*)\)", re.DOTALL)
for p in py_files:
    src = p.read_text(encoding="utf-8", errors="replace")
    for m in route_re.finditer(src):
        methods = "GET"
        mm = re.search(r"methods\s*=\s*\[([^\]]*)\]", m.group(3))
        if mm:
            methods = mm.group(1).replace('"', "").replace("'", "").strip()
        add(f"- `{m.group(2)}` [{methods}] - {p.relative_to(ROOT)}")
add("")

# 3) Templates
add("## 3) Templates")
tpl = ROOT / "templates"
if tpl.exists():
    for p in sorted(tpl.rglob("*.html")):
        add(f"- `{p.relative_to(ROOT)}`")
add("")

# 4) Security scan
add("## 4) Security scan (automated)")
patterns = {
    "debug=True": r"debug\s*=\s*True",
    "hardcoded-secret": r"(secret_key|SECRET_KEY|password|passwd|api_token)\s*=\s*['\"][^'\"]{6,}['\"]",
    "eval-exec": r"\b(eval|exec)\s*\(",
    "shell=True": r"shell\s*=\s*True",
    "pickle": r"\bpickle\.loads?\(",
    "os.system": r"os\.system\s*\(",
    "subprocess": r"subprocess\.",
    "sql-fstring": r"execute\(\s*f['\"]",
    "todo-fixme": r"(TODO|FIXME|XXX|HACK)",
}
findings = 0
for name, pat in patterns.items():
    rx = re.compile(pat)
    for p in py_files:
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if rx.search(line):
                add(f"- [{name}] `{p.relative_to(ROOT)}:{i}` -> {line.strip()[:90]}")
                findings += 1
add(f"- **TOTAL findings**: {findings}")
add("")

(REPORT_DIR / "phase0_audit.md").write_text("\n".join(out), encoding="utf-8")
print(f"✅ Report: {REPORT_DIR / 'phase0_audit.md'}")
print(f"   files={len(py_files)}  LOC={total}  security_findings={findings}")
