# Soozan Phase 0 Audit Report

## 1) Code inventory (LOC)
- `admin_infra.py`: 122 lines
- `admin_panel.py`: 470 lines
- `analytics.py`: 179 lines
- `app.py`: 111 lines
- `auth.py`: 79 lines
- `core.py`: 771 lines
- `dashboard.py`: 93 lines
- `export.py`: 264 lines
- `migrate_hash_passwords.py`: 85 lines
- `phase_a_patch.py`: 408 lines
- `renderer.py`: 120 lines
- `scanner.py`: 252 lines
- `test_full_regression.py`: 517 lines
- `test_phase1.py`: 259 lines
- `test_phase2.py`: 146 lines
- `test_phase3.py`: 169 lines
- `test_phase5.py`: 98 lines
- `test_phase6_security.py`: 168 lines
- `tools/phase0_audit.py`: 75 lines
- `ui.py`: 44 lines
- `viewer.py`: 430 lines
- `wizard.py`: 182 lines
- **TOTAL**: 5042 lines

## 2) Routes
- `/assets/<path:path>` [GET] - app.py
- `/` [GET] - app.py
- `/login` [GET, POST] - auth.py
- `/register` [GET, POST] - auth.py
- `/logout` [GET] - auth.py
- `/dashboard` [GET] - dashboard.py
- `/wizard` [GET] - wizard.py
- `/api/upload` [POST] - wizard.py

## 3) Templates
- `templates/app.html`
- `templates/auth.html`
- `templates/base.html`
- `templates/dashboard.html`
- `templates/enter.html`
- `templates/index.html`
- `templates/manage_enter.html`
- `templates/manage_panel.html`
- `templates/viewer.html`
- `templates/wizard.html`

## 4) Security scan (automated)
- [debug=True] `tools/phase0_audit.py:52` -> "debug=True": r"debug\s*=\s*True",
- [hardcoded-secret] `test_full_regression.py:189` -> password = "TestPassword123!"
- [eval-exec] `scanner.py:49` -> (r'\beval\s*\(', "eval() call"),
- [eval-exec] `scanner.py:50` -> (r'\bexec\s*\(', "exec() call"),
- [shell=True] `tools/phase0_audit.py:55` -> "shell=True": r"shell\s*=\s*True",
- [os.system] `scanner.py:47` -> (r'\bos\.system\s*\(', "os.system() call"),
- [subprocess] `scanner.py:176` -> result = subprocess.run(
- [subprocess] `scanner.py:187` -> except subprocess.TimeoutExpired:
- [subprocess] `test_full_regression.py:62` -> def ensure_server() -> subprocess.Popen:
- [subprocess] `test_full_regression.py:66` -> subprocess.run(["pkill", "-f", "python app.py"], capture_output=True)
- [subprocess] `test_full_regression.py:71` -> proc = subprocess.Popen(
- [subprocess] `test_full_regression.py:73` -> stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
- [subprocess] `test_full_regression.py:90` -> def cleanup(proc: subprocess.Popen):
- [subprocess] `test_phase5.py:75` -> subprocess.run(["bash", str(BASE / "backup.sh")], capture_output=True)
- [todo-fixme] `tools/phase0_audit.py:60` -> "todo-fixme": r"(TODO|FIXME|XXX|HACK)",
- **TOTAL findings**: 15
