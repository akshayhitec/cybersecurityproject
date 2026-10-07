# Phishing Email Forensics and Threat Analysis Tool — Plan

## Top-Level Overview

Build a complete college-level cybersecurity web application using Python/Flask, SQLite, and a dark-themed HTML/CSS/JS dashboard.

The tool accepts uploaded `.eml` email files, parses them safely, runs multiple forensic analysis modules (auth headers, URL extraction, phishing content detection, attachment metadata), calculates a weighted risk score, stores results in SQLite, renders a full forensic dashboard, and allows downloading a plain-text forensic report.

No uploaded content is executed, no URLs are visited, and all displayed content is sanitized.

---

## Sub-Tasks

---

### Sub-Task 1 — Project Scaffold and Configuration

**Intent**
Create the folder structure, `requirements.txt`, `config.py`, and the Flask app skeleton (`app.py`) with placeholder routes. This establishes the foundation every subsequent sub-task builds on.

**Expected Outcomes**
- All directories and placeholder files exist.
- `requirements.txt` lists all needed packages.
- `config.py` defines upload limits, allowed extensions, folder paths, and DB path.
- `app.py` has route stubs for `/`, `/analyze`, `/history`, `/report/<id>`.
- Running `python app.py` starts the server without errors.

**Todo List**
1. Create directory tree: `database/`, `forensics/`, `reports/generated/`, `static/css/`, `static/js/`, `static/img/`, `templates/`, `uploads/`.
2. Write `requirements.txt` (flask, Werkzeug, bleach, dnspython if needed, standard-library-only forensics where possible).
3. Write `config.py` with `MAX_CONTENT_LENGTH`, `UPLOAD_FOLDER`, `DB_PATH`, `ALLOWED_EXTENSIONS = {'.eml'}`.
4. Write `app.py` with Flask init, config loading, and stub routes that return placeholder strings.
5. Add `uploads/.gitkeep` and `reports/generated/.gitkeep`.

**Relevant Context**
- No existing codebase.
- `config.py` values will be imported by all other modules.

**Status** — `[ ] pending`

---

### Sub-Task 2 — SQLite Database Layer

**Intent**
Create the database module that initializes the schema on first run and exposes clean helper functions used by the Flask routes.

**Expected Outcomes**
- `database/db.py` creates `analyses` and `url_findings` tables on import if they do not exist.
- `save_analysis(data_dict)` inserts a full analysis record and returns the new `id`.
- `get_all_analyses()` returns a list of summary rows for the history page.
- `get_analysis_by_id(id)` returns the full record including `findings_json`.

**Todo List**
1. Write `database/db.py` with `init_db()` called at module import.
2. Define `analyses` table schema (see Database Design section).
3. Define `url_findings` table schema with FK to `analyses.id`.
4. Implement `save_analysis(data)` — inserts into both tables transactionally.
5. Implement `get_all_analyses()` — returns id, filename, uploaded_at, sender, subject, risk_score, risk_level.
6. Implement `get_analysis_by_id(id)` — returns full row with findings_json.

**Relevant Context**
- DB path comes from `config.py → DB_PATH`.
- `findings_json` is a JSON-serialized string of the complete findings dict.

**Status** — `[ ] pending`

---

### Sub-Task 3 — Email Parser Module

**Intent**
Build the safe parser that turns a raw `.eml` file into a structured Python dict of headers, body parts, and attachment metadata — without executing or rendering anything.

**Expected Outcomes**
- `forensics/parser.py` exposes `parse_email(file_path) -> dict`.
- Returned dict contains: `headers` (all raw headers as key-list dict), `from_addr`, `to_addr`, `reply_to`, `subject`, `date`, `plain_body`, `html_body`, `attachments` (list of dicts with `filename`, `content_type`, `size_bytes`, `payload_bytes`).
- Malformed or non-email files raise a caught `ParseError` with a safe message.

**Todo List**
1. Write `forensics/parser.py` using Python's `email` stdlib (`email.message_from_bytes`).
2. Walk MIME parts: collect `text/plain`, `text/html`, and attachment parts separately.
3. For attachments, record filename, declared content-type, and byte length only — do not decode executable payloads.
4. Decode header values safely using `email.header.decode_header`.
5. Define a local `ParseError` exception for invalid input.

**Relevant Context**
- Never use `eval`, `exec`, or shell calls inside this module.
- `html_body` is stored as a raw string but will be sanitized before display in templates.

**Status** — `[ ] pending`

---

### Sub-Task 4 — Authentication Header Analyzer

**Intent**
Inspect SPF, DKIM, and DMARC authentication results from the email headers and return structured pass/fail/none findings.

**Expected Outcomes**
- `forensics/auth_analyzer.py` exposes `analyze_auth(headers) -> dict`.
- Returned dict: `spf: {result, detail}`, `dkim: {result, detail}`, `dmarc: {result, detail}`.
- `result` is one of `"pass"`, `"fail"`, `"softfail"`, `"none"`, `"neutral"`.

**Todo List**
1. Write `forensics/auth_analyzer.py`.
2. Search `Received-SPF` header for result tokens (`pass`, `fail`, `softfail`, `neutral`, `none`).
3. Search `Authentication-Results` header for `spf=`, `dkim=`, `dmarc=` tokens.
4. Check for presence of `DKIM-Signature` header as a secondary DKIM indicator.
5. Return structured dict; default all results to `"none"` when headers are absent.

**Relevant Context**
- Headers are the raw dict produced by `forensics/parser.py`.
- Only string parsing — no DNS lookups at analysis time.

**Status** — `[ ] pending`

---

### Sub-Task 5 — URL Extractor and Suspicious URL Detector

**Intent**
Extract all URLs from email body and headers, then apply static heuristics to flag suspicious ones — without visiting any URL.

**Expected Outcomes**
- `forensics/url_extractor.py` exposes `extract_and_analyze_urls(plain_body, html_body, headers) -> list[dict]`.
- Each dict: `url`, `is_suspicious` (bool), `reasons` (list of strings).
- Suspicious checks include: IP-literal hostname, misleading subdomain, URL-encoded characters, suspicious TLDs, very long URLs, `@` symbol in URL, homograph indicators.

**Todo List**
1. Write `forensics/url_extractor.py`.
2. Extract URLs from `plain_body` using regex `https?://[^\s<>"]+`.
3. Extract `href` values from `html_body` using `html.parser` (no third-party HTML libs required).
4. Deduplicate URL list.
5. For each URL, run heuristic checks and collect reasons.
6. Flag: IP-literal host (`re` match for IPv4 pattern), `@` in URL, URL length > 100, percent-encoded sequences, suspicious TLDs (list: `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`), subdomain depth > 3.
7. Return list of finding dicts.

**Relevant Context**
- No outbound network calls whatsoever.
- URLs are never opened or resolved.

**Status** — `[ ] pending`

---

### Sub-Task 6 — Phishing Content Detector

**Intent**
Scan the email body and headers for language patterns and structural indicators that are characteristic of phishing attempts.

**Expected Outcomes**
- `forensics/phishing_detector.py` exposes `detect_phishing_indicators(plain_body, html_body, headers) -> list[dict]`.
- Each dict: `indicator_type`, `description`, `severity` (`low`/`medium`/`high`).
- Detected categories: urgency language, credential-harvesting phrases, brand impersonation, From/Reply-To mismatch, display-name spoofing, suspicious HTML attributes.

**Todo List**
1. Write `forensics/phishing_detector.py`.
2. Define keyword lists: urgency phrases (`"act immediately"`, `"account suspended"`, `"verify now"`, etc.), credential phrases (`"enter your password"`, `"confirm your details"`, etc.), brand names to check for impersonation (`PayPal`, `Microsoft`, `Apple`, `Amazon`, `Google`, `bank`, etc.).
3. Scan `plain_body` and `html_body` (stripped of tags) against keyword lists (case-insensitive).
4. Compare `From` header display name vs actual address domain for display-name spoofing.
5. Compare `From` domain vs `Reply-To` domain for mismatch.
6. Detect HTML tricks: hidden text (style=display:none), form elements, suspicious `action=` attributes in HTML.
7. Return list of indicator dicts.

**Relevant Context**
- Use `re` and simple string operations only.
- Strip HTML tags with `re` or `html.parser` before keyword scanning — never render.

**Status** — `[ ] pending`

---

### Sub-Task 7 — Attachment Analyzer

**Intent**
List all email attachments with metadata and flag dangerous file types — without decoding, executing, or saving executable payloads.

**Expected Outcomes**
- `forensics/attachment_analyzer.py` exposes `analyze_attachments(attachments) -> list[dict]`.
- Each dict: `filename`, `content_type`, `size_bytes`, `extension`, `is_dangerous` (bool), `danger_reason`.
- Dangerous extensions flagged: `.exe`, `.bat`, `.cmd`, `.scr`, `.vbs`, `.js`, `.jar`, `.ps1`, `.msi`, `.com`, `.pif`, `.hta`, `.reg`.

**Todo List**
1. Write `forensics/attachment_analyzer.py`.
2. Accept the `attachments` list from the parser.
3. For each attachment, extract the file extension using `os.path.splitext`.
4. Check extension against the dangerous list (case-insensitive).
5. Flag double extensions (e.g. `invoice.pdf.exe`).
6. Return enriched list of dicts.

**Relevant Context**
- `attachments` come from `forensics/parser.py` as `{filename, content_type, size_bytes}`.
- Payload bytes are never written to disk or decoded beyond what the parser already held in memory.

**Status** — `[ ] pending`

---

### Sub-Task 8 — Risk Scorer

**Intent**
Aggregate all module findings into a single numeric risk score (0–100) and a Low/Medium/High classification, with a per-indicator breakdown for transparency.

**Expected Outcomes**
- `forensics/risk_scorer.py` exposes `calculate_risk(auth, urls, indicators, attachments) -> dict`.
- Returned dict: `score` (int 0–100), `level` (`"Low"` / `"Medium"` / `"High"`), `breakdown` (list of `{label, points}` dicts).

**Scoring Table**

| Finding | Points |
|---|---|
| SPF fail | +20 |
| SPF softfail | +10 |
| SPF none | +5 |
| DKIM absent/invalid | +15 |
| DMARC fail/none | +10 |
| From/Reply-To mismatch | +15 |
| Suspicious URL (per URL, cap at 3) | +10 each |
| IP-literal URL | +10 |
| High-risk attachment extension | +20 |
| Urgency language | +10 |
| Credential-harvesting phrase | +15 |
| Brand impersonation | +10 |
| Display-name spoofing | +10 |

**Thresholds:** 0–30 = Low, 31–65 = Medium, 66–100 = High.

**Todo List**
1. Write `forensics/risk_scorer.py`.
2. Implement scoring logic from the table above.
3. Cap total at 100.
4. Produce a `breakdown` list so the UI can show per-indicator point contributions.
5. Map score to level using threshold constants.

**Relevant Context**
- All four module outputs are passed in from `app.py` after the analysis pipeline runs.

**Status** — `[ ] pending`

---

### Sub-Task 9 — Report Generator

**Intent**
Format the complete analysis results into a downloadable plain-text forensic report file.

**Expected Outcomes**
- `reports/report_generator.py` exposes `generate_report(analysis_data, analysis_id) -> str` (returns file path).
- Output is a `.txt` file saved to `reports/generated/report_<id>_<timestamp>.txt`.
- Report includes: metadata, auth findings, URL findings, phishing indicators, attachment list, risk score/level, breakdown, and a disclaimer.

**Todo List**
1. Write `reports/report_generator.py`.
2. Build a multi-section text template using f-strings.
3. Include a header with tool name, date/time, and analysis ID.
4. Write one section per module (Auth, URLs, Content Indicators, Attachments).
5. End with Risk Score summary and a forensic disclaimer ("For educational/forensic use only").
6. Save to `reports/generated/` with a safe filename.
7. Return relative path for DB storage and download link generation.

**Relevant Context**
- `analysis_data` is the full dict assembled in `app.py` before saving to DB.
- File is served via `flask.send_file` from the `/report/<id>` route.

**Status** — `[ ] pending`

---

### Sub-Task 10 — Flask Routes and Analysis Pipeline

**Intent**
Wire all modules together in `app.py` so the upload-to-results flow is complete and all routes are functional.

**Expected Outcomes**
- `POST /analyze`: validates file, saves to `uploads/`, runs the full forensics pipeline, saves to DB, generates report, redirects to results.
- `GET /results/<id>`: retrieves analysis from DB and renders `results.html`.
- `GET /history`: fetches all analyses from DB and renders `history.html`.
- `GET /report/<id>`: serves the `.txt` report file as a download.
- `GET /`: renders the upload form.

**Todo List**
1. Complete `app.py` route implementations.
2. In `/analyze`: validate extension + size, use `werkzeug.utils.secure_filename`, run parser → auth → urls → phishing → attachments → scorer → report generator → db save.
3. Pass `findings_json` as a JSON string to DB; deserialize when loading results.
4. Use `bleach` to sanitize any displayed email content in the template context (or handle in template with Jinja2 `| e` escaping).
5. Add error handling for `ParseError` — flash a user-friendly message and redirect to `/`.
6. Clean up temp upload file after analysis completes.

**Relevant Context**
- `forensics/__init__.py` can re-export the main functions for clean imports.
- All module functions are defined in Sub-Tasks 3–9.

**Status** — `[ ] pending`

---

### Sub-Task 11 — HTML Templates

**Intent**
Build the four Jinja2 templates that render the dashboard with a cybersecurity dark theme.

**Expected Outcomes**
- `base.html`: shared nav, dark theme link, Chart.js CDN.
- `index.html`: upload form with file-type hint, drag-and-drop styling.
- `results.html`: tabbed sections — Summary, Headers, Auth, URLs, Content, Attachments. Risk badge with color. Findings table. Download report button.
- `history.html`: sortable table of past analyses with links to results.

**Todo List**
1. Write `templates/base.html` with shared structure.
2. Write `templates/index.html` with styled upload form.
3. Write `templates/results.html` with tab navigation and all finding sections.
4. Write `templates/history.html` with analysis history table.
5. Ensure all email content output uses Jinja2 `{{ value | e }}` escaping.
6. Risk level badge uses CSS class driven by `risk_level` value.

**Relevant Context**
- Risk level → CSS class mapping: `low` = green badge, `medium` = amber badge, `high` = red badge.
- All raw email content (subject, body preview, headers) must be escaped, never rendered as HTML.

**Status** — `[ ] pending`

---

### Sub-Task 12 — CSS and JavaScript

**Intent**
Implement the cybersecurity-themed visual design and client-side interactivity.

**Expected Outcomes**
- `static/css/style.css`: dark background (`#0d1117`), green accent (`#00ff41`), monospace fonts for headers/code, responsive layout, risk badge colors.
- `static/js/dashboard.js`: animated risk score gauge or progress bar, findings breakdown bar chart using Chart.js, tab switching, copy-to-clipboard for raw headers.

**Todo List**
1. Write `static/css/style.css` with dark theme, card components, tab styles, badge variants.
2. Write `static/js/dashboard.js` with tab switching logic.
3. Implement Chart.js doughnut or bar chart for score breakdown if findings data is available.
4. Add copy-to-clipboard button for the raw headers panel.
5. Ensure responsive layout works on standard screen widths.

**Relevant Context**
- Chart.js is loaded from CDN in `base.html`.
- `findings_json` can be embedded in the template as a JS variable using `{{ findings | tojson | safe }}` only for non-sensitive structural data (counts, labels) — not raw email content.

**Status** — `[ ] pending`

---

## Database Schema Reference

```
analyses
  id              INTEGER   PRIMARY KEY AUTOINCREMENT
  filename        TEXT
  uploaded_at     DATETIME
  sender          TEXT
  recipient       TEXT
  subject         TEXT
  risk_score      INTEGER
  risk_level      TEXT
  findings_json   TEXT      (full JSON blob)
  report_path     TEXT

url_findings
  id              INTEGER   PRIMARY KEY AUTOINCREMENT
  analysis_id     INTEGER   FOREIGN KEY → analyses.id
  url             TEXT
  is_suspicious   BOOLEAN
  reason          TEXT
```

---

## Security Constraints (enforced throughout)

- File extension whitelist: `.eml` only.
- `werkzeug.utils.secure_filename` on all uploads.
- Upload file size capped via `MAX_CONTENT_LENGTH`.
- No shell calls, no `eval/exec` anywhere.
- No outbound HTTP requests.
- All template output escaped with Jinja2 auto-escaping.
- Uploaded file deleted from disk after analysis.
- `reports/generated/` files served only by ID — no directory listing.
