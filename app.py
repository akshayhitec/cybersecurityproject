"""
app.py
------
Main Flask application for the Phishing Email Forensics and Threat Analysis Tool.

Routes:
  GET  /              → Upload form (index.html)
  POST /analyze       → Process uploaded .eml file, run forensics pipeline
  GET  /results/<id>  → Display forensic findings for a specific analysis
  GET  /history       → Show all past analyses
  GET  /report/<id>   → Download the plain-text forensic report
  GET  /delete/<id>   → Delete an analysis from history
"""

import os
import json
from datetime import datetime, timezone

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, send_file, abort
)
from werkzeug.utils import secure_filename

import config
from database.db       import init_db, save_analysis, get_all_analyses, get_analysis_by_id
from forensics         import (
    parse_email, ParseError,
    analyze_auth,
    extract_and_analyze_urls,
    detect_phishing_indicators,
    analyze_attachments,
    calculate_risk,
)
from reports.report_generator import generate_report


# ── App setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key             = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH
app.config["UPLOAD_FOLDER"]      = config.UPLOAD_FOLDER

# Initialise the SQLite database tables at startup
with app.app_context():
    init_db()


# ── Helpers ────────────────────────────────────────────────────────────────

def _allowed_file(filename: str) -> bool:
    """
    Return True only if the file has an allowed extension (.eml).
    Uses the extension whitelist from config.py.
    """
    _, ext = os.path.splitext(filename.lower())
    return ext in config.ALLOWED_EXTENSIONS


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Landing page with the upload form."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Handle the .eml file upload and run the full forensics pipeline.

    Security measures applied here:
      - File extension validated against whitelist.
      - Filename sanitised with secure_filename().
      - File size limited by MAX_CONTENT_LENGTH.
      - Upload file deleted from disk after analysis.
      - ParseError is caught and shown as a user-friendly flash message.
    """

    # ── Step 1: Validate the uploaded file ────────────────────────────────
    if "email_file" not in request.files:
        flash("No file was included in the request.", "danger")
        return redirect(url_for("index"))

    uploaded_file = request.files["email_file"]

    if not uploaded_file.filename:
        flash("No file was selected.", "danger")
        return redirect(url_for("index"))

    if not _allowed_file(uploaded_file.filename):
        flash("Invalid file type. Only .eml files are accepted.", "danger")
        return redirect(url_for("index"))

    # ── Step 2: Save the uploaded file to disk (temporarily) ──────────────
    safe_name  = secure_filename(uploaded_file.filename)
    # Add a timestamp to the filename to avoid collisions
    timestamp  = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    saved_name = f"{timestamp}_{safe_name}"
    save_path  = os.path.join(app.config["UPLOAD_FOLDER"], saved_name)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    uploaded_file.save(save_path)

    try:
        # ── Step 3: Parse the email ────────────────────────────────────────
        parsed = parse_email(save_path)

        # ── Step 4: Run all forensics modules ─────────────────────────────
        auth_results = analyze_auth(parsed["headers"])

        url_results  = extract_and_analyze_urls(
            plain_body = parsed["plain_body"],
            html_body  = parsed["html_body"],
            headers    = parsed["headers"],
        )

        indicators   = detect_phishing_indicators(
            plain_body = parsed["plain_body"],
            html_body  = parsed["html_body"],
            headers    = parsed["headers"],
            from_addr  = parsed["from_addr"],
            reply_to   = parsed["reply_to"],
        )

        att_results  = analyze_attachments(parsed["attachments"])

        # ── Step 5: Calculate risk score ──────────────────────────────────
        risk = calculate_risk(
            auth_results = auth_results,
            url_results  = url_results,
            indicators   = indicators,
            attachments  = att_results,
        )

        # ── Step 6: Assemble the full findings dict ────────────────────────
        # This dict is stored as JSON in the database so results can be
        # reconstructed at any time without re-parsing the original file.
        findings = {
            "parsed"     : {
                "from_addr"  : parsed["from_addr"],
                "to_addr"    : parsed["to_addr"],
                "reply_to"   : parsed["reply_to"],
                "subject"    : parsed["subject"],
                "date"       : parsed["date"],
                # Only keep the first 2000 chars of body for DB storage
                "plain_body" : parsed["plain_body"][:2000],
                "headers"    : parsed["headers"],
            },
            "auth"       : auth_results,
            "urls"       : url_results,
            "indicators" : indicators,
            "attachments": att_results,
            "risk"       : risk,
        }

        # ── Step 7: Save to database (preliminary, without report path) ────
        analysis_id = save_analysis({
            "filename"   : safe_name,
            "sender"     : parsed["from_addr"],
            "recipient"  : parsed["to_addr"],
            "subject"    : parsed["subject"],
            "risk_score" : risk["score"],
            "risk_level" : risk["level"],
            "findings"   : findings,
            "report_path": "",         # Will be filled in by report generator
            "urls"       : url_results,
        })

        # ── Step 8: Generate the downloadable report ───────────────────────
        analysis_data_for_report = {
            "filename"   : safe_name,
            "parsed"     : parsed,
            "auth"       : auth_results,
            "urls"       : url_results,
            "indicators" : indicators,
            "attachments": att_results,
            "risk"       : risk,
        }

        try:
            report_path = generate_report(analysis_data_for_report, analysis_id)
        except Exception:
            report_path = ""   # Non-fatal — analysis still works without report

        # ── Step 9: Update DB record with the report path ──────────────────
        # Simple direct update (no helper needed for this single field)
        from database.db import get_connection
        conn = get_connection()
        conn.execute(
            "UPDATE analyses SET report_path = ? WHERE id = ?",
            (report_path, analysis_id)
        )
        conn.commit()
        conn.close()

    except ParseError as err:
        flash(f"Could not parse the email file: {err}", "danger")
        return redirect(url_for("index"))

    except Exception as err:
        flash(f"An unexpected error occurred during analysis: {err}", "danger")
        return redirect(url_for("index"))

    finally:
        # ── Step 10: Delete the uploaded file — never persist untrusted files
        if os.path.exists(save_path):
            os.remove(save_path)

    return redirect(url_for("results", analysis_id=analysis_id))


@app.route("/results/<int:analysis_id>")
def results(analysis_id: int):
    """
    Display the full forensic findings for one analysis.
    Loads from the database — the original .eml file is no longer needed.
    """
    record = get_analysis_by_id(analysis_id)
    if record is None:
        abort(404)

    findings = record.get("findings", {})

    return render_template(
        "results.html",
        record   = record,
        findings = findings,
        # Pass structured sub-sections directly for cleaner template access
        parsed      = findings.get("parsed",     {}),
        auth        = findings.get("auth",        {}),
        urls        = findings.get("urls",        []),
        indicators  = findings.get("indicators",  []),
        attachments = findings.get("attachments", []),
        risk        = findings.get("risk",        {}),
    )


@app.route("/history")
def history():
    """Show all past analyses from the database."""
    analyses = get_all_analyses()
    return render_template("history.html", analyses=analyses)


@app.route("/report/<int:analysis_id>")
def download_report(analysis_id: int):
    """
    Serve the plain-text forensic report as a file download.
    The file is served from reports/generated/ only — no path traversal possible.
    """
    record = get_analysis_by_id(analysis_id)
    if record is None:
        abort(404)

    report_path = record.get("report_path", "")
    if not report_path or not os.path.isfile(report_path):
        flash("Report file not found.  It may have been deleted.", "warning")
        return redirect(url_for("results", analysis_id=analysis_id))

    return send_file(
        os.path.abspath(report_path),
        as_attachment=True,
        download_name=f"forensic_report_{analysis_id}.txt",
        mimetype="text/plain",
    )


@app.route("/delete/<int:analysis_id>", methods=["POST"])
def delete_analysis(analysis_id: int):
    """Delete a single analysis record and its report file from the database."""
    record = get_analysis_by_id(analysis_id)
    if record is None:
        abort(404)

    # Delete report file if it exists
    report_path = record.get("report_path", "")
    if report_path and os.path.isfile(report_path):
        try:
            os.remove(report_path)
        except OSError:
            pass   # Non-fatal

    # Delete from database
    from database.db import get_connection
    conn = get_connection()
    conn.execute("DELETE FROM url_findings WHERE analysis_id = ?", (analysis_id,))
    conn.execute("DELETE FROM analyses     WHERE id = ?",          (analysis_id,))
    conn.commit()
    conn.close()

    flash("Analysis deleted.", "success")
    return redirect(url_for("history"))


# ── Template helpers ───────────────────────────────────────────────────────

@app.template_filter("risk_badge_class")
def risk_badge_class(level: str) -> str:
    """Map a risk level string to a CSS class name."""
    return {"Low": "badge-low", "Medium": "badge-medium", "High": "badge-high"}.get(level, "badge-low")


@app.template_filter("pretty_json")
def pretty_json_filter(value) -> str:
    """Pretty-print a Python object as JSON for the raw-headers panel."""
    return json.dumps(value, indent=2, ensure_ascii=False)


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Phishing Email Forensics Tool")
    print("  Running at http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host="127.0.0.1", port=5000)
