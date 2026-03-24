#!/usr/bin/env python3
"""
Lead Scout Web — NIS2 OSINT Scanner Web Interface
Flask-based web UI for the Lead Scout scanning tool.

Usage:
    python scout_web.py
    python scout_web.py --port 8080
    python scout_web.py --host 0.0.0.0 --port 5000
"""

import argparse
import csv
import io
import json
import logging
import os
import sys
import time
import threading
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Dict, List, Optional

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    Response,
    redirect,
    url_for,
    session,
    send_from_directory,
)
from werkzeug.security import generate_password_hash, check_password_hash

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from scout import LeadScout, CompanyInput, load_csv, load_json
from scoring.scorer import LeadScore, LeadTier

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "web" / "templates"),
    static_folder=str(Path(__file__).parent / "web" / "static"),
)
app.secret_key = os.environ.get("SCOUT_SECRET_KEY", uuid.uuid4().hex)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

_DEFAULT_USER = "admin"
_DEFAULT_PASS = "ShieldCheck2026!"

USERS = {
    os.environ.get("SCOUT_USER", _DEFAULT_USER): generate_password_hash(
        os.environ.get("SCOUT_PASS", _DEFAULT_PASS)
    ),
}


def login_required(f):
    """Decorator that redirects unauthenticated requests to the login page."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


# ---------------------------------------------------------------------------
# In-memory scan state (single-user; for multi-user wrap in a dict by session)
# ---------------------------------------------------------------------------


class ScanState:
    """Holds the state for the current (or last) scan."""

    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.stop_requested = False
        self.companies: List[CompanyInput] = []
        self.results: List[dict] = []
        self.log_lines: List[str] = []
        self.progress = 0
        self.total = 0
        self.current_company = ""
        self.report_html_path: Optional[str] = None
        self.report_json_path: Optional[str] = None

    def reset(self):
        with self.lock:
            self.results.clear()
            self.log_lines.clear()
            self.progress = 0
            self.total = 0
            self.current_company = ""
            self.stop_requested = False
            self.report_html_path = None
            self.report_json_path = None

    def add_log(self, msg: str):
        with self.lock:
            self.log_lines.append(msg)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "running": self.running,
                "progress": self.progress,
                "total": self.total,
                "current_company": self.current_company,
                "results": list(self.results),
                "log": list(self.log_lines[-200:]),
                "report_html": self.report_html_path,
                "report_json": self.report_json_path,
            }


state = ScanState()


# ---------------------------------------------------------------------------
# Log handler that feeds into ScanState
# ---------------------------------------------------------------------------


class WebLogHandler(logging.Handler):
    def __init__(self, scan_state: ScanState):
        super().__init__()
        self.scan_state = scan_state

    def emit(self, record):
        try:
            msg = self.format(record)
            self.scan_state.add_log(msg)
        except Exception:
            pass


web_log_handler = WebLogHandler(state)
web_log_handler.setLevel(logging.INFO)
web_log_handler.setFormatter(
    logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
)
logging.getLogger().addHandler(web_log_handler)


# ---------------------------------------------------------------------------
# Scan worker
# ---------------------------------------------------------------------------


def _scan_worker(
    companies: List[CompanyInput], timeout: float, delay: float, verbose: bool
):
    """Background thread that runs the scan."""
    state.running = True
    state.total = len(companies)

    try:
        scout = LeadScout(timeout=timeout, verbose=verbose)
        lead_scores: List[LeadScore] = []

        for i, company in enumerate(companies):
            if state.stop_requested:
                state.add_log("Scan stopped by user.")
                break

            state.current_company = company.name
            state.progress = i

            try:
                result = scout.scan_company(company)
                lead_scores.append(result)
                result_dict = result.to_dict()
                with state.lock:
                    state.results.append(result_dict)
            except Exception as e:
                state.add_log(f"ERROR scanning {company.name}: {e}")

            state.progress = i + 1

            if i < len(companies) - 1 and delay > 0 and not state.stop_requested:
                time.sleep(delay)

        # Generate reports
        if lead_scores:
            state.add_log("Generating reports…")
            output_dir = Path(__file__).parent / "output"
            output_dir.mkdir(parents=True, exist_ok=True)

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            md_path = str(output_dir / f"report_web_{ts}.md")
            json_path = str(output_dir / f"report_web_{ts}_data.json")
            html_path = str(output_dir / f"report_web_{ts}.html")

            scout.generate_report(
                lead_scores, md_path, json_output=json_path, html_output=html_path
            )

            state.report_html_path = f"/output/{Path(html_path).name}"
            state.report_json_path = json_path
            state.add_log(f"Reports saved to output/")

    except Exception as e:
        state.add_log(f"FATAL: {e}")
    finally:
        state.running = False
        state.current_company = ""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        pw_hash = USERS.get(username)
        if pw_hash and check_password_hash(pw_hash, password):
            session["authenticated"] = True
            session["username"] = username
            return redirect(url_for("index"))
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html", username=session.get("username", ""))


@app.route("/api/companies", methods=["GET"])
@login_required
def get_companies():
    with state.lock:
        return jsonify(
            [
                {
                    "name": c.name,
                    "domain": c.domain,
                    "sector": c.sector,
                    "employees": c.employees,
                }
                for c in state.companies
            ]
        )


@app.route("/api/companies", methods=["POST"])
@login_required
def add_company():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data"}), 400

    name = (data.get("name") or "").strip()
    domain = (data.get("domain") or "").strip()
    sector = (data.get("sector") or "Unknown").strip()

    if not name or not domain:
        return jsonify({"error": "Name and domain are required"}), 400

    employees_raw = data.get("employees", 100)
    try:
        employees = int(employees_raw)
    except (ValueError, TypeError):
        employees = 100

    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

    company = CompanyInput(name=name, domain=domain, sector=sector, employees=employees)
    with state.lock:
        state.companies.append(company)

    return jsonify({"ok": True, "count": len(state.companies)})


@app.route("/api/companies", methods=["DELETE"])
@login_required
def clear_companies():
    with state.lock:
        state.companies.clear()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:idx>", methods=["DELETE"])
@login_required
def remove_company(idx: int):
    with state.lock:
        if 0 <= idx < len(state.companies):
            state.companies.pop(idx)
            return jsonify({"ok": True})
    return jsonify({"error": "Invalid index"}), 404


@app.route("/api/upload", methods=["POST"])
@login_required
def upload_file():
    """Upload a CSV or JSON file of companies."""
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No file uploaded"}), 400

    filename = f.filename.lower()
    content = f.read().decode("utf-8-sig")

    try:
        if filename.endswith(".json"):
            data = json.loads(content)
            if isinstance(data, dict):
                data = data.get("companies", [])
            loaded = [
                CompanyInput(
                    name=item.get("name", ""),
                    domain=item.get("domain", "")
                    .replace("https://", "")
                    .replace("http://", "")
                    .rstrip("/"),
                    sector=item.get("sector", "Unknown"),
                    employees=int(item.get("employees", 100)),
                )
                for item in data
                if item.get("name") and item.get("domain")
            ]
        else:
            reader = csv.DictReader(io.StringIO(content))
            loaded = []
            for row in reader:
                name = (
                    row.get("name")
                    or row.get("Name")
                    or row.get("company")
                    or row.get("Company", "")
                )
                domain = (
                    row.get("domain") or row.get("Domain") or row.get("website", "")
                )
                sector = (
                    row.get("sector")
                    or row.get("Sector")
                    or row.get("industry")
                    or row.get("Industry", "Unknown")
                )
                emp_str = (
                    row.get("employees")
                    or row.get("Employees")
                    or row.get("size", "100")
                )
                emp_clean = "".join(c for c in emp_str if c.isdigit())
                employees = int(emp_clean) if emp_clean else 100

                if name and domain:
                    domain = (
                        domain.replace("https://", "")
                        .replace("http://", "")
                        .rstrip("/")
                    )
                    loaded.append(
                        CompanyInput(
                            name=name.strip(),
                            domain=domain.strip(),
                            sector=sector.strip(),
                            employees=employees,
                        )
                    )

        with state.lock:
            state.companies.extend(loaded)

        return jsonify(
            {"ok": True, "loaded": len(loaded), "total": len(state.companies)}
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/scan/start", methods=["POST"])
@login_required
def start_scan():
    if state.running:
        return jsonify({"error": "Scan already running"}), 409

    with state.lock:
        if not state.companies:
            return jsonify({"error": "No companies to scan"}), 400

    data = request.get_json() or {}
    timeout = float(data.get("timeout", 8))
    delay = float(data.get("delay", 1))
    verbose = bool(data.get("verbose", False))

    state.reset()

    companies_copy = list(state.companies)
    thread = threading.Thread(
        target=_scan_worker, args=(companies_copy, timeout, delay, verbose), daemon=True
    )
    thread.start()

    return jsonify({"ok": True, "total": len(companies_copy)})


@app.route("/api/scan/stop", methods=["POST"])
@login_required
def stop_scan():
    state.stop_requested = True
    return jsonify({"ok": True})


@app.route("/api/scan/status")
@login_required
def scan_status():
    return jsonify(state.snapshot())


@app.route("/api/scan/stream")
@login_required
def scan_stream():
    """Server-Sent Events stream for live updates."""

    def generate():
        last_len = 0
        while True:
            snap = state.snapshot()
            # Only send new log lines
            new_logs = snap["log"][last_len:]
            last_len = len(snap["log"])

            payload = {
                "running": snap["running"],
                "progress": snap["progress"],
                "total": snap["total"],
                "current_company": snap["current_company"],
                "results": snap["results"],
                "new_logs": new_logs,
                "report_html": snap["report_html"],
            }
            yield f"data: {json.dumps(payload)}\n\n"

            if (
                not snap["running"]
                and snap["progress"] >= snap["total"]
                and snap["total"] > 0
            ):
                # Send one final update then close
                yield f"data: {json.dumps(payload)}\n\n"
                break
            if not snap["running"] and snap["total"] == 0:
                break

            time.sleep(0.8)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/output/<path:filename>")
@login_required
def serve_output(filename: str):
    output_dir = Path(__file__).parent / "output"
    return send_from_directory(str(output_dir), filename)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Lead Scout Web UI")
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)"
    )
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    print(f"\n  Lead Scout Web — http://{args.host}:{args.port}\n")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
