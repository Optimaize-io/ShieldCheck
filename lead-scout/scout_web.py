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
from reports.pdf_report import PDFReportGenerator
from persistence import (
    init_db as persistence_init_db,
    list_current_companies,
    add_current_company as persistence_add_current_company,
    delete_current_company as persistence_delete_current_company,
    clear_current_companies as persistence_clear_current_companies,
    bulk_add_current_companies as persistence_bulk_add_current_companies,
    create_domain_list_snapshot,
    use_domain_list_as_current,
    record_scan_run,
    list_scan_runs_page,
    list_domain_lists_page,
    get_domain_list_items,
    user_owns_output_path,
)

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
# Persistence (SQLite)
# ---------------------------------------------------------------------------

persistence_init_db()

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

_DEFAULT_USER = "admin"
_DEFAULT_PASS = "ShieldCheck2026!"
_TEST_USER = "testuser"
_TEST_PASS = "ShieldCheckTest2026!"

USERS = {
    os.environ.get("SCOUT_USER", _DEFAULT_USER): generate_password_hash(
        os.environ.get("SCOUT_PASS", _DEFAULT_PASS)
    ),
    os.environ.get("SCOUT_TEST_USER", _TEST_USER): generate_password_hash(
        os.environ.get("SCOUT_TEST_PASS", _TEST_PASS)
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
# In-memory scan state (scoped per authenticated user)
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
        self.pdf_paths: Dict[str, str] = {}  # domain -> pdf filename

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
            self.pdf_paths.clear()

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
                "pdf_paths": dict(self.pdf_paths),
            }


_state_lock = threading.Lock()
_state_by_user: Dict[str, ScanState] = {}
_scan_context = threading.local()


def get_user_state(username: str) -> ScanState:
    with _state_lock:
        if username not in _state_by_user:
            _state_by_user[username] = ScanState()
        return _state_by_user[username]


def _reload_companies_from_db(username: str) -> None:
    """Hydrate in-memory state from the persisted working set for one user."""
    state = get_user_state(username)
    rows = list_current_companies(username)
    with state.lock:
        state.companies = [
            CompanyInput(
                name=r["name"],
                domain=r["domain"],
                sector=r["sector"],
                employees=int(r["employees"]),
            )
            for r in rows
        ]


# ---------------------------------------------------------------------------
# Log handler that feeds into ScanState
# ---------------------------------------------------------------------------


class WebLogHandler(logging.Handler):
    def emit(self, record):
        try:
            username = getattr(_scan_context, "username", None)
            if not username:
                return
            msg = self.format(record)
            get_user_state(username).add_log(msg)
        except Exception:
            pass


web_log_handler = WebLogHandler()
web_log_handler.setLevel(logging.INFO)
web_log_handler.setFormatter(
    logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
)
logging.getLogger().addHandler(web_log_handler)


# ---------------------------------------------------------------------------
# Scan worker
# ---------------------------------------------------------------------------


def _scan_worker(
    username: str,
    companies: List[CompanyInput],
    timeout: float,
    delay: float,
    verbose: bool,
    domain_list_id: int,
):
    """Background thread that runs the scan."""
    state = get_user_state(username)
    _scan_context.username = username
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

            try:
                record_scan_run(
                    owner_username=username,
                    domain_list_id=domain_list_id,
                    domain_count=len(lead_scores),
                    report_html_path=state.report_html_path,
                    report_json_path=f"/output/{Path(json_path).name}",
                )
            except Exception as e:
                state.add_log(f"WARNING: failed to persist scan run: {e}")

            # Generate individual PDF reports
            pdf_dir = output_dir / "pdfs"
            pdf_dir.mkdir(parents=True, exist_ok=True)
            try:
                pdf_gen = PDFReportGenerator()
                for lead in lead_scores:
                    try:
                        pdf_filename = (
                            f"security_report_{lead.domain.replace('.', '_')}.pdf"
                        )
                        pdf_path = str(pdf_dir / pdf_filename)
                        pdf_gen.generate(lead, pdf_path)
                        with state.lock:
                            state.pdf_paths[lead.domain] = pdf_filename
                        state.add_log(f"PDF generated for {lead.company_name}")
                    except Exception as e:
                        state.add_log(f"PDF failed for {lead.company_name}: {e}")
            except ImportError:
                state.add_log("PDF generation skipped (reportlab not installed)")
            except Exception as e:
                state.add_log(f"PDF generation error: {e}")

            state.add_log(f"Reports saved to output/")

    except Exception as e:
        state.add_log(f"FATAL: {e}")
    finally:
        state.running = False
        state.current_company = ""
        _scan_context.username = None


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
    username = session.get("username", "")
    return jsonify(list_current_companies(username))


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
    company_id = persistence_add_current_company(
        name=name,
        domain=domain,
        sector=sector,
        employees=employees,
        owner_username=session.get("username", ""),
    )
    _reload_companies_from_db(session.get("username", ""))

    return jsonify({"ok": True, "id": company_id})


@app.route("/api/companies", methods=["DELETE"])
@login_required
def clear_companies():
    username = session.get("username", "")
    persistence_clear_current_companies(username)
    _reload_companies_from_db(username)
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>", methods=["DELETE"])
@login_required
def remove_company(company_id: int):
    username = session.get("username", "")
    ok = persistence_delete_current_company(company_id, username)
    _reload_companies_from_db(username)
    if not ok:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


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

        inserted = persistence_bulk_add_current_companies(
            [
                {
                    "name": c.name,
                    "domain": c.domain,
                    "sector": c.sector,
                    "employees": c.employees,
                }
                for c in loaded
            ],
            owner_username=session.get("username", ""),
        )
        username = session.get("username", "")
        _reload_companies_from_db(username)

        return jsonify(
            {"ok": True, "loaded": inserted, "total": len(list_current_companies(username))}
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/scan/start", methods=["POST"])
@login_required
def start_scan():
    username = session.get("username", "")
    _reload_companies_from_db(username)
    state = get_user_state(username)
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
    domain_list_id = create_domain_list_snapshot(
        [
            {
                "name": c.name,
                "domain": c.domain,
                "sector": c.sector,
                "employees": c.employees,
            }
            for c in companies_copy
        ],
        owner_username=username,
    )
    thread = threading.Thread(
        target=_scan_worker,
        args=(username, companies_copy, timeout, delay, verbose, domain_list_id),
        daemon=True,
    )
    thread.start()

    return jsonify({"ok": True, "total": len(companies_copy)})


@app.route("/api/scan/stop", methods=["POST"])
@login_required
def stop_scan():
    state = get_user_state(session.get("username", ""))
    state.stop_requested = True
    return jsonify({"ok": True})


@app.route("/api/scan/status")
@login_required
def scan_status():
    state = get_user_state(session.get("username", ""))
    return jsonify(state.snapshot())


@app.route("/api/history/scans")
@login_required
def history_scans():
    username = session.get("username", "")
    try:
        page = int(request.args.get("page", 1))
    except Exception:
        page = 1
    try:
        page_size = int(request.args.get("page_size", 10))
    except Exception:
        page_size = 10
    total, items = list_scan_runs_page(
        owner_username=username, page=page, page_size=page_size
    )
    return jsonify({"page": page, "page_size": page_size, "total": total, "items": items})


@app.route("/api/history/domain-lists")
@login_required
def history_domain_lists():
    username = session.get("username", "")
    try:
        page = int(request.args.get("page", 1))
    except Exception:
        page = 1
    try:
        page_size = int(request.args.get("page_size", 10))
    except Exception:
        page_size = 10
    total, items = list_domain_lists_page(
        owner_username=username, page=page, page_size=page_size
    )
    return jsonify({"page": page, "page_size": page_size, "total": total, "items": items})


@app.route("/api/history/domain-lists/<int:domain_list_id>")
@login_required
def history_domain_list_items(domain_list_id: int):
    username = session.get("username", "")
    return jsonify(
        {
            "id": domain_list_id,
            "items": get_domain_list_items(domain_list_id, username),
        }
    )


@app.route("/api/history/domain-lists/<int:domain_list_id>/use", methods=["POST"])
@login_required
def use_history_domain_list(domain_list_id: int):
    username = session.get("username", "")
    try:
        count = use_domain_list_as_current(domain_list_id, username)
        _reload_companies_from_db(username)
        return jsonify({"ok": True, "count": count})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/scan/stream")
@login_required
def scan_stream():
    """Server-Sent Events stream for live updates."""
    state = get_user_state(session.get("username", ""))

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
                "pdf_paths": snap["pdf_paths"],
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


@app.route("/api/pdf/<domain>")
@login_required
def download_pdf(domain: str):
    """Download a PDF report for a specific domain."""
    state = get_user_state(session.get("username", ""))
    with state.lock:
        pdf_filename = state.pdf_paths.get(domain)
    if not pdf_filename:
        return jsonify({"error": "PDF not found for this domain"}), 404
    pdf_dir = Path(__file__).parent / "output" / "pdfs"
    return send_from_directory(str(pdf_dir), pdf_filename, as_attachment=True)


@app.route("/output/<path:filename>")
@login_required
def serve_output(filename: str):
    username = session.get("username", "")
    output_path = f"/output/{filename}"
    if not user_owns_output_path(username, output_path):
        return jsonify({"error": "Not found"}), 404
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
