#!/usr/bin/env python3
"""
Lead Scout Web - lead-finder application with account, plan, and token controls.
"""

import argparse
import csv
import io
import json
import logging
import os
import sys
import threading
import time
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

sys.path.insert(0, str(Path(__file__).parent))

from reports.pdf_report import PDFReportGenerator
from scout import CompanyInput, LeadScout
from scoring.scorer import LeadScore
from persistence import (
    FOLLOW_UP_STATUSES,
    account_owns_output_path,
    add_current_company as persistence_add_current_company,
    bootstrap_leadfinder_data,
    bulk_add_current_companies as persistence_bulk_add_current_companies,
    clear_current_companies as persistence_clear_current_companies,
    consume_scan_tokens,
    create_account_user,
    create_domain_list_snapshot,
    ensure_account_tokens,
    force_account_token_refresh,
    get_account_detail,
    get_account_summary,
    get_domain_list_items,
    get_lead_note,
    get_user_by_username,
    get_user_context,
    grant_tokens,
    init_db as persistence_init_db,
    list_accounts,
    list_account_users,
    list_current_companies,
    list_domain_lists_page,
    list_scan_runs_page,
    list_token_ledger,
    record_scan_run,
    remove_tokens,
    update_account_settings,
    upsert_lead_note,
    use_domain_list_as_current,
    delete_current_company as persistence_delete_current_company,
)


app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "web" / "templates"),
    static_folder=str(Path(__file__).parent / "web" / "static"),
)
app.secret_key = os.environ.get("SCOUT_SECRET_KEY", uuid.uuid4().hex)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

logger = logging.getLogger(__name__)

_DEFAULT_USER = "admin"
_DEFAULT_PASS = "ShieldCheck2026!"
_TEST_USER = "testuser"
_TEST_PASS = "ShieldCheckTest2026!"

persistence_init_db()
bootstrap_leadfinder_data(
    admin_username=os.environ.get("SCOUT_USER", _DEFAULT_USER),
    admin_password_hash=generate_password_hash(os.environ.get("SCOUT_PASS", _DEFAULT_PASS)),
    test_username=os.environ.get("SCOUT_TEST_USER", _TEST_USER),
    test_password_hash=generate_password_hash(os.environ.get("SCOUT_TEST_PASS", _TEST_PASS)),
)


def _session_user() -> Optional[Dict[str, Any]]:
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = get_user_context(int(user_id))
    if user and int(user.get("is_active", 0)) == 1:
        return user
    return None


def _is_platform_admin(user: Optional[Dict[str, Any]]) -> bool:
    return bool(user and user.get("role") == "platform_admin")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = _session_user()
        if not user:
            session.clear()
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


def account_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        user = _session_user()
        if not user or user.get("account_id") is None:
            return jsonify({"error": "Account context required"}), 403
        return f(*args, **kwargs)

    return decorated


def account_admin_required(f):
    @wraps(f)
    @account_required
    def decorated(*args, **kwargs):
        user = _session_user()
        if not user or user["role"] != "admin":
            return jsonify({"error": "Account admin access required"}), 403
        return f(*args, **kwargs)

    return decorated


def platform_admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        user = _session_user()
        if not user or user["role"] != "platform_admin":
            return jsonify({"error": "Platform admin access required"}), 403
        return f(*args, **kwargs)

    return decorated


class ScanState:
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
        self.pdf_paths: Dict[str, str] = {}

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
_state_by_account: Dict[int, ScanState] = {}
_scan_context = threading.local()


def get_account_state(account_id: int) -> ScanState:
    with _state_lock:
        if int(account_id) not in _state_by_account:
            _state_by_account[int(account_id)] = ScanState()
        return _state_by_account[int(account_id)]


def _reload_companies_from_db(account_id: int) -> None:
    state = get_account_state(account_id)
    rows = list_current_companies(account_id)
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


class WebLogHandler(logging.Handler):
    def emit(self, record):
        try:
            account_id = getattr(_scan_context, "account_id", None)
            if not account_id:
                return
            msg = self.format(record)
            get_account_state(int(account_id)).add_log(msg)
        except Exception:
            pass


web_log_handler = WebLogHandler()
web_log_handler.setLevel(logging.INFO)
web_log_handler.setFormatter(
    logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
)
logging.getLogger().addHandler(web_log_handler)


def _scan_worker(
    account_id: int,
    user_id: int,
    companies: List[CompanyInput],
    timeout: float,
    delay: float,
    verbose: bool,
    domain_list_id: int,
):
    state = get_account_state(account_id)
    _scan_context.account_id = account_id
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
                note_data = get_lead_note(account_id, company.domain)
                result_dict["lead_notes"] = note_data.get("notes", "")
                result_dict["follow_up_status"] = note_data.get("follow_up_status", "new")
                with state.lock:
                    state.results.append(result_dict)
            except Exception as exc:
                state.add_log(f"ERROR scanning {company.name}: {exc}")

            state.progress = i + 1
            if i < len(companies) - 1 and delay > 0 and not state.stop_requested:
                time.sleep(delay)

        if lead_scores:
            state.add_log("Generating reports...")
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
            state.report_json_path = f"/output/{Path(json_path).name}"

            try:
                record_scan_run(
                    owner_account_id=account_id,
                    created_by_user_id=user_id,
                    domain_list_id=domain_list_id,
                    domain_count=len(companies),
                    report_html_path=state.report_html_path,
                    report_json_path=state.report_json_path,
                )
            except Exception as exc:
                state.add_log(f"WARNING: failed to persist scan run: {exc}")

            pdf_dir = output_dir / "pdfs"
            pdf_dir.mkdir(parents=True, exist_ok=True)
            try:
                pdf_gen = PDFReportGenerator()
                for lead in lead_scores:
                    try:
                        pdf_filename = f"security_report_{lead.domain.replace('.', '_')}.pdf"
                        pdf_path = str(pdf_dir / pdf_filename)
                        pdf_gen.generate(lead, pdf_path)
                        with state.lock:
                            state.pdf_paths[lead.domain] = pdf_filename
                        state.add_log(f"PDF generated for {lead.company_name}")
                    except Exception as exc:
                        state.add_log(f"PDF failed for {lead.company_name}: {exc}")
            except ImportError:
                state.add_log("PDF generation skipped (reportlab not installed)")
            except Exception as exc:
                state.add_log(f"PDF generation error: {exc}")

            state.add_log("Reports saved to output/")

    except Exception as exc:
        state.add_log(f"FATAL: {exc}")
    finally:
        state.running = False
        state.current_company = ""
        _scan_context.account_id = None


@app.route("/login", methods=["GET", "POST"])
def login():
    if _session_user():
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_user_by_username(username)
        if user and int(user["is_active"]) == 1 and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = int(user["id"])
            session["username"] = user["username"]
            session["account_id"] = int(user["account_id"]) if user.get("account_id") is not None else None
            session["role"] = user["role"]
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
    user = _session_user()
    assert user is not None
    if _is_platform_admin(user):
        return render_template(
            "platform_admin.html",
            username=user["username"],
            role=user["role"],
            account_name="Platform Administration",
            plan_name="Global",
        )
    summary = get_account_summary(int(user["account_id"]))
    return render_template(
        "index.html",
        username=user["username"],
        role=user["role"],
        account_name=summary["account_name"],
        plan_name=summary["plan_name"],
    )


@app.route("/api/account/summary")
@login_required
def account_summary():
    user = _session_user()
    assert user is not None
    if _is_platform_admin(user):
        return jsonify(
            {
                "mode": "platform_admin",
                "account_name": "Platform Administration",
                "viewer": {
                    "username": user["username"],
                    "role": user["role"],
                },
            }
        )
    viewer = {
        "username": user["username"],
        "role": user["role"],
    }
    if user["role"] != "admin":
        return jsonify(
            {
                "mode": "account",
                "account_name": user.get("account_name") or "",
                "viewer": viewer,
            }
        )
    summary = get_account_summary(int(user["account_id"]))
    summary["viewer"] = viewer
    summary["mode"] = "account"
    return jsonify(summary)


@app.route("/api/account/users")
@account_admin_required
def account_users():
    user = _session_user()
    assert user is not None
    return jsonify(list_account_users(int(user["account_id"])))


@app.route("/api/account/users", methods=["POST"])
@account_admin_required
def create_user():
    user = _session_user()
    assert user is not None
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = (data.get("role") or "member").strip()
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    try:
        user_id = create_account_user(
            account_id=int(user["account_id"]),
            username=username,
            password_hash=generate_password_hash(password),
            role=role,
            created_by_user_id=int(user["id"]),
        )
        return jsonify({"ok": True, "id": user_id})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/account/token-ledger")
@account_admin_required
def token_ledger():
    user = _session_user()
    assert user is not None
    return jsonify(list_token_ledger(int(user["account_id"])))


@app.route("/api/lead-notes/<path:domain>")
@account_required
def lead_note(domain: str):
    user = _session_user()
    assert user is not None
    return jsonify(get_lead_note(int(user["account_id"]), domain))


@app.route("/api/lead-notes/<path:domain>", methods=["POST"])
@account_required
def save_lead_note(domain: str):
    user = _session_user()
    assert user is not None
    data = request.get_json() or {}
    notes = (data.get("notes") or "").strip()
    follow_up_status = (data.get("follow_up_status") or "new").strip()
    try:
        upsert_lead_note(
            account_id=int(user["account_id"]),
            domain=domain,
            notes=notes,
            follow_up_status=follow_up_status,
            updated_by_user_id=int(user["id"]),
        )
        return jsonify({"ok": True})
    except ValueError as exc:
        return jsonify({"error": str(exc), "allowed_statuses": FOLLOW_UP_STATUSES}), 400


@app.route("/api/companies", methods=["GET"])
@account_required
def get_companies():
    user = _session_user()
    assert user is not None
    return jsonify(list_current_companies(int(user["account_id"])))


@app.route("/api/companies", methods=["POST"])
@account_required
def add_company():
    user = _session_user()
    assert user is not None
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
        owner_account_id=int(user["account_id"]),
        created_by_user_id=int(user["id"]),
    )
    _reload_companies_from_db(int(user["account_id"]))
    return jsonify({"ok": True, "id": company_id})


@app.route("/api/companies", methods=["DELETE"])
@account_required
def clear_companies():
    user = _session_user()
    assert user is not None
    persistence_clear_current_companies(int(user["account_id"]))
    _reload_companies_from_db(int(user["account_id"]))
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>", methods=["DELETE"])
@account_required
def remove_company(company_id: int):
    user = _session_user()
    assert user is not None
    ok = persistence_delete_current_company(company_id, int(user["account_id"]))
    _reload_companies_from_db(int(user["account_id"]))
    if not ok:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/upload", methods=["POST"])
@account_required
def upload_file():
    user = _session_user()
    assert user is not None
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
                    domain=item.get("domain", "").replace("https://", "").replace("http://", "").rstrip("/"),
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
                domain = row.get("domain") or row.get("Domain") or row.get("website", "")
                sector = (
                    row.get("sector")
                    or row.get("Sector")
                    or row.get("industry")
                    or row.get("Industry", "Unknown")
                )
                emp_str = row.get("employees") or row.get("Employees") or row.get("size", "100")
                emp_clean = "".join(c for c in emp_str if c.isdigit())
                employees = int(emp_clean) if emp_clean else 100
                if name and domain:
                    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
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
            owner_account_id=int(user["account_id"]),
            created_by_user_id=int(user["id"]),
        )
        _reload_companies_from_db(int(user["account_id"]))
        return jsonify(
            {
                "ok": True,
                "loaded": inserted,
                "total": len(list_current_companies(int(user["account_id"]))),
            }
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/scan/start", methods=["POST"])
@account_required
def start_scan():
    user = _session_user()
    assert user is not None
    account_id = int(user["account_id"])
    ensure_account_tokens(account_id)
    _reload_companies_from_db(account_id)
    state = get_account_state(account_id)
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

    try:
        token_result = consume_scan_tokens(
            account_id=account_id,
            user_id=int(user["id"]),
            token_count=len(companies_copy),
            description=f"Lead finder scan for {len(companies_copy)} domain(s)",
            metadata={"domain_count": len(companies_copy)},
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

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
        owner_account_id=account_id,
        created_by_user_id=int(user["id"]),
    )
    thread = threading.Thread(
        target=_scan_worker,
        args=(account_id, int(user["id"]), companies_copy, timeout, delay, verbose, domain_list_id),
        daemon=True,
    )
    thread.start()

    return jsonify(
        {
            "ok": True,
            "total": len(companies_copy),
            "tokens_consumed": token_result["consumed"],
            "token_balances": token_result["balances_after"],
        }
    )


@app.route("/api/scan/stop", methods=["POST"])
@account_required
def stop_scan():
    user = _session_user()
    assert user is not None
    state = get_account_state(int(user["account_id"]))
    state.stop_requested = True
    return jsonify({"ok": True})


@app.route("/api/scan/status")
@account_required
def scan_status():
    user = _session_user()
    assert user is not None
    return jsonify(get_account_state(int(user["account_id"])).snapshot())


@app.route("/api/history/scans")
@account_required
def history_scans():
    user = _session_user()
    assert user is not None
    try:
        page = int(request.args.get("page", 1))
    except Exception:
        page = 1
    try:
        page_size = int(request.args.get("page_size", 10))
    except Exception:
        page_size = 10
    total, items = list_scan_runs_page(
        owner_account_id=int(user["account_id"]), page=page, page_size=page_size
    )
    return jsonify({"page": page, "page_size": page_size, "total": total, "items": items})


@app.route("/api/history/domain-lists")
@account_required
def history_domain_lists():
    user = _session_user()
    assert user is not None
    try:
        page = int(request.args.get("page", 1))
    except Exception:
        page = 1
    try:
        page_size = int(request.args.get("page_size", 10))
    except Exception:
        page_size = 10
    total, items = list_domain_lists_page(
        owner_account_id=int(user["account_id"]), page=page, page_size=page_size
    )
    return jsonify({"page": page, "page_size": page_size, "total": total, "items": items})


@app.route("/api/history/domain-lists/<int:domain_list_id>")
@account_required
def history_domain_list_items(domain_list_id: int):
    user = _session_user()
    assert user is not None
    return jsonify(
        {
            "id": domain_list_id,
            "items": get_domain_list_items(domain_list_id, int(user["account_id"])),
        }
    )


@app.route("/api/history/domain-lists/<int:domain_list_id>/use", methods=["POST"])
@account_required
def use_history_domain_list(domain_list_id: int):
    user = _session_user()
    assert user is not None
    try:
        count = use_domain_list_as_current(domain_list_id, int(user["account_id"]))
        _reload_companies_from_db(int(user["account_id"]))
        return jsonify({"ok": True, "count": count})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/scan/stream")
@account_required
def scan_stream():
    user = _session_user()
    assert user is not None
    state = get_account_state(int(user["account_id"]))

    def generate():
        last_len = 0
        while True:
            snap = state.snapshot()
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

            if not snap["running"] and snap["progress"] >= snap["total"] and snap["total"] > 0:
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
@account_required
def download_pdf(domain: str):
    user = _session_user()
    assert user is not None
    state = get_account_state(int(user["account_id"]))
    with state.lock:
        pdf_filename = state.pdf_paths.get(domain)
    if not pdf_filename:
        return jsonify({"error": "PDF not found for this domain"}), 404
    pdf_dir = Path(__file__).parent / "output" / "pdfs"
    return send_from_directory(str(pdf_dir), pdf_filename, as_attachment=True)


@app.route("/output/<path:filename>")
@account_required
def serve_output(filename: str):
    user = _session_user()
    assert user is not None
    output_path = f"/output/{filename}"
    if not account_owns_output_path(int(user["account_id"]), output_path):
        return jsonify({"error": "Not found"}), 404
    output_dir = Path(__file__).parent / "output"
    return send_from_directory(str(output_dir), filename)


@app.route("/api/platform/accounts")
@platform_admin_required
def platform_accounts():
    return jsonify(list_accounts())


@app.route("/api/platform/accounts/<int:account_id>")
@platform_admin_required
def platform_account_detail(account_id: int):
    try:
        return jsonify(get_account_detail(account_id))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@app.route("/api/platform/accounts/<int:account_id>/settings", methods=["POST"])
@platform_admin_required
def platform_account_settings(account_id: int):
    user = _session_user()
    assert user is not None
    data = request.get_json() or {}
    try:
        update_account_settings(
            account_id=account_id,
            plan_code=(data.get("plan_code") or None),
            billing_cycle=(data.get("billing_cycle") or None),
            subscription_status=(data.get("subscription_status") or None),
            next_token_refresh_at=(data.get("next_token_refresh_at") or None),
            actor_user_id=int(user["id"]),
        )
        return jsonify({"ok": True, "account": get_account_detail(account_id)})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/platform/accounts/<int:account_id>/grant-tokens", methods=["POST"])
@platform_admin_required
def platform_account_grant_tokens(account_id: int):
    user = _session_user()
    assert user is not None
    data = request.get_json() or {}
    token_count = int(data.get("token_count") or 0)
    note = (data.get("note") or "").strip()
    try:
        grant_tokens(
            account_id=account_id,
            created_by_user_id=int(user["id"]),
            token_count=token_count,
            note=note,
        )
        return jsonify({"ok": True, "account": get_account_detail(account_id)})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/platform/accounts/<int:account_id>/remove-tokens", methods=["POST"])
@platform_admin_required
def platform_account_remove_tokens(account_id: int):
    user = _session_user()
    assert user is not None
    data = request.get_json() or {}
    token_count = int(data.get("token_count") or 0)
    note = (data.get("note") or "").strip()
    try:
        remove_tokens(
            account_id=account_id,
            created_by_user_id=int(user["id"]),
            token_count=token_count,
            note=note,
        )
        return jsonify({"ok": True, "account": get_account_detail(account_id)})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/platform/accounts/<int:account_id>/refresh-now", methods=["POST"])
@platform_admin_required
def platform_account_refresh_now(account_id: int):
    user = _session_user()
    assert user is not None
    try:
        result = force_account_token_refresh(
            account_id=account_id,
            actor_user_id=int(user["id"]),
        )
        return jsonify({"ok": True, "result": result, "account": get_account_detail(account_id)})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


def main():
    parser = argparse.ArgumentParser(description="Lead Scout Web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", type=int, default=5000, help="Port")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    print(f"\n  Lead Scout Web - http://{args.host}:{args.port}\n")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
