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
    make_response,
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
    list_recent_scan_runs,
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


def _account_features(account_id: int) -> Dict[str, Any]:
    return dict(get_account_summary(int(account_id)).get("features") or {})


def _feature_value(features: Dict[str, Any], key: str) -> Any:
    return features.get(key)


def _feature_enabled(features: Dict[str, Any], key: str) -> bool:
    value = _feature_value(features, key)
    return value not in (None, False, "", "no", "false")


def _can_access_lead_workspace(features: Dict[str, Any]) -> bool:
    return _feature_enabled(features, "lead_notes") or _feature_enabled(
        features, "follow_up_status"
    )


def _filter_mode_for_features(features: Dict[str, Any]) -> str:
    if _feature_enabled(features, "advanced_filters"):
        return "advanced"
    value = _feature_value(features, "filter_sorting")
    if value is True:
        return "basic"
    if value == "limited":
        return "search_only"
    return "none"


def _allow_report_table_sort(features: Dict[str, Any]) -> bool:
    return _feature_enabled(features, "advanced_filters")


def _allowed_follow_up_statuses(features: Dict[str, Any]) -> List[str]:
    value = _feature_value(features, "follow_up_status")
    if value is True:
        return list(FOLLOW_UP_STATUSES)
    if value == "limited":
        return ["new", "contacting", "qualified"]
    return []


def _normalize_follow_up_status_for_features(features: Dict[str, Any], status: Any) -> str:
    allowed = _allowed_follow_up_statuses(features)
    normalized = str(status or "").strip()
    if normalized in allowed:
        return normalized
    return allowed[0] if allowed else "new"


def _sanitize_result_for_features(
    result_dict: Dict[str, Any], features: Dict[str, Any]
) -> Dict[str, Any]:
    sanitized = dict(result_dict)
    if not _feature_enabled(features, "conversation_starter"):
        sanitized["sales_angles"] = []
    if not _feature_enabled(features, "lead_notes"):
        sanitized.pop("lead_notes", None)
    if not _feature_enabled(features, "follow_up_status"):
        sanitized.pop("follow_up_status", None)
    return sanitized


def _sanitize_lead_for_features(lead: LeadScore, features: Dict[str, Any]) -> LeadScore:
    if not _feature_enabled(features, "conversation_starter"):
        lead.sales_angles = []
    elif _feature_enabled(features, "advanced_sales_advice"):
        lead.sales_angles = _build_advanced_sales_angles(lead)
    return lead


def _dimension_label(key: str) -> str:
    return key.replace("_", " ").title()


def _build_advanced_sales_angles(lead: LeadScore) -> List[str]:
    angles: List[str] = []
    scores = (lead.to_dict().get("scores") or {})
    for key, dim in scores.items():
        if not isinstance(dim, dict) or dim.get("analyzed") is False:
            continue
        missing = [item for item in (dim.get("missing") or []) if item]
        risks = [item for item in (dim.get("risks") or []) if item]
        if not missing:
            continue
        label = _dimension_label(key)
        score = dim.get("score")
        max_score = dim.get("max_score")
        score_text = (
            f"{score}/{max_score}"
            if isinstance(score, (int, float)) and isinstance(max_score, (int, float))
            else "N/A"
        )
        gap_text = missing[0]
        risk_text = risks[0] if risks else "This increases external security and compliance risk."
        business_impact = (
            "This is externally visible and creates a concrete discussion around exposure reduction, control maturity, and audit readiness."
        )
        next_step = (
            f"Next step: review the {label.lower()} gap, validate the affected controls, and define a remediation sequence with ownership and follow-up verification."
        )
        angles.append(
            f"{label} ({score_text}): Gap: {gap_text}. Risk: {risk_text} Business impact: {business_impact} {next_step}"
        )
        if len(angles) >= 5:
            break
    if not angles:
        return list(lead.sales_angles or [])
    return angles


def _output_path_to_fs_path(output_path: Optional[str]) -> Optional[Path]:
    if not output_path:
        return None
    filename = Path(str(output_path)).name
    return Path(__file__).parent / "output" / filename


def _load_report_json_payload(output_path: Optional[str]) -> Optional[Dict[str, Any]]:
    path = _output_path_to_fs_path(output_path)
    if path is None or not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


def _find_lead_in_report_payload(payload: Optional[Dict[str, Any]], domain: str) -> Optional[Dict[str, Any]]:
    if not payload:
        return None
    normalized = domain.strip().lower()
    for lead in payload.get("leads") or []:
        if str(lead.get("domain") or "").strip().lower() == normalized:
            return dict(lead)
    return None


def _account_owns_pdf_output(account_id: int, filename: str) -> bool:
    expected_name = Path(str(filename)).name
    for run in list_recent_scan_runs(int(account_id), limit=200):
        payload = _load_report_json_payload(run.get("report_json_path"))
        if not payload:
            continue
        for lead in payload.get("leads") or []:
            domain = str(lead.get("domain") or "").strip()
            if not domain:
                continue
            pdf_name = f"security_report_{domain.replace('.', '_')}.pdf"
            if pdf_name == expected_name:
                return True
    return False


def _comparison_status(delta: float) -> str:
    if delta < 0:
        return "worsened"
    if delta > 0:
        return "improved"
    return "unchanged"


def _compare_lead_versions(current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
    current_scores = current.get("scores") or {}
    previous_scores = previous.get("scores") or {}
    dimension_deltas: List[Dict[str, Any]] = []
    for key in sorted(set(current_scores.keys()) | set(previous_scores.keys())):
        current_dim = current_scores.get(key) or {}
        previous_dim = previous_scores.get(key) or {}
        current_score = current_dim.get("score")
        previous_score = previous_dim.get("score")
        if not isinstance(current_score, (int, float)) or not isinstance(previous_score, (int, float)):
            continue
        delta = float(current_score) - float(previous_score)
        dimension_deltas.append(
            {
                "key": key,
                "label": _dimension_label(key),
                "current_score": current_score,
                "current_max_score": current_dim.get("max_score"),
                "previous_score": previous_score,
                "previous_max_score": previous_dim.get("max_score"),
                "delta": delta,
                "status": _comparison_status(delta),
            }
        )
    current_gaps = set(current.get("key_gaps") or [])
    previous_gaps = set(previous.get("key_gaps") or [])
    score_delta = float(current.get("total_score") or 0) - float(previous.get("total_score") or 0)
    findings_delta = int(current.get("findings_count") or 0) - int(previous.get("findings_count") or 0)
    return {
        "domain": current.get("domain") or previous.get("domain"),
        "current": {
            "company_name": current.get("company_name"),
            "total_score": current.get("total_score"),
            "max_score": current.get("max_score"),
            "tier": current.get("tier"),
            "findings_count": current.get("findings_count"),
        },
        "previous": {
            "company_name": previous.get("company_name"),
            "total_score": previous.get("total_score"),
            "max_score": previous.get("max_score"),
            "tier": previous.get("tier"),
            "findings_count": previous.get("findings_count"),
        },
        "delta": {
            "score": score_delta,
            "findings_count": findings_delta,
            "status": _comparison_status(score_delta),
        },
        "dimension_deltas": dimension_deltas,
        "added_key_gaps": sorted(current_gaps - previous_gaps),
        "resolved_key_gaps": sorted(previous_gaps - current_gaps),
    }


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
    features = _account_features(account_id)
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
                result = _sanitize_lead_for_features(result, features)
                lead_scores.append(result)
                result_dict = result.to_dict()
                if _can_access_lead_workspace(features):
                    note_data = get_lead_note(account_id, company.domain)
                    if _feature_enabled(features, "lead_notes"):
                        result_dict["lead_notes"] = note_data.get("notes", "")
                    if _feature_enabled(features, "follow_up_status"):
                        result_dict["follow_up_status"] = _normalize_follow_up_status_for_features(
                            features,
                            note_data.get("follow_up_status", "new"),
                        )
                result_dict = _sanitize_result_for_features(result_dict, features)
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
                lead_scores,
                md_path,
                json_output=json_path,
                html_output=html_path,
                include_sales_angles=_feature_enabled(features, "conversation_starter"),
                include_json_export=_feature_enabled(features, "export_options"),
                html_filter_mode=_filter_mode_for_features(features),
                html_allow_table_sort=_allow_report_table_sort(features),
            )

            state.report_html_path = f"/output/{Path(html_path).name}"
            state.report_json_path = f"/output/{Path(json_path).name}"

            try:
                hot_leads_count = sum(1 for lead in lead_scores if "HOT" in str(lead.tier))
                warm_leads_count = sum(1 for lead in lead_scores if "WARM" in str(lead.tier))
                cool_leads_count = sum(1 for lead in lead_scores if "COOL" in str(lead.tier))
                record_scan_run(
                    owner_account_id=account_id,
                    created_by_user_id=user_id,
                    domain_list_id=domain_list_id,
                    domain_count=len(companies),
                    hot_leads_count=hot_leads_count,
                    warm_leads_count=warm_leads_count,
                    cool_leads_count=cool_leads_count,
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
    summary = get_account_summary(int(user["account_id"]))
    summary["allowed_follow_up_statuses"] = _allowed_follow_up_statuses(summary.get("features") or {})
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
    features = _account_features(int(user["account_id"]))
    if not _can_access_lead_workspace(features):
        return jsonify({"error": "Lead workspace is not available for this plan"}), 403
    note = get_lead_note(int(user["account_id"]), domain)
    note["allowed_statuses"] = _allowed_follow_up_statuses(features)
    note["follow_up_status"] = _normalize_follow_up_status_for_features(
        features,
        note.get("follow_up_status", "new"),
    )
    return jsonify(note)


@app.route("/api/lead-notes/<path:domain>", methods=["POST"])
@account_required
def save_lead_note(domain: str):
    user = _session_user()
    assert user is not None
    features = _account_features(int(user["account_id"]))
    if not _can_access_lead_workspace(features):
        return jsonify({"error": "Lead workspace is not available for this plan"}), 403
    allowed_statuses = _allowed_follow_up_statuses(features)
    data = request.get_json() or {}
    notes = (data.get("notes") or "").strip()
    follow_up_status = (data.get("follow_up_status") or "new").strip()
    if follow_up_status not in allowed_statuses:
        return (
            jsonify(
                {
                    "error": "Follow-up status is not available for this plan",
                    "allowed_statuses": allowed_statuses,
                }
            ),
            400,
        )
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
        return jsonify({"error": str(exc), "allowed_statuses": allowed_statuses}), 400


@app.route("/api/compare/domain/<path:domain>")
@account_required
def compare_domain(domain: str):
    user = _session_user()
    assert user is not None
    features = _account_features(int(user["account_id"]))
    if not _feature_enabled(features, "scan_comparison"):
        return jsonify({"error": "Scan comparison is not available for this plan"}), 403

    normalized_domain = domain.strip().lower()
    state = get_account_state(int(user["account_id"]))
    current_live = None
    with state.lock:
        for result in reversed(state.results):
            if str(result.get("domain") or "").strip().lower() == normalized_domain:
                current_live = dict(result)
                break

    recent_runs = list_recent_scan_runs(int(user["account_id"]), limit=100)
    current_source: Optional[Dict[str, Any]] = None
    previous_source: Optional[Dict[str, Any]] = None

    if current_live is not None:
        current_source = current_live
    skip_first_historical_match = current_live is not None

    for run in recent_runs:
        lead = _find_lead_in_report_payload(
            _load_report_json_payload(run.get("report_json_path")),
            normalized_domain,
        )
        if lead is None:
            continue
        if skip_first_historical_match:
            skip_first_historical_match = False
            continue
        if current_source is None:
            current_source = lead
            continue
        previous_source = lead
        break

    if current_source is None or previous_source is None:
        return jsonify({"error": "Not enough scan history found for this domain"}), 404

    return jsonify(_compare_lead_versions(current_source, previous_source))


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
    features = _account_features(int(user["account_id"]))
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
    if not _feature_enabled(features, "expanded_scan_history"):
        for item in items:
            item.pop("hot_leads_count", None)
            item.pop("warm_leads_count", None)
            item.pop("cool_leads_count", None)
            item.pop("report_json_path", None)
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
    is_pdf = filename.lower().startswith("pdfs/") and filename.lower().endswith(".pdf")
    if is_pdf:
        if not _account_owns_pdf_output(int(user["account_id"]), filename):
            return jsonify({"error": "Not found"}), 404
    elif not account_owns_output_path(int(user["account_id"]), output_path):
        return jsonify({"error": "Not found"}), 404
    features = _account_features(int(user["account_id"]))
    if filename.lower().endswith(".json") and not _feature_enabled(features, "export_options"):
        return jsonify({"error": "JSON export is not available for this plan"}), 403
    output_dir = Path(__file__).parent / "output"
    response = make_response(send_from_directory(str(output_dir), filename, as_attachment=is_pdf))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/api/export/csv")
@account_required
def export_csv():
    user = _session_user()
    assert user is not None
    features = _account_features(int(user["account_id"]))
    if not _feature_enabled(features, "csv_export"):
        return jsonify({"error": "CSV export is not available for this plan"}), 403

    state = get_account_state(int(user["account_id"]))
    results = state.snapshot().get("results") or []
    if not results:
        return jsonify({"error": "No results to export"}), 400

    include_follow_up_status = _feature_enabled(features, "follow_up_status")
    header = [
        "company_name",
        "domain",
        "tier",
        "score",
        "max_score",
        "findings_count",
        "sector",
    ]
    if include_follow_up_status:
        header.append("follow_up_status")
    rows = [header]
    for result in results:
        row = [
            result.get("company_name", ""),
            result.get("domain", ""),
            result.get("tier", ""),
            result.get("total_score", ""),
            result.get("max_score", ""),
            result.get("findings_count", ""),
            result.get("sector", ""),
        ]
        if include_follow_up_status:
            row.append(result.get("follow_up_status", ""))
        rows.append(row)

    def _csv_escape(value: Any) -> str:
        return '"' + str(value or "").replace('"', '""') + '"'

    csv_content = "\n".join(",".join(_csv_escape(value) for value in row) for row in rows)
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="lead_scout_export_{int(time.time())}.csv"'},
    )


@app.route("/api/export/json")
@account_required
def export_json():
    user = _session_user()
    assert user is not None
    features = _account_features(int(user["account_id"]))
    if not _feature_enabled(features, "export_options"):
        return jsonify({"error": "JSON export is not available for this plan"}), 403

    state = get_account_state(int(user["account_id"]))
    results = state.snapshot().get("results") or []
    if not results:
        return jsonify({"error": "No results to export"}), 400

    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "leads": results,
    }
    return Response(
        json.dumps(payload),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="lead_scout_export_{int(time.time())}.json"'},
    )


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
