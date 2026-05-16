import json
import sqlite3
from calendar import monthrange
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PLAN_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "starter": {
        "name": "Starter",
        "monthly_price_eur": 249,
        "yearly_price_eur": 249 * 12,
        "monthly_tokens": 50,
        "max_users": 1,
        "features": {
            "domain_scan": True,
            "cybersecurity_lead_score": True,
            "clear_explanation_of_findings": True,
            "basic_scan_history": True,
            "expanded_scan_history": False,
            "basic_pdf_report": True,
            "csv_export": True,
            "filter_sorting": "limited",
            "conversation_starter": False,
            "lead_notes": False,
            "follow_up_status": False,
            "scan_comparison": False,
            "crm_integration": False,
            "api_access": False,
            "two_level_reporting": False,
            "advanced_filters": False,
            "advanced_sales_advice": False,
            "white_label_reports": False,
            "custom_scoring_model": False,
            "custom_report_templates": False,
            "priority_support": False,
            "onboarding_support_package": False,
        },
    },
    "growth": {
        "name": "Growth",
        "monthly_price_eur": 599,
        "yearly_price_eur": 599 * 12,
        "monthly_tokens": 200,
        "max_users": 3,
        "features": {
            "domain_scan": True,
            "cybersecurity_lead_score": True,
            "clear_explanation_of_findings": True,
            "basic_scan_history": True,
            "expanded_scan_history": True,
            "basic_pdf_report": True,
            "csv_export": True,
            "filter_sorting": True,
            "conversation_starter": True,
            "lead_notes": "limited",
            "follow_up_status": "limited",
            "scan_comparison": False,
            "crm_integration": "optional_add_on",
            "api_access": False,
            "two_level_reporting": False,
            "advanced_filters": False,
            "advanced_sales_advice": False,
            "white_label_reports": False,
            "custom_scoring_model": False,
            "custom_report_templates": False,
            "priority_support": False,
            "onboarding_support_package": False,
            "lead_potential_ranking": True,
            "export_options": True,
        },
    },
    "scale": {
        "name": "Scale",
        "monthly_price_eur": 1199,
        "yearly_price_eur": 1199 * 12,
        "monthly_tokens": 750,
        "max_users": 8,
        "features": {
            "domain_scan": True,
            "cybersecurity_lead_score": True,
            "clear_explanation_of_findings": True,
            "basic_scan_history": True,
            "expanded_scan_history": True,
            "basic_pdf_report": True,
            "csv_export": True,
            "filter_sorting": True,
            "conversation_starter": True,
            "lead_notes": True,
            "follow_up_status": True,
            "scan_comparison": True,
            "crm_integration": "optional_or_contract",
            "api_access": "optional_add_on",
            "two_level_reporting": True,
            "advanced_filters": True,
            "advanced_sales_advice": True,
            "white_label_reports": False,
            "custom_scoring_model": False,
            "custom_report_templates": False,
            "priority_support": False,
            "onboarding_support_package": False,
            "lead_potential_ranking": True,
            "export_options": True,
            "team_usage": True,
        },
    },
    "enterprise": {
        "name": "Enterprise",
        "monthly_price_eur": 2500,
        "yearly_price_eur": 2500 * 12,
        "monthly_tokens": 0,
        "max_users": 0,
        "features": {
            "domain_scan": True,
            "cybersecurity_lead_score": True,
            "clear_explanation_of_findings": True,
            "basic_scan_history": True,
            "expanded_scan_history": True,
            "basic_pdf_report": True,
            "csv_export": True,
            "filter_sorting": True,
            "conversation_starter": True,
            "lead_notes": True,
            "follow_up_status": True,
            "scan_comparison": True,
            "crm_integration": True,
            "api_access": True,
            "two_level_reporting": True,
            "advanced_filters": True,
            "advanced_sales_advice": True,
            "white_label_reports": True,
            "custom_scoring_model": True,
            "custom_report_templates": True,
            "priority_support": True,
            "onboarding_support_package": True,
            "lead_potential_ranking": True,
            "export_options": True,
            "team_usage": True,
            "custom_scan_volume": True,
        },
    },
}

FOLLOW_UP_STATUSES = [
    "new",
    "contacting",
    "qualified",
    "proposal",
    "won",
    "lost",
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _add_months(dt: datetime, months: int) -> datetime:
    month_index = (dt.month - 1) + months
    year = dt.year + month_index // 12
    month = month_index % 12 + 1
    day = min(dt.day, monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def default_db_path() -> Path:
    return Path(__file__).parent / "data" / "lead_scout.sqlite3"


def connect(db_path: Optional[Path] = None) -> sqlite3.Connection:
    p = Path(db_path) if db_path else default_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r["name"] == column for r in rows)


def _column_notnull(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    for row in rows:
        if row["name"] == column:
            return bool(row["notnull"])
    return False


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
        (table,),
    ).fetchone()
    return row is not None


def init_db(db_path: Optional[Path] = None) -> None:
    conn = connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS plans (
              code TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              monthly_price_eur INTEGER NOT NULL,
              yearly_price_eur INTEGER NOT NULL,
              monthly_tokens INTEGER NOT NULL,
              max_users INTEGER NOT NULL,
              features_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              bootstrap_key TEXT UNIQUE,
              name TEXT NOT NULL,
              plan_code TEXT NOT NULL,
              billing_cycle TEXT NOT NULL DEFAULT 'monthly',
              subscription_status TEXT NOT NULL DEFAULT 'active',
              custom_monthly_tokens INTEGER,
              custom_max_users INTEGER,
              custom_features_json TEXT,
              next_token_refresh_at TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY(plan_code) REFERENCES plans(code) ON DELETE RESTRICT
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              account_id INTEGER,
              username TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL,
              is_active INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
            );
            """
        )

        if _table_exists(conn, "users") and _column_notnull(conn, "users", "account_id"):
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users_v2 (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  account_id INTEGER,
                  username TEXT NOT NULL UNIQUE,
                  password_hash TEXT NOT NULL,
                  role TEXT NOT NULL,
                  is_active INTEGER NOT NULL DEFAULT 1,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
                );
                """
            )
            conn.execute(
                """
                INSERT INTO users_v2(id, account_id, username, password_hash, role, is_active, created_at, updated_at)
                SELECT id, account_id, username, password_hash, role, is_active, created_at, updated_at
                FROM users
                """
            )
            conn.execute("DROP TABLE users")
            conn.execute("ALTER TABLE users_v2 RENAME TO users")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS token_buckets (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              account_id INTEGER NOT NULL,
              bucket_type TEXT NOT NULL,
              total_tokens INTEGER NOT NULL,
              remaining_tokens INTEGER NOT NULL,
              expires_at TEXT,
              source_label TEXT,
              note TEXT,
              created_by_user_id INTEGER,
              created_at TEXT NOT NULL,
              FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE,
              FOREIGN KEY(created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS token_ledger (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              account_id INTEGER NOT NULL,
              user_id INTEGER,
              bucket_id INTEGER,
              entry_type TEXT NOT NULL,
              token_delta INTEGER NOT NULL,
              source_type TEXT NOT NULL,
              description TEXT NOT NULL,
              metadata_json TEXT,
              created_at TEXT NOT NULL,
              FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE,
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
              FOREIGN KEY(bucket_id) REFERENCES token_buckets(id) ON DELETE SET NULL
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              account_id INTEGER NOT NULL,
              actor_user_id INTEGER,
              event_type TEXT NOT NULL,
              description TEXT NOT NULL,
              metadata_json TEXT,
              created_at TEXT NOT NULL,
              FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE,
              FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS lead_notes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              account_id INTEGER NOT NULL,
              domain TEXT NOT NULL,
              notes TEXT NOT NULL DEFAULT '',
              follow_up_status TEXT NOT NULL DEFAULT 'new',
              updated_by_user_id INTEGER,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE(account_id, domain),
              FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE,
              FOREIGN KEY(updated_by_user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS current_companies (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              owner_username TEXT,
              owner_account_id INTEGER,
              created_by_user_id INTEGER,
              name TEXT NOT NULL,
              domain TEXT NOT NULL,
              sector TEXT NOT NULL,
              employees INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(owner_account_id) REFERENCES accounts(id) ON DELETE CASCADE,
              FOREIGN KEY(created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_lists (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              owner_username TEXT,
              owner_account_id INTEGER,
              created_by_user_id INTEGER,
              created_at TEXT NOT NULL,
              domain_count INTEGER NOT NULL,
              FOREIGN KEY(owner_account_id) REFERENCES accounts(id) ON DELETE CASCADE,
              FOREIGN KEY(created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_list_items (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              domain_list_id INTEGER NOT NULL,
              name TEXT NOT NULL,
              domain TEXT NOT NULL,
              sector TEXT NOT NULL,
              employees INTEGER NOT NULL,
              FOREIGN KEY(domain_list_id) REFERENCES domain_lists(id) ON DELETE CASCADE
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              owner_username TEXT,
              owner_account_id INTEGER,
              created_by_user_id INTEGER,
              created_at TEXT NOT NULL,
              domain_count INTEGER NOT NULL,
              hot_leads_count INTEGER,
              warm_leads_count INTEGER,
              cool_leads_count INTEGER,
              domain_list_id INTEGER NOT NULL,
              report_html_path TEXT NOT NULL,
              report_json_path TEXT,
              FOREIGN KEY(owner_account_id) REFERENCES accounts(id) ON DELETE CASCADE,
              FOREIGN KEY(created_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
              FOREIGN KEY(domain_list_id) REFERENCES domain_lists(id) ON DELETE RESTRICT
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS self_check_runs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              token TEXT NOT NULL UNIQUE,
              created_at TEXT NOT NULL,
              submitted_at TEXT,
              completed_at TEXT,
              status TEXT NOT NULL,
              domain TEXT NOT NULL,
              company_name TEXT NOT NULL,
              sector TEXT NOT NULL,
              employees INTEGER NOT NULL,
              contact_name TEXT,
              contact_email TEXT,
              report_html_path TEXT,
              report_pdf_path TEXT,
              report_json_path TEXT,
              email_delivery_status TEXT,
              emailed_at TEXT,
              findings_count INTEGER,
              total_score REAL,
              max_score REAL,
              tier TEXT
            );
            """
        )

        if _table_exists(conn, "current_companies"):
            if not _column_exists(conn, "current_companies", "owner_account_id"):
                conn.execute("ALTER TABLE current_companies ADD COLUMN owner_account_id INTEGER")
            if not _column_exists(conn, "current_companies", "created_by_user_id"):
                conn.execute("ALTER TABLE current_companies ADD COLUMN created_by_user_id INTEGER")

        if _table_exists(conn, "domain_lists"):
            if not _column_exists(conn, "domain_lists", "owner_account_id"):
                conn.execute("ALTER TABLE domain_lists ADD COLUMN owner_account_id INTEGER")
            if not _column_exists(conn, "domain_lists", "created_by_user_id"):
                conn.execute("ALTER TABLE domain_lists ADD COLUMN created_by_user_id INTEGER")

        if _table_exists(conn, "scan_runs"):
            if not _column_exists(conn, "scan_runs", "owner_account_id"):
                conn.execute("ALTER TABLE scan_runs ADD COLUMN owner_account_id INTEGER")
            if not _column_exists(conn, "scan_runs", "created_by_user_id"):
                conn.execute("ALTER TABLE scan_runs ADD COLUMN created_by_user_id INTEGER")
            if not _column_exists(conn, "scan_runs", "hot_leads_count"):
                conn.execute("ALTER TABLE scan_runs ADD COLUMN hot_leads_count INTEGER")
            if not _column_exists(conn, "scan_runs", "warm_leads_count"):
                conn.execute("ALTER TABLE scan_runs ADD COLUMN warm_leads_count INTEGER")
            if not _column_exists(conn, "scan_runs", "cool_leads_count"):
                conn.execute("ALTER TABLE scan_runs ADD COLUMN cool_leads_count INTEGER")

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_account_username ON users(account_id, username);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_token_buckets_account_type ON token_buckets(account_id, bucket_type, created_at ASC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_token_ledger_account_created ON token_ledger(account_id, created_at DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_admin_audit_log_account_created ON admin_audit_log(account_id, created_at DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_current_companies_account_id ON current_companies(owner_account_id, id ASC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domain_lists_account_created ON domain_lists(owner_account_id, created_at DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_account_created ON scan_runs(owner_account_id, created_at DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_check_runs_token ON self_check_runs(token);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_check_runs_created_at ON self_check_runs(created_at DESC);"
        )
        conn.commit()
    finally:
        conn.close()


def bootstrap_leadfinder_data(
    *,
    admin_username: str,
    admin_password_hash: str,
    test_username: str,
    test_password_hash: str,
    db_path: Optional[Path] = None,
) -> int:
    conn = connect(db_path)
    try:
        now = _utc_now_iso()
        _seed_plans(conn, now)

        row = conn.execute(
            "SELECT id FROM accounts WHERE bootstrap_key = ? LIMIT 1",
            ("default",),
        ).fetchone()
        if row:
            account_id = int(row["id"])
            conn.execute(
                """
                UPDATE accounts
                SET updated_at = ?
                WHERE id = ?
                """,
                (now, account_id),
            )
        else:
            refresh_at = _add_months(_utc_now(), 1).isoformat()
            cur = conn.execute(
                """
                INSERT INTO accounts(
                  bootstrap_key, name, plan_code, billing_cycle, subscription_status,
                  next_token_refresh_at, created_at, updated_at
                )
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    "default",
                    "ShieldCheck Team",
                    "growth",
                    "monthly",
                    "active",
                    refresh_at,
                    now,
                    now,
                ),
            )
            account_id = int(cur.lastrowid)
            _grant_bucket(
                conn,
                account_id=account_id,
                bucket_type="monthly",
                total_tokens=PLAN_DEFINITIONS["growth"]["monthly_tokens"],
                expires_at=refresh_at,
                source_label="Growth monthly allocation",
                note="Initial bootstrap allocation",
                created_by_user_id=None,
                entry_type="monthly_allocation",
                description="Initial monthly allocation",
                metadata={"plan_code": "growth"},
            )

        _upsert_user(
            conn,
            account_id=None,
            username=admin_username,
            password_hash=admin_password_hash,
            role="platform_admin",
            now=now,
        )
        _upsert_user(
            conn,
            account_id=account_id,
            username=test_username,
            password_hash=test_password_hash,
            role="admin",
            now=now,
        )

        conn.execute(
            "UPDATE current_companies SET owner_account_id = ? WHERE owner_account_id IS NULL",
            (account_id,),
        )
        conn.execute(
            "UPDATE domain_lists SET owner_account_id = ? WHERE owner_account_id IS NULL",
            (account_id,),
        )
        conn.execute(
            "UPDATE scan_runs SET owner_account_id = ? WHERE owner_account_id IS NULL",
            (account_id,),
        )
        conn.commit()
        return account_id
    finally:
        conn.close()


def _seed_plans(conn: sqlite3.Connection, now: str) -> None:
    for code, plan in PLAN_DEFINITIONS.items():
        conn.execute(
            """
            INSERT INTO plans(
              code, name, monthly_price_eur, yearly_price_eur,
              monthly_tokens, max_users, features_json, created_at, updated_at
            )
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(code) DO UPDATE SET
              name = excluded.name,
              monthly_price_eur = excluded.monthly_price_eur,
              yearly_price_eur = excluded.yearly_price_eur,
              monthly_tokens = excluded.monthly_tokens,
              max_users = excluded.max_users,
              features_json = excluded.features_json,
              updated_at = excluded.updated_at
            """,
            (
                code,
                plan["name"],
                int(plan["monthly_price_eur"]),
                int(plan["yearly_price_eur"]),
                int(plan["monthly_tokens"]),
                int(plan["max_users"]),
                json.dumps(plan["features"], ensure_ascii=True, sort_keys=True),
                now,
                now,
            ),
        )


def _upsert_user(
    conn: sqlite3.Connection,
    *,
    account_id: Optional[int],
    username: str,
    password_hash: str,
    role: str,
    now: str,
) -> None:
    row = conn.execute(
        "SELECT id FROM users WHERE username = ? LIMIT 1",
        (username,),
    ).fetchone()
    if row:
        conn.execute(
            """
            UPDATE users
            SET account_id = ?, password_hash = ?, role = ?, is_active = 1, updated_at = ?
            WHERE id = ?
            """,
            (account_id, password_hash, role, now, int(row["id"])),
        )
    else:
        conn.execute(
            """
            INSERT INTO users(account_id, username, password_hash, role, is_active, created_at, updated_at)
            VALUES(?,?,?,?,1,?,?)
            """,
            (account_id, username, password_hash, role, now, now),
        )


def _get_plan_row(conn: sqlite3.Connection, code: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM plans WHERE code = ? LIMIT 1", (code,)).fetchone()
    if row is None:
        raise ValueError(f"Plan not found: {code}")
    return row


def _account_plan_snapshot(conn: sqlite3.Connection, account_id: int) -> Dict[str, Any]:
    row = conn.execute(
        """
        SELECT a.*, p.name AS plan_name, p.monthly_price_eur, p.yearly_price_eur,
               p.monthly_tokens AS plan_monthly_tokens, p.max_users AS plan_max_users,
               p.features_json AS plan_features_json
        FROM accounts a
        JOIN plans p ON p.code = a.plan_code
        WHERE a.id = ?
        LIMIT 1
        """,
        (account_id,),
    ).fetchone()
    if row is None:
        raise ValueError("Account not found")

    plan_features = json.loads(row["plan_features_json"])
    custom_features = json.loads(row["custom_features_json"]) if row["custom_features_json"] else {}
    features = {**plan_features, **custom_features}

    monthly_tokens = (
        int(row["custom_monthly_tokens"])
        if row["custom_monthly_tokens"] is not None
        else int(row["plan_monthly_tokens"])
    )
    max_users = (
        int(row["custom_max_users"])
        if row["custom_max_users"] is not None
        else int(row["plan_max_users"])
    )

    return {
        "account_id": int(row["id"]),
        "name": row["name"],
        "plan_code": row["plan_code"],
        "plan_name": row["plan_name"],
        "billing_cycle": row["billing_cycle"],
        "subscription_status": row["subscription_status"],
        "monthly_price_eur": int(row["monthly_price_eur"]),
        "yearly_price_eur": int(row["yearly_price_eur"]),
        "monthly_tokens": monthly_tokens,
        "max_users": max_users,
        "features": features,
        "next_token_refresh_at": row["next_token_refresh_at"],
    }


def _grant_bucket(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    bucket_type: str,
    total_tokens: int,
    expires_at: Optional[str],
    source_label: str,
    note: str,
    created_by_user_id: Optional[int],
    entry_type: str,
    description: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> int:
    now = _utc_now_iso()
    cur = conn.execute(
        """
        INSERT INTO token_buckets(
          account_id, bucket_type, total_tokens, remaining_tokens, expires_at,
          source_label, note, created_by_user_id, created_at
        )
        VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (
            account_id,
            bucket_type,
            int(total_tokens),
            int(total_tokens),
            expires_at,
            source_label,
            note,
            created_by_user_id,
            now,
        ),
    )
    bucket_id = int(cur.lastrowid)
    conn.execute(
        """
        INSERT INTO token_ledger(
          account_id, user_id, bucket_id, entry_type, token_delta,
          source_type, description, metadata_json, created_at
        )
        VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (
            account_id,
            created_by_user_id,
            bucket_id,
            entry_type,
            int(total_tokens),
            bucket_type,
            description,
            json.dumps(metadata or {}, ensure_ascii=True, sort_keys=True),
            now,
        ),
    )
    return bucket_id


def _expire_monthly_tokens_if_due(conn: sqlite3.Connection, account_id: int, now_dt: datetime) -> None:
    plan = _account_plan_snapshot(conn, account_id)
    next_refresh = _parse_iso(plan["next_token_refresh_at"])
    if next_refresh is None:
        next_refresh = _add_months(now_dt, 1)
        conn.execute(
            "UPDATE accounts SET next_token_refresh_at = ?, updated_at = ? WHERE id = ?",
            (next_refresh.isoformat(), now_dt.isoformat(), account_id),
        )
        return

    while now_dt >= next_refresh:
        rows = conn.execute(
            """
            SELECT id, remaining_tokens
            FROM token_buckets
            WHERE account_id = ? AND bucket_type = 'monthly' AND remaining_tokens > 0
            """,
            (account_id,),
        ).fetchall()
        for row in rows:
            remaining = int(row["remaining_tokens"])
            if remaining <= 0:
                continue
            conn.execute(
                "UPDATE token_buckets SET remaining_tokens = 0, expires_at = ? WHERE id = ?",
                (next_refresh.isoformat(), int(row["id"])),
            )
            conn.execute(
                """
                INSERT INTO token_ledger(
                  account_id, user_id, bucket_id, entry_type, token_delta,
                  source_type, description, metadata_json, created_at
                )
                VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    account_id,
                    None,
                    int(row["id"]),
                    "expire",
                    -remaining,
                    "monthly",
                    "Expired unused monthly tokens",
                    json.dumps({}, ensure_ascii=True, sort_keys=True),
                    next_refresh.isoformat(),
                ),
            )

        if plan["subscription_status"] == "active" and plan["monthly_tokens"] > 0:
            next_cycle = _add_months(next_refresh, 1)
            _grant_bucket(
                conn,
                account_id=account_id,
                bucket_type="monthly",
                total_tokens=plan["monthly_tokens"],
                expires_at=next_cycle.isoformat(),
                source_label=f"{plan['plan_name']} monthly allocation",
                note=f"Monthly allocation for {next_refresh.date().isoformat()} cycle",
                created_by_user_id=None,
                entry_type="monthly_allocation",
                description="Monthly token allocation",
                metadata={
                    "plan_code": plan["plan_code"],
                    "billing_cycle": plan["billing_cycle"],
                    "cycle_start": next_refresh.isoformat(),
                },
            )

        next_refresh = _add_months(next_refresh, 1)
        conn.execute(
            "UPDATE accounts SET next_token_refresh_at = ?, updated_at = ? WHERE id = ?",
            (next_refresh.isoformat(), now_dt.isoformat(), account_id),
        )


def ensure_account_tokens(account_id: int, db_path: Optional[Path] = None) -> None:
    conn = connect(db_path)
    try:
        _expire_monthly_tokens_if_due(conn, int(account_id), _utc_now())
        conn.commit()
    finally:
        conn.close()


def get_user_by_username(
    username: str, db_path: Optional[Path] = None
) -> Optional[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT u.id, u.account_id, u.username, u.password_hash, u.role, u.is_active,
                   a.name AS account_name, a.plan_code, a.billing_cycle, a.subscription_status
            FROM users u
            LEFT JOIN accounts a ON a.id = u.account_id
            WHERE u.username = ?
            LIMIT 1
            """,
            (username,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_context(user_id: int, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT u.id, u.account_id, u.username, u.role, u.is_active,
                   a.name AS account_name, a.plan_code, a.billing_cycle, a.subscription_status
            FROM users u
            LEFT JOIN accounts a ON a.id = u.account_id
            WHERE u.id = ?
            LIMIT 1
            """,
            (int(user_id),),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_accounts(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id
            FROM accounts
            ORDER BY created_at ASC, id ASC
            """
        ).fetchall()
        items: List[Dict[str, Any]] = []
        for row in rows:
            account_id = int(row["id"])
            _expire_monthly_tokens_if_due(conn, account_id, _utc_now())
            summary = get_account_summary(account_id, db_path=db_path)
            items.append(summary)
        conn.commit()
        return items
    finally:
        conn.close()


def get_account_summary(account_id: int, db_path: Optional[Path] = None) -> Dict[str, Any]:
    ensure_account_tokens(account_id, db_path=db_path)
    conn = connect(db_path)
    try:
        plan = _account_plan_snapshot(conn, int(account_id))
        user_count = int(
            conn.execute(
                "SELECT COUNT(*) FROM users WHERE account_id = ? AND is_active = 1",
                (int(account_id),),
            ).fetchone()[0]
        )
        balances = _get_token_balance(conn, int(account_id))
        return {
            "account_id": plan["account_id"],
            "account_name": plan["name"],
            "plan_code": plan["plan_code"],
            "plan_name": plan["plan_name"],
            "billing_cycle": plan["billing_cycle"],
            "subscription_status": plan["subscription_status"],
            "monthly_tokens": plan["monthly_tokens"],
            "max_users": plan["max_users"],
            "user_count": user_count,
            "features": plan["features"],
            "next_token_refresh_at": plan["next_token_refresh_at"],
            "token_balances": balances,
        }
    finally:
        conn.close()


def get_account_detail(account_id: int, db_path: Optional[Path] = None) -> Dict[str, Any]:
    summary = get_account_summary(account_id, db_path=db_path)
    summary["users"] = list_account_users(account_id, db_path=db_path)
    summary["token_ledger"] = list_token_ledger(account_id, limit=15, db_path=db_path)
    summary["admin_audit_log"] = list_account_admin_events(account_id, limit=20, db_path=db_path)
    return summary


def update_account_settings(
    *,
    account_id: int,
    plan_code: Optional[str] = None,
    billing_cycle: Optional[str] = None,
    subscription_status: Optional[str] = None,
    next_token_refresh_at: Optional[str] = None,
    actor_user_id: Optional[int] = None,
    db_path: Optional[Path] = None,
) -> None:
    assignments: List[str] = []
    params: List[Any] = []
    normalized_next_token_refresh_at: Optional[str] = None

    if plan_code is not None:
        if plan_code not in PLAN_DEFINITIONS:
            raise ValueError("Invalid plan code")
        assignments.append("plan_code = ?")
        params.append(plan_code)

    if billing_cycle is not None:
        if billing_cycle not in {"monthly", "yearly"}:
            raise ValueError("Invalid billing cycle")
        assignments.append("billing_cycle = ?")
        params.append(billing_cycle)

    if subscription_status is not None:
        if subscription_status not in {"active", "paused", "cancelled"}:
            raise ValueError("Invalid subscription status")
        assignments.append("subscription_status = ?")
        params.append(subscription_status)

    if next_token_refresh_at is not None:
        parsed = _parse_iso(next_token_refresh_at)
        if parsed is None:
            raise ValueError("Invalid refresh datetime")
        normalized_next_token_refresh_at = parsed.isoformat()
        assignments.append("next_token_refresh_at = ?")
        params.append(normalized_next_token_refresh_at)

    if not assignments:
        return

    assignments.append("updated_at = ?")
    params.append(_utc_now_iso())
    params.append(int(account_id))

    conn = connect(db_path)
    try:
        before = get_account_summary(int(account_id), db_path=db_path)
        row = conn.execute("SELECT 1 FROM accounts WHERE id = ? LIMIT 1", (int(account_id),)).fetchone()
        if row is None:
            raise ValueError("Account not found")
        conn.execute(
            f"UPDATE accounts SET {', '.join(assignments)} WHERE id = ?",
            params,
        )
        changed = {}
        if plan_code is not None and before.get("plan_code") != plan_code:
            changed["plan_code"] = {"before": before.get("plan_code"), "after": plan_code}
        if billing_cycle is not None and before.get("billing_cycle") != billing_cycle:
            changed["billing_cycle"] = {"before": before.get("billing_cycle"), "after": billing_cycle}
        if subscription_status is not None and before.get("subscription_status") != subscription_status:
            changed["subscription_status"] = {
                "before": before.get("subscription_status"),
                "after": subscription_status,
            }
        if (
            normalized_next_token_refresh_at is not None
            and before.get("next_token_refresh_at") != normalized_next_token_refresh_at
        ):
            changed["next_token_refresh_at"] = {
                "before": before.get("next_token_refresh_at"),
                "after": normalized_next_token_refresh_at,
            }
        if changed:
            _record_admin_audit_event(
                conn,
                account_id=int(account_id),
                actor_user_id=actor_user_id,
                event_type="account_settings_updated",
                description="Updated account settings",
                metadata={"changed_fields": changed},
            )
        conn.commit()
    finally:
        conn.close()


def _get_token_balance(conn: sqlite3.Connection, account_id: int) -> Dict[str, int]:
    rows = conn.execute(
        """
        SELECT bucket_type, COALESCE(SUM(remaining_tokens), 0) AS total
        FROM token_buckets
        WHERE account_id = ?
        GROUP BY bucket_type
        """,
        (int(account_id),),
    ).fetchall()
    grouped = {row["bucket_type"]: int(row["total"]) for row in rows}
    monthly = grouped.get("monthly", 0)
    purchased = grouped.get("purchased", 0)
    granted = grouped.get("granted", 0)
    return {
        "monthly": monthly,
        "purchased": purchased,
        "granted": granted,
        "total": monthly + purchased + granted,
    }


def _record_admin_audit_event(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    actor_user_id: Optional[int],
    event_type: str,
    description: str,
    metadata: Optional[Dict[str, Any]] = None,
    created_at: Optional[str] = None,
) -> None:
    conn.execute(
        """
        INSERT INTO admin_audit_log(
          account_id, actor_user_id, event_type, description, metadata_json, created_at
        )
        VALUES(?,?,?,?,?,?)
        """,
        (
            int(account_id),
            int(actor_user_id) if actor_user_id is not None else None,
            event_type,
            description,
            json.dumps(metadata or {}, ensure_ascii=True, sort_keys=True),
            created_at or _utc_now_iso(),
        ),
    )


def list_token_ledger(
    account_id: int, limit: int = 25, db_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    ensure_account_tokens(account_id, db_path=db_path)
    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT tl.id, tl.entry_type, tl.token_delta, tl.source_type, tl.description,
                   tl.metadata_json, tl.created_at, u.username
            FROM token_ledger tl
            LEFT JOIN users u ON u.id = tl.user_id
            WHERE tl.account_id = ?
            ORDER BY tl.created_at DESC, tl.id DESC
            LIMIT ?
            """,
            (int(account_id), max(1, int(limit))),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
            items.append(item)
        return items
    finally:
        conn.close()


def list_account_admin_events(
    account_id: int, limit: int = 25, db_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT aal.id, aal.event_type, aal.description, aal.metadata_json, aal.created_at, u.username
            FROM admin_audit_log aal
            LEFT JOIN users u ON u.id = aal.actor_user_id
            WHERE aal.account_id = ?
            ORDER BY aal.created_at DESC, aal.id DESC
            LIMIT ?
            """,
            (int(account_id), max(1, int(limit))),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
            items.append(item)
        return items
    finally:
        conn.close()


def list_account_users(account_id: int, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id, username, role, is_active, created_at, updated_at
            FROM users
            WHERE account_id = ?
            ORDER BY role DESC, username ASC
            """,
            (int(account_id),),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def create_account_user(
    *,
    account_id: int,
    username: str,
    password_hash: str,
    role: str,
    created_by_user_id: int,
    db_path: Optional[Path] = None,
) -> int:
    if role not in {"admin", "member"}:
        raise ValueError("Invalid role")

    ensure_account_tokens(account_id, db_path=db_path)
    conn = connect(db_path)
    try:
        plan = _account_plan_snapshot(conn, int(account_id))
        if plan["max_users"] > 0:
            user_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM users WHERE account_id = ? AND is_active = 1",
                    (int(account_id),),
                ).fetchone()[0]
            )
            if user_count >= plan["max_users"]:
                raise ValueError("User limit reached for this plan")

        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? LIMIT 1",
            (username,),
        ).fetchone()
        if existing is not None:
            raise ValueError("Username already exists")

        now = _utc_now_iso()
        cur = conn.execute(
            """
            INSERT INTO users(account_id, username, password_hash, role, is_active, created_at, updated_at)
            VALUES(?,?,?,?,1,?,?)
            """,
            (int(account_id), username, password_hash, role, now, now),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def grant_tokens(
    *,
    account_id: int,
    created_by_user_id: int,
    token_count: int,
    note: str,
    db_path: Optional[Path] = None,
) -> None:
    if int(token_count) <= 0:
        raise ValueError("Token count must be positive")

    conn = connect(db_path)
    try:
        _grant_bucket(
            conn,
            account_id=int(account_id),
            bucket_type="granted",
            total_tokens=int(token_count),
            expires_at=None,
            source_label="Admin grant",
            note=note.strip() or "Admin token grant",
            created_by_user_id=int(created_by_user_id),
            entry_type="grant",
            description="Admin granted extra tokens",
            metadata={"note": note.strip()},
        )
        _record_admin_audit_event(
            conn,
            account_id=int(account_id),
            actor_user_id=int(created_by_user_id),
            event_type="tokens_granted",
            description="Granted extra tokens to account",
            metadata={"token_count": int(token_count), "note": note.strip()},
        )
        conn.commit()
    finally:
        conn.close()


def remove_tokens(
    *,
    account_id: int,
    created_by_user_id: int,
    token_count: int,
    note: str,
    db_path: Optional[Path] = None,
) -> None:
    if int(token_count) <= 0:
        raise ValueError("Token count must be positive")

    conn = connect(db_path)
    try:
        _expire_monthly_tokens_if_due(conn, int(account_id), _utc_now())
        balances = _get_token_balance(conn, int(account_id))
        if balances["total"] < int(token_count):
            raise ValueError("Not enough tokens to remove")

        remaining_to_remove = int(token_count)
        rows = conn.execute(
            """
            SELECT id, bucket_type, remaining_tokens
            FROM token_buckets
            WHERE account_id = ? AND remaining_tokens > 0
            ORDER BY
              CASE bucket_type
                WHEN 'granted' THEN 1
                WHEN 'purchased' THEN 2
                WHEN 'monthly' THEN 3
                ELSE 9
              END,
              created_at ASC,
              id ASC
            """,
            (int(account_id),),
        ).fetchall()

        for row in rows:
            if remaining_to_remove <= 0:
                break
            available = int(row["remaining_tokens"])
            take = min(available, remaining_to_remove)
            if take <= 0:
                continue
            conn.execute(
                "UPDATE token_buckets SET remaining_tokens = remaining_tokens - ? WHERE id = ?",
                (take, int(row["id"])),
            )
            conn.execute(
                """
                INSERT INTO token_ledger(
                  account_id, user_id, bucket_id, entry_type, token_delta,
                  source_type, description, metadata_json, created_at
                )
                VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    int(account_id),
                    int(created_by_user_id),
                    int(row["id"]),
                    "admin_debit",
                    -take,
                    row["bucket_type"],
                    "Admin removed tokens",
                    json.dumps({"note": note.strip()}, ensure_ascii=True, sort_keys=True),
                    _utc_now_iso(),
                ),
            )
            remaining_to_remove -= take

        if remaining_to_remove != 0:
            raise RuntimeError("Token removal did not settle correctly")

        _record_admin_audit_event(
            conn,
            account_id=int(account_id),
            actor_user_id=int(created_by_user_id),
            event_type="tokens_removed",
            description="Removed tokens from account",
            metadata={"token_count": int(token_count), "note": note.strip()},
        )
        conn.commit()
    finally:
        conn.close()


def force_account_token_refresh(
    *,
    account_id: int,
    actor_user_id: int,
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    conn = connect(db_path)
    try:
        before = _account_plan_snapshot(conn, int(account_id))
        balances_before = _get_token_balance(conn, int(account_id))
        now_iso = _utc_now_iso()
        row = conn.execute("SELECT 1 FROM accounts WHERE id = ? LIMIT 1", (int(account_id),)).fetchone()
        if row is None:
            raise ValueError("Account not found")
        conn.execute(
            "UPDATE accounts SET next_token_refresh_at = ?, updated_at = ? WHERE id = ?",
            (now_iso, now_iso, int(account_id)),
        )
        _expire_monthly_tokens_if_due(conn, int(account_id), _utc_now())
        balances_after = _get_token_balance(conn, int(account_id))
        after = _account_plan_snapshot(conn, int(account_id))
        _record_admin_audit_event(
            conn,
            account_id=int(account_id),
            actor_user_id=int(actor_user_id),
            event_type="token_refresh_forced",
            description="Forced token refresh",
            metadata={
                "previous_refresh_at": before["next_token_refresh_at"],
                "next_refresh_at": after["next_token_refresh_at"],
                "balances_before": balances_before,
                "balances_after": balances_after,
            },
        )
        conn.commit()
        return {
            "previous_refresh_at": before["next_token_refresh_at"],
            "next_refresh_at": after["next_token_refresh_at"],
            "balances_before": balances_before,
            "balances_after": balances_after,
        }
    finally:
        conn.close()


def purchase_tokens_stub(
    *,
    account_id: int,
    created_by_user_id: int,
    token_count: int,
    note: str,
    db_path: Optional[Path] = None,
) -> None:
    if int(token_count) <= 0:
        raise ValueError("Token count must be positive")

    conn = connect(db_path)
    try:
        _grant_bucket(
            conn,
            account_id=int(account_id),
            bucket_type="purchased",
            total_tokens=int(token_count),
            expires_at=None,
            source_label="Billing stub purchase",
            note=note.strip() or "Stub token purchase",
            created_by_user_id=int(created_by_user_id),
            entry_type="purchase",
            description="Purchased extra tokens (billing stub)",
            metadata={"note": note.strip(), "billing_stub": True},
        )
        conn.commit()
    finally:
        conn.close()


def consume_scan_tokens(
    *,
    account_id: int,
    user_id: int,
    token_count: int,
    description: str,
    metadata: Optional[Dict[str, Any]] = None,
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    if int(token_count) <= 0:
        raise ValueError("Token count must be positive")

    conn = connect(db_path)
    try:
        _expire_monthly_tokens_if_due(conn, int(account_id), _utc_now())
        balances = _get_token_balance(conn, int(account_id))
        if balances["total"] < int(token_count):
            raise ValueError("Not enough tokens")

        remaining_to_consume = int(token_count)
        allocations: List[Dict[str, Any]] = []
        rows = conn.execute(
            """
            SELECT id, bucket_type, remaining_tokens
            FROM token_buckets
            WHERE account_id = ? AND remaining_tokens > 0
            ORDER BY
              CASE bucket_type
                WHEN 'monthly' THEN 1
                WHEN 'purchased' THEN 2
                WHEN 'granted' THEN 3
                ELSE 9
              END,
              created_at ASC,
              id ASC
            """,
            (int(account_id),),
        ).fetchall()

        for row in rows:
            if remaining_to_consume <= 0:
                break
            available = int(row["remaining_tokens"])
            take = min(available, remaining_to_consume)
            if take <= 0:
                continue
            conn.execute(
                "UPDATE token_buckets SET remaining_tokens = remaining_tokens - ? WHERE id = ?",
                (take, int(row["id"])),
            )
            conn.execute(
                """
                INSERT INTO token_ledger(
                  account_id, user_id, bucket_id, entry_type, token_delta,
                  source_type, description, metadata_json, created_at
                )
                VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    int(account_id),
                    int(user_id),
                    int(row["id"]),
                    "consume",
                    -take,
                    row["bucket_type"],
                    description,
                    json.dumps(metadata or {}, ensure_ascii=True, sort_keys=True),
                    _utc_now_iso(),
                ),
            )
            allocations.append(
                {
                    "bucket_id": int(row["id"]),
                    "bucket_type": row["bucket_type"],
                    "tokens": take,
                }
            )
            remaining_to_consume -= take

        if remaining_to_consume != 0:
            raise RuntimeError("Token consumption did not settle correctly")

        conn.commit()
        balances_after = _get_token_balance(conn, int(account_id))
        return {"consumed": int(token_count), "allocations": allocations, "balances_after": balances_after}
    finally:
        conn.close()


def list_current_companies(
    account_id: int, db_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id, name, domain, sector, employees
            FROM current_companies
            WHERE owner_account_id = ?
            ORDER BY id ASC
            """,
            (int(account_id),),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_current_company(
    *,
    name: str,
    domain: str,
    sector: str,
    employees: int,
    owner_account_id: int,
    created_by_user_id: int,
    db_path: Optional[Path] = None,
) -> int:
    conn = connect(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO current_companies(
              owner_account_id, created_by_user_id, name, domain, sector, employees, created_at
            )
            VALUES(?,?,?,?,?,?,?)
            """,
            (
                int(owner_account_id),
                int(created_by_user_id),
                name,
                domain,
                sector,
                int(employees),
                _utc_now_iso(),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def delete_current_company(
    company_id: int, owner_account_id: int, db_path: Optional[Path] = None
) -> bool:
    conn = connect(db_path)
    try:
        cur = conn.execute(
            "DELETE FROM current_companies WHERE id = ? AND owner_account_id = ?",
            (int(company_id), int(owner_account_id)),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def clear_current_companies(
    owner_account_id: int, db_path: Optional[Path] = None
) -> None:
    conn = connect(db_path)
    try:
        conn.execute(
            "DELETE FROM current_companies WHERE owner_account_id = ?",
            (int(owner_account_id),),
        )
        conn.commit()
    finally:
        conn.close()


def bulk_add_current_companies(
    companies: List[Dict[str, Any]],
    owner_account_id: int,
    created_by_user_id: int,
    db_path: Optional[Path] = None,
) -> int:
    if not companies:
        return 0
    conn = connect(db_path)
    try:
        now = _utc_now_iso()
        conn.executemany(
            """
            INSERT INTO current_companies(
              owner_account_id, created_by_user_id, name, domain, sector, employees, created_at
            )
            VALUES(?,?,?,?,?,?,?)
            """,
            [
                (
                    int(owner_account_id),
                    int(created_by_user_id),
                    c["name"],
                    c["domain"],
                    c.get("sector", "Unknown"),
                    int(c.get("employees", 100)),
                    now,
                )
                for c in companies
            ],
        )
        conn.commit()
        return len(companies)
    finally:
        conn.close()


def create_domain_list_snapshot(
    companies: List[Dict[str, Any]],
    owner_account_id: int,
    created_by_user_id: int,
    db_path: Optional[Path] = None,
) -> int:
    conn = connect(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO domain_lists(owner_account_id, created_by_user_id, created_at, domain_count)
            VALUES(?,?,?,?)
            """,
            (int(owner_account_id), int(created_by_user_id), _utc_now_iso(), len(companies)),
        )
        domain_list_id = int(cur.lastrowid)
        if companies:
            conn.executemany(
                """
                INSERT INTO domain_list_items(domain_list_id, name, domain, sector, employees)
                VALUES(?,?,?,?,?)
                """,
                [
                    (
                        domain_list_id,
                        c["name"],
                        c["domain"],
                        c.get("sector", "Unknown"),
                        int(c.get("employees", 100)),
                    )
                    for c in companies
                ],
            )
        conn.commit()
        return domain_list_id
    finally:
        conn.close()


def _report_output_to_fs_path(output_path: Optional[str]) -> Optional[Path]:
    if not output_path:
        return None
    normalized = str(output_path).strip()
    if not normalized:
        return None
    filename = Path(normalized).name
    return Path(__file__).parent / "output" / filename


def _scan_run_counts_from_report_json(report_json_path: Optional[str]) -> Dict[str, int]:
    path = _report_output_to_fs_path(report_json_path)
    if path is None or not path.exists():
        return {"hot_leads_count": 0, "warm_leads_count": 0, "cool_leads_count": 0}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        summary = data.get("summary") or {}
        return {
            "hot_leads_count": int(summary.get("hot_leads") or 0),
            "warm_leads_count": int(summary.get("warm_leads") or 0),
            "cool_leads_count": int(summary.get("cool_leads") or 0),
        }
    except Exception:
        return {"hot_leads_count": 0, "warm_leads_count": 0, "cool_leads_count": 0}


def list_domain_lists_page(
    *, owner_account_id: int, page: int, page_size: int, db_path: Optional[Path] = None
) -> Tuple[int, List[Dict[str, Any]]]:
    page = max(1, int(page))
    page_size = max(1, min(200, int(page_size)))
    offset = (page - 1) * page_size

    conn = connect(db_path)
    try:
        total = int(
            conn.execute(
                "SELECT COUNT(*) FROM domain_lists WHERE owner_account_id = ?",
                (int(owner_account_id),),
            ).fetchone()[0]
        )
        rows = conn.execute(
            """
            SELECT id, created_at, domain_count
            FROM domain_lists
            WHERE owner_account_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (int(owner_account_id), page_size, offset),
        ).fetchall()
        return total, [dict(r) for r in rows]
    finally:
        conn.close()


def get_domain_list_items(
    domain_list_id: int, owner_account_id: int, db_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT dli.name, dli.domain, dli.sector, dli.employees
            FROM domain_list_items dli
            JOIN domain_lists dl ON dl.id = dli.domain_list_id
            WHERE dli.domain_list_id = ? AND dl.owner_account_id = ?
            ORDER BY dli.id ASC
            """,
            (int(domain_list_id), int(owner_account_id)),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def use_domain_list_as_current(
    domain_list_id: int, owner_account_id: int, db_path: Optional[Path] = None
) -> int:
    conn = connect(db_path)
    try:
        owner_row = conn.execute(
            "SELECT 1 FROM domain_lists WHERE id = ? AND owner_account_id = ?",
            (int(domain_list_id), int(owner_account_id)),
        ).fetchone()
        if owner_row is None:
            raise ValueError("Domain list not found")

        rows = conn.execute(
            """
            SELECT name, domain, sector, employees
            FROM domain_list_items dli
            JOIN domain_lists dl ON dl.id = dli.domain_list_id
            WHERE dli.domain_list_id = ? AND dl.owner_account_id = ?
            ORDER BY dli.id ASC
            """,
            (int(domain_list_id), int(owner_account_id)),
        ).fetchall()

        conn.execute(
            "DELETE FROM current_companies WHERE owner_account_id = ?",
            (int(owner_account_id),),
        )
        if rows:
            now = _utc_now_iso()
            conn.executemany(
                """
                INSERT INTO current_companies(
                  owner_account_id, name, domain, sector, employees, created_at
                )
                VALUES(?,?,?,?,?,?)
                """,
                [
                    (
                        int(owner_account_id),
                        r["name"],
                        r["domain"],
                        r["sector"],
                        int(r["employees"]),
                        now,
                    )
                    for r in rows
                ],
            )
        conn.commit()
        return len(rows)
    finally:
        conn.close()


def record_scan_run(
    *,
    domain_list_id: int,
    domain_count: int,
    hot_leads_count: int,
    warm_leads_count: int,
    cool_leads_count: int,
    report_html_path: str,
    owner_account_id: int,
    created_by_user_id: int,
    report_json_path: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> int:
    conn = connect(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO scan_runs(
              owner_account_id, created_by_user_id, created_at, domain_count,
              hot_leads_count, warm_leads_count, cool_leads_count,
              domain_list_id, report_html_path, report_json_path
            )
            VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                int(owner_account_id),
                int(created_by_user_id),
                _utc_now_iso(),
                int(domain_count),
                int(hot_leads_count),
                int(warm_leads_count),
                int(cool_leads_count),
                int(domain_list_id),
                report_html_path,
                report_json_path,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_scan_runs_page(
    *, owner_account_id: int, page: int, page_size: int, db_path: Optional[Path] = None
) -> Tuple[int, List[Dict[str, Any]]]:
    page = max(1, int(page))
    page_size = max(1, min(200, int(page_size)))
    offset = (page - 1) * page_size

    conn = connect(db_path)
    try:
        total = int(
            conn.execute(
                "SELECT COUNT(*) FROM scan_runs WHERE owner_account_id = ?",
                (int(owner_account_id),),
            ).fetchone()[0]
        )
        rows = conn.execute(
            """
            SELECT
              id,
              created_at,
              domain_count,
              hot_leads_count,
              warm_leads_count,
              cool_leads_count,
              report_html_path,
              report_json_path,
              domain_list_id
            FROM scan_runs
            WHERE owner_account_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (int(owner_account_id), page_size, offset),
        ).fetchall()
        items: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            if any(item.get(key) is None for key in ("hot_leads_count", "warm_leads_count", "cool_leads_count")):
                item.update(_scan_run_counts_from_report_json(item.get("report_json_path")))
            items.append(item)
        return total, items
    finally:
        conn.close()


def list_recent_scan_runs(
    owner_account_id: int, limit: int = 50, db_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT
              id,
              created_at,
              domain_count,
              hot_leads_count,
              warm_leads_count,
              cool_leads_count,
              report_html_path,
              report_json_path,
              domain_list_id
            FROM scan_runs
            WHERE owner_account_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (int(owner_account_id), max(1, min(500, int(limit)))),
        ).fetchall()
        items: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            if any(item.get(key) is None for key in ("hot_leads_count", "warm_leads_count", "cool_leads_count")):
                item.update(_scan_run_counts_from_report_json(item.get("report_json_path")))
            items.append(item)
        return items
    finally:
        conn.close()


def account_owns_output_path(
    owner_account_id: int, output_path: str, db_path: Optional[Path] = None
) -> bool:
    conn = connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT 1
            FROM scan_runs
            WHERE owner_account_id = ?
              AND (report_html_path = ? OR report_json_path = ?)
            LIMIT 1
            """,
            (int(owner_account_id), output_path, output_path),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def get_lead_note(
    account_id: int, domain: str, db_path: Optional[Path] = None
) -> Dict[str, Any]:
    conn = connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT notes, follow_up_status, updated_at
            FROM lead_notes
            WHERE account_id = ? AND domain = ?
            LIMIT 1
            """,
            (int(account_id), domain),
        ).fetchone()
        if row is None:
            return {"notes": "", "follow_up_status": "new", "updated_at": None}
        return dict(row)
    finally:
        conn.close()


def upsert_lead_note(
    *,
    account_id: int,
    domain: str,
    notes: str,
    follow_up_status: str,
    updated_by_user_id: int,
    db_path: Optional[Path] = None,
) -> None:
    if follow_up_status not in FOLLOW_UP_STATUSES:
        raise ValueError("Invalid follow-up status")

    conn = connect(db_path)
    try:
        now = _utc_now_iso()
        conn.execute(
            """
            INSERT INTO lead_notes(
              account_id, domain, notes, follow_up_status, updated_by_user_id, created_at, updated_at
            )
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(account_id, domain) DO UPDATE SET
              notes = excluded.notes,
              follow_up_status = excluded.follow_up_status,
              updated_by_user_id = excluded.updated_by_user_id,
              updated_at = excluded.updated_at
            """,
            (
                int(account_id),
                domain,
                notes,
                follow_up_status,
                int(updated_by_user_id),
                now,
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def create_self_check_run(
    *,
    token: str,
    domain: str,
    company_name: str,
    sector: str,
    employees: int,
    status: str = "queued",
    db_path: Optional[Path] = None,
) -> int:
    conn = connect(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO self_check_runs(
              token, created_at, status, domain, company_name, sector, employees
            )
            VALUES(?,?,?,?,?,?,?)
            """,
            (
                token,
                _utc_now_iso(),
                status,
                domain,
                company_name,
                sector,
                int(employees),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def update_self_check_run(
    token: str,
    *,
    status: Optional[str] = None,
    contact_name: Optional[str] = None,
    contact_email: Optional[str] = None,
    report_html_path: Optional[str] = None,
    report_pdf_path: Optional[str] = None,
    report_json_path: Optional[str] = None,
    email_delivery_status: Optional[str] = None,
    findings_count: Optional[int] = None,
    total_score: Optional[float] = None,
    max_score: Optional[float] = None,
    tier: Optional[str] = None,
    set_submitted_at: bool = False,
    set_completed_at: bool = False,
    set_emailed_at: bool = False,
    db_path: Optional[Path] = None,
) -> None:
    assignments = []
    params: List[Any] = []

    updates = {
        "status": status,
        "contact_name": contact_name,
        "contact_email": contact_email,
        "report_html_path": report_html_path,
        "report_pdf_path": report_pdf_path,
        "report_json_path": report_json_path,
        "email_delivery_status": email_delivery_status,
        "findings_count": findings_count,
        "total_score": total_score,
        "max_score": max_score,
        "tier": tier,
    }
    for column, value in updates.items():
        if value is not None:
            assignments.append(f"{column} = ?")
            params.append(value)

    if set_submitted_at:
        assignments.append("submitted_at = ?")
        params.append(_utc_now_iso())
    if set_completed_at:
        assignments.append("completed_at = ?")
        params.append(_utc_now_iso())
    if set_emailed_at:
        assignments.append("emailed_at = ?")
        params.append(_utc_now_iso())

    if not assignments:
        return

    params.append(token)
    conn = connect(db_path)
    try:
        conn.execute(
            f"UPDATE self_check_runs SET {', '.join(assignments)} WHERE token = ?",
            params,
        )
        conn.commit()
    finally:
        conn.close()


def get_self_check_run(token: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM self_check_runs WHERE token = ? LIMIT 1",
            (token,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
