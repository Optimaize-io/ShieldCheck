import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _utc_now_iso() -> str:
    # Store ISO timestamps in UTC for stable ordering across DST/timezones.
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def default_db_path() -> Path:
    # Keep the DB inside the project so it persists across restarts.
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


def init_db(db_path: Optional[Path] = None) -> None:
    conn = connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS current_companies (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              owner_username TEXT NOT NULL,
              name TEXT NOT NULL,
              domain TEXT NOT NULL,
              sector TEXT NOT NULL,
              employees INTEGER NOT NULL,
              created_at TEXT NOT NULL
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_lists (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              owner_username TEXT NOT NULL,
              created_at TEXT NOT NULL,
              domain_count INTEGER NOT NULL
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
              owner_username TEXT NOT NULL,
              created_at TEXT NOT NULL,
              domain_count INTEGER NOT NULL,
              domain_list_id INTEGER NOT NULL,
              report_html_path TEXT NOT NULL,
              report_json_path TEXT,
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

        # Lightweight migration for existing single-user databases.
        for table in ("current_companies", "domain_lists", "scan_runs"):
            if not _column_exists(conn, table, "owner_username"):
                conn.execute(f"ALTER TABLE {table} ADD COLUMN owner_username TEXT")
                conn.execute(
                    f"UPDATE {table} SET owner_username = 'admin' WHERE owner_username IS NULL"
                )

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_created_at ON scan_runs(created_at DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_owner_created_at ON scan_runs(owner_username, created_at DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domain_lists_created_at ON domain_lists(created_at DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domain_lists_owner_created_at ON domain_lists(owner_username, created_at DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_current_companies_id ON current_companies(id ASC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_current_companies_owner_id ON current_companies(owner_username, id ASC);"
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


# ---------------------------------------------------------------------------
# Current companies (working set)
# ---------------------------------------------------------------------------


def list_current_companies(
    owner_username: str, db_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id, name, domain, sector, employees
            FROM current_companies
            WHERE owner_username = ?
            ORDER BY id ASC
            """,
            (owner_username,),
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
    owner_username: str,
    db_path: Optional[Path] = None,
) -> int:
    conn = connect(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO current_companies(owner_username, name, domain, sector, employees, created_at)
            VALUES(?,?,?,?,?,?)
            """,
            (owner_username, name, domain, sector, int(employees), _utc_now_iso()),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def delete_current_company(
    company_id: int, owner_username: str, db_path: Optional[Path] = None
) -> bool:
    conn = connect(db_path)
    try:
        cur = conn.execute(
            "DELETE FROM current_companies WHERE id = ? AND owner_username = ?",
            (company_id, owner_username),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def clear_current_companies(
    owner_username: str, db_path: Optional[Path] = None
) -> None:
    conn = connect(db_path)
    try:
        conn.execute(
            "DELETE FROM current_companies WHERE owner_username = ?",
            (owner_username,),
        )
        conn.commit()
    finally:
        conn.close()


def bulk_add_current_companies(
    companies: List[Dict[str, Any]],
    owner_username: str,
    db_path: Optional[Path] = None,
) -> int:
    if not companies:
        return 0
    conn = connect(db_path)
    try:
        now = _utc_now_iso()
        conn.executemany(
            """
            INSERT INTO current_companies(owner_username, name, domain, sector, employees, created_at)
            VALUES(?,?,?,?,?,?)
            """,
            [
                (
                    owner_username,
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


# ---------------------------------------------------------------------------
# Domain list snapshots
# ---------------------------------------------------------------------------


def create_domain_list_snapshot(
    companies: List[Dict[str, Any]],
    owner_username: str,
    db_path: Optional[Path] = None,
) -> int:
    conn = connect(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO domain_lists(owner_username, created_at, domain_count) VALUES(?,?,?)",
            (owner_username, _utc_now_iso(), len(companies)),
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


def list_domain_lists_page(
    *, owner_username: str, page: int, page_size: int, db_path: Optional[Path] = None
) -> Tuple[int, List[Dict[str, Any]]]:
    page = max(1, int(page))
    page_size = max(1, min(200, int(page_size)))
    offset = (page - 1) * page_size

    conn = connect(db_path)
    try:
        total = int(
            conn.execute(
                "SELECT COUNT(*) FROM domain_lists WHERE owner_username = ?",
                (owner_username,),
            ).fetchone()[0]
        )
        rows = conn.execute(
            """
            SELECT id, created_at, domain_count
            FROM domain_lists
            WHERE owner_username = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (owner_username, page_size, offset),
        ).fetchall()
        return total, [dict(r) for r in rows]
    finally:
        conn.close()


def get_domain_list_items(
    domain_list_id: int, owner_username: str, db_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT name, domain, sector, employees
            FROM domain_list_items dli
            JOIN domain_lists dl ON dl.id = dli.domain_list_id
            WHERE dli.domain_list_id = ? AND dl.owner_username = ?
            ORDER BY dli.id ASC
            """,
            (int(domain_list_id), owner_username),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Activate domain list snapshot as current working set
# ---------------------------------------------------------------------------


def use_domain_list_as_current(
    domain_list_id: int, owner_username: str, db_path: Optional[Path] = None
) -> int:
    """Replace current_companies with the items from a historical domain_list."""
    conn = connect(db_path)
    try:
        owner_row = conn.execute(
            "SELECT 1 FROM domain_lists WHERE id = ? AND owner_username = ?",
            (int(domain_list_id), owner_username),
        ).fetchone()
        if owner_row is None:
            raise ValueError("Domain list not found")

        rows = conn.execute(
            """
            SELECT name, domain, sector, employees
            FROM domain_list_items dli
            JOIN domain_lists dl ON dl.id = dli.domain_list_id
            WHERE dli.domain_list_id = ? AND dl.owner_username = ?
            ORDER BY dli.id ASC
            """,
            (int(domain_list_id), owner_username),
        ).fetchall()

        conn.execute(
            "DELETE FROM current_companies WHERE owner_username = ?",
            (owner_username,),
        )
        if rows:
            now = _utc_now_iso()
            conn.executemany(
                """
                INSERT INTO current_companies(owner_username, name, domain, sector, employees, created_at)
                VALUES(?,?,?,?,?,?)
                """,
                [
                    (
                        owner_username,
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


# ---------------------------------------------------------------------------
# Scan runs (HTML overview history)
# ---------------------------------------------------------------------------


def record_scan_run(
    *,
    domain_list_id: int,
    domain_count: int,
    report_html_path: str,
    owner_username: str,
    report_json_path: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> int:
    conn = connect(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO scan_runs(owner_username, created_at, domain_count, domain_list_id, report_html_path, report_json_path)
            VALUES(?,?,?,?,?,?)
            """,
            (
                owner_username,
                _utc_now_iso(),
                int(domain_count),
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
    *, owner_username: str, page: int, page_size: int, db_path: Optional[Path] = None
) -> Tuple[int, List[Dict[str, Any]]]:
    page = max(1, int(page))
    page_size = max(1, min(200, int(page_size)))
    offset = (page - 1) * page_size

    conn = connect(db_path)
    try:
        total = int(
            conn.execute(
                "SELECT COUNT(*) FROM scan_runs WHERE owner_username = ?",
                (owner_username,),
            ).fetchone()[0]
        )
        rows = conn.execute(
            """
            SELECT id, created_at, domain_count, report_html_path, domain_list_id
            FROM scan_runs
            WHERE owner_username = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (owner_username, page_size, offset),
        ).fetchall()
        return total, [dict(r) for r in rows]
    finally:
        conn.close()


def user_owns_output_path(
    owner_username: str, output_path: str, db_path: Optional[Path] = None
) -> bool:
    conn = connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT 1
            FROM scan_runs
            WHERE owner_username = ?
              AND (report_html_path = ? OR report_json_path = ?)
            LIMIT 1
            """,
            (owner_username, output_path, output_path),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Self-check runs
# ---------------------------------------------------------------------------


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
