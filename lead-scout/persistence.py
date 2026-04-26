import sqlite3
from dataclasses import dataclass
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


def init_db(db_path: Optional[Path] = None) -> None:
    conn = connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS current_companies (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_created_at ON scan_runs(created_at DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domain_lists_created_at ON domain_lists(created_at DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_current_companies_id ON current_companies(id ASC);"
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Current companies (working set)
# ---------------------------------------------------------------------------


def list_current_companies(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, name, domain, sector, employees FROM current_companies ORDER BY id ASC"
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
    db_path: Optional[Path] = None,
) -> int:
    conn = connect(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO current_companies(name, domain, sector, employees, created_at)
            VALUES(?,?,?,?,?)
            """,
            (name, domain, sector, int(employees), _utc_now_iso()),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def delete_current_company(company_id: int, db_path: Optional[Path] = None) -> bool:
    conn = connect(db_path)
    try:
        cur = conn.execute("DELETE FROM current_companies WHERE id = ?", (company_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def clear_current_companies(db_path: Optional[Path] = None) -> None:
    conn = connect(db_path)
    try:
        conn.execute("DELETE FROM current_companies")
        conn.commit()
    finally:
        conn.close()


def bulk_add_current_companies(
    companies: List[Dict[str, Any]], db_path: Optional[Path] = None
) -> int:
    if not companies:
        return 0
    conn = connect(db_path)
    try:
        now = _utc_now_iso()
        conn.executemany(
            """
            INSERT INTO current_companies(name, domain, sector, employees, created_at)
            VALUES(?,?,?,?,?)
            """,
            [
                (
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
    companies: List[Dict[str, Any]], db_path: Optional[Path] = None
) -> int:
    conn = connect(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO domain_lists(created_at, domain_count) VALUES(?,?)",
            (_utc_now_iso(), len(companies)),
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
    *, page: int, page_size: int, db_path: Optional[Path] = None
) -> Tuple[int, List[Dict[str, Any]]]:
    page = max(1, int(page))
    page_size = max(1, min(200, int(page_size)))
    offset = (page - 1) * page_size

    conn = connect(db_path)
    try:
        total = int(conn.execute("SELECT COUNT(*) FROM domain_lists").fetchone()[0])
        rows = conn.execute(
            """
            SELECT id, created_at, domain_count
            FROM domain_lists
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (page_size, offset),
        ).fetchall()
        return total, [dict(r) for r in rows]
    finally:
        conn.close()


def get_domain_list_items(
    domain_list_id: int, db_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT name, domain, sector, employees
            FROM domain_list_items
            WHERE domain_list_id = ?
            ORDER BY id ASC
            """,
            (int(domain_list_id),),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Activate domain list snapshot as current working set
# ---------------------------------------------------------------------------


def use_domain_list_as_current(
    domain_list_id: int, db_path: Optional[Path] = None
) -> int:
    """Replace current_companies with the items from a historical domain_list."""
    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT name, domain, sector, employees
            FROM domain_list_items
            WHERE domain_list_id = ?
            ORDER BY id ASC
            """,
            (int(domain_list_id),),
        ).fetchall()

        conn.execute("DELETE FROM current_companies")
        if rows:
            now = _utc_now_iso()
            conn.executemany(
                """
                INSERT INTO current_companies(name, domain, sector, employees, created_at)
                VALUES(?,?,?,?,?)
                """,
                [(r["name"], r["domain"], r["sector"], int(r["employees"]), now) for r in rows],
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
    report_json_path: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> int:
    conn = connect(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO scan_runs(created_at, domain_count, domain_list_id, report_html_path, report_json_path)
            VALUES(?,?,?,?,?)
            """,
            (
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
    *, page: int, page_size: int, db_path: Optional[Path] = None
) -> Tuple[int, List[Dict[str, Any]]]:
    page = max(1, int(page))
    page_size = max(1, min(200, int(page_size)))
    offset = (page - 1) * page_size

    conn = connect(db_path)
    try:
        total = int(conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0])
        rows = conn.execute(
            """
            SELECT id, created_at, domain_count, report_html_path, domain_list_id
            FROM scan_runs
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (page_size, offset),
        ).fetchall()
        return total, [dict(r) for r in rows]
    finally:
        conn.close()
