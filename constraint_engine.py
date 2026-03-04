"""
Continuum Constraint Policy Engine
Flask server @ port 8001

Evaluates leave requests against 13+ configurable rules per company.
Each rule can be blocking (reject) or warning (escalate).
"""

import os
import json
import time
import logging
from datetime import datetime, date, timedelta
from typing import Any, Optional
from flask import Flask, request, jsonify
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("constraint-engine")

# ── Prometheus metrics (best-effort) ─────────────────────────────────────────

try:
    from prometheus_flask_exporter import PrometheusMetrics

    metrics = PrometheusMetrics(app)
    logger.info("Prometheus metrics enabled at /metrics")
except ImportError:
    logger.warning("prometheus-flask-exporter not installed – /metrics disabled")


# ── Database Connection ──────────────────────────────────────────────────────


def get_db_connection():
    """Get PostgreSQL connection using DATABASE_URL or DIRECT_URL."""
    # Use DIRECT_URL if available (recommended for direct connections)
    # DATABASE_URL may have pgbouncer params that psycopg2 doesn't support
    database_url = os.environ.get("DIRECT_URL", "") or os.environ.get("DATABASE_URL", "")
    if not database_url:
        return None
    
    # Strip pgbouncer and connection_limit params that psycopg2 doesn't understand
    if "?" in database_url:
        base_url, params = database_url.split("?", 1)
        param_list = params.split("&")
        filtered_params = [p for p in param_list if not p.startswith(("pgbouncer", "connection_limit"))]
        database_url = base_url + ("?" + "&".join(filtered_params) if filtered_params else "")
    
    try:
        conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        logger.error("Database connection failed: %s", e)
        return None


# ── Auth Middleware ───────────────────────────────────────────────────────────


def require_auth(f):
    """Validate request comes from an authorized source."""

    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key", "")
        cron_secret = os.environ.get("CRON_SECRET", "")

        # Allow internal calls with valid API key
        if api_key and cron_secret and api_key == cron_secret:
            return f(*args, **kwargs)

        # Allow localhost in development
        if request.remote_addr in ("127.0.0.1", "::1", "localhost"):
            return f(*args, **kwargs)

        # In production, check origin
        origin = request.headers.get("Origin", "")
        app_url = os.environ.get("NEXT_PUBLIC_APP_URL", "http://localhost:3000")
        if origin and origin.startswith(app_url):
            return f(*args, **kwargs)

        return jsonify({"error": "Unauthorized"}), 401

    return decorated


# ── Default Rule Configs ─────────────────────────────────────────────────────

DEFAULT_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "RULE001",
        "name": "Max Leave Duration",
        "description": "Maximum consecutive days allowed per leave type",
        "category": "validation",
        "is_blocking": True,
        "priority": 1,
        "config": {
            "max_days": {
                "CL": 3, "SL": 7, "PL": 15, "EL": 15, "AL": 20,
                "ML": 182, "PTL": 15, "BL": 5, "MRL": 5, "STL": 5,
                "WFH": 5, "OD": 10, "VOL": 3, "LWP": 30, "SAB": 180,
            },
        },
    },
    {
        "rule_id": "RULE002",
        "name": "Leave Balance Check",
        "description": "Cannot exceed available balance (unless negative balance enabled)",
        "category": "validation",
        "is_blocking": True,
        "priority": 2,
        "config": {"check_pending": True, "allow_negative": False},
    },
    {
        "rule_id": "RULE003",
        "name": "Min Team Coverage",
        "description": "Minimum percentage of team that must remain present",
        "category": "business",
        "is_blocking": True,
        "priority": 3,
        "config": {"min_coverage_percent": 60, "apply_to_department": True},
    },
    {
        "rule_id": "RULE004",
        "name": "Max Concurrent Leave",
        "description": "Maximum employees on leave simultaneously from same department",
        "category": "business",
        "is_blocking": True,
        "priority": 4,
        "config": {"max_concurrent": 2, "scope": "department"},
    },
    {
        "rule_id": "RULE005",
        "name": "Blackout Period",
        "description": "Company-wide blocked dates where leave is not allowed",
        "category": "business",
        "is_blocking": True,
        "priority": 5,
        "config": {"blackout_dates": [], "exempt_leave_types": ["SL", "BL", "ML"]},
    },
    {
        "rule_id": "RULE006",
        "name": "Advance Notice",
        "description": "Minimum notice days required before leave start date",
        "category": "validation",
        "is_blocking": False,
        "priority": 6,
        "config": {
            "notice_days": {
                "CL": 1, "SL": 0, "PL": 7, "EL": 7, "AL": 7,
                "ML": 30, "PTL": 7, "BL": 0, "MRL": 14, "STL": 7,
                "WFH": 1, "OD": 1, "VOL": 3, "LWP": 7, "SAB": 30,
            },
        },
    },
    {
        "rule_id": "RULE007",
        "name": "Consecutive Leave Limit",
        "description": "Maximum consecutive leave days per type in a rolling period",
        "category": "validation",
        "is_blocking": False,
        "priority": 7,
        "config": {
            "max_consecutive": {"CL": 3, "SL": 7, "default": 10},
            "rolling_period_days": 30,
        },
    },
    {
        "rule_id": "RULE008",
        "name": "Sandwich Rule",
        "description": "Weekends/holidays between two leave periods count as leave days",
        "category": "business",
        "is_blocking": True,
        "priority": 8,
        "config": {
            "enabled": True,
            "apply_to": ["CL", "PL", "EL", "AL"],
            "exempt": ["SL", "ML", "BL"],
        },
    },
    {
        "rule_id": "RULE009",
        "name": "Min Gap Between Leaves",
        "description": "Minimum days between two separate leave requests",
        "category": "business",
        "is_blocking": False,
        "priority": 9,
        "config": {"min_gap_days": 7, "apply_to_same_type": True},
    },
    {
        "rule_id": "RULE010",
        "name": "Probation Restriction",
        "description": "Restrict leave during probation period",
        "category": "compliance",
        "is_blocking": True,
        "priority": 10,
        "config": {
            "probation_months": 6,
            "allowed_during_probation": ["SL", "CL"],
            "max_during_probation": {"SL": 3, "CL": 3},
        },
    },
    {
        "rule_id": "RULE011",
        "name": "Critical Project Freeze",
        "description": "No leave allowed during critical project periods",
        "category": "business",
        "is_blocking": True,
        "priority": 11,
        "config": {"freeze_periods": [], "exempt_leave_types": ["SL", "BL", "ML"]},
    },
    {
        "rule_id": "RULE012",
        "name": "Document Requirement",
        "description": "Medical/supporting documents required for specific conditions",
        "category": "compliance",
        "is_blocking": False,
        "priority": 12,
        "config": {
            "require_document_after_days": 3,
            "require_for_types": ["SL", "ML"],
            "require_for_all_above_days": 5,
        },
    },
    {
        "rule_id": "RULE013",
        "name": "Monthly Quota",
        "description": "Maximum leave days allowed per month per type",
        "category": "validation",
        "is_blocking": True,
        "priority": 13,
        "config": {"monthly_max": {"CL": 3, "SL": 3, "default": 5}},
    },
]


def _get_rule_config(rule_id: str, company_rules: list[dict] | None = None, leave_request: dict | None = None) -> dict:
    """Return merged config for *rule_id* (company overrides + defaults).
    
    Company rules can be passed directly or extracted from leave_request["_company_rules"].
    """
    defaults = next((r for r in DEFAULT_RULES if r["rule_id"] == rule_id), {})
    
    # Try to get company_rules from leave_request if not passed directly
    if not company_rules and leave_request:
        company_rules = leave_request.get("_company_rules", [])
    
    if not company_rules:
        return defaults
    override = next((r for r in company_rules if r.get("rule_id") == rule_id), None)
    if not override:
        return defaults
    merged = {**defaults, **override}
    merged["config"] = {**defaults.get("config", {}), **override.get("config", {})}
    return merged


def _rule_result(
    rule_id: str,
    name: str,
    passed: bool,
    is_blocking: bool,
    category: str,
    message: str,
    details: dict | None = None,
) -> dict:
    """Standardised result dict returned by every rule evaluator."""
    return {
        "rule_id": rule_id,
        "name": name,
        "passed": passed,
        "is_blocking": is_blocking,
        "category": category,
        "message": message,
        "details": details or {},
    }


# ── Helpers ──────────────────────────────────────────────────────────────────


def _parse_date(value: Any) -> date | None:
    """Parse a date from string or date object."""
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ"):
            try:
                return datetime.strptime(value, fmt).date()
            except ValueError:
                continue
    return None


def _fetch_company_rules(conn, company_id: str) -> list[dict]:
    """Fetch active LeaveRule rows for a company."""
    if conn is None:
        return []
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT rule_id, rule_type, name, description, category,
                       is_blocking, is_active, priority, config,
                       departments, effective_from, effective_to
                FROM "LeaveRule"
                WHERE company_id = %s AND is_active = true
                ORDER BY priority
                """,
                (company_id,),
            )
            rows = cur.fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error("Failed to fetch company rules: %s", e)
        return []


def _fetch_leave_balance(conn, employee_id: str, leave_type: str) -> dict | None:
    """Fetch current-year balance for an employee/type."""
    if conn is None:
        return None
    try:
        current_year = date.today().year
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT annual_entitlement, carried_forward, used_days,
                       pending_days, encashed_days, remaining
                FROM "LeaveBalance"
                WHERE emp_id = %s AND leave_type = %s AND year = %s
                """,
                (employee_id, leave_type, current_year),
            )
            row = cur.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error("Failed to fetch leave balance: %s", e)
        return None


def _fetch_employee(conn, employee_id: str) -> dict | None:
    """Fetch employee record."""
    if conn is None:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, first_name, last_name, department,
                       designation, status, date_of_joining, probation_end_date,
                       manager_id, org_id as company_id, gender
                FROM "Employee"
                WHERE id = %s
                """,
                (employee_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error("Failed to fetch employee: %s", e)
        return None


def _fetch_department_leaves(
    conn, company_id: str, department: str, start_date: date, end_date: date,
    exclude_employee_id: str | None = None,
) -> list[dict]:
    """Fetch approved/pending leaves for a department in the given period."""
    if conn is None:
        return []
    try:
        with conn.cursor() as cur:
            query = """
                SELECT lr.emp_id, lr.start_date, lr.end_date, lr.total_days,
                       lr.status, lr.leave_type
                FROM "LeaveRequest" lr
                JOIN "Employee" e ON e.id = lr.emp_id
                WHERE e.company_id = %s
                  AND e.department = %s
                  AND lr.status IN ('approved', 'pending')
                  AND lr.start_date <= %s
                  AND lr.end_date >= %s
            """
            params: list[Any] = [company_id, department, end_date, start_date]
            if exclude_employee_id:
                query += " AND lr.emp_id != %s"
                params.append(exclude_employee_id)
            cur.execute(query, params)
            return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.error("Failed to fetch department leaves: %s", e)
        return []


def _fetch_department_size(conn, company_id: str, department: str) -> int:
    """Count active employees in a department."""
    if conn is None:
        return 0
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM "Employee"
                WHERE company_id = %s AND department = %s AND status = 'active'
                """,
                (company_id, department),
            )
            row = cur.fetchone()
            return int(row["cnt"]) if row else 0
    except Exception as e:
        logger.error("Failed to fetch department size: %s", e)
        return 0


def _fetch_employee_recent_leaves(
    conn, employee_id: str, leave_type: str | None, days_back: int,
) -> list[dict]:
    """Fetch recent approved/pending leaves for an employee."""
    if conn is None:
        return []
    try:
        cutoff = date.today() - timedelta(days=days_back)
        with conn.cursor() as cur:
            query = """
                SELECT start_date, end_date, total_days, leave_type, status
                FROM "LeaveRequest"
                WHERE emp_id = %s
                  AND status IN ('approved', 'pending')
                  AND end_date >= %s
            """
            params: list[Any] = [employee_id, cutoff]
            if leave_type:
                query += " AND leave_type = %s"
                params.append(leave_type)
            query += " ORDER BY start_date"
            cur.execute(query, params)
            return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.error("Failed to fetch recent leaves: %s", e)
        return []


def _fetch_company(conn, company_id: str) -> dict | None:
    """Fetch company record."""
    if conn is None:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, negative_balance, probation_period_days,
                       work_days, half_day_hours, leave_year_start
                FROM "Company"
                WHERE id = %s
                """,
                (company_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error("Failed to fetch company: %s", e)
        return None


def _fetch_monthly_used(conn, employee_id: str, leave_type: str, month: int, year: int) -> float:
    """Sum total_days for an employee/type in a given month."""
    if conn is None:
        return 0.0
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COALESCE(SUM(total_days), 0) AS total
                FROM "LeaveRequest"
                WHERE emp_id = %s
                  AND leave_type = %s
                  AND status IN ('approved', 'pending')
                  AND EXTRACT(MONTH FROM start_date) = %s
                  AND EXTRACT(YEAR FROM start_date) = %s
                """,
                (employee_id, leave_type, month, year),
            )
            row = cur.fetchone()
            return float(row["total"]) if row else 0.0
    except Exception as e:
        logger.error("Failed to fetch monthly usage: %s", e)
        return 0.0


# ── Rule Evaluators ──────────────────────────────────────────────────────────


def evaluate_rule_001(
    leave_request: dict, company_config: dict | None, conn=None
) -> dict:
    """RULE001 – Max Leave Duration."""
    t0 = time.monotonic()
    rule_id = "RULE001"
    rule = _get_rule_config(rule_id, leave_request=leave_request)
    name = rule["name"]
    is_blocking = rule["is_blocking"]
    category = rule["category"]

    try:
        total_days = float(leave_request.get("total_days", 0))
        leave_type = leave_request.get("leave_type", "")
        max_days_map: dict = rule["config"].get("max_days", {})
        max_days = max_days_map.get(leave_type, 30)

        if total_days > max_days:
            msg = (
                f"{leave_type} leave cannot exceed {max_days} consecutive days "
                f"(requested {total_days})"
            )
            result = _rule_result(rule_id, name, False, is_blocking, category, msg, {
                "max_days": max_days, "requested_days": total_days,
            })
        else:
            result = _rule_result(
                rule_id, name, True, is_blocking, category,
                f"Duration {total_days} day(s) within limit of {max_days}",
                {"max_days": max_days, "requested_days": total_days},
            )
    except Exception as e:
        logger.error("RULE001 error: %s", e)
        result = _rule_result(
            rule_id, name, False, is_blocking, category,
            f"Rule evaluation error: {e}",
        )

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    logger.info("RULE001 evaluated in %sms – passed=%s", elapsed, result["passed"])
    return result


def evaluate_rule_002(
    leave_request: dict, company_config: dict | None, conn=None
) -> dict:
    """RULE002 – Leave Balance Check."""
    t0 = time.monotonic()
    rule_id = "RULE002"
    rule = _get_rule_config(rule_id, leave_request=leave_request)
    name = rule["name"]
    is_blocking = rule["is_blocking"]
    category = rule["category"]

    try:
        total_days = float(leave_request.get("total_days", 0))
        leave_type = leave_request.get("leave_type", "")
        employee_id = leave_request.get("employee_id", "")

        # Check if negative balance allowed
        allow_negative = rule["config"].get("allow_negative", False)
        if company_config and company_config.get("negative_balance"):
            allow_negative = True

        # Try to fetch balance from DB
        balance = _fetch_leave_balance(conn, employee_id, leave_type)

        # Also accept pre-supplied balance in leave_request
        if balance is None:
            balance = leave_request.get("balance")

        if balance is None:
            # No balance data – pass with warning if we allow negative
            if allow_negative:
                result = _rule_result(
                    rule_id, name, True, is_blocking, category,
                    "Balance data unavailable; negative balance allowed",
                )
            else:
                result = _rule_result(
                    rule_id, name, False, is_blocking, category,
                    "Balance data unavailable; cannot verify entitlement",
                )
        else:
            entitlement = float(balance.get("annual_entitlement", 0))
            carried = float(balance.get("carried_forward", 0))
            used = float(balance.get("used_days", 0))
            pending = float(balance.get("pending_days", 0))
            encashed = float(balance.get("encashed_days", 0))
            remaining = entitlement + carried - used - pending - encashed

            if remaining < total_days and not allow_negative:
                msg = (
                    f"Insufficient {leave_type} balance: {remaining} remaining, "
                    f"{total_days} requested"
                )
                result = _rule_result(rule_id, name, False, is_blocking, category, msg, {
                    "remaining": remaining,
                    "requested": total_days,
                    "entitlement": entitlement,
                    "carried_forward": carried,
                    "used": used,
                    "pending": pending,
                    "encashed": encashed,
                })
            else:
                result = _rule_result(
                    rule_id, name, True, is_blocking, category,
                    f"Balance OK: {remaining} remaining after this request",
                    {"remaining": remaining, "requested": total_days},
                )
    except Exception as e:
        logger.error("RULE002 error: %s", e)
        result = _rule_result(
            rule_id, name, False, is_blocking, category,
            f"Rule evaluation error: {e}",
        )

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    logger.info("RULE002 evaluated in %sms – passed=%s", elapsed, result["passed"])
    return result


def evaluate_rule_003(
    leave_request: dict, company_config: dict | None, conn=None
) -> dict:
    """RULE003 – Min Team Coverage (60%)."""
    t0 = time.monotonic()
    rule_id = "RULE003"
    rule = _get_rule_config(rule_id, leave_request=leave_request)
    name = rule["name"]
    is_blocking = rule["is_blocking"]
    category = rule["category"]

    try:
        company_id = leave_request.get("company_id", "")
        employee_id = leave_request.get("employee_id", "")
        department = leave_request.get("department", "")
        start_date = _parse_date(leave_request.get("start_date"))
        end_date = _parse_date(leave_request.get("end_date"))

        min_pct = rule["config"].get("min_coverage_percent", 60)

        if not department or not start_date or not end_date:
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                "Insufficient data to check team coverage; skipping",
            )

        team_size = _fetch_department_size(conn, company_id, department)
        if team_size <= 1:
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                "Team size too small to enforce coverage rule",
                {"team_size": team_size},
            )

        overlapping = _fetch_department_leaves(
            conn, company_id, department, start_date, end_date, employee_id,
        )
        on_leave = len({r["emp_id"] for r in overlapping}) + 1  # +1 for current
        present = team_size - on_leave
        coverage = round((present / team_size) * 100, 1)

        if coverage < min_pct:
            msg = (
                f"Team coverage would drop to {coverage}% "
                f"(minimum {min_pct}% required)"
            )
            result = _rule_result(rule_id, name, False, is_blocking, category, msg, {
                "team_size": team_size, "on_leave": on_leave,
                "coverage_pct": coverage, "min_pct": min_pct,
            })
        else:
            result = _rule_result(
                rule_id, name, True, is_blocking, category,
                f"Team coverage {coverage}% meets minimum {min_pct}%",
                {"team_size": team_size, "on_leave": on_leave, "coverage_pct": coverage},
            )
    except Exception as e:
        logger.error("RULE003 error: %s", e)
        result = _rule_result(
            rule_id, name, False, is_blocking, category,
            f"Rule evaluation error: {e}",
        )

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    logger.info("RULE003 evaluated in %sms – passed=%s", elapsed, result["passed"])
    return result


def evaluate_rule_004(
    leave_request: dict, company_config: dict | None, conn=None
) -> dict:
    """RULE004 – Max Concurrent Leave."""
    t0 = time.monotonic()
    rule_id = "RULE004"
    rule = _get_rule_config(rule_id, leave_request=leave_request)
    name = rule["name"]
    is_blocking = rule["is_blocking"]
    category = rule["category"]

    try:
        company_id = leave_request.get("company_id", "")
        employee_id = leave_request.get("employee_id", "")
        department = leave_request.get("department", "")
        start_date = _parse_date(leave_request.get("start_date"))
        end_date = _parse_date(leave_request.get("end_date"))

        max_concurrent = rule["config"].get("max_concurrent", 2)

        if not department or not start_date or not end_date:
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                "Insufficient data to check concurrent leaves; skipping",
            )

        overlapping = _fetch_department_leaves(
            conn, company_id, department, start_date, end_date, employee_id,
        )
        concurrent = len({r["emp_id"] for r in overlapping}) + 1

        if concurrent > max_concurrent:
            msg = (
                f"{concurrent} employees would be on leave simultaneously "
                f"(max {max_concurrent})"
            )
            result = _rule_result(rule_id, name, False, is_blocking, category, msg, {
                "concurrent": concurrent, "max_concurrent": max_concurrent,
            })
        else:
            result = _rule_result(
                rule_id, name, True, is_blocking, category,
                f"Concurrent leaves ({concurrent}) within limit ({max_concurrent})",
                {"concurrent": concurrent, "max_concurrent": max_concurrent},
            )
    except Exception as e:
        logger.error("RULE004 error: %s", e)
        result = _rule_result(
            rule_id, name, False, is_blocking, category,
            f"Rule evaluation error: {e}",
        )

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    logger.info("RULE004 evaluated in %sms – passed=%s", elapsed, result["passed"])
    return result


def evaluate_rule_005(
    leave_request: dict, company_config: dict | None, conn=None
) -> dict:
    """RULE005 – Blackout Period."""
    t0 = time.monotonic()
    rule_id = "RULE005"
    rule = _get_rule_config(rule_id, leave_request=leave_request)
    name = rule["name"]
    is_blocking = rule["is_blocking"]
    category = rule["category"]

    try:
        leave_type = leave_request.get("leave_type", "")
        start_date = _parse_date(leave_request.get("start_date"))
        end_date = _parse_date(leave_request.get("end_date"))

        exempt = rule["config"].get("exempt_leave_types", [])
        if leave_type in exempt:
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                f"{leave_type} is exempt from blackout restrictions",
            )

        # Gather blackout periods from config + DB
        blackout_dates: list[dict] = list(rule["config"].get("blackout_dates", []))

        # Also check DB for blackout rules
        company_id = leave_request.get("company_id", "")
        if conn and company_id:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT config FROM "LeaveRule"
                        WHERE company_id = %s AND rule_type = 'blackout'
                          AND is_active = true
                        """,
                        (company_id,),
                    )
                    for row in cur.fetchall():
                        cfg = row.get("config") or {}
                        if isinstance(cfg, str):
                            cfg = json.loads(cfg)
                        periods = cfg.get("periods", cfg.get("blackout_dates", []))
                        blackout_dates.extend(periods)
            except Exception as e:
                logger.warning("RULE005 DB lookup: %s", e)

        if not blackout_dates or not start_date or not end_date:
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                "No blackout periods configured",
            )

        for bp in blackout_dates:
            bp_start = _parse_date(bp.get("start") or bp.get("start_date"))
            bp_end = _parse_date(bp.get("end") or bp.get("end_date"))
            if bp_start and bp_end:
                if start_date <= bp_end and end_date >= bp_start:
                    bp_name = bp.get("name", "blackout period")
                    msg = (
                        f"Dates overlap with {bp_name} "
                        f"({bp_start} to {bp_end})"
                    )
                    elapsed = round((time.monotonic() - t0) * 1000, 2)
                    logger.info("RULE005 evaluated in %sms – passed=False", elapsed)
                    return _rule_result(rule_id, name, False, is_blocking, category, msg, {
                        "blackout_name": bp_name,
                        "blackout_start": str(bp_start),
                        "blackout_end": str(bp_end),
                    })

        result = _rule_result(
            rule_id, name, True, is_blocking, category,
            "No blackout period conflict",
        )
    except Exception as e:
        logger.error("RULE005 error: %s", e)
        result = _rule_result(
            rule_id, name, False, is_blocking, category,
            f"Rule evaluation error: {e}",
        )

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    logger.info("RULE005 evaluated in %sms – passed=%s", elapsed, result["passed"])
    return result


def evaluate_rule_006(
    leave_request: dict, company_config: dict | None, conn=None
) -> dict:
    """RULE006 – Advance Notice (warning only)."""
    t0 = time.monotonic()
    rule_id = "RULE006"
    rule = _get_rule_config(rule_id, leave_request=leave_request)
    name = rule["name"]
    is_blocking = rule["is_blocking"]  # False
    category = rule["category"]

    try:
        leave_type = leave_request.get("leave_type", "")
        start_date = _parse_date(leave_request.get("start_date"))
        request_date = _parse_date(leave_request.get("request_date")) or date.today()

        notice_map: dict = rule["config"].get("notice_days", {})
        min_notice = notice_map.get(leave_type, 1)

        if not start_date:
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                "No start date provided; skipping notice check",
            )

        days_notice = (start_date - request_date).days

        if days_notice < min_notice:
            msg = (
                f"Only {days_notice} day(s) notice given; "
                f"{leave_type} requires {min_notice} day(s)"
            )
            result = _rule_result(rule_id, name, False, is_blocking, category, msg, {
                "days_notice": days_notice, "required": min_notice,
            })
        else:
            result = _rule_result(
                rule_id, name, True, is_blocking, category,
                f"Advance notice of {days_notice} day(s) meets requirement",
                {"days_notice": days_notice, "required": min_notice},
            )
    except Exception as e:
        logger.error("RULE006 error: %s", e)
        result = _rule_result(
            rule_id, name, False, is_blocking, category,
            f"Rule evaluation error: {e}",
        )

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    logger.info("RULE006 evaluated in %sms – passed=%s", elapsed, result["passed"])
    return result


def evaluate_rule_007(
    leave_request: dict, company_config: dict | None, conn=None
) -> dict:
    """RULE007 – Consecutive Leave Limit (across multiple requests)."""
    t0 = time.monotonic()
    rule_id = "RULE007"
    rule = _get_rule_config(rule_id, leave_request=leave_request)
    name = rule["name"]
    is_blocking = rule["is_blocking"]  # False (warning)
    category = rule["category"]

    try:
        employee_id = leave_request.get("employee_id", "")
        leave_type = leave_request.get("leave_type", "")
        total_days = float(leave_request.get("total_days", 0))
        start_date = _parse_date(leave_request.get("start_date"))
        end_date = _parse_date(leave_request.get("end_date"))

        max_consec_map: dict = rule["config"].get("max_consecutive", {})
        max_consec = max_consec_map.get(leave_type, max_consec_map.get("default", 10))
        rolling_days = rule["config"].get("rolling_period_days", 30)

        recent = _fetch_employee_recent_leaves(conn, employee_id, leave_type, rolling_days)

        # Sum recent + current
        recent_total = sum(float(r.get("total_days", 0)) for r in recent)
        combined = recent_total + total_days

        # Check if any recent leave is adjacent (consecutive)
        adjacent_days = total_days
        if start_date and recent:
            for r in recent:
                r_end = _parse_date(r.get("end_date"))
                r_start = _parse_date(r.get("start_date"))
                if r_end and r_start:
                    gap = (start_date - r_end).days
                    if 0 <= gap <= 2:  # adjacent or 1-day gap (weekend)
                        adjacent_days += float(r.get("total_days", 0))

        if adjacent_days > max_consec:
            msg = (
                f"Consecutive {leave_type} days ({adjacent_days}) would exceed "
                f"limit of {max_consec} in {rolling_days}-day window"
            )
            result = _rule_result(rule_id, name, False, is_blocking, category, msg, {
                "adjacent_days": adjacent_days, "max_consecutive": max_consec,
                "rolling_days": rolling_days,
            })
        else:
            result = _rule_result(
                rule_id, name, True, is_blocking, category,
                f"Consecutive {leave_type} days ({adjacent_days}) within limit ({max_consec})",
                {"adjacent_days": adjacent_days, "max_consecutive": max_consec},
            )
    except Exception as e:
        logger.error("RULE007 error: %s", e)
        result = _rule_result(
            rule_id, name, False, is_blocking, category,
            f"Rule evaluation error: {e}",
        )

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    logger.info("RULE007 evaluated in %sms – passed=%s", elapsed, result["passed"])
    return result


def evaluate_rule_008(
    leave_request: dict, company_config: dict | None, conn=None
) -> dict:
    """RULE008 – Sandwich Rule."""
    t0 = time.monotonic()
    rule_id = "RULE008"
    rule = _get_rule_config(rule_id, leave_request=leave_request)
    name = rule["name"]
    is_blocking = rule["is_blocking"]
    category = rule["category"]

    try:
        leave_type = leave_request.get("leave_type", "")
        employee_id = leave_request.get("employee_id", "")
        start_date = _parse_date(leave_request.get("start_date"))
        end_date = _parse_date(leave_request.get("end_date"))

        if not rule["config"].get("enabled", True):
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                "Sandwich rule is disabled",
            )

        exempt = rule["config"].get("exempt", [])
        if leave_type in exempt:
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                f"{leave_type} is exempt from sandwich rule",
            )

        apply_to = rule["config"].get("apply_to", [])
        if apply_to and leave_type not in apply_to:
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                f"Sandwich rule does not apply to {leave_type}",
            )

        if not start_date or not end_date:
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                "Dates not available for sandwich check",
            )

        # Check if leave is on a Friday (weekday 4) and there's a leave on
        # the following Monday, or vice-versa.
        sandwich_detected = False
        sandwich_details: dict[str, Any] = {}

        # Scenario: leave ends on Friday → check for Monday leave
        if end_date.weekday() == 4:  # Friday
            next_monday = end_date + timedelta(days=3)
            recent = _fetch_employee_recent_leaves(conn, employee_id, None, 10)
            for r in recent:
                r_start = _parse_date(r.get("start_date"))
                if r_start and r_start == next_monday:
                    sandwich_detected = True
                    sandwich_details = {
                        "leave_end": str(end_date),
                        "weekend": f"{end_date + timedelta(days=1)} – {end_date + timedelta(days=2)}",
                        "next_leave_start": str(next_monday),
                    }
                    break

        # Scenario: leave starts on Monday → check for preceding Friday leave
        if not sandwich_detected and start_date.weekday() == 0:  # Monday
            prev_friday = start_date - timedelta(days=3)
            recent = _fetch_employee_recent_leaves(conn, employee_id, None, 10)
            for r in recent:
                r_end = _parse_date(r.get("end_date"))
                if r_end and r_end == prev_friday:
                    sandwich_detected = True
                    sandwich_details = {
                        "prev_leave_end": str(prev_friday),
                        "weekend": f"{start_date - timedelta(days=2)} – {start_date - timedelta(days=1)}",
                        "leave_start": str(start_date),
                    }
                    break

        if sandwich_detected:
            msg = "Weekend sandwiched between leave periods counts as leave"
            result = _rule_result(
                rule_id, name, False, is_blocking, category, msg, sandwich_details,
            )
        else:
            result = _rule_result(
                rule_id, name, True, is_blocking, category,
                "No sandwich pattern detected",
            )
    except Exception as e:
        logger.error("RULE008 error: %s", e)
        result = _rule_result(
            rule_id, name, False, is_blocking, category,
            f"Rule evaluation error: {e}",
        )

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    logger.info("RULE008 evaluated in %sms – passed=%s", elapsed, result["passed"])
    return result


def evaluate_rule_009(
    leave_request: dict, company_config: dict | None, conn=None
) -> dict:
    """RULE009 – Min Gap Between Leaves (warning only)."""
    t0 = time.monotonic()
    rule_id = "RULE009"
    rule = _get_rule_config(rule_id, leave_request=leave_request)
    name = rule["name"]
    is_blocking = rule["is_blocking"]  # False
    category = rule["category"]

    try:
        employee_id = leave_request.get("employee_id", "")
        leave_type = leave_request.get("leave_type", "")
        start_date = _parse_date(leave_request.get("start_date"))
        end_date = _parse_date(leave_request.get("end_date"))

        min_gap = rule["config"].get("min_gap_days", 7)
        same_type_only = rule["config"].get("apply_to_same_type", True)

        if not start_date or not end_date:
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                "Dates unavailable; skipping gap check",
            )

        lt_filter = leave_type if same_type_only else None
        recent = _fetch_employee_recent_leaves(conn, employee_id, lt_filter, 60)

        gap_violation = False
        closest_gap = None
        for r in recent:
            r_end = _parse_date(r.get("end_date"))
            r_start = _parse_date(r.get("start_date"))
            if r_end and r_start:
                gap_before = (start_date - r_end).days
                gap_after = (r_start - end_date).days
                gap = min(
                    gap_before if gap_before > 0 else 9999,
                    gap_after if gap_after > 0 else 9999,
                )
                if 0 < gap < min_gap:
                    gap_violation = True
                    closest_gap = gap
                    break

        if gap_violation:
            msg = (
                f"Only {closest_gap} day(s) gap between leaves; "
                f"minimum {min_gap} day(s) recommended"
            )
            result = _rule_result(rule_id, name, False, is_blocking, category, msg, {
                "gap_days": closest_gap, "min_gap": min_gap,
            })
        else:
            result = _rule_result(
                rule_id, name, True, is_blocking, category,
                f"Minimum gap of {min_gap} day(s) satisfied",
            )
    except Exception as e:
        logger.error("RULE009 error: %s", e)
        result = _rule_result(
            rule_id, name, False, is_blocking, category,
            f"Rule evaluation error: {e}",
        )

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    logger.info("RULE009 evaluated in %sms – passed=%s", elapsed, result["passed"])
    return result


def evaluate_rule_010(
    leave_request: dict, company_config: dict | None, conn=None
) -> dict:
    """RULE010 – Probation Restriction."""
    t0 = time.monotonic()
    rule_id = "RULE010"
    rule = _get_rule_config(rule_id, leave_request=leave_request)
    name = rule["name"]
    is_blocking = rule["is_blocking"]
    category = rule["category"]

    try:
        employee_id = leave_request.get("employee_id", "")
        leave_type = leave_request.get("leave_type", "")

        allowed = rule["config"].get("allowed_during_probation", ["SL", "CL"])
        probation_months = rule["config"].get("probation_months", 6)

        # Determine probation status
        employee = _fetch_employee(conn, employee_id)
        if employee is None:
            employee = leave_request.get("employee", {})

        status = (employee.get("status") or "").lower() if employee else ""
        joined = _parse_date(employee.get("date_of_joining")) if employee else None
        probation_end = _parse_date(employee.get("probation_end_date")) if employee else None

        is_probation = False
        if status == "probation" or status == "onboarding":
            is_probation = True
        elif probation_end and date.today() < probation_end:
            is_probation = True
        elif joined:
            cutoff = joined + timedelta(days=probation_months * 30)
            if date.today() < cutoff:
                is_probation = True

        if not is_probation:
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                "Employee is not in probation",
            )

        if leave_type not in allowed:
            msg = (
                f"{leave_type} is not allowed during probation. "
                f"Permitted types: {', '.join(allowed)}"
            )
            result = _rule_result(rule_id, name, False, is_blocking, category, msg, {
                "allowed_types": allowed, "requested": leave_type,
            })
        else:
            result = _rule_result(
                rule_id, name, True, is_blocking, category,
                f"{leave_type} is permitted during probation",
            )
    except Exception as e:
        logger.error("RULE010 error: %s", e)
        result = _rule_result(
            rule_id, name, False, is_blocking, category,
            f"Rule evaluation error: {e}",
        )

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    logger.info("RULE010 evaluated in %sms – passed=%s", elapsed, result["passed"])
    return result


def evaluate_rule_011(
    leave_request: dict, company_config: dict | None, conn=None
) -> dict:
    """RULE011 – Critical Project Freeze."""
    t0 = time.monotonic()
    rule_id = "RULE011"
    rule = _get_rule_config(rule_id, leave_request=leave_request)
    name = rule["name"]
    is_blocking = rule["is_blocking"]
    category = rule["category"]

    try:
        leave_type = leave_request.get("leave_type", "")
        start_date = _parse_date(leave_request.get("start_date"))
        end_date = _parse_date(leave_request.get("end_date"))
        company_id = leave_request.get("company_id", "")

        exempt = rule["config"].get("exempt_leave_types", [])
        if leave_type in exempt:
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                f"{leave_type} is exempt from project freeze",
            )

        freeze_periods: list[dict] = list(rule["config"].get("freeze_periods", []))

        # Fetch from DB
        if conn and company_id:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT config FROM "LeaveRule"
                        WHERE company_id = %s AND rule_type = 'project_freeze'
                          AND is_active = true
                        """,
                        (company_id,),
                    )
                    for row in cur.fetchall():
                        cfg = row.get("config") or {}
                        if isinstance(cfg, str):
                            cfg = json.loads(cfg)
                        periods = cfg.get("periods", cfg.get("freeze_periods", []))
                        freeze_periods.extend(periods)
            except Exception as e:
                logger.warning("RULE011 DB lookup: %s", e)

        if not freeze_periods or not start_date or not end_date:
            return _rule_result(
                rule_id, name, True, is_blocking, category,
                "No project freeze periods configured",
            )

        for fp in freeze_periods:
            fp_start = _parse_date(fp.get("start") or fp.get("start_date"))
            fp_end = _parse_date(fp.get("end") or fp.get("end_date"))
            if fp_start and fp_end:
                if start_date <= fp_end and end_date >= fp_start:
                    fp_name = fp.get("name", "project freeze")
                    msg = (
                        f"Dates overlap with {fp_name} "
                        f"({fp_start} to {fp_end})"
                    )
                    elapsed = round((time.monotonic() - t0) * 1000, 2)
                    logger.info("RULE011 evaluated in %sms – passed=False", elapsed)
                    return _rule_result(rule_id, name, False, is_blocking, category, msg, {
                        "freeze_name": fp_name,
                        "freeze_start": str(fp_start),
                        "freeze_end": str(fp_end),
                    })

        result = _rule_result(
            rule_id, name, True, is_blocking, category,
            "No project freeze conflict",
        )
    except Exception as e:
        logger.error("RULE011 error: %s", e)
        result = _rule_result(
            rule_id, name, False, is_blocking, category,
            f"Rule evaluation error: {e}",
        )

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    logger.info("RULE011 evaluated in %sms – passed=%s", elapsed, result["passed"])
    return result


def evaluate_rule_012(
    leave_request: dict, company_config: dict | None, conn=None
) -> dict:
    """RULE012 – Document Requirement (warning only)."""
    t0 = time.monotonic()
    rule_id = "RULE012"
    rule = _get_rule_config(rule_id, leave_request=leave_request)
    name = rule["name"]
    is_blocking = rule["is_blocking"]  # False
    category = rule["category"]

    try:
        leave_type = leave_request.get("leave_type", "")
        total_days = float(leave_request.get("total_days", 0))
        has_attachment = bool(leave_request.get("attachment_url"))

        require_after = rule["config"].get("require_document_after_days", 3)
        require_types = rule["config"].get("require_for_types", [])
        require_all_above = rule["config"].get("require_for_all_above_days", 5)

        needs_doc = False
        reason = ""

        if leave_type in require_types and total_days > require_after:
            needs_doc = True
            reason = (
                f"{leave_type} > {require_after} days requires supporting document"
            )
        elif total_days > require_all_above:
            needs_doc = True
            reason = (
                f"Any leave > {require_all_above} days requires supporting document"
            )

        if needs_doc and not has_attachment:
            result = _rule_result(
                rule_id, name, False, is_blocking, category, reason, {
                    "document_required": True,
                    "has_attachment": False,
                    "days": total_days,
                },
            )
        else:
            result = _rule_result(
                rule_id, name, True, is_blocking, category,
                "Document requirement satisfied" if needs_doc else "No document required",
                {"document_required": needs_doc, "has_attachment": has_attachment},
            )
    except Exception as e:
        logger.error("RULE012 error: %s", e)
        result = _rule_result(
            rule_id, name, False, is_blocking, category,
            f"Rule evaluation error: {e}",
        )

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    logger.info("RULE012 evaluated in %sms – passed=%s", elapsed, result["passed"])
    return result


def evaluate_rule_013(
    leave_request: dict, company_config: dict | None, conn=None
) -> dict:
    """RULE013 – Monthly Quota."""
    t0 = time.monotonic()
    rule_id = "RULE013"
    rule = _get_rule_config(rule_id, leave_request=leave_request)
    name = rule["name"]
    is_blocking = rule["is_blocking"]
    category = rule["category"]

    try:
        employee_id = leave_request.get("employee_id", "")
        leave_type = leave_request.get("leave_type", "")
        total_days = float(leave_request.get("total_days", 0))
        start_date = _parse_date(leave_request.get("start_date"))

        monthly_max_map: dict = rule["config"].get("monthly_max", {})
        monthly_max = monthly_max_map.get(
            leave_type, monthly_max_map.get("default", 5)
        )

        month = start_date.month if start_date else date.today().month
        year = start_date.year if start_date else date.today().year

        used_this_month = _fetch_monthly_used(conn, employee_id, leave_type, month, year)
        projected = used_this_month + total_days

        if projected > monthly_max:
            msg = (
                f"Monthly {leave_type} usage would be {projected} days "
                f"(limit {monthly_max})"
            )
            result = _rule_result(rule_id, name, False, is_blocking, category, msg, {
                "used_this_month": used_this_month,
                "requested": total_days,
                "projected": projected,
                "monthly_max": monthly_max,
            })
        else:
            result = _rule_result(
                rule_id, name, True, is_blocking, category,
                f"Monthly usage ({projected}) within limit ({monthly_max})",
                {"used_this_month": used_this_month, "projected": projected,
                 "monthly_max": monthly_max},
            )
    except Exception as e:
        logger.error("RULE013 error: %s", e)
        result = _rule_result(
            rule_id, name, False, is_blocking, category,
            f"Rule evaluation error: {e}",
        )

    elapsed = round((time.monotonic() - t0) * 1000, 2)
    logger.info("RULE013 evaluated in %sms – passed=%s", elapsed, result["passed"])
    return result


# ── Evaluation Orchestrator ──────────────────────────────────────────────────

ALL_EVALUATORS = [
    evaluate_rule_001,
    evaluate_rule_002,
    evaluate_rule_003,
    evaluate_rule_004,
    evaluate_rule_005,
    evaluate_rule_006,
    evaluate_rule_007,
    evaluate_rule_008,
    evaluate_rule_009,
    evaluate_rule_010,
    evaluate_rule_011,
    evaluate_rule_012,
    evaluate_rule_013,
]


def calculate_confidence_score(
    violations: list[dict], warnings: list[dict]
) -> float:
    """Compute confidence score from violations and warnings.

    Starts at 1.0.
    Each blocking violation:  -0.5
    Each warning:             -0.1
    Clamped to [0.0, 1.0].
    """
    score = 1.0
    score -= len(violations) * 0.5
    score -= len(warnings) * 0.1
    return max(0.0, min(1.0, round(score, 2)))


def derive_recommendation(score: float) -> str:
    """Map confidence score to a recommendation."""
    if score >= 0.7:
        return "APPROVE"
    if score >= 0.4:
        return "REVIEW"
    return "REJECT"


def evaluate_all(leave_request: dict, conn=None) -> dict:
    """Run every rule and aggregate results.

    Returns the full evaluation payload.
    """
    t0 = time.monotonic()

    company_id = leave_request.get("company_id", "")
    company_config: dict | None = None
    company_rules: list[dict] = []

    if conn and company_id:
        company_config = _fetch_company(conn, company_id)
        company_rules = _fetch_company_rules(conn, company_id)
    
    # Inject company_rules into leave_request so evaluators can access them
    leave_request["_company_rules"] = company_rules
    logger.info("Loaded %d company-specific rules for company %s", len(company_rules), company_id)

    violations: list[dict] = []
    warnings: list[dict] = []
    rule_results: dict[str, dict] = {}

    for evaluator in ALL_EVALUATORS:
        try:
            result = evaluator(leave_request, company_config, conn)
        except Exception as e:
            # Fail closed – treat unexpected errors as blocking violations
            suffix = evaluator.__name__.split("_")[-1]  # e.g. "001"
            rule_id = f"RULE{suffix}"
            result = _rule_result(
                rule_id, "Unknown", False, True, "validation",
                f"Unexpected error: {e}",
            )

        rule_results[result["rule_id"]] = result

        if not result["passed"]:
            if result["is_blocking"]:
                violations.append(result)
            else:
                warnings.append(result)

    confidence = calculate_confidence_score(violations, warnings)
    recommendation = derive_recommendation(confidence)
    elapsed_ms = round((time.monotonic() - t0) * 1000, 2)

    logger.info(
        "Evaluation complete in %sms – violations=%d warnings=%d score=%.2f rec=%s",
        elapsed_ms, len(violations), len(warnings), confidence, recommendation,
    )

    return {
        "passed": len(violations) == 0,
        "violations": violations,
        "warnings": warnings,
        "rule_results": rule_results,
        "confidence_score": confidence,
        "recommendation": recommendation,
        "evaluation_time_ms": elapsed_ms,
    }


# ── API Routes ───────────────────────────────────────────────────────────────


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    db_ok = False
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
            db_ok = True
        except Exception:
            db_ok = False
        finally:
            conn.close()
    return jsonify({
        "status": "healthy",
        "service": "constraint-engine",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "db_connected": db_ok,
    })


@app.route("/api/evaluate", methods=["POST"])
@require_auth
def api_evaluate():
    """Evaluate a leave request against all constraint rules."""
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body required"}), 400

    required = ["company_id", "employee_id", "leave_type", "start_date", "end_date", "total_days"]
    missing = [k for k in required if k not in body]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    conn = get_db_connection()
    try:
        result = evaluate_all(body, conn)
        return jsonify(result)
    except Exception as e:
        logger.error("Evaluation failed: %s", e)
        # Fail closed
        return jsonify({
            "passed": False,
            "violations": [{"rule_id": "ENGINE", "message": str(e)}],
            "warnings": [],
            "rule_results": {},
            "confidence_score": 0.0,
            "recommendation": "REJECT",
        }), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/rules", methods=["GET"])
@require_auth
def api_rules():
    """List all available rule definitions."""
    rules = []
    for r in DEFAULT_RULES:
        rules.append({
            "rule_id": r["rule_id"],
            "name": r["name"],
            "description": r["description"],
            "category": r["category"],
            "is_blocking": r["is_blocking"],
            "priority": r["priority"],
            "config": r["config"],
        })
    return jsonify({"rules": rules, "total": len(rules)})


@app.route("/api/validate-rules", methods=["POST"])
@require_auth
def api_validate_rules():
    """Validate a set of rules without full evaluation."""
    body = request.get_json(silent=True)
    if not body or "rules" not in body:
        return jsonify({"error": "Request body must contain 'rules' array"}), 400

    errors: list[str] = []
    valid_ids = {r["rule_id"] for r in DEFAULT_RULES}

    for idx, rule in enumerate(body["rules"]):
        if not isinstance(rule, dict):
            errors.append(f"Rule at index {idx} must be an object")
            continue
        rid = rule.get("rule_id", "")
        if not rid:
            errors.append(f"Rule at index {idx} missing 'rule_id'")
        elif rid not in valid_ids:
            errors.append(f"Unknown rule_id '{rid}' at index {idx}")
        if "is_blocking" in rule and not isinstance(rule["is_blocking"], bool):
            errors.append(f"'is_blocking' must be boolean at index {idx}")
        if "config" in rule and not isinstance(rule["config"], dict):
            errors.append(f"'config' must be an object at index {idx}")

    return jsonify({"valid": len(errors) == 0, "errors": errors})


# ── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("CONSTRAINT_ENGINE_PORT", 8001))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info("Starting Constraint Engine on port %s (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)
