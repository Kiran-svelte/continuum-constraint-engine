"""Tests for constraint engine rules.

All tests use mock data and do not require a database connection.
"""

import pytest
from datetime import date, timedelta
from constraint_engine import (
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
    calculate_confidence_score,
    derive_recommendation,
    evaluate_all,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _base_request(**overrides) -> dict:
    """Return a minimal leave request dict with sensible defaults."""
    req = {
        "company_id": "comp-1",
        "employee_id": "emp-1",
        "leave_type": "CL",
        "start_date": str(date.today() + timedelta(days=10)),
        "end_date": str(date.today() + timedelta(days=11)),
        "total_days": 2,
        "is_half_day": False,
    }
    req.update(overrides)
    return req


# ── RULE001: Max Leave Duration ──────────────────────────────────────────────

class TestRule001MaxDuration:
    def test_within_limit(self):
        req = _base_request(leave_type="CL", total_days=2)
        result = evaluate_rule_001(req, None)
        assert result["passed"] is True
        assert result["rule_id"] == "RULE001"

    def test_exceeds_limit(self):
        req = _base_request(leave_type="CL", total_days=5)
        result = evaluate_rule_001(req, None)
        assert result["passed"] is False
        assert result["is_blocking"] is True
        assert "3" in result["message"]

    def test_exact_limit(self):
        req = _base_request(leave_type="CL", total_days=3)
        result = evaluate_rule_001(req, None)
        assert result["passed"] is True

    def test_long_leave_type(self):
        req = _base_request(leave_type="ML", total_days=180)
        result = evaluate_rule_001(req, None)
        assert result["passed"] is True

    def test_unknown_type_uses_default(self):
        req = _base_request(leave_type="ZZZZ", total_days=25)
        result = evaluate_rule_001(req, None)
        assert result["passed"] is True  # default max is 30


# ── RULE002: Leave Balance Check ─────────────────────────────────────────────

class TestRule002Balance:
    def test_sufficient_balance(self):
        req = _base_request(
            total_days=2,
            balance={
                "annual_entitlement": 12,
                "carried_forward": 0,
                "used_days": 3,
                "pending_days": 0,
                "encashed_days": 0,
            },
        )
        result = evaluate_rule_002(req, None)
        assert result["passed"] is True

    def test_insufficient_balance(self):
        req = _base_request(
            total_days=10,
            balance={
                "annual_entitlement": 12,
                "carried_forward": 0,
                "used_days": 10,
                "pending_days": 0,
                "encashed_days": 0,
            },
        )
        result = evaluate_rule_002(req, None)
        assert result["passed"] is False
        assert result["is_blocking"] is True

    def test_negative_balance_allowed(self):
        req = _base_request(
            total_days=10,
            balance={
                "annual_entitlement": 5,
                "carried_forward": 0,
                "used_days": 5,
                "pending_days": 0,
                "encashed_days": 0,
            },
        )
        company = {"negative_balance": True}
        result = evaluate_rule_002(req, company)
        assert result["passed"] is True

    def test_no_balance_data_reject(self):
        req = _base_request(total_days=2)
        result = evaluate_rule_002(req, None)
        assert result["passed"] is False


# ── RULE003: Min Team Coverage ───────────────────────────────────────────────

class TestRule003TeamCoverage:
    def test_passes_without_department(self):
        req = _base_request()
        result = evaluate_rule_003(req, None)
        assert result["passed"] is True
        assert "Insufficient data" in result["message"]

    def test_passes_with_department_no_db(self):
        req = _base_request(department="Engineering")
        result = evaluate_rule_003(req, None)
        # No DB → team_size=0 → skip
        assert result["passed"] is True


# ── RULE004: Max Concurrent Leave ────────────────────────────────────────────

class TestRule004MaxConcurrent:
    def test_passes_without_department(self):
        req = _base_request()
        result = evaluate_rule_004(req, None)
        assert result["passed"] is True

    def test_passes_with_department_no_db(self):
        req = _base_request(department="Engineering")
        result = evaluate_rule_004(req, None)
        # concurrent=1 (only self) ≤ max 2
        assert result["passed"] is True


# ── RULE005: Blackout Period ─────────────────────────────────────────────────

class TestRule005Blackout:
    def test_no_blackout_configured(self):
        req = _base_request()
        result = evaluate_rule_005(req, None)
        assert result["passed"] is True

    def test_exempt_leave_type(self):
        req = _base_request(leave_type="SL")
        result = evaluate_rule_005(req, None)
        assert result["passed"] is True
        assert "exempt" in result["message"]

    def test_blackout_overlap(self, monkeypatch):
        """Inject blackout dates via monkeypatch to avoid mutating global state."""
        from constraint_engine import DEFAULT_RULES
        import copy

        start = date.today() + timedelta(days=10)
        end = date.today() + timedelta(days=11)
        patched_rules = copy.deepcopy(DEFAULT_RULES)
        rule = next(r for r in patched_rules if r["rule_id"] == "RULE005")
        rule["config"]["blackout_dates"] = [
            {"name": "Year End Freeze", "start": str(start), "end": str(end)},
        ]
        monkeypatch.setattr("constraint_engine.DEFAULT_RULES", patched_rules)

        req = _base_request(
            leave_type="CL",
            start_date=str(start),
            end_date=str(end),
        )
        result = evaluate_rule_005(req, None)
        assert result["passed"] is False
        assert "Year End Freeze" in result["message"]


# ── RULE006: Advance Notice ──────────────────────────────────────────────────

class TestRule006AdvanceNotice:
    def test_sufficient_notice(self):
        req = _base_request(
            leave_type="CL",
            start_date=str(date.today() + timedelta(days=10)),
            request_date=str(date.today()),
        )
        result = evaluate_rule_006(req, None)
        assert result["passed"] is True

    def test_insufficient_notice(self):
        req = _base_request(
            leave_type="PL",
            start_date=str(date.today() + timedelta(days=2)),
            request_date=str(date.today()),
        )
        result = evaluate_rule_006(req, None)
        assert result["passed"] is False
        assert result["is_blocking"] is False  # warning only

    def test_sick_leave_no_notice(self):
        req = _base_request(
            leave_type="SL",
            start_date=str(date.today()),
            request_date=str(date.today()),
        )
        result = evaluate_rule_006(req, None)
        assert result["passed"] is True


# ── RULE007: Consecutive Leave Limit ─────────────────────────────────────────

class TestRule007ConsecutiveLimit:
    def test_within_limit(self):
        req = _base_request(leave_type="CL", total_days=2)
        result = evaluate_rule_007(req, None)
        assert result["passed"] is True

    def test_exceeds_limit(self):
        req = _base_request(leave_type="CL", total_days=4)
        result = evaluate_rule_007(req, None)
        assert result["passed"] is False
        assert result["is_blocking"] is False  # warning


# ── RULE008: Sandwich Rule ───────────────────────────────────────────────────

class TestRule008Sandwich:
    def test_no_sandwich(self):
        # Mid-week leave
        wed = date.today()
        while wed.weekday() != 2:
            wed += timedelta(days=1)
        req = _base_request(
            leave_type="CL",
            start_date=str(wed),
            end_date=str(wed),
        )
        result = evaluate_rule_008(req, None)
        assert result["passed"] is True

    def test_exempt_type(self):
        req = _base_request(leave_type="SL")
        result = evaluate_rule_008(req, None)
        assert result["passed"] is True
        assert "exempt" in result["message"]

    def test_disabled(self, monkeypatch):
        from constraint_engine import DEFAULT_RULES
        import copy

        patched_rules = copy.deepcopy(DEFAULT_RULES)
        rule = next(r for r in patched_rules if r["rule_id"] == "RULE008")
        rule["config"]["enabled"] = False
        monkeypatch.setattr("constraint_engine.DEFAULT_RULES", patched_rules)

        req = _base_request(leave_type="CL")
        result = evaluate_rule_008(req, None)
        assert result["passed"] is True
        assert "disabled" in result["message"]


# ── RULE009: Min Gap Between Leaves ──────────────────────────────────────────

class TestRule009MinGap:
    def test_no_recent_leaves(self):
        req = _base_request()
        result = evaluate_rule_009(req, None)
        assert result["passed"] is True

    def test_no_dates_skips(self):
        req = _base_request()
        del req["start_date"]
        del req["end_date"]
        result = evaluate_rule_009(req, None)
        assert result["passed"] is True


# ── RULE010: Probation Restriction ───────────────────────────────────────────

class TestRule010Probation:
    def test_not_in_probation(self):
        req = _base_request(
            employee={"status": "active", "joined_at": "2020-01-01"},
        )
        result = evaluate_rule_010(req, None)
        assert result["passed"] is True
        assert "not in probation" in result["message"]

    def test_probation_allowed_type(self):
        req = _base_request(
            leave_type="SL",
            employee={"status": "probation"},
        )
        result = evaluate_rule_010(req, None)
        assert result["passed"] is True

    def test_probation_restricted_type(self):
        req = _base_request(
            leave_type="PL",
            employee={"status": "probation"},
        )
        result = evaluate_rule_010(req, None)
        assert result["passed"] is False
        assert result["is_blocking"] is True

    def test_probation_by_end_date(self):
        req = _base_request(
            leave_type="PL",
            employee={
                "status": "active",
                "probation_end_date": str(date.today() + timedelta(days=30)),
            },
        )
        result = evaluate_rule_010(req, None)
        assert result["passed"] is False


# ── RULE011: Critical Project Freeze ─────────────────────────────────────────

class TestRule011ProjectFreeze:
    def test_no_freeze_configured(self):
        req = _base_request()
        result = evaluate_rule_011(req, None)
        assert result["passed"] is True

    def test_exempt_type(self):
        req = _base_request(leave_type="SL")
        result = evaluate_rule_011(req, None)
        assert result["passed"] is True

    def test_freeze_overlap(self, monkeypatch):
        from constraint_engine import DEFAULT_RULES
        import copy

        start = date.today() + timedelta(days=10)
        end = date.today() + timedelta(days=11)
        patched_rules = copy.deepcopy(DEFAULT_RULES)
        rule = next(r for r in patched_rules if r["rule_id"] == "RULE011")
        rule["config"]["freeze_periods"] = [
            {"name": "Sprint Freeze", "start": str(start), "end": str(end)},
        ]
        monkeypatch.setattr("constraint_engine.DEFAULT_RULES", patched_rules)

        req = _base_request(
            leave_type="CL",
            start_date=str(start),
            end_date=str(end),
        )
        result = evaluate_rule_011(req, None)
        assert result["passed"] is False
        assert "Sprint Freeze" in result["message"]


# ── RULE012: Document Requirement ────────────────────────────────────────────

class TestRule012DocumentRequirement:
    def test_no_doc_needed_short_leave(self):
        req = _base_request(leave_type="CL", total_days=1)
        result = evaluate_rule_012(req, None)
        assert result["passed"] is True

    def test_doc_needed_sick_leave(self):
        req = _base_request(leave_type="SL", total_days=4)
        result = evaluate_rule_012(req, None)
        assert result["passed"] is False
        assert result["is_blocking"] is False

    def test_doc_present(self):
        req = _base_request(
            leave_type="SL", total_days=5,
            attachment_url="https://example.com/doc.pdf",
        )
        result = evaluate_rule_012(req, None)
        assert result["passed"] is True

    def test_long_leave_any_type(self):
        req = _base_request(leave_type="CL", total_days=6)
        result = evaluate_rule_012(req, None)
        assert result["passed"] is False


# ── RULE013: Monthly Quota ───────────────────────────────────────────────────

class TestRule013MonthlyQuota:
    def test_within_quota(self):
        req = _base_request(leave_type="CL", total_days=2)
        result = evaluate_rule_013(req, None)
        assert result["passed"] is True

    def test_exceeds_quota(self):
        req = _base_request(leave_type="CL", total_days=4)
        result = evaluate_rule_013(req, None)
        assert result["passed"] is False
        assert result["is_blocking"] is True


# ── Confidence Score & Recommendation ────────────────────────────────────────

class TestConfidenceScore:
    def test_perfect_score(self):
        assert calculate_confidence_score([], []) == 1.0

    def test_one_violation(self):
        v = [{"rule_id": "X"}]
        assert calculate_confidence_score(v, []) == 0.5

    def test_two_violations(self):
        v = [{"rule_id": "A"}, {"rule_id": "B"}]
        assert calculate_confidence_score(v, []) == 0.0

    def test_warnings_only(self):
        w = [{"rule_id": "W1"}, {"rule_id": "W2"}]
        assert calculate_confidence_score([], w) == 0.8

    def test_mixed(self):
        v = [{"rule_id": "V1"}]
        w = [{"rule_id": "W1"}]
        assert calculate_confidence_score(v, w) == 0.4

    def test_clamped_at_zero(self):
        v = [{"rule_id": "V"} for _ in range(5)]
        assert calculate_confidence_score(v, []) == 0.0


class TestRecommendation:
    def test_approve(self):
        assert derive_recommendation(0.9) == "APPROVE"
        assert derive_recommendation(0.7) == "APPROVE"

    def test_review(self):
        assert derive_recommendation(0.5) == "REVIEW"
        assert derive_recommendation(0.4) == "REVIEW"

    def test_reject(self):
        assert derive_recommendation(0.3) == "REJECT"
        assert derive_recommendation(0.0) == "REJECT"


# ── Full Evaluation (no DB) ─────────────────────────────────────────────────

class TestEvaluateAll:
    def test_clean_request(self):
        req = _base_request(
            total_days=1,
            leave_type="CL",
            balance={
                "annual_entitlement": 12,
                "carried_forward": 0,
                "used_days": 0,
                "pending_days": 0,
                "encashed_days": 0,
            },
            employee={"status": "active", "joined_at": "2020-01-01"},
        )
        result = evaluate_all(req)
        assert "passed" in result
        assert "confidence_score" in result
        assert "recommendation" in result
        assert len(result["rule_results"]) == 13

    def test_failing_request(self):
        req = _base_request(
            total_days=50,
            leave_type="CL",
        )
        result = evaluate_all(req)
        assert result["passed"] is False
        assert len(result["violations"]) > 0
        assert result["confidence_score"] < 1.0
