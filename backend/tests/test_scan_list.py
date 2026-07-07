"""
GET /api/scans (discovery/listing page) tests, plus the shared helpers it
was refactored to share with GET /scan/{id}/status (_compute_progress,
_compute_module_errors, _current_module).

Run with:
    cd backend && python3 -m pytest tests/test_scan_list.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uuid
from datetime import datetime
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from routers.scan import (
    list_scans, _compute_progress, _compute_module_errors, _current_module,
    STATUS_BUCKETS,
)
from models import ScanStatus


def _fake_scan(status=ScanStatus.complete, module_statuses=None, risk_score=42,
                raw_findings=None, domain="example.com"):
    scan = MagicMock()
    scan.id = uuid.uuid4()
    scan.domain = domain
    scan.status = status
    scan.module_statuses = module_statuses or {}
    scan.risk_score = risk_score
    scan.raw_findings = raw_findings or {}
    scan.created_at = datetime(2026, 1, 1, 12, 0, 0)
    scan.updated_at = datetime(2026, 1, 1, 12, 5, 0)
    return scan


def _db_for_list(reaped=None, status_counts=None, page_scans=None, total_matching=0):
    """
    list_scans() makes exactly 3 distinct db.query(...) calls in this order:
    1. _reap_stuck_scans's own db.query(Scan).filter(...).all()
    2. the GROUP BY status-counts aggregate
    3. the main paginated Scan query (chained .filter/.with_entities/.order_by/.offset/.limit)
    """
    reap_query = MagicMock()
    reap_query.filter.return_value.all.return_value = reaped or []

    status_query = MagicMock()
    status_query.group_by.return_value.all.return_value = status_counts or []

    scan_query = MagicMock()
    scan_query.filter.return_value = scan_query  # chainable, self-returning
    scan_query.with_entities.return_value.scalar.return_value = total_matching
    scan_query.order_by.return_value.offset.return_value.limit.return_value.all.return_value = page_scans or []

    db = MagicMock()
    db.query.side_effect = [reap_query, status_query, scan_query]
    return db


class TestComputeProgress:
    def test_queued_is_zero(self):
        assert _compute_progress(_fake_scan(status=ScanStatus.queued)) == 0

    def test_running_scales_with_completed_modules(self):
        # 4 of 8 canonical modules complete -> 20 + (4/8)*60 = 50
        module_statuses = {"recon": "complete", "webscan": "complete",
                            "ssl_tls": "complete", "headers": "complete",
                            "owasp": "running", "tech_fingerprint": "queued",
                            "nuclei": "queued", "enumeration": "queued"}
        scan = _fake_scan(status=ScanStatus.running, module_statuses=module_statuses)
        assert _compute_progress(scan) == 50

    def test_analysing_is_80(self):
        assert _compute_progress(_fake_scan(status=ScanStatus.analysing)) == 80

    def test_awaiting_user_decision_is_80_not_zero(self):
        """Real fix confirmed with the user: a scan paused for a decision
        already finished all 8 modules - showing 0% (the old missing-entry
        default) was misleading."""
        assert _compute_progress(_fake_scan(status=ScanStatus.awaiting_user_decision)) == 80

    def test_complete_is_100(self):
        assert _compute_progress(_fake_scan(status=ScanStatus.complete)) == 100

    def test_failed_is_zero(self):
        assert _compute_progress(_fake_scan(status=ScanStatus.failed)) == 0


class TestComputeModuleErrors:
    def test_non_awaiting_decision_is_none(self):
        assert _compute_module_errors(_fake_scan(status=ScanStatus.running)) is None

    def test_awaiting_decision_returns_failed_module_names_only(self):
        raw_findings = {
            "module_results": [
                {"module": "recon", "status": "failed", "error": "nmap crashed"},
                {"module": "webscan", "status": "success"},
                {"module": "owasp", "status": "timeout", "error": "soft time limit"},
            ],
        }
        scan = _fake_scan(status=ScanStatus.awaiting_user_decision, raw_findings=raw_findings)
        errors = _compute_module_errors(scan)
        assert set(errors.keys()) == {"recon", "owasp"}
        assert errors["recon"] == "nmap crashed"


class TestCurrentModule:
    def test_analysing_returns_synthetic_value(self):
        assert _current_module(_fake_scan(status=ScanStatus.analysing)) == "Analysing"

    def test_not_running_returns_none(self):
        assert _current_module(_fake_scan(status=ScanStatus.complete)) is None
        assert _current_module(_fake_scan(status=ScanStatus.queued)) is None

    def test_multiple_running_picks_canonical_order(self):
        # webscan and owasp both "running" - recon comes first in
        # SCAN_MODULE_IDS canonical order, but neither of these two do -
        # webscan precedes owasp in that list, so webscan should win.
        module_statuses = {"recon": "complete", "webscan": "running",
                            "ssl_tls": "complete", "headers": "complete",
                            "owasp": "running", "tech_fingerprint": "queued",
                            "nuclei": "queued", "enumeration": "queued"}
        scan = _fake_scan(status=ScanStatus.running, module_statuses=module_statuses)
        assert _current_module(scan) == "webscan"

    def test_none_running_returns_none(self):
        module_statuses = {m: "queued" for m in
                            ("recon", "webscan", "ssl_tls", "headers", "owasp",
                             "tech_fingerprint", "nuclei", "enumeration")}
        scan = _fake_scan(status=ScanStatus.running, module_statuses=module_statuses)
        assert _current_module(scan) is None


class TestListScans:
    def test_no_filter_returns_all_with_global_counts(self):
        status_counts = [(ScanStatus.running, 2), (ScanStatus.complete, 5), (ScanStatus.failed, 1)]
        scans = [_fake_scan(status=ScanStatus.complete) for _ in range(5)]
        db = _db_for_list(status_counts=status_counts, page_scans=scans, total_matching=5)

        result = list_scans(status=None, db=db)

        assert result.counts["completed"] == 5
        assert result.counts["failed"] == 1
        assert result.counts["running"] == 2
        assert result.counts["total"] == 8
        assert len(result.scans) == 5
        assert result.total == 5

    def test_unknown_status_filter_is_422(self):
        db = _db_for_list()
        with pytest.raises(HTTPException) as exc:
            list_scans(status="not-a-real-status", db=db)
        assert exc.value.status_code == 422

    def test_unknown_sort_key_is_422(self):
        db = _db_for_list()
        with pytest.raises(HTTPException) as exc:
            list_scans(sort="not-a-column", db=db)
        assert exc.value.status_code == 422

    def test_invalid_order_is_422(self):
        db = _db_for_list()
        with pytest.raises(HTTPException) as exc:
            list_scans(order="sideways", db=db)
        assert exc.value.status_code == 422

    def test_counts_stay_global_when_a_filter_is_applied(self):
        """The one behavior most likely to regress if this query gets
        'simplified' later: counts must reflect the WHOLE table, not just
        the current filter, so tab badges never zero out under an active
        filter."""
        status_counts = [(ScanStatus.running, 3), (ScanStatus.failed, 7)]
        db = _db_for_list(status_counts=status_counts, page_scans=[], total_matching=0)

        result = list_scans(status="completed", db=db)

        assert result.counts["running"] == 3
        assert result.counts["failed"] == 7
        assert result.counts["total"] == 10

    def test_pagination_math_and_clamping(self):
        db = _db_for_list(status_counts=[], page_scans=[], total_matching=45)
        result = list_scans(page=2, page_size=20, db=db)
        assert result.page == 2
        assert result.page_size == 20
        assert result.total_pages == 3  # ceil(45/20)

        # page_size clamped to [1, 100]
        db2 = _db_for_list(status_counts=[], page_scans=[], total_matching=0)
        result2 = list_scans(page=0, page_size=500, db=db2)
        assert result2.page == 1          # clamped up to 1
        assert result2.page_size == 100   # clamped down to 100

    def test_list_item_module_errors_is_names_only(self):
        raw_findings = {"module_results": [
            {"module": "recon", "status": "failed", "error": "boom"},
        ]}
        scan = _fake_scan(status=ScanStatus.awaiting_user_decision, raw_findings=raw_findings)
        db = _db_for_list(status_counts=[], page_scans=[scan], total_matching=1)

        result = list_scans(status="awaiting_user_decision", db=db)

        item = result.scans[0]
        assert item.module_errors == ["recon"]
        assert item.awaiting_user_decision is True
        assert item.progress == 80

    def test_modules_completed_and_total(self):
        module_statuses = {"recon": "complete", "webscan": "complete",
                            "ssl_tls": "running", "headers": "queued",
                            "owasp": "queued", "tech_fingerprint": "queued",
                            "nuclei": "queued", "enumeration": "queued"}
        scan = _fake_scan(status=ScanStatus.running, module_statuses=module_statuses)
        db = _db_for_list(status_counts=[], page_scans=[scan], total_matching=1)

        result = list_scans(db=db)

        assert result.scans[0].modules_completed == 2
        assert result.scans[0].modules_total == 8


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
