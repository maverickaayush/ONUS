"""
Operator decision flow (retry/continue/cancel) tests for tasks/scan_orchestrator.py
and the /api/scan/{id}/decision endpoint in routers/scan.py.

Run with:
    cd backend && python3 -m pytest tests/test_decision_flow.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock

from tasks.scan_orchestrator import (
    aggregate_and_analyse, retry_failed_modules, continue_after_decision,
    _merge_retry_results, _failed_modules, _can_retry, _incomplete_modules_warning,
    MAX_RETRIES_PER_MODULE,
)
from models import ScanStatus

SCAN_ID = "22222222-2222-2222-2222-222222222222"
DOMAIN = "example.com"


def _fake_scan(status=ScanStatus.running, raw_findings=None):
    scan = MagicMock()
    scan.id = SCAN_ID
    scan.domain = DOMAIN
    scan.status = status
    scan.raw_findings = raw_findings or {}
    scan.module_statuses = {}
    scan.started_at = None
    return scan


def _db_with(scan):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = scan
    return db


def _envelope(module, status, error=None):
    return {"module": module, "status": status, "findings": [], "tool_versions": {},
            "finding_count": 0, "duration_seconds": 1.0, "error": error}


ALL_SUCCESS = [_envelope(m, "success") for m in
               ("recon", "webscan", "ssl_tls", "headers", "owasp",
                "tech_fingerprint", "nuclei", "enumeration")]


class TestPauseTrigger:
    def test_failed_module_pauses(self):
        results = [e if e["module"] != "recon" else _envelope("recon", "failed", "nmap timed out")
                   for e in ALL_SUCCESS]
        scan = _fake_scan()
        db = _db_with(scan)
        with patch("database.SessionLocal", return_value=db), \
             patch("tasks.scan_orchestrator._finalize") as finalize:
            aggregate_and_analyse(results, SCAN_ID, DOMAIN)
        finalize.assert_not_called()
        assert scan.status == ScanStatus.awaiting_user_decision
        assert scan.raw_findings["module_results"] == results

    def test_timeout_module_pauses(self):
        results = [e if e["module"] != "webscan" else _envelope("webscan", "timeout", "soft time limit exceeded")
                   for e in ALL_SUCCESS]
        scan = _fake_scan()
        db = _db_with(scan)
        with patch("database.SessionLocal", return_value=db), \
             patch("tasks.scan_orchestrator._finalize") as finalize:
            aggregate_and_analyse(results, SCAN_ID, DOMAIN)
        finalize.assert_not_called()
        assert scan.status == ScanStatus.awaiting_user_decision

    def test_partial_does_not_pause(self):
        results = [e if e["module"] != "tech_fingerprint" else _envelope("tech_fingerprint", "partial", "wafw00f failed")
                   for e in ALL_SUCCESS]
        with patch("tasks.scan_orchestrator._finalize") as finalize:
            aggregate_and_analyse(results, SCAN_ID, DOMAIN)
        finalize.assert_called_once_with(results, SCAN_ID, DOMAIN)

    def test_all_success_does_not_pause(self):
        with patch("tasks.scan_orchestrator._finalize") as finalize:
            aggregate_and_analyse(ALL_SUCCESS, SCAN_ID, DOMAIN)
        finalize.assert_called_once_with(ALL_SUCCESS, SCAN_ID, DOMAIN)


class TestRetry:
    def test_retry_redispatches_only_failed_modules_and_increments_count(self):
        results = [e if e["module"] not in ("recon", "webscan")
                   else _envelope(e["module"], "failed", "boom") for e in ALL_SUCCESS]
        scan = _fake_scan(status=ScanStatus.awaiting_user_decision,
                           raw_findings={"module_results": results, "retry_counts": {}})
        db = _db_with(scan)

        with patch("database.SessionLocal", return_value=db), \
             patch("tasks.scan_orchestrator.chord") as mock_chord, \
             patch("tasks.scan_orchestrator.group") as mock_group, \
             patch("tasks.base_task.update_module_status") as mock_update_status:
            retry_failed_modules(SCAN_ID, DOMAIN)

        mock_group.assert_called_once()
        signatures = list(mock_group.call_args.args[0])
        retried_task_names = {sig.task for sig in signatures}
        assert retried_task_names == {"tasks.recon.run_recon", "tasks.webscan.run_webscan"}
        assert scan.raw_findings["retry_counts"] == {"recon": 1, "webscan": 1}
        assert scan.status == ScanStatus.running
        assert mock_update_status.call_count == 2
        mock_chord.assert_called_once()

    def test_dispatch_failure_does_not_burn_the_retry_budget(self):
        """
        Real bug found live (Opus review): retry_counts used to be
        incremented and persisted BEFORE the chord() dispatch - a transient
        broker failure there still consumed the module's one-and-only retry
        even though nothing was ever dispatched. Confirm a chord() dispatch
        failure leaves retry_counts untouched and status back at
        awaiting_user_decision, so a second Retry attempt is still possible.
        """
        results = [e if e["module"] != "recon" else _envelope("recon", "failed", "boom") for e in ALL_SUCCESS]
        scan = _fake_scan(status=ScanStatus.awaiting_user_decision,
                           raw_findings={"module_results": results, "retry_counts": {}})
        db = _db_with(scan)

        with patch("database.SessionLocal", return_value=db), \
             patch("tasks.scan_orchestrator.chord", side_effect=RuntimeError("broker unreachable")), \
             patch("tasks.scan_orchestrator.group") as mock_group, \
             patch("tasks.base_task.update_module_status"):
            retry_failed_modules(SCAN_ID, DOMAIN)

        assert scan.raw_findings["retry_counts"] == {}
        assert scan.status == ScanStatus.awaiting_user_decision

    def test_no_retry_eligible_modules_short_circuits(self):
        results = [e if e["module"] != "recon" else _envelope("recon", "failed", "boom") for e in ALL_SUCCESS]
        scan = _fake_scan(status=ScanStatus.awaiting_user_decision,
                           raw_findings={"module_results": results,
                                         "retry_counts": {"recon": MAX_RETRIES_PER_MODULE}})
        db = _db_with(scan)

        with patch("database.SessionLocal", return_value=db), \
             patch("tasks.scan_orchestrator.chord") as mock_chord:
            retry_failed_modules(SCAN_ID, DOMAIN)

        mock_chord.assert_not_called()
        # status untouched - still awaiting decision, no retry dispatched
        assert scan.status == ScanStatus.awaiting_user_decision

    def test_second_failure_disables_retry(self):
        # recon already used its one retry and failed again
        merged = [e if e["module"] != "recon" else _envelope("recon", "failed", "boom again") for e in ALL_SUCCESS]
        scan = _fake_scan(raw_findings={"retry_counts": {"recon": 1}})
        db = _db_with(scan)

        with patch("database.SessionLocal", return_value=db), \
             patch("tasks.scan_orchestrator._finalize") as finalize:
            _merge_retry_results([_envelope("recon", "failed", "boom again")], SCAN_ID, DOMAIN, merged, ["recon"])

        finalize.assert_not_called()
        assert scan.status == ScanStatus.awaiting_user_decision
        assert _can_retry(_failed_modules(merged), {"recon": 1}) is False


class TestContinue:
    def test_continue_finalizes_with_failed_modules_still_marked_failed(self):
        results = [e if e["module"] != "recon" else _envelope("recon", "failed", "boom") for e in ALL_SUCCESS]
        scan = _fake_scan(status=ScanStatus.awaiting_user_decision,
                           raw_findings={"module_results": results})
        db = _db_with(scan)

        with patch("database.SessionLocal", return_value=db), \
             patch("tasks.scan_orchestrator._finalize") as finalize:
            continue_after_decision(SCAN_ID, DOMAIN)

        finalize.assert_called_once_with(results, SCAN_ID, DOMAIN)

    def test_incomplete_modules_warning_set_when_a_module_failed(self):
        module_execution = [{"module": "recon", "status": "failed"}, {"module": "webscan", "status": "success"}]
        assert _incomplete_modules_warning(module_execution) is not None

    def test_incomplete_modules_warning_none_when_all_succeeded(self):
        module_execution = [{"module": "recon", "status": "success"}, {"module": "webscan", "status": "partial"}]
        assert _incomplete_modules_warning(module_execution) is None


class TestCancelEndpoint:
    def test_cancel_sets_status_and_never_touches_pdf_generation(self):
        from routers.scan import submit_scan_decision
        from schemas import ScanDecisionRequest

        scan = _fake_scan(status=ScanStatus.awaiting_user_decision)
        db = _db_with(scan)

        with patch("reports.generator.generate_pdf") as mock_pdf:
            submit_scan_decision(SCAN_ID, ScanDecisionRequest(action="cancel"), db)

        assert scan.status == ScanStatus.cancelled
        db.commit.assert_called()
        mock_pdf.assert_not_called()
        # domain/id preserved - cancel is a status change, not a rewrite
        assert scan.domain == DOMAIN
        assert scan.id == SCAN_ID


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
