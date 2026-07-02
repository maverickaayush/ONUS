"""
Tool-version reporting + module execution status visibility tests.

Run with:
    cd backend && python3 -m pytest tests/test_module_visibility.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock

import pytest
from celery.exceptions import SoftTimeLimitExceeded

from tasks.base_task import build_module_result, get_tool_version
from analysis.aggregator import aggregate

REQUIRED_ENVELOPE_KEYS = {'module', 'status', 'findings', 'tool_versions',
                          'finding_count', 'duration_seconds', 'error'}


class TestBuildModuleResult:

    def test_shape_and_defaults(self):
        r = build_module_result('recon', [{'a': 1}], {'nmap': '7.94'})
        assert REQUIRED_ENVELOPE_KEYS <= set(r.keys())
        assert r['status'] == 'success'
        assert r['error'] is None
        assert r['finding_count'] == 1

    def test_finding_count_derived_from_findings_not_passed_separately(self):
        r = build_module_result('x', [{}, {}, {}], {})
        assert r['finding_count'] == 3

    def test_duration_rounded_to_2dp(self):
        r = build_module_result('x', [], {}, duration_seconds=1.23456)
        assert r['duration_seconds'] == 1.23


class TestGetToolVersion:

    def test_missing_tool_reports_not_installed(self):
        assert get_tool_version('definitely-not-a-real-tool-xyz') == 'not installed'

    def test_real_tool_returns_nonempty_string(self):
        # python3 itself is guaranteed present in this test environment.
        version = get_tool_version('python3', '--version')
        assert version not in ('not installed', '')


class TestToolVersionsMergeInAggregator:
    """Fix 1 - tool_versions dynamically collected from every module,
    including modules that produced zero findings."""

    def test_tool_versions_merged_from_multiple_modules(self):
        recon = build_module_result('recon', [], {'nmap': '7.94', 'subfinder': '2.6.3'})
        webscan = build_module_result('webscan', [], {'zap': '2.14.0', 'nikto': '2.5.0'})
        tech = build_module_result('tech_fingerprint', [], {'whatweb': '0.5.5', 'wafw00f': '2.3.0'})
        enumeration = build_module_result('enumeration', [], {'ffuf': '2.1.0'})

        result = aggregate([recon, webscan, tech, enumeration])

        versions = result['scan_metadata']['tool_versions']
        assert versions == {
            'nmap': '7.94', 'subfinder': '2.6.3',
            'zap': '2.14.0', 'nikto': '2.5.0',
            'whatweb': '0.5.5', 'wafw00f': '2.3.0',
            'ffuf': '2.1.0',
        }

    def test_module_with_zero_findings_still_reports_tool_versions(self):
        """A module that ran cleanly and found nothing must still appear in
        the Tool Versions table - previously only modules with findings
        were even considered."""
        clean_module = build_module_result('ssl_tls', [], {'testssl': '3.2', 'sslscan': '2.1.6'})
        result = aggregate([clean_module])
        assert result['scan_metadata']['tool_versions'] == {'testssl': '3.2', 'sslscan': '2.1.6'}

    def test_bare_list_module_result_degrades_gracefully(self):
        """A module not yet updated to the envelope shape (defensive
        fallback) must not crash aggregation, just lose its tool_versions."""
        old_style = [{'type': 'open_port', 'evidence': 'x', 'severity': 'Info',
                       'module': 'recon', 'found_by': ['recon']}]
        result = aggregate([old_style])
        assert result['total'] == 1
        assert result['scan_metadata']['tool_versions'] == {}


class TestModuleExecutionStatusVisibility:
    """Fix 2 - a module that fails must be distinguishable from a module
    that ran cleanly and found nothing."""

    def test_module_exception_captured_as_failed_not_silent_zero_findings(self):
        """Simulate an internal module function raising - the outer task
        must catch it and report status='failed' with a non-empty error,
        not silently return an empty findings list indistinguishable from
        a clean scan."""
        from tasks.nuclei_scan import run_nuclei

        with patch('tasks.nuclei_scan.update_module_status'), \
             patch('tasks.nuclei_scan._run_nuclei', side_effect=RuntimeError('nuclei: command not found')):
            result = run_nuclei.run('scan-1', 'example.com')

        assert result['status'] == 'failed'
        assert result['error']
        assert 'nuclei: command not found' in result['error']
        assert result['findings'] == []
        assert result['finding_count'] == 0

    def test_clean_module_is_success_not_failed(self):
        """Contrast case: a module that runs cleanly and finds nothing is
        'success', not silently indistinguishable from a failure."""
        from tasks.nuclei_scan import run_nuclei

        with patch('tasks.nuclei_scan.update_module_status'), \
             patch('tasks.nuclei_scan._run_nuclei', return_value=[]), \
             patch('tasks.nuclei_scan.get_tool_version', return_value='3.3.0'):
            result = run_nuclei.run('scan-1', 'example.com')

        assert result['status'] == 'success'
        assert result['error'] is None
        assert result['findings'] == []

    def test_soft_timeout_reported_as_timeout_not_failed(self):
        """A module that hits its soft Celery time limit (catchable, unlike
        a hard SIGKILL) must report status='timeout', not a generic 'failed'
        or a silent empty result."""
        from tasks.headers import run_headers

        with patch('tasks.headers.update_module_status'), \
             patch('tasks.headers._run_headers', side_effect=SoftTimeLimitExceeded()):
            result = run_headers.run('scan-1', 'example.com')

        assert result['status'] == 'timeout'
        assert result['error']

    def test_partial_status_for_tech_fingerprint_one_tool_failing(self):
        """tech_fingerprint.py already distinguishes 'one of two sub-tools
        failed' via whatweb_ok/wafw00f_ok - a legitimate existing partial
        signal, not invented detection."""
        from tasks.tech_fingerprint import run_tech_fingerprint

        with patch('tasks.tech_fingerprint.update_module_status'), \
             patch('tasks.tech_fingerprint._run_whatweb', return_value=[]), \
             patch('tasks.tech_fingerprint._run_wafw00f', side_effect=Exception('wafw00f: timed out')):
            result = run_tech_fingerprint.run('scan-1', 'example.com')

        assert result['status'] == 'partial'
        assert 'wafw00f' in result['error']

    def test_module_execution_list_includes_every_module_even_clean_ones(self):
        recon = build_module_result('recon', [], {'nmap': '7.94'}, status='success')
        webscan = build_module_result('webscan', [], {}, status='success')
        nuclei = build_module_result('nuclei', [], {}, status='failed', error='nuclei: not found')

        result = aggregate([recon, webscan, nuclei])
        modules = {m['module']: m for m in result['module_execution']}

        assert set(modules) == {'recon', 'webscan', 'nuclei'}
        assert modules['recon']['status'] == 'success'
        assert modules['nuclei']['status'] == 'failed'
        assert modules['nuclei']['error'] == 'nuclei: not found'


class TestIncompleteModulesWarning:

    def test_warning_present_when_a_module_failed(self):
        from tasks.scan_orchestrator import _incomplete_modules_warning

        module_execution = [
            {'module': 'recon', 'status': 'success', 'error': None},
            {'module': 'nuclei', 'status': 'failed', 'error': 'not found'},
        ]
        warning = _incomplete_modules_warning(module_execution)
        assert warning is not None
        assert '1 of 2' in warning

    def test_no_warning_when_all_modules_succeed(self):
        from tasks.scan_orchestrator import _incomplete_modules_warning

        module_execution = [
            {'module': 'recon', 'status': 'success', 'error': None},
            {'module': 'webscan', 'status': 'success', 'error': None},
        ]
        assert _incomplete_modules_warning(module_execution) is None

    def test_partial_does_not_count_as_incomplete(self):
        from tasks.scan_orchestrator import _incomplete_modules_warning

        module_execution = [
            {'module': 'tech_fingerprint', 'status': 'partial', 'error': 'one tool failed'},
        ]
        assert _incomplete_modules_warning(module_execution) is None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
