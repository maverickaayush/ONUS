"""
Tool-version reporting + module execution status visibility tests.

Run with:
    cd backend && python3 -m pytest tests/test_module_visibility.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import subprocess
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


class TestGetToolVersionAnsiStripping:
    """subfinder/nuclei/sslscan/wafw00f color their -version/--version
    output even with stdout piped to a subprocess - real bytes captured
    from each tool running inside the actual worker container (docker
    compose exec worker <tool> -version), not hand-typed escape codes."""

    _REAL_SAMPLES = {
        'subfinder': (b'[\x1b[34mINF\x1b[0m] Current Version: v2.6.6',
                      '[INF] Current Version: v2.6.6'),
        'nuclei': (b'[\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.3.7',
                   '[INF] Nuclei Engine Version: v3.3.7'),
        'sslscan': (b'\x1b[1;34m\t\t2.0.7', '2.0.7'),
    }

    @pytest.mark.parametrize('tool', list(_REAL_SAMPLES.keys()))
    def test_ansi_codes_stripped_from_real_captured_output(self, tool):
        raw_bytes, expected = self._REAL_SAMPLES[tool]
        mock_result = MagicMock(stdout=raw_bytes, stderr=b'')
        with patch('tasks.base_task.shutil.which', return_value=f'/usr/bin/{tool}'), \
             patch('tasks.base_task.subprocess.run', return_value=mock_result):
            assert get_tool_version(tool, '-version') == expected

    def test_testssl_unknown_passes_through_unchanged(self):
        """testssl.sh's real failure mode: the subprocess call raises
        (e.g. timeout) rather than returning stripped-to-empty output -
        must still report 'unknown', not blow up or return ''."""
        with patch('tasks.base_task.shutil.which', return_value='/usr/bin/testssl.sh'), \
             patch('tasks.base_task.subprocess.run', side_effect=subprocess.TimeoutExpired('testssl.sh', 5)):
            assert get_tool_version('testssl.sh', '--version') == 'unknown'

    def test_ansi_only_output_with_no_visible_text_falls_back_to_unknown(self):
        """An edge case the real tools above don't happen to hit: if a
        tool's output were pure escape codes with zero visible characters,
        stripping must still collapse to 'unknown', not an empty string."""
        mock_result = MagicMock(stdout=b'\x1b[0m\x1b[1m', stderr=b'')
        with patch('tasks.base_task.shutil.which', return_value='/usr/bin/faketool'), \
             patch('tasks.base_task.subprocess.run', return_value=mock_result):
            assert get_tool_version('faketool', '--version') == 'unknown'


class TestGetToolVersionBannerSkipping:
    """httpx/naabu/katana/wafw00f print a multi-line ASCII-art banner BEFORE
    their real version line - taking line 0 (the pre-fix behavior) grabs a
    banner fragment instead of the version. Real bytes captured by running
    each tool inside the actual worker container, not hand-typed."""

    _REAL_BANNER_SAMPLES = {
        'httpx': (
            b'\n    __    __  __       _  __\n   / /_  / /_/ /_____ | |/ /\n'
            b'  / __ \\/ __/ __/ __ \\|   /\n / / / / /_/ /_/ /_/ /   |\n'
            b'/_/ /_/\\__/\\__/ .___/_/|_|\n             /_/\n\n\t\tprojectdiscovery.io\n\n'
            b'[\x1b[34mINF\x1b[0m] Current Version: v1.6.9\n',
            '[INF] Current Version: v1.6.9',
        ),
        'naabu': (
            b'\n                  __\n  ___  ___  ___ _/ /  __ __\n'
            b' / _ \\/ _ \\/ _ \\/ _ \\/ // /\n/_//_/\\_,_/\\_,_/_.__/\\_,_/\n\n'
            b'\t\tprojectdiscovery.io\n\n[\x1b[34mINF\x1b[0m] Current Version: 2.3.3\n',
            '[INF] Current Version: 2.3.3',
        ),
        'katana': (
            b"\n   __        __                \n  / /_____ _/ /____ ____  ___ _\n"
            b" /  '_/ _  / __/ _  / _ \\/ _  /\n/_/\\_\\\\_,_/\\__/\\_,_/_//_/\\_,_/\t\t\t\t\t\t\t \n\n"
            b'\t\tprojectdiscovery.io\n\n[\x1b[34mINF\x1b[0m] Current version: v1.1.2\n',
            '[INF] Current version: v1.1.2',
        ),
        'wafw00f': (
            b'\n                \x1b[1;97m______\n               \x1b[1;97m/      \\\n'
            b'              \x1b[1;97m(  W00f! )\n               \x1b[1;97m\\  ____/\n'
            b'               \x1b[1;97m,,    \x1b[1;92m__            \x1b[1;93m404 Hack Not Found\n'
            b'           \x1b[1;96m|`-.__   \x1b[1;92m/ /                     \x1b[1;91m __     __\n'
            b'           \x1b[1;96m/"  _/  \x1b[1;92m/_/                       \x1b[1;91m\\ \\   / /\n'
            b'          \x1b[1;94m*===*    \x1b[1;92m/                          \x1b[1;91m\\ \\_/ /  \x1b[1;93m405 Not Allowed\n'
            b'         \x1b[1;96m/     )__//                           \x1b[1;91m\\   /\n'
            b'    \x1b[1;96m/|  /     /---`                        \x1b[1;93m403 Forbidden\n'
            b'    \x1b[1;96m\\\\/`   \\ |                                 \x1b[1;91m/ _ \\\n'
            b'    \x1b[1;96m`\\    /_\\\\_              \x1b[1;93m502 Bad Gateway  \x1b[1;91m/ / \\ \\  \x1b[1;93m500 Internal Error\n'
            b'      \x1b[1;96m`_____``-`                             \x1b[1;91m/_/   \\_\\\n\n'
            b'                        \x1b[1;96m~ WAFW00F : \x1b[1;94mv2.2.0 ~\x1b[1;97m\n'
            b'        The Web Application Firewall Fingerprinting Toolkit\n    \x1b[0m\n'
            b'[+] The version of WAFW00F you have is \x1b[1;94mv2.2.0\x1b[0m\n'
            b'[+] WAFW00F is provided under the \x1b[1;96mBSD 3-Clause\x1b[0m license.\n',
            '~ WAFW00F : v2.2.0 ~',
        ),
    }

    @pytest.mark.parametrize('tool', list(_REAL_BANNER_SAMPLES.keys()))
    def test_real_version_line_found_past_the_banner(self, tool):
        raw_bytes, expected = self._REAL_BANNER_SAMPLES[tool]
        mock_result = MagicMock(stdout=raw_bytes, stderr=b'')
        with patch('tasks.base_task.shutil.which', return_value=f'/usr/bin/{tool}'), \
             patch('tasks.base_task.subprocess.run', return_value=mock_result):
            assert get_tool_version(tool, '-version') == expected

    @pytest.mark.parametrize('tool,raw,expected', [
        ('nmap', b'Nmap version 7.93 ( https://nmap.org )\nPlatform: x86_64\n',
         'Nmap version 7.93 ( https://nmap.org )'),
        ('whois', b'Version 5.5.17.\n\nReport bugs to <md+whois@linux.it>.\n', 'Version 5.5.17.'),
        ('nikto', b'Nikto 2.6.0 (LW 2.5)\n', 'Nikto 2.6.0 (LW 2.5)'),
        ('ffuf', b'ffuf version: 2.1.0\n', 'ffuf version: 2.1.0'),
        ('amass', b'v4.2.0\n', 'v4.2.0'),
    ])
    def test_tools_whose_version_was_already_on_line_0_are_unaffected(self, tool, raw, expected):
        """Regression guard: tools that already worked correctly before
        this fix (their version line already IS line 0) must not change."""
        mock_result = MagicMock(stdout=raw, stderr=b'')
        with patch('tasks.base_task.shutil.which', return_value=f'/usr/bin/{tool}'), \
             patch('tasks.base_task.subprocess.run', return_value=mock_result):
            assert get_tool_version(tool, '--version') == expected

    def test_no_line_looks_like_a_version_falls_back_to_line_0(self):
        """whatweb's real failure mode in this environment: a plain error
        message with no version-like line anywhere. Must fall back to the
        first line (still informative), not 'unknown' - the tool DID run
        and DID produce output, just not a version."""
        mock_result = MagicMock(
            stdout=b'WhatWeb is not installed and is missing dependencies.\n', stderr=b'')
        with patch('tasks.base_task.shutil.which', return_value='/usr/bin/whatweb'), \
             patch('tasks.base_task.subprocess.run', return_value=mock_result):
            assert get_tool_version('whatweb', '--version') == \
                'WhatWeb is not installed and is missing dependencies.'


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
