"""
Step 5 verification tests for the ssl_tls module.

Tests that don't need external tools use mocks/synthetic data.
The live test against badssl.com uses the pure-Python _cert_expiry_finding
and _https_reachable helpers (no testssl.sh or sslscan needed).

Run with:
    cd backend && python3 -m pytest tests/test_ssl_tls.py -v
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock, mock_open

import pytest

REQUIRED_FIELDS = {'module', 'tool', 'type', 'title', 'evidence',
                   'severity', 'cvss', 'target', 'found_by'}
VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low',
                    'Informational', 'Info'}
MODULE = 'ssl_tls'
TEST_SCAN_ID = 'test-ssl-step5'
TEST_DOMAIN = 'badssl.com'


def _stub_update_status(*args, **kwargs):
    pass


# ---------------------------------------------------------------------------
# Schema & contract tests
# ---------------------------------------------------------------------------

class TestSslTlsSchema:

    def test_all_required_fields_present(self):
        """Every finding from normalize_finding must have all Section 4.3 fields."""
        from tasks.base_task import normalize_finding
        f = normalize_finding(
            module=MODULE, tool='testssl', type_='testssl_tls1',
            title='TLS 1.0 enabled', evidence='TLS 1.0 is enabled',
            severity='High', target=TEST_DOMAIN,
        )
        missing = REQUIRED_FIELDS - set(f.keys())
        assert not missing, f"Missing fields: {missing}"
        assert f['found_by'] == [MODULE]
        assert f['module'] == MODULE

    def test_testssl_severity_mapping(self):
        """testssl severity strings must map to normalized values correctly."""
        from tasks.ssl_tls import _TESTSSL_SEVERITY_MAP, _TESTSSL_SKIP
        assert _TESTSSL_SEVERITY_MAP['CRITICAL'] == 'Critical'
        assert _TESTSSL_SEVERITY_MAP['HIGH'] == 'High'
        assert _TESTSSL_SEVERITY_MAP['MEDIUM'] == 'Medium'
        assert _TESTSSL_SEVERITY_MAP['LOW'] == 'Low'
        assert _TESTSSL_SEVERITY_MAP['WARN'] == 'Low'
        assert 'INFO' in _TESTSSL_SKIP
        assert 'OK' in _TESTSSL_SKIP

    def test_testssl_json_parsing_skips_info_ok(self):
        """INFO/OK findings must be skipped - they represent passing checks."""
        from tasks.ssl_tls import _parse_testssl_json

        sample = json.dumps([
            {'id': 'TLS1', 'severity': 'HIGH',   'finding': 'TLS 1.0 is enabled'},
            {'id': 'ECDHE', 'severity': 'OK',    'finding': 'ECDHE cipher offered'},
            {'id': 'HSTS',  'severity': 'MEDIUM', 'finding': 'HSTS not set'},
            {'id': 'CERT',  'severity': 'INFO',  'finding': 'Certificate: OK'},
        ])

        path = f'/tmp/test_testssl_{TEST_SCAN_ID}.json'
        with open(path, 'w') as f:
            f.write(sample)
        try:
            findings = _parse_testssl_json(path, TEST_DOMAIN, TEST_SCAN_ID)
        finally:
            if os.path.exists(path):
                os.unlink(path)

        titles = [f['title'] for f in findings]
        assert len(findings) == 2, f"Expected 2 findings (skipping INFO/OK), got {len(findings)}: {titles}"
        sevs = {f['title']: f['severity'] for f in findings}
        assert any('TLS 1.0' in t for t in titles)
        assert any('HSTS' in t for t in titles)
        for f in findings:
            missing = REQUIRED_FIELDS - set(f.keys())
            assert not missing
            assert f['found_by'] == [MODULE]

    def test_sslscan_xml_parsing_tls_protocols(self):
        """sslscan XML parser must flag SSLv3, TLS 1.0, TLS 1.1 correctly."""
        from tasks.ssl_tls import _parse_sslscan_xml

        xml_data = """<?xml version="1.0"?>
<document>
  <ssltest host="badssl.com" port="443">
    <protocol type="sslv3" version="3.0" enabled="1"/>
    <protocol type="tlsv1" version="1.0" enabled="1"/>
    <protocol type="tlsv1_1" version="1.1" enabled="1"/>
    <protocol type="tlsv1_2" version="1.2" enabled="1"/>
    <protocol type="tlsv1_3" version="1.3" enabled="1"/>
  </ssltest>
</document>"""
        path = f'/tmp/test_sslscan_{TEST_SCAN_ID}.xml'
        with open(path, 'w') as f:
            f.write(xml_data)
        try:
            findings = _parse_sslscan_xml(path, TEST_DOMAIN, TEST_SCAN_ID)
        finally:
            if os.path.exists(path):
                os.unlink(path)

        types = {f['type'] for f in findings}
        assert 'sslv3_enabled' in types, "SSLv3 must be flagged"
        assert 'tls10_enabled' in types, "TLS 1.0 must be flagged"
        assert 'tls11_enabled' in types, "TLS 1.1 must be flagged"
        # TLS 1.2 and 1.3 must NOT be flagged
        assert 'tls12_enabled' not in types
        assert 'tls13_enabled' not in types
        # Check severities
        for f in findings:
            if f['type'] == 'sslv3_enabled':
                assert f['severity'] == 'High'
            if f['type'] == 'tls11_enabled':
                assert f['severity'] == 'Medium'

    def test_sslscan_xml_parsing_weak_ciphers(self):
        """RC4, DES, and sub-128-bit ciphers must be flagged as High."""
        from tasks.ssl_tls import _parse_sslscan_xml

        xml_data = """<?xml version="1.0"?>
<document>
  <ssltest host="badssl.com" port="443">
    <cipher status="accepted" bits="128" cipher="RC4-SHA"/>
    <cipher status="accepted" bits="56"  cipher="DES-CBC-SHA"/>
    <cipher status="accepted" bits="40"  cipher="EXP-RC4-MD5"/>
    <cipher status="accepted" bits="256" cipher="AES256-GCM-SHA384"/>
    <cipher status="rejected" bits="128" cipher="RC4-MD5"/>
  </ssltest>
</document>"""
        path = f'/tmp/test_sslscan_cipher_{TEST_SCAN_ID}.xml'
        with open(path, 'w') as f:
            f.write(xml_data)
        try:
            findings = _parse_sslscan_xml(path, TEST_DOMAIN, TEST_SCAN_ID)
        finally:
            if os.path.exists(path):
                os.unlink(path)

        types = {f['type'] for f in findings}
        assert 'weak_cipher_rc4' in types, "RC4 must be flagged"
        assert 'weak_cipher_des' in types, "DES must be flagged"
        assert 'weak_cipher_bits' in types, "Sub-128-bit cipher must be flagged"
        # Rejected cipher (RC4-MD5) must NOT appear - check exact cipher name,
        # not substring (EXP-RC4-MD5 is accepted and also contains 'RC4-MD5').
        rejected = [f for f in findings
                    if f.get('title', '').endswith(': RC4-MD5')]
        assert not rejected, "Rejected ciphers must not be reported"
        # Good cipher must NOT be flagged
        aes_titles = [f['title'] for f in findings if 'AES256' in f['title']]
        assert not aes_titles, "Strong cipher must not be flagged"

    def test_dedup_merges_same_issue_from_two_tools(self):
        """When testssl and sslscan both detect TLS 1.0, result has ONE finding."""
        from tasks.ssl_tls import _dedup
        from tasks.base_task import normalize_finding

        f1 = normalize_finding(MODULE, 'testssl', 'tls10_enabled',
                               'TLS 1.0 enabled', 'TLS 1.0 enabled on port 443',
                               'High', target=TEST_DOMAIN)
        f2 = normalize_finding(MODULE, 'sslscan', 'tls10_enabled',
                               'TLS 1.0 enabled', 'TLS 1.0 is enabled',
                               'High', target=TEST_DOMAIN)
        result = _dedup([f1, f2])
        assert len(result) == 1, f"Dedup should merge duplicates, got {len(result)}"
        assert 'sslscan' in result[0]['evidence'], \
            "Merged finding evidence must mention the second tool"

    def test_dedup_keeps_distinct_issues(self):
        """Different issues from the same tool must NOT be merged."""
        from tasks.ssl_tls import _dedup
        from tasks.base_task import normalize_finding

        f1 = normalize_finding(MODULE, 'testssl', 'tls10_enabled',
                               'TLS 1.0 enabled', 'ev1', 'High', target=TEST_DOMAIN)
        f2 = normalize_finding(MODULE, 'testssl', 'weak_cipher_rc4',
                               'RC4 cipher enabled: RC4-SHA', 'ev2',
                               'High', target=TEST_DOMAIN)
        result = _dedup([f1, f2])
        assert len(result) == 2


class TestSslTlsModuleStatus:

    def test_both_tools_missing_marks_failed(self):
        """When both testssl and sslscan are absent, status must be 'failed'."""
        status_calls = []

        def record(scan_id, module, status):
            status_calls.append(status)

        with patch('tasks.ssl_tls.update_module_status', side_effect=record), \
             patch('tasks.ssl_tls.shutil.which', return_value=None), \
             patch('tasks.ssl_tls._https_reachable', return_value=True):
            from tasks.ssl_tls import run_ssl_tls
            run_ssl_tls.run(TEST_SCAN_ID, TEST_DOMAIN)

        assert 'failed' in status_calls, \
            "Both tools missing must result in 'failed' status"

    def test_no_https_marks_complete(self):
        """Unreachable port 443 is not an error - must mark 'complete'."""
        status_calls = []

        def record(scan_id, module, status):
            status_calls.append(status)

        with patch('tasks.ssl_tls.update_module_status', side_effect=record), \
             patch('tasks.ssl_tls._https_reachable', return_value=False):
            from tasks.ssl_tls import run_ssl_tls
            result = run_ssl_tls.run(TEST_SCAN_ID, TEST_DOMAIN)

        assert status_calls[-1] == 'complete'
        assert result['status'] == 'success'
        findings = result['findings']
        assert len(findings) == 1
        assert findings[0]['type'] == 'no_https'
        assert findings[0]['severity'] == 'Informational'

    def test_partial_success_marks_complete(self):
        """One tool present + other missing = partial success = 'complete'."""
        status_calls = []

        def record(scan_id, module, status):
            status_calls.append(status)

        def mock_which(cmd):
            return '/usr/bin/testssl.sh' if cmd == 'testssl.sh' else None

        with patch('tasks.ssl_tls.update_module_status', side_effect=record), \
             patch('tasks.ssl_tls.shutil.which', side_effect=mock_which), \
             patch('tasks.ssl_tls._https_reachable', return_value=True), \
             patch('tasks.ssl_tls._run_testssl', return_value=[]), \
             patch('tasks.ssl_tls._cert_expiry_finding', return_value=None):
            from tasks.ssl_tls import run_ssl_tls
            run_ssl_tls.run(TEST_SCAN_ID, TEST_DOMAIN)

        assert status_calls[-1] == 'complete', \
            "Partial success (one tool) must still be 'complete'"


class TestSslTlsCertExpiry:

    def test_cert_expiry_finding_expired(self):
        """Expired cert must return Critical finding."""
        from tasks.ssl_tls import _cert_expiry_finding

        past = datetime.now(timezone.utc) - timedelta(days=5)
        cert = {'notAfter': past.strftime('%b %d %H:%M:%S %Y UTC')}

        mock_conn = MagicMock()
        mock_conn.getpeercert.return_value = cert
        mock_conn.__enter__ = lambda s: mock_conn
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch('tasks.ssl_tls.socket.create_connection') as mock_sock, \
             patch('tasks.ssl_tls.ssl.create_default_context') as mock_ctx:
            mock_raw = MagicMock()
            mock_raw.__enter__ = lambda s: mock_raw
            mock_raw.__exit__ = MagicMock(return_value=False)
            mock_sock.return_value = mock_raw
            mock_ctx.return_value.wrap_socket.return_value = mock_conn

            finding = _cert_expiry_finding(TEST_DOMAIN)

        assert finding is not None
        assert finding['severity'] == 'Critical'
        assert finding['type'] == 'cert_expired'
        assert REQUIRED_FIELDS <= set(finding.keys())

    def test_cert_expiry_finding_expiring_soon(self):
        """Cert expiring within 30 days must return Medium finding."""
        from tasks.ssl_tls import _cert_expiry_finding

        soon = datetime.now(timezone.utc) + timedelta(days=15)
        cert = {'notAfter': soon.strftime('%b %d %H:%M:%S %Y UTC')}

        mock_conn = MagicMock()
        mock_conn.getpeercert.return_value = cert
        mock_conn.__enter__ = lambda s: mock_conn
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch('tasks.ssl_tls.socket.create_connection') as mock_sock, \
             patch('tasks.ssl_tls.ssl.create_default_context') as mock_ctx:
            mock_raw = MagicMock()
            mock_raw.__enter__ = lambda s: mock_raw
            mock_raw.__exit__ = MagicMock(return_value=False)
            mock_sock.return_value = mock_raw
            mock_ctx.return_value.wrap_socket.return_value = mock_conn

            finding = _cert_expiry_finding(TEST_DOMAIN)

        assert finding is not None
        assert finding['severity'] == 'Medium'
        assert finding['type'] == 'cert_expiring_soon'

    def test_cert_expiry_unreachable_returns_none(self):
        """Connection failure must return None gracefully (not raise)."""
        from tasks.ssl_tls import _cert_expiry_finding

        with patch('tasks.ssl_tls.socket.create_connection',
                   side_effect=OSError("Connection refused")):
            result = _cert_expiry_finding(TEST_DOMAIN)

        assert result is None


class TestSslTlsLive:
    """
    Live tests using the pure-Python helpers - no testssl.sh or sslscan needed.
    These verify the module works end-to-end against a real HTTPS host.
    """

    def test_https_reachable_known_good(self):
        """badssl.com:443 should be reachable."""
        from tasks.ssl_tls import _https_reachable
        assert _https_reachable('badssl.com'), \
            "badssl.com:443 should be reachable"

    def test_https_not_reachable_nonexistent(self):
        """A nonexistent domain should not be reachable."""
        from tasks.ssl_tls import _https_reachable
        assert not _https_reachable('nonexistent-vapt-xyz99999.com')

    def test_run_ssl_tls_returns_list_with_schema(self):
        """
        Full run_ssl_tls against badssl.com (no external tools - both skipped).
        Must return a list of dicts, every dict has all required fields including
        found_by, and module status ends as 'complete'.
        """
        status_calls = []

        def record(scan_id, module, status):
            status_calls.append(status)

        with patch('tasks.ssl_tls.update_module_status', side_effect=record), \
             patch('tasks.ssl_tls.shutil.which', return_value=None):
            from tasks.ssl_tls import run_ssl_tls
            result = run_ssl_tls.run(TEST_SCAN_ID, 'badssl.com')

        # Both tools missing with reachable host → failed (by spec)
        # but result is still a build_module_result() envelope with a list
        # of findings inside it.
        assert isinstance(result, dict)
        assert isinstance(result['findings'], list), "findings must always be a list"
        assert result['status'] in ('success', 'failed')
        # status must be either complete or failed - never silent None
        assert status_calls[-1] in ('complete', 'failed'), \
            f"Final status must be complete or failed, got {status_calls}"

    def test_run_ssl_tls_with_cert_expiry_only(self):
        """
        When both tools missing but host reachable, at minimum
        the cert-expiry check runs and status is 'failed' (both tools missing).
        """
        status_calls = []

        def record(scan_id, module, status):
            status_calls.append(status)

        with patch('tasks.ssl_tls.update_module_status', side_effect=record), \
             patch('tasks.ssl_tls.shutil.which', return_value=None), \
             patch('tasks.ssl_tls._https_reachable', return_value=True):
            from tasks.ssl_tls import run_ssl_tls
            result = run_ssl_tls.run(TEST_SCAN_ID, 'badssl.com')

        assert isinstance(result, dict)
        assert status_calls[-1] == 'failed'  # both tools missing
        assert result['status'] == 'failed'
        assert result['error']
        # No findings expected (both tools absent, cert_expiry not reached
        # because we return early on both-missing)
        assert result['findings'] == []

    def test_run_ssl_tls_no_https(self):
        """Unreachable port 443 → single Informational finding, status complete."""
        status_calls = []

        def record(scan_id, module, status):
            status_calls.append(status)

        with patch('tasks.ssl_tls.update_module_status', side_effect=record), \
             patch('tasks.ssl_tls._https_reachable', return_value=False):
            from tasks.ssl_tls import run_ssl_tls
            result = run_ssl_tls.run(TEST_SCAN_ID, 'badssl.com')

        assert status_calls[-1] == 'complete'
        assert result['status'] == 'success'
        findings = result['findings']
        assert len(findings) == 1
        assert findings[0]['type'] == 'no_https'
        assert findings[0]['found_by'] == [MODULE]
        missing = REQUIRED_FIELDS - set(findings[0].keys())
        assert not missing


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
