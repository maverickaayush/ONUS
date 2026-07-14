"""tasks/dispatch.py - the local/Modal routing seam and its failure behavior.

Modal is mocked throughout, so these run without a Modal account or network."""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tasks import dispatch
from tasks.dispatch import dispatch_scan, _pure_fn, _MODULE_FILE
from tasks.base_task import SCAN_MODULE_IDS


class TestPureResolution:
    def test_every_module_resolves_to_its_pure_half(self):
        for mid in SCAN_MODULE_IDS:
            fn = _pure_fn(mid)
            assert fn.__name__ == f'scan_{mid}'

    def test_nuclei_id_maps_to_nuclei_scan_file(self):
        # the one id whose file name differs
        assert _MODULE_FILE['nuclei'] == 'nuclei_scan'
        assert _pure_fn('nuclei').__module__ == 'tasks.nuclei_scan'


class TestLocalRouting:
    def test_local_runs_pure_half_in_process(self):
        envelope = {'module': 'headers', 'status': 'success', 'findings': []}
        fake = MagicMock(return_value=envelope)
        with patch.object(dispatch.settings, 'SCANNER_BACKEND', 'local'), \
             patch('tasks.dispatch._pure_fn', return_value=fake):
            out = dispatch_scan('headers', 'sid', 'example.com')
        assert out is envelope
        fake.assert_called_once_with('sid', 'example.com', None)

    def test_auth_fetched_and_passed_only_for_auth_modules(self):
        fake = MagicMock(return_value={'status': 'success'})
        with patch.object(dispatch.settings, 'SCANNER_BACKEND', 'local'), \
             patch('tasks.dispatch._pure_fn', return_value=fake), \
             patch('tasks.auth_store.get_scan_auth', return_value={'u': 'p'}) as ga:
            dispatch_scan('owasp', 'sid', 'example.com')   # auth module
            ga.assert_called_once()
            assert fake.call_args[0][2] == {'u': 'p'}
        fake.reset_mock()
        with patch.object(dispatch.settings, 'SCANNER_BACKEND', 'local'), \
             patch('tasks.dispatch._pure_fn', return_value=fake), \
             patch('tasks.auth_store.get_scan_auth') as ga2:
            dispatch_scan('headers', 'sid', 'example.com')  # non-auth module
            ga2.assert_not_called()
            assert fake.call_args[0][2] is None


class TestModalRouting:
    def test_modal_backend_calls_remote(self):
        # modal is imported lazily inside _run_modal; inject a fake module so
        # `import modal` there resolves without the real SDK installed.
        envelope = {'module': 'recon', 'status': 'success', 'findings': []}
        fake_fn = MagicMock()
        fake_fn.remote.return_value = envelope
        fake_modal = MagicMock()
        fake_modal.Function.from_name.return_value = fake_fn
        with patch.object(dispatch.settings, 'SCANNER_BACKEND', 'modal'), \
             patch.dict('sys.modules', {'modal': fake_modal}):
            out = dispatch_scan('recon', 'sid', 'example.com')
        assert out is envelope
        fake_fn.remote.assert_called_once_with('sid', 'example.com', None)
        fake_modal.Function.from_name.assert_called_once_with(
            dispatch.settings.MODAL_APP_NAME, 'scan_recon')


class TestFailureBecomesEnvelope:
    def test_modal_error_becomes_failed_envelope(self):
        with patch.object(dispatch.settings, 'SCANNER_BACKEND', 'modal'), \
             patch('tasks.dispatch._run_modal', side_effect=RuntimeError('boom')):
            out = dispatch_scan('nuclei', 'sid', 'example.com')
        assert out['status'] == 'failed'
        assert out['module'] == 'nuclei'
        assert 'RuntimeError' in out['error']
        assert out['findings'] == []

    def test_modal_timeout_becomes_timeout_envelope(self):
        class FunctionTimeoutError(Exception):
            pass
        with patch.object(dispatch.settings, 'SCANNER_BACKEND', 'modal'), \
             patch('tasks.dispatch._run_modal', side_effect=FunctionTimeoutError('deadline')):
            out = dispatch_scan('webscan', 'sid', 'example.com')
        # 'timeout' in the exception class name -> status='timeout' (so the
        # orchestrator's decision-flow treats it as a timeout, not a crash)
        assert out['status'] == 'timeout'

    def test_local_pure_half_raising_becomes_failed_envelope(self):
        # scan_X normally catches its own errors, but dispatch is the last net.
        with patch.object(dispatch.settings, 'SCANNER_BACKEND', 'local'), \
             patch('tasks.dispatch._pure_fn', return_value=MagicMock(side_effect=ValueError('x'))):
            out = dispatch_scan('ssl_tls', 'sid', 'example.com')
        assert out['status'] == 'failed'
        assert 'ValueError' in out['error']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
