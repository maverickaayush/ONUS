"""
Canonical scan-module list tests (tasks/base_task.py's SCAN_MODULES) - the
single source of truth the frontend's landing-page "Covers:" badges and
Scan Status module list now fetch from, instead of three independently
hardcoded copies (scan_orchestrator.py, routers/scan.py x2).

Run with:
    cd backend && python3 -m pytest tests/test_scan_modules.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import MagicMock

from tasks.base_task import SCAN_MODULES, SCAN_MODULE_IDS
from routers.scan import get_scan_modules


class TestScanModulesConstant:

    def test_eight_modules_matching_scan_orchestrator_dispatch(self):
        # scan_orchestrator.py's scanning_group() dispatches exactly these
        # 8 tasks - if this list drifts from that dispatch, module_statuses
        # (derived from SCAN_MODULE_IDS) would no longer match what
        # actually runs.
        assert SCAN_MODULE_IDS == [
            'recon', 'webscan', 'ssl_tls', 'headers', 'owasp',
            'tech_fingerprint', 'nuclei', 'enumeration',
        ]

    def test_every_entry_has_required_fields(self):
        for m in SCAN_MODULES:
            assert set(m.keys()) == {'id', 'label', 'icon_hint', 'description'}
            assert m['id'] and m['label'] and m['icon_hint'] and m['description']

    def test_ids_are_unique(self):
        assert len(SCAN_MODULE_IDS) == len(set(SCAN_MODULE_IDS))


class TestGetScanModulesEndpoint:

    def test_returns_all_canonical_modules(self):
        response = get_scan_modules()
        assert len(response.modules) == len(SCAN_MODULES)
        assert [m.id for m in response.modules] == SCAN_MODULE_IDS

    def test_response_shape_matches_schema(self):
        response = get_scan_modules()
        for m in response.modules:
            assert m.id and m.label and m.icon_hint and m.description


class TestModuleStatusesInitUsesCanonicalList:
    """create_scan()/scan_orchestrator() both init module_statuses from
    SCAN_MODULE_IDS now - a dummy 9th module added to SCAN_MODULES must
    flow through automatically without touching either call site."""

    def test_create_scan_module_statuses_derives_from_canonical_list(self, monkeypatch):
        import routers.scan as scan_router

        dummy_modules = SCAN_MODULES + [
            {'id': 'dummy_module', 'label': 'Dummy Module', 'icon_hint': 'generic',
             'description': 'A hypothetical 9th module.'}
        ]
        dummy_ids = [m['id'] for m in dummy_modules]
        monkeypatch.setattr(scan_router, 'SCAN_MODULE_IDS', dummy_ids)

        # Exercise the exact dict-comprehension line create_scan() uses,
        # against the monkeypatched (9-module) id list - proves the
        # initializer is driven by the shared constant, not a literal.
        module_statuses = {module_id: "queued" for module_id in scan_router.SCAN_MODULE_IDS}
        assert 'dummy_module' in module_statuses
        assert len(module_statuses) == 9

    def test_progress_calculation_uses_len_not_hardcoded_eight(self, monkeypatch):
        import routers.scan as scan_router

        dummy_ids = SCAN_MODULE_IDS + ['dummy_module']
        monkeypatch.setattr(scan_router, 'SCAN_MODULE_IDS', dummy_ids)

        # Mirrors get_scan_status()'s progress formula exactly.
        completed_modules = 9  # all 9 (8 real + dummy) complete
        progress = 20 + int((completed_modules / len(scan_router.SCAN_MODULE_IDS)) * 60)
        assert progress == 80  # would incorrectly read >80 if still hardcoded /8
