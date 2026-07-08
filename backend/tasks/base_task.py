import logging
import re
import shutil
import subprocess
from typing import Optional

from celery import Task

from config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical scan-module list - the single source of truth for "what modules
# exist." Order matches scan_orchestrator.py's scanning_group() dispatch
# order. Every place that previously hardcoded its own copy of these 8
# module names (scan_orchestrator.py's and routers/scan.py's module_statuses
# initializers, the GET /api/scan/modules endpoint the frontend's module
# list and stepper are wired to) now derives from this list instead - see
# ARCHITECTURE.md Section 4.3 for where to register a 9th module.
#
# icon_hint is a semantic category, not a specific icon file - the frontend
# maps known hints to bespoke icons and falls back to a generic icon for any
# hint it doesn't recognize yet, so a new module here renders correctly on
# day one without a matching frontend code change.
# ---------------------------------------------------------------------------
SCAN_MODULES = [
    {'id': 'recon', 'label': 'Recon', 'icon_hint': 'network',
     'description': 'DNS enumeration, subdomain discovery, WHOIS lookups, and open port detection.'},
    {'id': 'webscan', 'label': 'Web Scan', 'icon_hint': 'web',
     'description': 'Active vulnerability scanning via OWASP ZAP and Nikto, plus JS-aware crawling with Katana.'},
    {'id': 'ssl_tls', 'label': 'SSL/TLS', 'icon_hint': 'lock',
     'description': 'Certificate validity, cipher strength, protocol versions, and HSTS enforcement.'},
    {'id': 'headers', 'label': 'Headers', 'icon_hint': 'list',
     'description': 'Checks all security response headers: CSP, X-Frame-Options, HSTS, CORS, and more.'},
    {'id': 'owasp', 'label': 'OWASP Top 10', 'icon_hint': 'alert',
     'description': 'Tests for injection, broken auth, XSS, IDOR, security misconfigurations, and open redirects.'},
    {'id': 'tech_fingerprint', 'label': 'Tech Fingerprint', 'icon_hint': 'fingerprint',
     'description': 'Identifies CMS, frameworks, and outdated software; detects WAF presence.'},
    {'id': 'nuclei', 'label': 'Nuclei CVE Scan', 'icon_hint': 'target',
     'description': 'Template-based scanning for known CVEs, misconfigurations, and exposed panels.'},
    {'id': 'enumeration', 'label': 'Dir Enumeration', 'icon_hint': 'folder',
     'description': 'Brute-forces hidden files, directories, and admin panels via FFUF.'},
]
SCAN_MODULE_IDS = [m['id'] for m in SCAN_MODULES]

# Several ProjectDiscovery/CLI tools (subfinder, nuclei, sslscan, wafw00f)
# color their --version/-version output even with stdout piped to a
# non-tty subprocess - the raw escape bytes otherwise leak straight into
# the report's Tool Versions table. Matches any CSI sequence (SGR color
# is the common case, but this covers the general form), not just 'm'.
_ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

# httpx/naabu/katana/wafw00f print a multi-line ASCII-art banner BEFORE
# their real version line (confirmed by running each inside the worker
# container) - taking line 0 grabs a banner fragment instead. Matches
# either the word "version" (subfinder/nuclei/httpx/naabu/katana/nmap/
# whois/ffuf/wafw00f all say it somewhere in their real version line) or
# a bare dotted-number token (sslscan/nikto/amass, which don't). ASCII-art
# side-decorations (e.g. wafw00f's "404 Hack Not Found") never match
# either - no literal dot between digits, no literal word "version".
_VERSION_LINE_RE = re.compile(r'version|\bv?\d+\.\d+', re.IGNORECASE)


def scaled_timeout(base_seconds: int) -> int:
    """
    Scale a module's tool subprocess timeout or Celery soft/hard limit by
    config.SCAN_TIMEOUT_MULTIPLIER (default 1.5x over the original lab-tuned
    baselines - see config.py). Every module timeout should route through
    this instead of hardcoding its own real-world-adjusted number, so the
    whole scan's patience is one env-tunable knob.
    """
    return max(base_seconds, round(base_seconds * settings.SCAN_TIMEOUT_MULTIPLIER))


def mount_retry_adapter(session, total: int = 2, backoff_factor: float = 0.5):
    """
    Real-world hosts often sit behind a WAF/CDN that throttles with 429/503
    under sustained scan traffic - without a retry, a transient throttle
    response partway through a scan silently reads as "page returned 429",
    which for owasp.py's active tests means a genuine vulnerability on that
    page can go undetected (a false negative indistinguishable from a clean
    result). Retries idempotent-safe methods only (GET/HEAD/OPTIONS) with
    backoff - a scanning module doing a one-shot POST login (auth_login.py)
    should not blindly retry that, so this is opt-in per session, not global.
    Returns the same session for chaining.
    """
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    retry = Retry(
        total=total, backoff_factor=backoff_factor,
        status_forcelist=[429, 502, 503, 504],
        allowed_methods=['GET', 'HEAD', 'OPTIONS'],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def resolve_target_url(domain: str, timeout: int = 10) -> str:
    """
    Try https first, fall back to http on any connection-level failure -
    the shared entry point every module's target URL should route through
    instead of hardcoding f'https://{domain}'. Mirrors headers.py's original
    inline https-then-http probe (Section 4.3.4), which is why headers.py
    alone kept finding real results against HTTP-only targets while every
    other web-facing module (webscan/owasp/tech_fingerprint/nuclei/
    enumeration) silently no-op'd - each hardcoded https unconditionally,
    so a target with nothing listening on 443 always failed their first
    request and returned empty findings, indistinguishable from a clean scan.
    Both schemes failing returns 'https://{domain}' unchanged - the caller's
    own request will fail too and each module already reports that
    gracefully (an Informational 'unreachable' finding, not a crash).

    Uses the *final* response's scheme (post-redirects), not the scheme
    requested - a plain 'http://{domain}' probe that 301s to https is common
    (e.g. an HSTS redirect), and returning 'http://...' in that case would
    make every downstream module eat a redirect hop on its first request,
    and silently break checks that intentionally disable redirects to
    detect them (owasp.py's open_redirect test). The host itself is never
    replaced with wherever the redirect chain lands - only the scheme is
    taken from it - since scanning whatever host a redirect points to,
    rather than the authorized domain, would silently widen scan scope.
    """
    import requests
    from urllib.parse import urlsplit

    for scheme in ('https', 'http'):
        try:
            resp = requests.get(f'{scheme}://{domain}', timeout=timeout, verify=False,
                                 allow_redirects=True)
            final_scheme = urlsplit(resp.url).scheme or scheme
            return f'{final_scheme}://{domain}'
        except requests.exceptions.SSLError:
            continue
        except Exception:
            continue
    return f'https://{domain}'


def get_tool_version(tool: str, *version_flags: str, timeout: int = 5) -> str:
    """
    Return the first line of `tool <version_flags>` output that actually
    looks like a version string (see _VERSION_LINE_RE), falling back to
    the literal first line if no line matches, or 'not installed'/'unknown'
    as before. Every scanning module uses this to build its own
    tool_versions dict - call once per module run, not once per finding.
    """
    if not shutil.which(tool):
        return 'not installed'
    try:
        r = subprocess.run([tool, *version_flags], capture_output=True,
                            timeout=timeout, check=False)
        raw = (r.stdout or r.stderr or b'').decode(errors='ignore')
        out = _ANSI_ESCAPE_RE.sub('', raw).strip()
        if not out:
            return 'unknown'
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if not lines:
            return 'unknown'
        return next((l for l in lines if _VERSION_LINE_RE.search(l)), lines[0])
    except Exception:
        return 'unknown'


def build_module_result(module: str, findings: list, tool_versions: Optional[dict] = None,
                         status: str = 'success', error: Optional[str] = None,
                         duration_seconds: float = 0.0) -> dict:
    """
    Envelope every scanning module's Celery task returns, instead of a bare
    findings list. Lets the aggregator report which tools actually ran
    (Section 4.4) and makes module execution status visible instead of a
    failed module silently looking identical to a clean scan.

    status is one of 'success' | 'failed' | 'timeout' - never invented
    beyond what the module can actually observe about itself.
    """
    return {
        'module': module,
        'status': status,
        'findings': findings,
        'tool_versions': tool_versions or {},
        'finding_count': len(findings),
        'duration_seconds': round(duration_seconds, 2),
        'error': error,
    }


def update_module_status(scan_id: str, module_name: str, status: str) -> None:
    """
    Write a single module's status update directly to the DB.

    Real bug found live (browser-driven test against a real scan): all 8
    modules run concurrently and each independently calls this function -
    a plain Python read-modify-write (read the whole module_statuses dict,
    mutate one key, write the whole dict back) loses updates under that
    concurrency. A fast module (e.g. headers, unreachable-target fast path)
    can write 'complete', then a slower module that had already read an
    OLDER snapshot of the dict writes its own update afterward, overwriting
    the fast module's status back to stale data - observed live as a scan
    showing 'complete' overall while one module stayed stuck at 'running'
    forever. Uses Postgres's jsonb_set in a single atomic UPDATE instead of
    a read-then-write round trip, so concurrent callers can never clobber
    each other's key.
    """
    from database import SessionLocal
    from models import Scan
    from sqlalchemy import text

    db = SessionLocal()
    try:
        db.execute(
            text(
                "UPDATE scans SET module_statuses = "
                "jsonb_set(coalesce(module_statuses, '{}'::jsonb), ARRAY[CAST(:module_name AS text)], to_jsonb(CAST(:status AS text))) "
                "WHERE id = :scan_id"
            ),
            {"module_name": module_name, "status": status, "scan_id": scan_id},
        )
        db.commit()
    except Exception as e:
        logger.error("update_module_status failed scan=%s module=%s: %s", scan_id, module_name, e)
    finally:
        db.close()


def normalize_finding(
    module: str,
    tool: str,
    type_: str,
    title: str,
    evidence: str,
    severity: str = 'Info',
    cvss: float = 0.0,
    target: str = '',
    confidence: str = 'probable',
    verifiable: bool = False,
    verification_target: Optional[dict] = None,
) -> dict:
    """
    Return a normalized finding dict matching the Section 4.3 schema.
    Every scanning module must use this helper - the aggregator depends on
    the presence of found_by and the exact field names.

    confidence: 'confirmed' | 'probable' | 'unverified' - the module's own
    baseline call. 'confirmed' means the module already has definitive proof
    (e.g. a DBMS error string) with no verifier dispatch needed. 'probable'
    (default) is the normal case for a module-level signal that could be a
    false positive. verifiable/verification_target opt a finding into the
    verify_findings() re-observation stage (analysis/verifier.py).
    """
    return {
        'module': module,
        'tool': tool,
        'type': type_,
        'title': title,
        'evidence': str(evidence)[:500],
        'severity': severity,
        'cvss': cvss,
        'target': target,
        'found_by': [module],
        'confidence': confidence,
        'verifiable': verifiable,
        'verification_target': verification_target,
    }


class BaseTask(Task):
    """
    Shared Celery base task for all five scanning modules.

    Scanning modules register with ``base=BaseTask`` and import the helpers
    via the contract line:

        from tasks.base_task import BaseTask, normalize_finding, update_module_status

    The helpers are also exposed as static methods (``self.normalize_finding``,
    ``self.update_module_status``). ``on_failure`` is a logging safety net -
    each module is still expected to catch its own exceptions, mark itself
    ``failed`` and return ``[]`` so the chord callback always fires with all
    five results.
    """
    abstract = True

    normalize_finding = staticmethod(normalize_finding)
    update_module_status = staticmethod(update_module_status)

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        logger.error("Scanning task %s failed (task_id=%s): %s", self.name, task_id, exc)
