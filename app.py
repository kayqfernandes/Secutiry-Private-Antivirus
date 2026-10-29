"""Compatibility entry point for the security analyzer."""
import sys

from src.security_analyzer.core.models import APP_NAME, Finding, classify, is_executable, is_temp_candidate, sha256_file, temp_roots
from src.security_analyzer.core.scanner import Scanner
from src.security_analyzer.integrations.authenticode import powershell, signature_status
from src.security_analyzer.integrations.defender import defender_scan
from src.security_analyzer.integrations.drives import drives
from src.security_analyzer.integrations.reputation import reputation_lookup
from src.security_analyzer.integrations.startup import startup_entries
from src.security_analyzer.remediation.registry import matching_startup_values
from resource.designer import App


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-check"]:
        from src.security_analyzer.selfcheck import run
        raise SystemExit(run())
    App().mainloop()
