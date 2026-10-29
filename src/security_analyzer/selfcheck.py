"""Safe runtime check used to validate a packaged Windows build."""
from __future__ import annotations
import threading
import tempfile
from pathlib import Path
from .core.scanner import Scanner

def run() -> int:
    """Exercise local scanning on a disposable fixture; never touches user files."""
    try:
        with tempfile.TemporaryDirectory(prefix="security-analyzer-selfcheck-") as temporary:
            base=Path(temporary)
            root=base/"fixture"
            root.mkdir()
            sample=root/"smoke-check.txt"
            sample.write_bytes(b"packaged application self-check")
            scanner=Scanner(base/"audit.jsonl")
            findings,count,cancelled,_summary=scanner.scan([str(root)],lambda *_:None,threading.Event())
            if cancelled or count!=1 or len(findings)!=1 or findings[0].path!=str(sample):
                return 2
            if not findings[0].sha256:
                return 3
        return 0
    except Exception:
        return 1
