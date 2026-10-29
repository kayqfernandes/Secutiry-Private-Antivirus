"""Append-only local audit log writer."""
from __future__ import annotations
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

MAX_AUDIT_BYTES=5*1024*1024
_AUDIT_LOCK=threading.Lock()

def write_audit_event(audit_path: Path,event: str,details: dict):
    line=json.dumps({"time":datetime.now(timezone.utc).isoformat(),"event":event,"details":details},ensure_ascii=False)+"\n"
    encoded_size=len(line.encode("utf-8"))
    with _AUDIT_LOCK:
        audit_path.parent.mkdir(parents=True,exist_ok=True)
        if audit_path.exists() and audit_path.stat().st_size+encoded_size>MAX_AUDIT_BYTES:
            backup=audit_path.with_name(audit_path.name+".1")
            if backup.exists():backup.unlink()
            audit_path.replace(backup)
        with audit_path.open("a",encoding="utf-8") as stream:
            stream.write(line)
