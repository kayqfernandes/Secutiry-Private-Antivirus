"""Structured JSON report creation and writing."""
from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

def build_report(findings,scan_summary=None) -> dict:
    labels=("Perigoso","Alto risco","Suspeito","Baixo risco","Inconclusivo")
    summary={risk:sum(f.risk==risk for f in findings) for risk in labels}
    decisions={label:sum(f.manual_classification==label for f in findings) for label in ("Perigoso","Baixo risco")}
    rows=[]
    for finding in findings:
        row=asdict(finding)
        row.pop("file_identity",None)
        rows.append(row)
    return {"generated_at":datetime.now(timezone.utc).isoformat(),"summary":summary,"manual_decisions":decisions,"scan_summary":asdict(scan_summary) if scan_summary else None,"findings":rows}

def write_report(target: str,payload: dict) -> None:
    Path(target).write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding="utf-8")
