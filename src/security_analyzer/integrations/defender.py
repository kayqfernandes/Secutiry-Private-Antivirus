"""Optional Microsoft Defender on-demand scan integration."""
from __future__ import annotations
import json
from .authenticode import powershell

def defender_scan(scan_type: str="FullScan",path: str|None=None) -> list[dict]:
    if scan_type=="CustomScan":start=f"Start-MpScan -ScanType CustomScan -ScanPath '{(path or '').replace(chr(39),chr(39)*2)}' -AsJob -ErrorAction Stop"
    else:start="Start-MpScan -ScanType FullScan -AsJob -ErrorAction Stop"
    command=f"""
$before = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | ForEach-Object {{ $_.DetectionID }})
$scanStarted = Get-Date
$job = {start}
$finished = Wait-Job -Job $job -Timeout 3500
if (-not $finished -or $job.State -ne 'Completed') {{ throw 'A verificação do Defender excedeu o tempo de espera.' }}
Receive-Job -Job $job -ErrorAction Stop | Out-Null
$rows = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object {{ $_.DetectionID -notin $before -and $_.InitialDetectionTime -ge $scanStarted }} | ForEach-Object {{
    [pscustomobject]@{{ detection_id=$_.DetectionID; detected_at=$_.InitialDetectionTime.ToUniversalTime().ToString('o'); resources=@($_.Resources) }}
}})
ConvertTo-Json -InputObject $rows -Compress -Depth 4
"""
    output=powershell(command,timeout=3600)
    try:parsed=json.loads(output) if output else []
    except json.JSONDecodeError:parsed=[]
    if isinstance(parsed,str):parsed=[parsed]
    if isinstance(parsed,dict):parsed=[parsed]
    return [x for x in parsed or [] if isinstance(x,dict)]
