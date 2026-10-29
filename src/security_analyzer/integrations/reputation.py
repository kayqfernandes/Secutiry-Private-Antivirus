"""Optional hash-only reputation lookup."""
from __future__ import annotations
import json, urllib.request

def reputation_lookup(digest: str,api_key: str) -> str:
    req=urllib.request.Request("https://www.virustotal.com/api/v3/files/"+digest,headers={"x-apikey":api_key,"Accept":"application/json"})
    with urllib.request.urlopen(req,timeout=12) as response:data=json.loads(response.read().decode("utf-8"))
    stats=data.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
    return f"VirusTotal: {stats.get('malicious',0)} detecção(ões), {stats.get('suspicious',0)} suspeita(s) (terceiros)."
