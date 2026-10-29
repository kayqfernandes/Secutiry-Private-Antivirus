"""Filesystem traversal and per-file analysis."""
from __future__ import annotations
import os, threading, urllib.error
from pathlib import Path
from .models import Finding, ScanSummary, classify, file_identity, is_executable, is_link_or_reparse_point, sha256_file
from ..integrations.authenticode import signature_status
from ..integrations.reputation import reputation_lookup
from ..storage.audit import write_audit_event

class _ChangedDuringAnalysis(Exception):
    pass

class Scanner:
    def __init__(self,audit_path: Path):self.audit_path=audit_path
    def audit(self,event: str,details: dict):
        write_audit_event(self.audit_path,event,details)
    def scan(self,roots: list[str],callback,cancel: threading.Event,api_key=""):
        count=0;findings=[];summary=ScanSummary()
        for root in roots:
            root_path=os.path.abspath(root)
            if is_link_or_reparse_point(root_path):
                summary.skipped_reparse_points+=1
                continue
            canonical_root=os.path.realpath(root_path)
            if not os.path.isdir(canonical_root):
                summary.unavailable_roots+=1
                continue
            def on_walk_error(_error):
                summary.inaccessible_directories+=1
            for current,dirs,files in os.walk(canonical_root,onerror=on_walk_error,followlinks=False):
                if cancel.is_set():return findings,count,True,summary
                kept_dirs=[]
                for directory in dirs:
                    candidate=os.path.join(current,directory)
                    if is_link_or_reparse_point(candidate):
                        summary.skipped_reparse_points+=1
                    elif not _is_within_root(canonical_root,candidate):
                        summary.skipped_outside_root+=1
                    else:
                        kept_dirs.append(directory)
                dirs[:]=kept_dirs
                for filename in files:
                    if cancel.is_set():return findings,count,True,summary
                    path=os.path.join(current,filename)
                    if is_link_or_reparse_point(path):
                        summary.skipped_reparse_points+=1
                        continue
                    if not _is_within_root(canonical_root,path):
                        summary.skipped_outside_root+=1
                        continue
                    count+=1;summary.files_seen=count
                    file_stat=None
                    try:
                        identity=file_identity(path)
                        file_stat=os.stat(path,follow_symlinks=False)
                        digest=sha256_file(path)
                        executable=is_executable(path)
                        sig=signature_status(path) if executable else "N/A"
                        if file_identity(path)!=identity:
                            raise _ChangedDuringAnalysis("O arquivo foi substituído durante a verificação.")
                        if executable and sha256_file(path)!=digest:
                            raise _ChangedDuringAnalysis("O conteúdo mudou durante a verificação da assinatura.")
                        risk,why,kind=classify(path,sig)
                        rep="Não consultada"
                        if api_key:
                            try:rep=reputation_lookup(digest,api_key)
                            except urllib.error.HTTPError as e:rep=f"Consulta falhou (HTTP {e.code})."
                            except Exception:rep="Consulta falhou; sem resultado disponível."
                        if file_identity(path)!=identity:
                            raise _ChangedDuringAnalysis("O arquivo foi substituído durante a análise.")
                        finding=Finding(path,digest,kind,sig,risk,why,rep,file_identity=identity,
                                        size_bytes=file_stat.st_size,modified_time=file_stat.st_mtime)
                    except _ChangedDuringAnalysis as exc:
                        summary.changed_files+=1
                        finding=Finding(path,kind="Executável" if is_executable(path) else "Arquivo",risk="Inconclusivo",reasons=f"{exc} Hash e assinatura não podem ser associados com segurança.",size_bytes=file_stat.st_size if file_stat else None,modified_time=file_stat.st_mtime if file_stat else None)
                    except OSError as exc:
                        summary.unreadable_files+=1
                        risk,why,kind=classify(path,hash_ok=False);finding=Finding(path,"",kind,"Não verificada",risk,f"{why} {exc}",size_bytes=file_stat.st_size if file_stat else None,modified_time=file_stat.st_mtime if file_stat else None)
                    findings.append(finding);callback(finding,count)
        return findings,count,False,summary

def _is_within_root(root: str,path: str) -> bool:
    try:
        return os.path.commonpath((os.path.realpath(root),os.path.realpath(path)))==os.path.realpath(root)
    except (OSError,ValueError):
        return False
