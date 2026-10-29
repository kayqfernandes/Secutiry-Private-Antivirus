"""Data models and local, explainable classification helpers."""
from __future__ import annotations
import hashlib, os, stat
from dataclasses import dataclass
from pathlib import Path
APP_NAME = "Analisador de Segurança Pessoal"
EXECUTABLES = {".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"}
TEMP_MARKERS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\")

@dataclass
class Finding:
    path: str
    sha256: str = ""
    kind: str = "Arquivo"
    signature: str = "Não verificada"
    risk: str = "Inconclusivo"
    reasons: str = ""
    reputation: str = "Não consultada"
    manual_classification: str = ""
    source: str = "Análise local"
    file_identity: str = ""
    size_bytes: int | None = None
    modified_time: float | None = None

@dataclass
class ScanSummary:
    files_seen: int = 0
    unreadable_files: int = 0
    changed_files: int = 0
    inaccessible_directories: int = 0
    unavailable_roots: int = 0
    skipped_reparse_points: int = 0
    skipped_outside_root: int = 0
    startup_items_found: int = 0
    startup_errors: int = 0

def is_link_or_reparse_point(path: str) -> bool:
    """Return true for symlinks and Windows reparse points (junctions, etc.)."""
    if os.path.islink(path):
        return True
    try:
        attributes = getattr(os.stat(path, follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return False
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_attribute)
def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): digest.update(block)
    return digest.hexdigest()

def is_sha256_digest(value: str) -> bool:
    return isinstance(value,str) and len(value)==64 and all(char in "0123456789abcdefABCDEF" for char in value)

def file_identity(path: str) -> str:
    """Return a path-independent snapshot key plus metadata for regular files."""
    if is_link_or_reparse_point(path):
        raise OSError("Arquivo é link ou ponto de nova análise.")
    info=os.stat(path,follow_symlinks=False)
    return file_identity_from_stat(info)

def file_identity_from_stat(info) -> str:
    attributes=getattr(info,"st_file_attributes",0)
    if attributes & getattr(stat,"FILE_ATTRIBUTE_REPARSE_POINT",0x400):
        raise OSError("Arquivo é link ou ponto de nova análise.")
    if not stat.S_ISREG(info.st_mode):
        raise OSError("Caminho não é arquivo regular.")
    return f"{info.st_dev}:{info.st_ino}:{info.st_size}:{info.st_mtime_ns}"

def is_executable(path: str) -> bool: return Path(path).suffix.lower() in EXECUTABLES

def temp_roots() -> list[str]:
    roots=[os.environ.get("TEMP"),os.environ.get("TMP"),os.path.join(os.environ.get("LOCALAPPDATA",""),"Temp"),os.path.join(os.environ.get("WINDIR",r"C:\Windows"),"Temp")]
    return list(dict.fromkeys(os.path.abspath(p) for p in roots if p and os.path.isdir(p)))

def is_temp_candidate(path: str) -> bool:
    p=os.path.normcase(os.path.abspath(path))
    for root in temp_roots():
        try:
            r=os.path.normcase(os.path.abspath(root))
            if os.path.commonpath((p,r))==r:return True
        except (ValueError,OSError):pass
    return any(marker in path.lower() for marker in TEMP_MARKERS)

def classify(path: str, signature: str="Não verificada", defender_hit: bool=False, hash_ok: bool=True) -> tuple[str,str,str]:
    executable=is_executable(path)
    if defender_hit:return "Alto risco","Uma detecção disponível do Microsoft Defender menciona este caminho; confira data e detalhes.","Executável" if executable else "Arquivo"
    if not hash_ok:return "Inconclusivo","Não foi possível calcular o hash; o arquivo pode estar inacessível ou ter mudado.","Executável" if executable else "Arquivo"
    reasons=[]
    if executable and is_temp_candidate(path):reasons.append("Executável em uma pasta temporária.")
    if signature=="Inválida":reasons.append("Assinatura digital inválida ou não confiável segundo o Windows.")
    elif executable and signature=="Não assinada":reasons.append("Executável sem assinatura digital verificada.")
    if reasons:return "Suspeito"," ".join(reasons)+" Isso requer análise; não confirma malware.","Executável" if executable else "Arquivo"
    if executable and signature=="Válida":return "Baixo risco","Assinatura válida segundo o Windows; isso não garante que o arquivo seja seguro.","Executável"
    return "Inconclusivo","Nenhuma detecção local conhecida; não é possível concluir que o arquivo é seguro.","Executável" if executable else "Arquivo"

