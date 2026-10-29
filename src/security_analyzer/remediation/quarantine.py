"""File moves used by the explicit quarantine and restore actions."""
from __future__ import annotations
import json, os, uuid
from datetime import datetime, timezone
from pathlib import Path
from ..core.models import file_identity, is_link_or_reparse_point, is_sha256_digest, sha256_file
from .locked_file import LockedFile

def _reject_reparse_route(path: Path) -> None:
    absolute=Path(os.path.abspath(path))
    for component in (absolute,*absolute.parents):
        if os.path.lexists(component) and is_link_or_reparse_point(str(component)):
            raise OSError("O caminho de restauração contém link ou ponto de nova análise.")

def _write_manifest(metadata_path: Path,meta: dict) -> None:
    pending=metadata_path.with_name(metadata_path.name+".pending")
    with pending.open("x",encoding="utf-8") as stream:
        stream.write(json.dumps(meta,ensure_ascii=False,indent=2))
        stream.flush();os.fsync(stream.fileno())
    os.replace(pending,metadata_path)

def _remove_if_present(path: Path) -> None:
    try:path.unlink()
    except FileNotFoundError:pass

def quarantine_file(path: str,expected_sha256: str,expected_identity: str,quarantine_dir: Path) -> dict:
    source=Path(path)
    if not is_sha256_digest(expected_sha256):raise OSError("Hash de referência ausente ou inválido; faça uma nova varredura antes da quarentena.")
    if not expected_identity:raise OSError("Identidade do arquivo ausente; faça uma nova varredura antes da quarentena.")
    if quarantine_dir.exists() and is_link_or_reparse_point(str(quarantine_dir)):
        raise OSError("A pasta de quarentena não pode ser um link ou ponto de nova análise.")
    quarantine_dir.mkdir(parents=True,exist_ok=True);_reject_reparse_route(quarantine_dir)
    stored=quarantine_dir/(uuid.uuid4().hex+".quarantined");meta_path=quarantine_dir/(stored.stem+".json")
    meta={"original_path":str(source.resolve()),"quarantine_path":str(stored.resolve()),"sha256":expected_sha256.casefold(),"quarantined_at":datetime.now(timezone.utc).isoformat()}
    pending=meta_path.with_name(meta_path.name+".pending")
    with LockedFile(path) as locked:
        if locked.identity!=expected_identity:raise OSError("O arquivo foi substituído desde a análise; faça nova busca.")
        actual_sha256=locked.sha256()
        if actual_sha256.casefold()!=expected_sha256.casefold():raise OSError("Arquivo mudou desde a análise; faça nova busca.")
        if locked.volume_id==quarantine_dir.stat().st_dev:
            locked.rename_to(stored)
            try:
                _write_manifest(meta_path,meta)
            except OSError:
                try:locked.rename_to(source)
                except OSError as rollback_error:
                    raise OSError(f"Arquivo movido para {stored}, mas a gravação dos metadados e a reversão falharam: {rollback_error}")
                raise
        else:
            try:
                copied_sha256=locked.copy_to(stored)
                if copied_sha256.casefold()!=expected_sha256.casefold():raise OSError("O conteúdo mudou durante a cópia para quarentena.")
                _write_manifest(meta_path,meta)
                locked.delete()
            except OSError:
                _remove_if_present(stored);_remove_if_present(meta_path);_remove_if_present(pending)
                raise
    return meta

def inspect_quarantine_entry(metadata_path: Path,quarantine_dir: Path) -> dict:
    """Validate the manifest, quarantine containment, and stored-content hash."""
    if not quarantine_dir.is_dir() or is_link_or_reparse_point(str(quarantine_dir)):
        raise OSError("Pasta de quarentena inválida.")
    root=Path(os.path.realpath(quarantine_dir))
    if metadata_path.is_symlink() or is_link_or_reparse_point(str(metadata_path)):
        raise OSError("O manifesto da quarentena não pode ser um link.")
    if not metadata_path.is_file():
        raise OSError("Manifesto de quarentena não encontrado.")
    manifest=Path(os.path.realpath(metadata_path))
    if manifest.parent!=root or manifest.suffix.lower()!=".json":
        raise OSError("Manifesto fora da pasta de quarentena.")
    try:
        meta=json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as exc:
        raise OSError("Manifesto de quarentena inválido.") from exc
    if not isinstance(meta,dict):raise OSError("Manifesto de quarentena inválido.")
    source=root/(manifest.stem+".quarantined")
    recorded_source=meta.get("quarantine_path")
    if not isinstance(recorded_source,str) or os.path.normcase(os.path.abspath(recorded_source))!=os.path.normcase(str(source)):
        raise OSError("O caminho registrado não corresponde ao arquivo desta quarentena.")
    if not source.is_file() or is_link_or_reparse_point(str(source)):
        raise OSError("Arquivo em quarentena inválido ou ausente.")
    expected=meta.get("sha256","")
    if not isinstance(expected,str) or (expected and (len(expected)!=64 or any(c not in "0123456789abcdefABCDEF" for c in expected))):
        raise OSError("Hash inválido no manifesto de quarentena.")
    actual=sha256_file(str(source))
    if expected and actual.casefold()!=str(expected).casefold():
        raise OSError("O hash do arquivo em quarentena não confere com o manifesto.")
    original=meta.get("original_path")
    if not isinstance(original,str) or not Path(original).is_absolute():
        raise OSError("Caminho original inválido no manifesto.")
    destination=Path(os.path.abspath(original))
    try:
        if os.path.normcase(os.path.commonpath((str(root),str(destination))))==os.path.normcase(str(root)):
            raise OSError("O destino de restauração não pode ficar dentro da quarentena.")
    except ValueError:
        pass
    _reject_reparse_route(destination)
    return {"metadata_path":manifest,"source":source,"destination":destination,"meta":meta,"legacy_hash_missing":not bool(expected)}

def restore_file(metadata_path: Path,quarantine_dir: Path) -> dict:
    """Revalidate immediately before restoring; caller must confirm the destination."""
    entry=inspect_quarantine_entry(metadata_path,quarantine_dir)
    source=entry["source"];destination=entry["destination"];meta=entry["meta"]
    if destination.exists():raise OSError("Caminho original ocupado; escolha outro local manualmente.")
    destination.parent.mkdir(parents=True,exist_ok=True)
    _reject_reparse_route(destination)
    if destination.exists():raise OSError("Caminho original ocupado; escolha outro local manualmente.")
    with LockedFile(str(source)) as locked:
        actual_sha256=locked.sha256()
        expected=meta.get("sha256","")
        if expected and actual_sha256.casefold()!=expected.casefold():
            raise OSError("O arquivo mudou durante a validação; a restauração foi cancelada.")
        if locked.volume_id==destination.parent.stat().st_dev:
            locked.rename_to(destination)
        else:
            _reject_reparse_route(destination)
            copied_sha256=locked.copy_to(destination)
            if copied_sha256.casefold()!=actual_sha256.casefold():
                _remove_if_present(destination)
                raise OSError("A cópia de restauração não passou na verificação SHA-256.")
            try:locked.delete()
            except OSError:
                _remove_if_present(destination)
                raise
    try:entry["metadata_path"].unlink()
    except OSError as exc:meta["cleanup_warning"]=f"Arquivo restaurado, mas o manifesto não pôde ser removido: {exc}"
    return meta
