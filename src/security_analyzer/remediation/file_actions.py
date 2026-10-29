"""Explicit file deletion operations bound to the verified Windows file handle."""
from __future__ import annotations
import os
from pathlib import Path
from ..core.models import is_link_or_reparse_point, is_sha256_digest, is_temp_candidate
from .locked_file import LockedFile

def _require_analysis_hash(expected_sha256: str) -> None:
    if not is_sha256_digest(expected_sha256):
        raise OSError("Hash de referência ausente ou inválido; faça uma nova varredura antes de excluir.")

def _require_analysis_identity(expected_identity: str) -> None:
    if not expected_identity:
        raise OSError("Identidade do arquivo ausente; faça uma nova varredura antes de excluir.")

def _reject_reparse_route(path: str) -> None:
    absolute=Path(os.path.abspath(path))
    for component in (absolute,*absolute.parents):
        if os.path.lexists(component) and is_link_or_reparse_point(str(component)):
            raise OSError("O caminho contém link ou ponto de nova análise.")

def _delete_verified_file(path: str,expected_sha256: str,expected_identity: str) -> None:
    _require_analysis_hash(expected_sha256)
    _require_analysis_identity(expected_identity)
    _reject_reparse_route(path)
    with LockedFile(path) as locked:
        if locked.identity!=expected_identity:
            raise OSError("O arquivo foi substituído desde a análise; faça nova busca.")
        if locked.sha256().casefold()!=expected_sha256.casefold():
            raise OSError("Arquivo mudou desde a análise; faça nova busca.")
        locked.delete()

def delete_file(path: str,expected_sha256: str,expected_identity: str) -> None:
    _delete_verified_file(path,expected_sha256,expected_identity)

def delete_temp_file(path: str,expected_sha256: str,expected_identity: str) -> None:
    if not is_temp_candidate(path):
        raise OSError("Caminho não está em uma pasta temporária reconhecida.")
    _delete_verified_file(path,expected_sha256,expected_identity)
