"""Read-only static inspection for common source and script files."""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from .models import is_link_or_reparse_point


MAX_INSPECTION_BYTES = 1024 * 1024
SOURCE_EXTENSIONS = {
    ".bat", ".cmd", ".js", ".mjs", ".cjs", ".py", ".ps1", ".psm1", ".psd1",
    ".vbs", ".vbe", ".hta", ".wsf", ".wsh", ".sh", ".php", ".rb", ".pl",
    ".pyw", ".lua", ".ts", ".tsx", ".jsx", ".java", ".c", ".h", ".cc", ".cpp",
    ".cs", ".go", ".rs", ".sql", ".swift", ".kt", ".kts", ".dart", ".r", ".m",
    ".scala", ".groovy",
}

_RULES = (
    ("Execução dinâmica", re.compile(r"\b(?:Invoke-Expression|iex)\b|\b(?:eval|exec)\s*\(", re.I)),
    ("Download de conteúdo remoto", re.compile(r"\b(?:DownloadString|DownloadFile|Invoke-WebRequest|Start-BitsTransfer|WebClient)\b", re.I)),
    ("Conteúdo codificado ou ofuscado", re.compile(r"\b(?:FromBase64String|base64\.b64decode|atob)\b|(?:^|\s)-enc(?:odedcommand)?\b", re.I)),
    ("Alteração de inicialização automática", re.compile(r"CurrentVersion\\Run|shell:startup|schtasks(?:\.exe)?", re.I)),
    ("Criação ou execução de processos", re.compile(r"\b(?:subprocess\.(?:Popen|run|call)|os\.system|WScript\.Shell|ShellExecute)\b", re.I)),
)


def _decode_source(data: bytes) -> tuple[str, str]:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace"), "UTF-16"
    if b"\x00" in data:
        raise OSError("O arquivo parece binário; a visualização de código foi cancelada.")
    try:
        return data.decode("utf-8-sig"), "UTF-8"
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace"), "Windows-1252"


def inspect_source_file(path: str) -> dict:
    """Read a bounded source file as text and report heuristic indicators only."""
    target = Path(os.path.abspath(path))
    if target.suffix.casefold() not in SOURCE_EXTENSIONS:
        raise OSError("A inspeção de código está disponível somente para extensões de texto reconhecidas.")
    if is_link_or_reparse_point(str(target)):
        raise OSError("Links e pontos de nova análise não podem ser abertos na inspeção de código.")
    try:
        info = target.stat(follow_symlinks=False)
    except OSError as exc:
        raise OSError(f"Não foi possível ler os dados do arquivo: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise OSError("O item selecionado não é um arquivo regular.")
    try:
        with target.open("rb") as stream:
            data = stream.read(MAX_INSPECTION_BYTES + 1)
    except OSError as exc:
        raise OSError(f"Não foi possível ler o arquivo: {exc}") from exc

    truncated = len(data) > MAX_INSPECTION_BYTES
    text, encoding = _decode_source(data[:MAX_INSPECTION_BYTES])
    indicators = []
    for label, pattern in _RULES:
        matches = list(pattern.finditer(text))[:4]
        for match in matches:
            line = text.count("\n", 0, match.start()) + 1
            indicators.append({"label": label, "line": line})
    return {
        "path": str(target),
        "text": text,
        "size_bytes": info.st_size,
        "encoding": encoding,
        "truncated": truncated,
        "indicators": indicators,
    }
