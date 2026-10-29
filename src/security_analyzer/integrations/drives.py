"""Windows logical-drive and mounted-volume inventory."""
from __future__ import annotations

import ctypes
import os
import shutil
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class VolumeInfo:
    """Read-only inventory data for one mounted volume."""
    root: str
    label: str
    drive_type: str
    total_bytes: int | None
    free_bytes: int | None
    status: str
    error: str = ""


_DRIVE_TYPES = {
    0: "Desconhecido",
    1: "Sem mídia / indisponível",
    2: "Removível",
    3: "Fixo",
    4: "Rede",
    5: "CD/DVD",
    6: "RAM",
}


def drives() -> list[str]:
    """Return mounted logical-drive roots, preserving the legacy API."""
    if os.name != "nt":
        return [str(Path.home())]
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    return [f"{chr(65+i)}:\\" for i in range(26) if mask & (1 << i)]


def _drive_type(root: str) -> str:
    if os.name != "nt":
        return "Pasta local"
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_drive_type = kernel32.GetDriveTypeW
        get_drive_type.argtypes = [wintypes.LPCWSTR]
        get_drive_type.restype = wintypes.UINT
        return _DRIVE_TYPES.get(int(get_drive_type(root)), "Desconhecido")
    except (AttributeError, OSError):
        return "Desconhecido"


def _volume_label(root: str) -> str:
    if os.name != "nt":
        return Path(root).name or root
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_volume_information = kernel32.GetVolumeInformationW
        get_volume_information.argtypes = [
            wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
            wintypes.LPDWORD, wintypes.LPDWORD, wintypes.LPDWORD,
            wintypes.LPWSTR, wintypes.DWORD,
        ]
        get_volume_information.restype = wintypes.BOOL
        label = ctypes.create_unicode_buffer(261)
        serial = wintypes.DWORD()
        max_component = wintypes.DWORD()
        flags = wintypes.DWORD()
        filesystem = ctypes.create_unicode_buffer(64)
        ok = get_volume_information(root, label, len(label), ctypes.byref(serial),
                                    ctypes.byref(max_component), ctypes.byref(flags),
                                    filesystem, len(filesystem))
        return label.value if ok and label.value else ""
    except (AttributeError, OSError):
        return ""


def enumerate_volumes() -> list[VolumeInfo]:
    """List mounted volumes and capacity without enumerating their files."""
    result = []
    for root in drives():
        label = _volume_label(root) or root.rstrip("\\/")
        drive_type = _drive_type(root)
        try:
            usage = shutil.disk_usage(root)
            result.append(VolumeInfo(root, label, drive_type, usage.total, usage.free,
                                     "Disponível"))
        except OSError as exc:
            result.append(VolumeInfo(root, label, drive_type, None, None,
                                     "Indisponível", str(exc)))
    return result
