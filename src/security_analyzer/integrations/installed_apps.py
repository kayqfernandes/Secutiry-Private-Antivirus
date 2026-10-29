"""Read-only inventory of installed desktop applications registered by Windows."""
from __future__ import annotations

import codecs
import os
import struct
from dataclasses import dataclass
from datetime import date, datetime


@dataclass(frozen=True)
class InstalledApplication:
    name: str
    publisher: str
    install_location: str
    estimated_size_bytes: int | None
    install_date: str
    last_used_at: float | None = None


@dataclass(frozen=True)
class ApplicationInventory:
    applications: tuple[InstalledApplication, ...]
    unreadable_entries: int = 0
    activity_records: int = 0
    activity_available: bool = True


_UNINSTALL_SUBKEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
)
_USER_ASSIST_SUBKEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
_EXCLUDED_RELEASE_TYPES = {"update", "security update", "hotfix", "update rollup", "service pack"}
_EXCLUDED_NAME_PREFIXES = (
    "security update for microsoft", "update for microsoft", "update for windows",
    "hotfix", "microsoft visual c++ redistributable", "microsoft .net framework",
    "microsoft windows desktop runtime",
)


def _value(winreg, key, name, default=None):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return default


def _truthy_registry_flag(value) -> bool:
    if isinstance(value, str):
        return value.strip().casefold() in {"1", "true", "yes"}
    return bool(value)


def _normalized(path: str) -> str:
    expanded = os.path.expandvars(str(path or "").strip().strip('"'))
    return os.path.normcase(os.path.abspath(expanded)) if expanded else ""


def _is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((_normalized(path), _normalized(root))) == _normalized(root)
    except (OSError, ValueError):
        return False


def _is_windows_component(winreg, key, name: str, location: str) -> bool:
    if _truthy_registry_flag(_value(winreg, key, "SystemComponent", 0)):
        return True
    if _truthy_registry_flag(_value(winreg, key, "WindowsComponent", 0)):
        return True
    if _value(winreg, key, "ParentKeyName", ""):
        return True
    release_type = str(_value(winreg, key, "ReleaseType", "")).strip().casefold()
    if release_type in _EXCLUDED_RELEASE_TYPES:
        return True
    if name.casefold().startswith(_EXCLUDED_NAME_PREFIXES):
        return True
    windows_dir = os.environ.get("WINDIR", r"C:\Windows")
    if _is_within(location, windows_dir):
        return True
    if "\\windowsapps\\" in _normalized(location).casefold():
        return True
    return False


def _parse_install_date(value) -> str:
    text = str(value or "").strip()
    if len(text) != 8 or not text.isdigit():
        return ""
    try:
        return date(int(text[:4]), int(text[4:6]), int(text[6:8])).isoformat()
    except ValueError:
        return ""


def _userassist_records(winreg, now: float) -> tuple[dict[str, float], int, bool]:
    """Read available Explorer launch timestamps; malformed or unknown records are ignored."""
    records: dict[str, float] = {}
    unreadable = 0
    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _USER_ASSIST_SUBKEY, 0, winreg.KEY_READ)
    except OSError:
        return records, 0, False
    try:
        subkey_count = winreg.QueryInfoKey(root)[0]
        for index in range(subkey_count):
            try:
                guid = winreg.EnumKey(root, index)
                count_key = winreg.OpenKey(root, guid + r"\Count", 0, winreg.KEY_READ)
            except OSError:
                unreadable += 1
                continue
            try:
                value_count = winreg.QueryInfoKey(count_key)[1]
                for value_index in range(value_count):
                    try:
                        encoded_path, data, _kind = winreg.EnumValue(count_key, value_index)
                        path = codecs.decode(str(encoded_path), "rot_13").strip()
                        if len(data) < 68 or not (len(path) >= 3 and path[1:3] == ":\\"):
                            continue
                        filetime = struct.unpack_from("<Q", data, 60)[0]
                        timestamp = filetime / 10_000_000 - 11644473600
                        # Discard malformed values and implausible timestamps rather than labeling them as use.
                        if timestamp < 946684800 or timestamp > now + 86400:
                            continue
                        key = _normalized(path)
                        if key:
                            records[key] = max(timestamp, records.get(key, 0.0))
                    except (OSError, TypeError, ValueError, struct.error):
                        unreadable += 1
            finally:
                try:
                    winreg.CloseKey(count_key)
                except (AttributeError, OSError):
                    pass
    finally:
        try:
            winreg.CloseKey(root)
        except (AttributeError, OSError):
            pass
    return records, unreadable, True


def enumerate_installed_applications(root: str, winreg_module=None, *, now: float | None = None) -> ApplicationInventory:
    """List registered desktop apps installed on ``root``; never traverses app folders."""
    if winreg_module is None:
        try:
            import winreg as winreg_module
        except ImportError:
            return ApplicationInventory((), activity_available=False)
    now = now if now is not None else datetime.now().timestamp()
    usage, unreadable, activity_available = _userassist_records(winreg_module, now)
    found: dict[tuple[str, str], InstalledApplication] = {}
    hives = (winreg_module.HKEY_LOCAL_MACHINE, winreg_module.HKEY_CURRENT_USER)
    for hive in hives:
        for uninstall_path in _UNINSTALL_SUBKEYS:
            try:
                parent = winreg_module.OpenKey(hive, uninstall_path, 0, winreg_module.KEY_READ)
            except OSError:
                continue
            try:
                entry_count = winreg_module.QueryInfoKey(parent)[0]
                for entry_index in range(entry_count):
                    try:
                        entry_name = winreg_module.EnumKey(parent, entry_index)
                        entry = winreg_module.OpenKey(parent, entry_name, 0, winreg_module.KEY_READ)
                    except OSError:
                        unreadable += 1
                        continue
                    try:
                        name = str(_value(winreg_module, entry, "DisplayName", "")).strip()
                        location = str(_value(winreg_module, entry, "InstallLocation", "")).strip()
                        if not name or not location or not _is_within(location, root):
                            continue
                        if not os.path.isdir(location) or _is_windows_component(winreg_module, entry, name, location):
                            continue
                        raw_size = _value(winreg_module, entry, "EstimatedSize")
                        try:
                            estimated_size = int(raw_size) * 1024 if int(raw_size) > 0 else None
                        except (TypeError, ValueError, OverflowError):
                            estimated_size = None
                        last_used = max(
                            (timestamp for used_path, timestamp in usage.items()
                             if _is_within(used_path, location)),
                            default=None,
                        )
                        app = InstalledApplication(
                            name=name,
                            publisher=str(_value(winreg_module, entry, "Publisher", "")).strip(),
                            install_location=_normalized(location),
                            estimated_size_bytes=estimated_size,
                            install_date=_parse_install_date(_value(winreg_module, entry, "InstallDate", "")),
                            last_used_at=last_used,
                        )
                        found[(app.name.casefold(), app.install_location)] = app
                    finally:
                        try:
                            winreg_module.CloseKey(entry)
                        except (AttributeError, OSError):
                            pass
            finally:
                try:
                    winreg_module.CloseKey(parent)
                except (AttributeError, OSError):
                    pass
    applications = tuple(sorted(
        found.values(),
        key=lambda app: (app.estimated_size_bytes is None, -(app.estimated_size_bytes or 0), app.name.casefold()),
    ))
    return ApplicationInventory(applications, unreadable, len(usage), activity_available)
