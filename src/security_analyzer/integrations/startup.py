"""Read common Windows startup locations and report partial-access errors."""
from __future__ import annotations
from dataclasses import dataclass,field
import os
from pathlib import Path
from ..remediation.registry import RUN_KEYS

@dataclass
class StartupResult:
    entries: list[str]=field(default_factory=list)
    errors: list[str]=field(default_factory=list)

def startup_entries() -> StartupResult:
    if os.name!="nt":return StartupResult()
    result=StartupResult()
    try:
        import winreg
        hives={"HKCU":winreg.HKEY_CURRENT_USER,"HKLM":winreg.HKEY_LOCAL_MACHINE}
    except Exception as exc:
        return StartupResult(errors=[f"Registro de inicialização indisponível: {exc}"])

    for hive_name,subkey in RUN_KEYS:
        try:
            with winreg.OpenKey(hives[hive_name],subkey) as key:
                for index in range(winreg.QueryInfoKey(key)[1]):
                    try:
                        name,value,_=winreg.EnumValue(key,index)
                        result.entries.append(f"Registro de inicialização: {name} → {value}")
                    except OSError as exc:
                        result.errors.append(f"{hive_name}\\{subkey} valor {index}: {exc}")
        except FileNotFoundError:
            continue
        except OSError as exc:
            result.errors.append(f"{hive_name}\\{subkey}: {exc}")

    folders=(os.environ.get("APPDATA"),os.environ.get("PROGRAMDATA"))
    for folder_value in folders:
        if not folder_value:continue
        folder=Path(folder_value)/r"Microsoft\Windows\Start Menu\Programs\Startup"
        try:
            for item in folder.iterdir():result.entries.append(f"Inicialização: {item}")
        except FileNotFoundError:
            continue
        except OSError as exc:
            result.errors.append(f"{folder}: {exc}")
    return result
