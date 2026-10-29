"""Explicitly scoped cleanup of reviewed Windows startup references."""
from __future__ import annotations
from dataclasses import dataclass
import os

RUN_KEYS = (
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
)

@dataclass(frozen=True)
class StartupValue:
    hive: str
    subkey: str
    name: str
    value: str
    value_type: int

    @property
    def label(self) -> str:
        return f"{self.hive}\\{self.subkey}\\{self.name}"

def _contains_path_reference(value: str,target: str) -> bool:
    """Match a full path token, including quoted command values with arguments."""
    start=0
    while (index:=value.find(target,start))!=-1:
        end=index+len(target)
        left_ok=index==0 or value[index-1] in "\"' \t="
        right_ok=end==len(value) or value[end] in "\"' \t,;)"
        if left_ok and right_ok:return True
        start=index+1
    return False

def _windows_registry():
    import winreg
    return winreg,{"HKCU":winreg.HKEY_CURRENT_USER,"HKLM":winreg.HKEY_LOCAL_MACHINE}

def matching_startup_values(file_path: str,remove: bool=False,reviewed_values: list[StartupValue]|None=None) -> tuple[list[StartupValue],list[str]]:
    """Find matching Run values; removal requires and revalidates the reviewed snapshot."""
    if os.name!="nt":return [],["Limpeza do Registro só está disponível no Windows."]
    if remove and not reviewed_values:
        return [],["Nenhum valor revisado foi fornecido; nada foi removido."]
    winreg,hives=_windows_registry()
    target=os.path.normcase(os.path.abspath(file_path)).casefold()
    matches=[];errors=[]

    if not remove:
        for hive_name,subkey in RUN_KEYS:
            try:
                with winreg.OpenKey(hives[hive_name],subkey,0,winreg.KEY_QUERY_VALUE) as key:
                    for index in range(winreg.QueryInfoKey(key)[1]):
                        try:
                            name,value,value_type=winreg.EnumValue(key,index)
                            normalized=os.path.normcase(value).casefold() if isinstance(value,str) else ""
                            if normalized and _contains_path_reference(normalized,target):
                                matches.append(StartupValue(hive_name,subkey,name,value,value_type))
                        except OSError:
                            continue
            except FileNotFoundError:
                continue
            except OSError as exc:
                errors.append(f"{hive_name}\\{subkey}: {exc}")
        return matches,errors

    allowed_keys=set(RUN_KEYS)
    for reviewed in reviewed_values or []:
        if not isinstance(reviewed,StartupValue) or (reviewed.hive,reviewed.subkey) not in allowed_keys:
            errors.append("Um valor revisado contém uma chave fora do escopo permitido.")
            continue
        try:
            with winreg.OpenKey(hives[reviewed.hive],reviewed.subkey,0,winreg.KEY_QUERY_VALUE|winreg.KEY_SET_VALUE) as key:
                try:
                    current_value,current_type=winreg.QueryValueEx(key,reviewed.name)
                except FileNotFoundError:
                    errors.append(f"{reviewed.label}: valor removido ou alterado; nenhuma ação executada.")
                    continue
                normalized=os.path.normcase(current_value).casefold() if isinstance(current_value,str) else ""
                if current_value!=reviewed.value or current_type!=reviewed.value_type or not normalized or not _contains_path_reference(normalized,target):
                    errors.append(f"{reviewed.label}: valor alterado desde a confirmação; não removido.")
                    continue
                winreg.DeleteValue(key,reviewed.name)
                matches.append(reviewed)
        except OSError as exc:
            errors.append(f"{reviewed.label}: {exc}")
    return matches,errors
