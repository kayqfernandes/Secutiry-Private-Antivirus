"""Windows PowerShell and Authenticode integration."""
from __future__ import annotations
import os, subprocess

def powershell(command: str, timeout: int=20) -> str:
    if os.name!="nt":raise OSError("Integração disponível somente no Windows.")
    return subprocess.check_output(["powershell.exe","-NoProfile","-NonInteractive","-Command",command],text=True,stderr=subprocess.STDOUT,timeout=timeout,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0)).strip()

def signature_status(path: str) -> str:
    try:output=powershell(f"$s=Get-AuthenticodeSignature -LiteralPath '{path.replace(chr(39),chr(39)*2)}'; $s.Status.ToString()",timeout=12)
    except Exception:return "Não verificada"
    return {"Valid":"Válida","NotSigned":"Não assinada","HashMismatch":"Inválida","NotTrusted":"Inválida","UnknownError":"Inválida"}.get(output,"Não verificada")
