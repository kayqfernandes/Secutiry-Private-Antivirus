"""Windows file operations bound to a verified, non-reparse file handle."""
from __future__ import annotations
import ctypes
import hashlib
import msvcrt
import os
from ctypes import wintypes
from pathlib import Path
from ..core.models import file_identity_from_stat

GENERIC_READ=0x80000000
DELETE=0x00010000
FILE_SHARE_READ=0x00000001
OPEN_EXISTING=3
FILE_FLAG_OPEN_REPARSE_POINT=0x00200000
FILE_FLAG_SEQUENTIAL_SCAN=0x08000000
FILE_RENAME_INFO_CLASS=3
FILE_DISPOSITION_INFO_CLASS=4

class _FileDispositionInfo(ctypes.Structure):
    _fields_=[("DeleteFile",ctypes.c_ubyte)]

class _FileRenameInfo(ctypes.Structure):
    _fields_=[("ReplaceIfExists",ctypes.c_ubyte),("RootDirectory",wintypes.HANDLE),("FileNameLength",wintypes.DWORD),("FileName",wintypes.WCHAR*1)]

def _extended_path(path: Path) -> str:
    absolute=os.path.abspath(path)
    if absolute.startswith("\\\\?\\"):return absolute
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\"+absolute[2:]
    return "\\\\?\\"+absolute

class LockedFile:
    """Open without write/delete sharing, verify/hash and mutate that same handle."""
    def __init__(self,path: str):
        self.path=Path(path)
        self.stream=None
        self.identity=""
        self.volume_id=None

    def __enter__(self):
        if os.name!="nt":raise OSError("Operações por handle estão disponíveis somente no Windows.")
        kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
        kernel.CreateFileW.restype=wintypes.HANDLE
        invalid=wintypes.HANDLE(-1).value
        handle=kernel.CreateFileW(_extended_path(self.path),GENERIC_READ|DELETE,FILE_SHARE_READ,None,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,None)
        if handle==invalid:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            descriptor=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
        except Exception:
            kernel.CloseHandle(handle)
            raise
        try:
            self.stream=os.fdopen(descriptor,"rb")
            info=os.fstat(descriptor)
            self.identity=file_identity_from_stat(info)
            self.volume_id=info.st_dev
            return self
        except Exception:
            os.close(descriptor)
            self.stream=None
            raise

    def __exit__(self,_type,_value,_traceback):
        if self.stream is not None:
            self.stream.close()
            self.stream=None

    def sha256(self) -> str:
        if self.stream is None:raise OSError("Handle de arquivo fechado.")
        self.stream.seek(0)
        digest=hashlib.sha256()
        for block in iter(lambda:self.stream.read(1024*1024),b""):
            digest.update(block)
        self.stream.seek(0)
        return digest.hexdigest()

    def copy_to(self,destination: Path) -> str:
        if self.stream is None:raise OSError("Handle de arquivo fechado.")
        self.stream.seek(0)
        digest=hashlib.sha256()
        with destination.open("xb") as output:
            for block in iter(lambda:self.stream.read(1024*1024),b""):
                output.write(block)
                digest.update(block)
            output.flush()
            os.fsync(output.fileno())
        self.stream.seek(0)
        return digest.hexdigest()

    def delete(self) -> None:
        if self.stream is None:raise OSError("Handle de arquivo fechado.")
        kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        kernel.SetFileInformationByHandle.argtypes=[wintypes.HANDLE,wintypes.INT,wintypes.LPVOID,wintypes.DWORD]
        kernel.SetFileInformationByHandle.restype=wintypes.BOOL
        handle=msvcrt.get_osfhandle(self.stream.fileno())
        info=_FileDispositionInfo(1)
        if not kernel.SetFileInformationByHandle(handle,FILE_DISPOSITION_INFO_CLASS,ctypes.byref(info),ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())

    def rename_to(self,destination: Path) -> None:
        if self.stream is None:raise OSError("Handle de arquivo fechado.")
        target=_extended_path(destination)
        encoded=target.encode("utf-16-le")
        name_offset=_FileRenameInfo.FileName.offset
        # The Win32 API expects sizeof(FILE_RENAME_INFO) plus the variable name
        # payload, although the payload starts at FileName.offset.
        buffer_size=ctypes.sizeof(_FileRenameInfo)+len(encoded)
        buffer=ctypes.create_string_buffer(buffer_size)
        info=ctypes.cast(buffer,ctypes.POINTER(_FileRenameInfo)).contents
        info.ReplaceIfExists=0
        info.RootDirectory=None
        info.FileNameLength=len(encoded)
        ctypes.memmove(ctypes.addressof(buffer)+name_offset,encoded,len(encoded))
        kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        kernel.SetFileInformationByHandle.argtypes=[wintypes.HANDLE,wintypes.INT,wintypes.LPVOID,wintypes.DWORD]
        kernel.SetFileInformationByHandle.restype=wintypes.BOOL
        handle=msvcrt.get_osfhandle(self.stream.fileno())
        if not kernel.SetFileInformationByHandle(handle,FILE_RENAME_INFO_CLASS,buffer,buffer_size):
            raise ctypes.WinError(ctypes.get_last_error())
