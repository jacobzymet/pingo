"""Private local storage permissions on Windows and POSIX."""

import csv
import ctypes
import functools
import os
import re
import subprocess
from pathlib import Path


@functools.lru_cache(maxsize=1)
def _user_sid():
    identity = subprocess.check_output(
        [
            str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/whoami.exe"),
            "/user",
            "/fo",
            "csv",
            "/nh",
        ],
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
        timeout=15,
    )
    sid = next(csv.reader([identity.strip()]))[1]
    if not re.fullmatch(r"S-1-(?:\d+-)*\d+", sid):
        raise OSError("could not identify the current Windows user")
    return sid


def _windows_private(path, directory):
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    convert.restype = ctypes.c_int
    apply = advapi.SetFileSecurityW
    apply.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p]
    apply.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    inheritance = "OICI" if directory else ""
    # Replace the complete DACL, including explicit grants to unrelated users.
    descriptor = "D:P" + "".join(
        f"(A;{inheritance};FA;;;{sid})" for sid in (_user_sid(), "SY", "BA")
    )
    pointer = ctypes.c_void_p()
    if not convert(descriptor, 1, ctypes.byref(pointer), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not apply(str(path), 0x80000004, pointer):  # protected DACL
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(pointer)


def private_file(path):
    if os.name == "nt":
        _windows_private(path, False)
    else:
        path.chmod(0o600)


def private_directory(path):
    if path.is_symlink() or (
        path.exists() and getattr(path.lstat(), "st_file_attributes", 0) & 0x400
    ):
        raise ValueError("private storage directory must not be a symbolic link")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "nt":
        _windows_private(path, True)
    else:
        path.chmod(0o700)
