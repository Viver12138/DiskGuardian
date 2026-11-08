"""Authenticode verification through WinVerifyTrust (no PowerShell per file).

Only the trust result is returned. Certificates, chains, and publisher names are
deliberately not extracted: a signature result is evidence, never a verdict.
"""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes

_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_SAFER_FLAG = 0x100

TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
CERT_E_UNTRUSTEDROOT = 0x800B0109
CERT_E_EXPIRED = 0x800B0101
CERT_E_CHAINING = 0x800B010A
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
TRUST_E_BAD_DIGEST = 0x80096010

_STATE_LABELS = {
    TRUST_E_NOSIGNATURE: "unsigned",
    TRUST_E_SUBJECT_FORM_UNKNOWN: "unsigned",
    TRUST_E_PROVIDER_UNKNOWN: "unavailable",
    CERT_E_UNTRUSTEDROOT: "untrusted-root",
    CERT_E_EXPIRED: "expired-certificate",
    CERT_E_CHAINING: "chain-error",
    TRUST_E_EXPLICIT_DISTRUST: "explicitly-distrusted",
    TRUST_E_BAD_DIGEST: "corrupt-signature",
}


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


_ACTION = _GUID(
    0xAAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)

try:
    _wintrust = ctypes.WinDLL("wintrust")
    _wintrust.WinVerifyTrust.argtypes = [wintypes.HANDLE, ctypes.POINTER(_GUID), ctypes.c_void_p]
    _wintrust.WinVerifyTrust.restype = ctypes.c_long
except OSError:  # pragma: no cover - only on non-Windows hosts
    _wintrust = None


def verify(path: str) -> str:
    """Return "valid", a specific failure label, or "unavailable"."""
    if _wintrust is None:
        return "unavailable"
    normalized = os.path.abspath(path)
    if not os.path.isfile(normalized):
        return "missing"
    file_info = _WINTRUST_FILE_INFO(
        cbStruct=ctypes.sizeof(_WINTRUST_FILE_INFO),
        pcwszFilePath=normalized,
        hFile=None,
        pgKnownSubject=None,
    )
    data = _WINTRUST_DATA(
        cbStruct=ctypes.sizeof(_WINTRUST_DATA),
        pPolicyCallbackData=None,
        pSIPClientData=None,
        dwUIChoice=_WTD_UI_NONE,
        fdwRevocationChecks=_WTD_REVOKE_NONE,
        dwUnionChoice=_WTD_CHOICE_FILE,
        pFile=ctypes.pointer(file_info),
        dwStateAction=_WTD_STATEACTION_VERIFY,
        hWVTStateData=None,
        pwszURLReference=None,
        dwProvFlags=_WTD_SAFER_FLAG,
        dwUIContext=0,
        pSignatureSettings=None,
    )
    try:
        result = int(_wintrust.WinVerifyTrust(None, ctypes.byref(_ACTION), ctypes.byref(data)))
    except OSError:
        return "unavailable"
    finally:
        data.dwStateAction = _WTD_STATEACTION_CLOSE
        try:
            _wintrust.WinVerifyTrust(None, ctypes.byref(_ACTION), ctypes.byref(data))
        except OSError:
            pass

    if result == 0:
        return "valid"
    unsigned = result & 0xFFFFFFFF
    return _STATE_LABELS.get(unsigned, f"untrusted-{unsigned:08x}")
