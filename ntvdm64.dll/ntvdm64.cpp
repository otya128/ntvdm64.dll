#include "pch.h"
#ifndef TEST
#define assert(x)
#else
#include <assert.h>
#endif

static void my_memcpy(void *Dest, void const *Source, SIZE_T Size)
{
    LPBYTE DestByte = (LPBYTE)Dest;
    LPBYTE SourceByte = (LPBYTE)Source;
    while (Size--) *DestByte++ = *SourceByte++;
}

static size_t my_wcslen(LPCWSTR String)
{
    size_t Length = 0;
    while (*String++) Length++;
    return Length;
}

static LPWSTR ReplaceCommandLine(LPCWSTR lpCommandLine, LPCWSTR lpApplicationName, LPCWSTR lpProgramCommandLine)
{
    auto len = my_wcslen(lpCommandLine);
    auto mlen = my_wcslen(lpApplicationName);
    auto clen = my_wcslen(lpProgramCommandLine);
    auto mcnt = 0;
    auto ccnt = 0;
    for (size_t i = 0; i < len; i++)
    {
        if (lpCommandLine[i] == L'%' && i + 1 < len)
        {
            if (lpCommandLine[i + 1] == L'm')
            {
                mcnt++;
                continue;
            }
            else if (lpCommandLine[i + 1] == L'c')
            {
                ccnt++;
                continue;
            }
        }
    }
    auto NewLength = len - 2 * mcnt - 2 * ccnt + mlen * mcnt + clen * ccnt + 1;
    auto NewCommandLine = reinterpret_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), 0, NewLength * sizeof(WCHAR)));
    if (!NewCommandLine)
    {
        return nullptr;
    }
    size_t NewPos = 0;
    for (size_t i = 0; i < len; i++)
    {
        if (lpCommandLine[i] == L'%' && i + 1 < len)
        {
            if (lpCommandLine[i + 1] == L'm')
            {
                my_memcpy(NewCommandLine + NewPos, lpApplicationName, mlen * sizeof(WCHAR));
                i++;
                NewPos += mlen;
                continue;
            }
            else if (lpCommandLine[i + 1] == L'c')
            {
                my_memcpy(NewCommandLine + NewPos, lpProgramCommandLine, clen * sizeof(WCHAR));
                i++;
                NewPos += clen;
                continue;
            }
        }
        NewCommandLine[NewPos] = lpCommandLine[i];
        NewPos++;
    }
    NewCommandLine[NewLength - 1] = L'\0';
    assert(NewLength == NewPos + 1);
    return NewCommandLine;
}

static BOOL MatchEntry(HKEY hEntryKey, LPCWSTR *lpApplicationName, LPCWSTR *lpCommandLine)
{
    DWORD type = 0;
    WCHAR InternalName[100];
    DWORD cbInternalName = sizeof(InternalName);
    WCHAR ProductName[100];
    DWORD cbProductName = sizeof(ProductName);
    WCHAR ProductVersion[100];
    DWORD cbProductVersion = sizeof(ProductVersion);
    WCHAR RegCommandLine[100];
    DWORD cbCommandLine = sizeof(RegCommandLine);
    WCHAR MappedExeName[100];
    DWORD cbMappedExeName = sizeof(MappedExeName);
    if (RegQueryValueExW(hEntryKey, L"InternalName", nullptr, &type, reinterpret_cast<LPBYTE>(InternalName), &cbInternalName) != ERROR_SUCCESS || type != REG_SZ)
    {
        return FALSE;
    }
    if (RegQueryValueExW(hEntryKey, L"ProductName", nullptr, &type, reinterpret_cast<LPBYTE>(ProductName), &cbProductName) != ERROR_SUCCESS || type != REG_SZ)
    {
        return FALSE;
    }
    if (RegQueryValueExW(hEntryKey, L"ProductVersion", nullptr, &type, reinterpret_cast<LPBYTE>(ProductVersion), &cbProductVersion) != ERROR_SUCCESS || type != REG_SZ)
    {
        return FALSE;
    }
    if (!InternalName[0] || InternalName[0] != L'*' || InternalName[1])
    {
        return FALSE;
    }
    if (!ProductName[0] || ProductName[0] != L'*' || ProductName[1])
    {
        return FALSE;
    }
    if (!ProductVersion[0] || ProductVersion[0] != L'*' || ProductVersion[1])
    {
        return FALSE;
    }
    if (RegQueryValueExW(hEntryKey, L"CommandLine", nullptr, &type, reinterpret_cast<LPBYTE>(RegCommandLine), &cbCommandLine) != ERROR_SUCCESS || type != REG_SZ)
    {
        return FALSE;
    }
    if (RegQueryValueExW(hEntryKey, L"MappedExeName", nullptr, &type, reinterpret_cast<LPBYTE>(MappedExeName), &cbMappedExeName) != ERROR_SUCCESS || type != REG_SZ)
    {
        return FALSE;
    }
    auto ReplacedCommandLine = ReplaceCommandLine(RegCommandLine, *lpApplicationName, *lpCommandLine);
    if (!ReplacedCommandLine)
    {
        return FALSE;
    }
    auto NewApplicationName = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cbMappedExeName);
    if (!NewApplicationName)
    {
        HeapFree(GetProcessHeap(), 0, (LPVOID)ReplacedCommandLine);
        return FALSE;
    }
    my_memcpy(NewApplicationName, MappedExeName, cbMappedExeName);
    *lpCommandLine = ReplacedCommandLine;
    *lpApplicationName = NewApplicationName;
    return TRUE;
}

static BOOL Process(LPCWSTR *ApplicationName, LPCWSTR *CommandLine)
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NtVdm64", 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
    {
        return false;
    }
    DWORD dwIndex = 0;
    WCHAR NameBuf[1000];
    DWORD cchName = ARRAYSIZE(NameBuf);
    BOOL Success = false;
    while (!Success)
    {
        if (RegEnumKeyW(hKey, dwIndex, NameBuf, cchName) != ERROR_SUCCESS)
        {
            break;
        }
        dwIndex++;
        HKEY hEntryKey = nullptr;
        if (RegOpenKeyW(hKey, NameBuf, &hEntryKey) != ERROR_SUCCESS)
        {
            continue;
        }
        if (MatchEntry(hEntryKey, ApplicationName, CommandLine))
        {
            Success = true;
        }
        RegCloseKey(hEntryKey);
    }
    RegCloseKey(hKey);
    return Success;
}

extern "C" BOOL WINAPI NtVdm64CreateProcessInternalW(HANDLE hUserToken,
    LPCWSTR lpApplicationName,
    LPCWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hNewToken)
{
    auto pCreateProcessInternalW = (BOOL(WINAPI*)(HANDLE hUserToken,
        LPCWSTR lpApplicationName,
        LPCWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation,
        PHANDLE hNewToken))GetProcAddress(GetModuleHandleW(L"kernel32"), "CreateProcessInternalW");
    LPCWSTR NewApplicationName = lpApplicationName;
    LPCWSTR NewCommandLine = lpCommandLine;
    auto Result = Process(&NewApplicationName, &NewCommandLine);
    if (Result)
    {
        Result = pCreateProcessInternalW(hUserToken,
            NewApplicationName,
            NewCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation,
            hNewToken);
    }
    if (NewApplicationName != lpApplicationName)
    {
        HeapFree(GetProcessHeap(), 0, (LPVOID)NewApplicationName);
    }
    if (NewCommandLine != lpCommandLine)
    {
        HeapFree(GetProcessHeap(), 0, (LPVOID)NewCommandLine);
    }
    return Result;
}

extern "C" DWORD WINAPI NtVdm64RaiseInvalid16BitError(LPCWSTR Argument1)
{
    HMODULE user32 = LoadLibraryW(L"user32.dll");
    auto pMessageBoxW = (int(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT))GetProcAddress(user32, "MessageBoxW");
    pMessageBoxW(NULL, Argument1, L"NtVdm64RaiseInvalid16BitError", MB_OK);
    FreeLibrary(user32);
    return 0;
}

#ifdef TEST
int main(int argc, char **argv)
{
    auto app = L"TEST.EXE";
    auto cmd = L"testtest test";
    assert(!wcscmp(ReplaceCommandLine(L"%m", L"Mapped", L"cmd"), L"Mapped"));
    assert(!wcscmp(ReplaceCommandLine(L"%c", L"Mapped", L"cmd"), L"cmd"));
    assert(!wcscmp(ReplaceCommandLine(L"%m %c", L"Mapped", L"cmd"), L"Mapped cmd"));
    Process(&app, &cmd);
}
#endif
