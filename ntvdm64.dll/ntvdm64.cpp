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

static void SplitCommandLine(LPCWSTR CommandLine, LPCWSTR *FirstArgument, LPCWSTR *RemainArguments)
{
    size_t SplitPosition = 0;
    if (CommandLine[0] == L'"')
    {
        for (SplitPosition = 1; CommandLine[SplitPosition]; SplitPosition++)
        {
            if (CommandLine[SplitPosition] == '\"')
            {
                SplitPosition++;
                break;
            }
        }
    }
    else
    {
        for (SplitPosition = 0; CommandLine[SplitPosition]; SplitPosition++)
        {
            if (CommandLine[SplitPosition] == L' ' || CommandLine[SplitPosition] == L'\t')
            {
                break;
            }
        }
    }
    auto f = reinterpret_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SplitPosition + 1) * sizeof(WCHAR)));
    if (!f)
    {
        *RemainArguments = nullptr;
        *FirstArgument = nullptr;
        return;
    }
    my_memcpy(f, CommandLine, SplitPosition * sizeof(WCHAR));
    f[SplitPosition] = L'\0';
    *FirstArgument = f;
    *RemainArguments = CommandLine + SplitPosition;
}

static LPWSTR ReplaceCommandLine(LPCWSTR lpCommandLine, LPCWSTR lpApplicationName, LPCWSTR lpProgramCommandLine)
{
    LPCWSTR ApplicationNameInProgramCommandLine;
    SplitCommandLine(lpProgramCommandLine, &ApplicationNameInProgramCommandLine, &lpProgramCommandLine);
    auto appNameLen = my_wcslen(ApplicationNameInProgramCommandLine);
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
    auto NewLength = appNameLen + 1 /* space */ + len - 2 * mcnt /* %m */ - 2 * ccnt /* %c */ + mlen * mcnt + clen * ccnt + 1;
    auto NewCommandLine = reinterpret_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), 0, NewLength * sizeof(WCHAR)));
    if (!NewCommandLine)
    {
        return nullptr;
    }
    size_t NewPos = 0;
    my_memcpy(NewCommandLine, ApplicationNameInProgramCommandLine, appNameLen * sizeof(WCHAR));
    NewPos += appNameLen;
    NewCommandLine[appNameLen] = L' ';
    NewPos++;
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
        Result = pCreateProcessInternalW(
            hUserToken,
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
#include <stdio.h>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")
static void parse(LPCWSTR cmdline)
{
    int num = 0;
    auto res = CommandLineToArgvW(cmdline, &num);
    for (int i = 0; i < num; i++)
    {
        wprintf(L"[%i] = %s\n", i, res[i]);
    }
    wprintf(L"cmdline = %s\n====\n", cmdline);
    LocalFree(res);
}

static void msvcrt_vs_shell32(LPCWSTR cmdline)
{
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    CreateProcessW(path, (LPWSTR)cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    parse(cmdline);
}

int main(int argc, char **argv)
{
    auto app = L"TEST.EXE";
    auto cmd = L"testtest test";
    for (int i = 0; i < argc; i++)
    {
        printf("[%i] = %s\n", i, argv[i]);
    }
    printf("cmdline = %s\n", GetCommandLineA());
    if (argc == 2 && !strcmp(argv[1], "test"))
    {
        // msvcrt vs shell32
        // msvcrt:  "aaa"bbb  => [0] = "aaabbb"
        // shell32: "aaa"bbb  => [0] = "aaa" [1] = "bbb"
        // msvcrt:  "aaa" bbb => [0] = "aaa" [1] = "bbb"
        // shell32: "aaa" bbb => [0] = "aaa" [1] = "bbb"
        msvcrt_vs_shell32(L"\"aaa\"bbb");
        msvcrt_vs_shell32(L"\"aaa\" bbb");
        msvcrt_vs_shell32(L" aaa");
        msvcrt_vs_shell32(L"\"a\" aaa");
        msvcrt_vs_shell32(L"\"a\"aaa");
        msvcrt_vs_shell32(L"\"a\"\taaa");
        msvcrt_vs_shell32(L"\"a\\\"\"\taaa");
        msvcrt_vs_shell32(L"a\\\\\\\\\"b c\" d e");
        msvcrt_vs_shell32(L"_ a\\\\\\\\\"b c\" d e");
        msvcrt_vs_shell32(L"\"1 2 3 4\" 222");
        msvcrt_vs_shell32(L"\"1 2 3\\\" 4\" 222");
        msvcrt_vs_shell32(L"123\"456 789\" abc");
    }
    {
        LPCWSTR First, Remain;
        SplitCommandLine(L"test.exe argtest aaa", &First, &Remain);
        assert(!wcscmp(First, L"test.exe"));
        assert(!wcscmp(Remain, L" argtest aaa"));
        HeapFree(GetProcessHeap(), 0, (LPVOID)First);
    }
    {
        LPCWSTR First, Remain;
        SplitCommandLine(L"  test.exe argtest aaa", &First, &Remain);
        assert(!wcscmp(First, L""));
        assert(!wcscmp(Remain, L"  test.exe argtest aaa"));
        HeapFree(GetProcessHeap(), 0, (LPVOID)First);
    }
    {
        LPCWSTR First, Remain;
        SplitCommandLine(L"test.exe   argtest aaa", &First, &Remain);
        assert(!wcscmp(First, L"test.exe"));
        assert(!wcscmp(Remain, L"   argtest aaa"));
        HeapFree(GetProcessHeap(), 0, (LPVOID)First);
    }
    {
        LPCWSTR First, Remain;
        SplitCommandLine(L"\"test.exe\"   argtest aaa", &First, &Remain);
        assert(!wcscmp(First, L"\"test.exe\""));
        assert(!wcscmp(Remain, L"   argtest aaa"));
        HeapFree(GetProcessHeap(), 0, (LPVOID)First);
    }
    {
        LPCWSTR First, Remain;
        SplitCommandLine(L"\"test\\\\.exe\"   argtest aaa", &First, &Remain);
        assert(!wcscmp(First, L"\"test\\\\.exe\""));
        assert(!wcscmp(Remain, L"   argtest aaa"));
        HeapFree(GetProcessHeap(), 0, (LPVOID)First);
    }
    {
        LPCWSTR First, Remain;
        SplitCommandLine(L"\"test\\\".exe\"   argtest aaa", &First, &Remain);
        assert(!wcscmp(First, L"\"test\\\""));
        assert(!wcscmp(Remain, L".exe\"   argtest aaa"));
        HeapFree(GetProcessHeap(), 0, (LPVOID)First);
    }
    {
        LPCWSTR First, Remain;
        SplitCommandLine(L"\"test\\\".ex e\"\"aaa\"   argtest aaa", &First, &Remain);
        assert(!wcscmp(First, L"\"test\\\""));
        assert(!wcscmp(Remain, L".ex e\"\"aaa\"   argtest aaa"));
        HeapFree(GetProcessHeap(), 0, (LPVOID)First);
    }
    assert(!wcscmp(ReplaceCommandLine(L"%m", L"Mapped", L"cmd"), L"cmd Mapped"));
    assert(!wcscmp(ReplaceCommandLine(L"%c", L"Mapped", L"cmd"), L"cmd "));
    assert(!wcscmp(ReplaceCommandLine(L"%m %c", L"Mapped", L"cmd"), L"cmd Mapped "));
    assert(!wcscmp(ReplaceCommandLine(L"%m %c", L"Mapped", L"cmd args"), L"cmd Mapped  args"));
#if 0
    // original implementation
    assert(!wcscmp(ReplaceCommandLine(L"%m %c", L"Mapped", L"\"cmd\" args"), L"\"cmd Mapped \" args"));
#else
    assert(!wcscmp(ReplaceCommandLine(L"%m %c", L"Mapped", L"\"cmd\" args"), L"\"cmd\" Mapped  args"));
#endif
    Process(&app, &cmd);
}
#endif
