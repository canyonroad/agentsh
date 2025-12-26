// shim/windows/inject.cpp
// Helper to launch a process with envshim.dll injected
// Usage: envshim-inject.exe <program> [args...]

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <detours.h>
#include <stdio.h>
#include <stdlib.h>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        fwprintf(stderr, L"Usage: %s <program> [args...]\n", argv[0]);
        fwprintf(stderr, L"\nLaunches a program with agentsh environment variable protection.\n");
        return 1;
    }

    // Find the DLL path (same directory as this exe)
    wchar_t dllPath[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, dllPath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        fwprintf(stderr, L"Error: Could not determine module path\n");
        return 1;
    }

    // Replace exe name with dll name
    wchar_t* lastSlash = wcsrchr(dllPath, L'\\');
    if (lastSlash) {
        wcscpy_s(lastSlash + 1, MAX_PATH - (lastSlash - dllPath + 1), L"envshim.dll");
    } else {
        wcscpy_s(dllPath, MAX_PATH, L"envshim.dll");
    }

    // Check DLL exists
    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"Error: Could not find envshim.dll at %s\n", dllPath);
        return 1;
    }

    // Build command line
    wchar_t cmdLine[32768] = {0};
    for (int i = 1; i < argc; i++) {
        if (i > 1) wcscat_s(cmdLine, sizeof(cmdLine)/sizeof(wchar_t), L" ");

        // Quote if contains spaces
        if (wcschr(argv[i], L' ')) {
            wcscat_s(cmdLine, sizeof(cmdLine)/sizeof(wchar_t), L"\"");
            wcscat_s(cmdLine, sizeof(cmdLine)/sizeof(wchar_t), argv[i]);
            wcscat_s(cmdLine, sizeof(cmdLine)/sizeof(wchar_t), L"\"");
        } else {
            wcscat_s(cmdLine, sizeof(cmdLine)/sizeof(wchar_t), argv[i]);
        }
    }

    // Create process with DLL injected
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    char dllPathA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, dllPath, -1, dllPathA, MAX_PATH, NULL, NULL);

    BOOL result = DetourCreateProcessWithDllExW(
        NULL,           // lpApplicationName
        cmdLine,        // lpCommandLine
        NULL,           // lpProcessAttributes
        NULL,           // lpThreadAttributes
        TRUE,           // bInheritHandles
        CREATE_DEFAULT_ERROR_MODE,  // dwCreationFlags
        NULL,           // lpEnvironment
        NULL,           // lpCurrentDirectory
        &si,            // lpStartupInfo
        &pi,            // lpProcessInformation
        dllPathA,       // lpDllName
        NULL            // pfCreateProcessW
    );

    if (!result) {
        DWORD err = GetLastError();
        fwprintf(stderr, L"Error: Failed to create process (error %lu)\n", err);
        return 1;
    }

    // Wait for process to complete
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return (int)exitCode;
}
