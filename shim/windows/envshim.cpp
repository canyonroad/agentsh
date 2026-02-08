// shim/windows/envshim.cpp
// Environment variable interception shim for Windows
// Requires Microsoft Detours: https://github.com/microsoft/Detours
// Compile: cl /LD envshim.cpp /link detours.lib
// Usage: Inject this DLL into target process or use IFEO

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <detours.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <wchar.h>

// Configuration
#define MAX_PATTERNS 256
#define MAX_PATTERN_LEN 256
#define POLICY_FILE_ENV L"AGENTSH_ENV_POLICY_FILE"
#define DEFAULT_POLICY_FILE L"C:\\ProgramData\\agentsh\\env-policy.conf"
#define PIPE_NAME L"\\\\.\\pipe\\agentsh-env"

// Pattern list
typedef struct {
    wchar_t patterns[MAX_PATTERNS][MAX_PATTERN_LEN];
    int count;
} PatternList;

static PatternList allowed_patterns = {0};
static PatternList blocked_patterns = {0};
static PatternList sensitive_patterns = {0};

static int policy_loaded = 0;
static int policy_mode_allowlist = 1;
static int log_access = 1;
static HANDLE log_pipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION init_cs;
static int initialized = 0;

// GetEnvironmentStrings is special: the ANSI function is named GetEnvironmentStrings
// (no A suffix), but when UNICODE is defined it becomes a macro for GetEnvironmentStringsW.
// We must grab the ANSI function pointer before the macro takes effect.
#ifdef UNICODE
#undef GetEnvironmentStrings
#endif
// Original function pointers
static DWORD (WINAPI *Real_GetEnvironmentVariableA)(LPCSTR, LPSTR, DWORD) = GetEnvironmentVariableA;
static DWORD (WINAPI *Real_GetEnvironmentVariableW)(LPCWSTR, LPWSTR, DWORD) = GetEnvironmentVariableW;
static LPCH (WINAPI *Real_GetEnvironmentStringsA)(void) = GetEnvironmentStrings;
static LPWCH (WINAPI *Real_GetEnvironmentStringsW)(void) = GetEnvironmentStringsW;
static BOOL (WINAPI *Real_SetEnvironmentVariableA)(LPCSTR, LPCSTR) = SetEnvironmentVariableA;
static BOOL (WINAPI *Real_SetEnvironmentVariableW)(LPCWSTR, LPCWSTR) = SetEnvironmentVariableW;

// Forward declarations
static void load_policy(void);
static int match_glob_w(const wchar_t* str, const wchar_t* pattern);
static int is_blocked_w(const wchar_t* name);
static int is_allowed_w(const wchar_t* name);
static int is_sensitive_w(const wchar_t* name);
static void emit_event_w(const wchar_t* var, const wchar_t* op, int allowed, int sensitive);
static void init_logging(void);

// String helper: convert to wide
static void to_wide(wchar_t* dest, const char* src, size_t len) {
    MultiByteToWideChar(CP_ACP, 0, src, -1, dest, (int)len);
}

// String helper: uppercase
static void to_upper_w(wchar_t* dest, const wchar_t* src, size_t len) {
    size_t i;
    for (i = 0; i < len - 1 && src[i]; i++) {
        dest[i] = towupper(src[i]);
    }
    dest[i] = L'\0';
}

// Glob pattern matching
static int match_glob_w(const wchar_t* str, const wchar_t* pattern) {
    while (*pattern) {
        if (*pattern == L'*') {
            pattern++;
            if (!*pattern) return 1;
            while (*str) {
                if (match_glob_w(str, pattern)) return 1;
                str++;
            }
            return 0;
        }
        if (towlower(*str) != towlower(*pattern)) return 0;
        str++;
        pattern++;
    }
    return !*str;
}

// Check if variable matches any blocked pattern
static int is_blocked_w(const wchar_t* name) {
    for (int i = 0; i < blocked_patterns.count; i++) {
        if (match_glob_w(name, blocked_patterns.patterns[i])) {
            return 1;
        }
    }
    return 0;
}

// Check if variable matches any allowed pattern
static int is_allowed_w(const wchar_t* name) {
    if (is_blocked_w(name)) {
        return 0;
    }

    if (!policy_mode_allowlist) {
        return 1;
    }

    for (int i = 0; i < allowed_patterns.count; i++) {
        if (match_glob_w(name, allowed_patterns.patterns[i])) {
            return 1;
        }
    }
    return 0;
}

// Check if variable is sensitive
static int is_sensitive_w(const wchar_t* name) {
    wchar_t upper[MAX_PATTERN_LEN];
    to_upper_w(upper, name, MAX_PATTERN_LEN);

    for (int i = 0; i < sensitive_patterns.count; i++) {
        wchar_t pattern_upper[MAX_PATTERN_LEN];
        to_upper_w(pattern_upper, sensitive_patterns.patterns[i], MAX_PATTERN_LEN);
        if (wcsstr(upper, pattern_upper)) {
            return 1;
        }
    }
    return 0;
}

// Initialize logging pipe
static void init_logging(void) {
    log_pipe = CreateFileW(
        PIPE_NAME,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
}

// Emit event to agentsh daemon
static void emit_event_w(const wchar_t* var, const wchar_t* op, int allowed, int sensitive) {
    if (log_pipe == INVALID_HANDLE_VALUE || !log_access) return;

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    double timestamp = (double)(uli.QuadPart - 116444736000000000ULL) / 10000000.0;

    char msg[1024];
    char var_utf8[MAX_PATTERN_LEN];
    char op_utf8[32];
    WideCharToMultiByte(CP_UTF8, 0, var ? var : L"*", -1, var_utf8, sizeof(var_utf8), NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, op, -1, op_utf8, sizeof(op_utf8), NULL, NULL);

    const char* event_type;
    if (wcscmp(op, L"read") == 0) event_type = "env_read";
    else if (wcscmp(op, L"list") == 0) event_type = "env_list";
    else if (wcscmp(op, L"write") == 0) event_type = "env_write";
    else if (wcscmp(op, L"delete") == 0) event_type = "env_delete";
    else event_type = "env_access";

    int len = _snprintf_s(msg, sizeof(msg), _TRUNCATE,
        "{"
        "\"type\":\"%s\","
        "\"timestamp\":%.6f,"
        "\"decision\":\"%s\","
        "\"platform\":\"windows-detours\","
        "\"metadata\":{"
            "\"variable\":\"%s\","
            "\"operation\":\"%s\","
            "\"sensitive\":%s,"
            "\"pid\":%lu"
        "}"
        "}",
        event_type,
        timestamp,
        allowed ? "allow" : "deny",
        var_utf8,
        op_utf8,
        sensitive ? "true" : "false",
        GetCurrentProcessId()
    );

    if (len > 0) {
        DWORD written;
        WriteFile(log_pipe, msg, len, &written, NULL);
    }
}

// Add pattern to list
static void add_pattern_w(PatternList* list, const wchar_t* pattern) {
    if (list->count >= MAX_PATTERNS) return;
    wcsncpy_s(list->patterns[list->count], MAX_PATTERN_LEN, pattern, _TRUNCATE);
    list->count++;
}

// Parse comma-separated patterns
static void parse_patterns_w(PatternList* list, const wchar_t* str) {
    wchar_t buf[4096];
    wcsncpy_s(buf, sizeof(buf)/sizeof(wchar_t), str, _TRUNCATE);

    wchar_t* context = NULL;
    wchar_t* token = wcstok_s(buf, L",", &context);
    while (token) {
        while (*token && iswspace(*token)) token++;
        wchar_t* end = token + wcslen(token) - 1;
        while (end > token && iswspace(*end)) *end-- = L'\0';

        if (*token) {
            add_pattern_w(list, token);
        }
        token = wcstok_s(NULL, L",", &context);
    }
}

// Load policy from file
static void load_policy(void) {
    if (policy_loaded) return;

    wchar_t policy_file[MAX_PATH];
    DWORD len = Real_GetEnvironmentVariableW(POLICY_FILE_ENV, policy_file, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        wcscpy_s(policy_file, MAX_PATH, DEFAULT_POLICY_FILE);
    }

    FILE* f = NULL;
    _wfopen_s(&f, policy_file, L"r, ccs=UTF-8");
    if (!f) {
        policy_mode_allowlist = 0;
        policy_loaded = 1;
        return;
    }

    wchar_t line[4096];
    while (fgetws(line, sizeof(line)/sizeof(wchar_t), f)) {
        wchar_t* p = line;
        while (*p && iswspace(*p)) p++;
        if (!*p || *p == L'#') continue;

        wchar_t* nl = wcschr(line, L'\n');
        if (nl) *nl = L'\0';

        wchar_t* eq = wcschr(p, L'=');
        if (!eq) continue;
        *eq = L'\0';
        wchar_t* key = p;
        wchar_t* value = eq + 1;

        wchar_t* key_end = eq - 1;
        while (key_end > key && iswspace(*key_end)) *key_end-- = L'\0';
        while (*value && iswspace(*value)) value++;

        if (_wcsicmp(key, L"mode") == 0) {
            policy_mode_allowlist = (_wcsicmp(value, L"allowlist") == 0);
        } else if (_wcsicmp(key, L"allowlist") == 0 || _wcsicmp(key, L"allowed") == 0) {
            parse_patterns_w(&allowed_patterns, value);
        } else if (_wcsicmp(key, L"blocklist") == 0 || _wcsicmp(key, L"blocked") == 0) {
            parse_patterns_w(&blocked_patterns, value);
        } else if (_wcsicmp(key, L"sensitive_patterns") == 0 || _wcsicmp(key, L"sensitive") == 0) {
            parse_patterns_w(&sensitive_patterns, value);
        } else if (_wcsicmp(key, L"log_access") == 0) {
            log_access = (_wcsicmp(value, L"true") == 0 || wcscmp(value, L"1") == 0);
        }
    }

    fclose(f);
    policy_loaded = 1;
}

// Initialize the shim
static void shim_init(void) {
    EnterCriticalSection(&init_cs);
    if (!initialized) {
        load_policy();
        init_logging();
        initialized = 1;
    }
    LeaveCriticalSection(&init_cs);
}

// === Hooked functions ===

DWORD WINAPI Hook_GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize) {
    if (!initialized) shim_init();
    if (!lpName) return 0;

    wchar_t nameW[MAX_PATTERN_LEN];
    to_wide(nameW, lpName, MAX_PATTERN_LEN);

    int sensitive = is_sensitive_w(nameW);
    int allowed = is_allowed_w(nameW);

    emit_event_w(nameW, L"read", allowed, sensitive);

    if (!allowed) {
        SetLastError(ERROR_ENVVAR_NOT_FOUND);
        return 0;
    }

    return Real_GetEnvironmentVariableA(lpName, lpBuffer, nSize);
}

DWORD WINAPI Hook_GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize) {
    if (!initialized) shim_init();
    if (!lpName) return 0;

    int sensitive = is_sensitive_w(lpName);
    int allowed = is_allowed_w(lpName);

    emit_event_w(lpName, L"read", allowed, sensitive);

    if (!allowed) {
        SetLastError(ERROR_ENVVAR_NOT_FOUND);
        return 0;
    }

    return Real_GetEnvironmentVariableW(lpName, lpBuffer, nSize);
}

BOOL WINAPI Hook_SetEnvironmentVariableA(LPCSTR lpName, LPCSTR lpValue) {
    if (!initialized) shim_init();
    if (!lpName) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    wchar_t nameW[MAX_PATTERN_LEN];
    to_wide(nameW, lpName, MAX_PATTERN_LEN);

    int sensitive = is_sensitive_w(nameW);
    int allowed = is_allowed_w(nameW);

    const wchar_t* op = lpValue ? L"write" : L"delete";
    emit_event_w(nameW, op, allowed, sensitive);

    if (!allowed) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    return Real_SetEnvironmentVariableA(lpName, lpValue);
}

BOOL WINAPI Hook_SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue) {
    if (!initialized) shim_init();
    if (!lpName) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    int sensitive = is_sensitive_w(lpName);
    int allowed = is_allowed_w(lpName);

    const wchar_t* op = lpValue ? L"write" : L"delete";
    emit_event_w(lpName, op, allowed, sensitive);

    if (!allowed) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    return Real_SetEnvironmentVariableW(lpName, lpValue);
}

// GetEnvironmentStrings returns the entire block - we filter it
LPCH WINAPI Hook_GetEnvironmentStringsA(void) {
    if (!initialized) shim_init();

    emit_event_w(L"*", L"list", 1, 0);

    // Get original strings
    LPCH orig = Real_GetEnvironmentStringsA();
    if (!orig) return orig;

    // Count size needed and filter
    size_t orig_size = 0;
    for (LPCH p = orig; *p; p += strlen(p) + 1) {
        orig_size += strlen(p) + 1;
    }
    orig_size++; // Final null

    // Allocate filtered buffer
    LPCH filtered = (LPCH)LocalAlloc(LMEM_FIXED, orig_size);
    if (!filtered) {
        FreeEnvironmentStringsA(orig);
        return NULL;
    }

    LPCH dst = filtered;
    for (LPCH p = orig; *p; p += strlen(p) + 1) {
        // Extract name
        const char* eq = strchr(p, '=');
        if (!eq) continue;

        char name[MAX_PATTERN_LEN];
        size_t name_len = eq - p;
        if (name_len >= sizeof(name)) continue;
        strncpy_s(name, sizeof(name), p, name_len);
        name[name_len] = '\0';

        wchar_t nameW[MAX_PATTERN_LEN];
        to_wide(nameW, name, MAX_PATTERN_LEN);

        if (is_allowed_w(nameW)) {
            size_t len = strlen(p) + 1;
            memcpy(dst, p, len);
            dst += len;
        }
    }
    *dst = '\0';

    FreeEnvironmentStringsA(orig);
    return filtered;
}

LPWCH WINAPI Hook_GetEnvironmentStringsW(void) {
    if (!initialized) shim_init();

    emit_event_w(L"*", L"list", 1, 0);

    LPWCH orig = Real_GetEnvironmentStringsW();
    if (!orig) return orig;

    // Count size needed
    size_t orig_size = 0;
    for (LPWCH p = orig; *p; p += wcslen(p) + 1) {
        orig_size += wcslen(p) + 1;
    }
    orig_size++; // Final null

    // Allocate filtered buffer
    LPWCH filtered = (LPWCH)LocalAlloc(LMEM_FIXED, orig_size * sizeof(wchar_t));
    if (!filtered) {
        FreeEnvironmentStringsW(orig);
        return NULL;
    }

    LPWCH dst = filtered;
    for (LPWCH p = orig; *p; p += wcslen(p) + 1) {
        const wchar_t* eq = wcschr(p, L'=');
        if (!eq) continue;

        wchar_t name[MAX_PATTERN_LEN];
        size_t name_len = eq - p;
        if (name_len >= MAX_PATTERN_LEN) continue;
        wcsncpy_s(name, MAX_PATTERN_LEN, p, name_len);
        name[name_len] = L'\0';

        if (is_allowed_w(name)) {
            size_t len = wcslen(p) + 1;
            memcpy(dst, p, len * sizeof(wchar_t));
            dst += len;
        }
    }
    *dst = L'\0';

    FreeEnvironmentStringsW(orig);
    return filtered;
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    (void)hModule;
    (void)lpReserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        InitializeCriticalSection(&init_cs);
        DetourRestoreAfterWith();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)Real_GetEnvironmentVariableA, Hook_GetEnvironmentVariableA);
        DetourAttach(&(PVOID&)Real_GetEnvironmentVariableW, Hook_GetEnvironmentVariableW);
        DetourAttach(&(PVOID&)Real_SetEnvironmentVariableA, Hook_SetEnvironmentVariableA);
        DetourAttach(&(PVOID&)Real_SetEnvironmentVariableW, Hook_SetEnvironmentVariableW);
        DetourAttach(&(PVOID&)Real_GetEnvironmentStringsA, Hook_GetEnvironmentStringsA);
        DetourAttach(&(PVOID&)Real_GetEnvironmentStringsW, Hook_GetEnvironmentStringsW);
        DetourTransactionCommit();
        break;

    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)Real_GetEnvironmentVariableA, Hook_GetEnvironmentVariableA);
        DetourDetach(&(PVOID&)Real_GetEnvironmentVariableW, Hook_GetEnvironmentVariableW);
        DetourDetach(&(PVOID&)Real_SetEnvironmentVariableA, Hook_SetEnvironmentVariableA);
        DetourDetach(&(PVOID&)Real_SetEnvironmentVariableW, Hook_SetEnvironmentVariableW);
        DetourDetach(&(PVOID&)Real_GetEnvironmentStringsA, Hook_GetEnvironmentStringsA);
        DetourDetach(&(PVOID&)Real_GetEnvironmentStringsW, Hook_GetEnvironmentStringsW);
        DetourTransactionCommit();

        if (log_pipe != INVALID_HANDLE_VALUE) {
            CloseHandle(log_pipe);
        }
        DeleteCriticalSection(&init_cs);
        break;
    }

    return TRUE;
}
