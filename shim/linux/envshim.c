// shim/linux/envshim.c
// Environment variable interception shim for Linux
// Compile: gcc -shared -fPIC -o libenvshim.so envshim.c -ldl
// Usage: LD_PRELOAD=/path/to/libenvshim.so command

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

// Configuration
#define MAX_PATTERNS 256
#define MAX_PATTERN_LEN 256
#define SOCKET_PATH_ENV "AGENTSH_ENV_SOCKET"
#define POLICY_FILE_ENV "AGENTSH_ENV_POLICY_FILE"
#define DEFAULT_SOCKET "/run/agentsh/env.sock"
#define DEFAULT_POLICY_FILE "/etc/agentsh/env-policy.conf"

// Original function pointers
static char* (*real_getenv)(const char*) = NULL;
static int (*real_putenv)(char*) = NULL;
static int (*real_setenv)(const char*, const char*, int) = NULL;
static int (*real_unsetenv)(const char*) = NULL;
static char* (*real_secure_getenv)(const char*) = NULL;

// Policy configuration
typedef struct {
    char patterns[MAX_PATTERNS][MAX_PATTERN_LEN];
    int count;
} PatternList;

static PatternList allowed_patterns = {0};
static PatternList blocked_patterns = {0};
static PatternList sensitive_patterns = {0};

static int policy_loaded = 0;
static int policy_mode_allowlist = 1;  // Default to allowlist mode (more secure)
static int log_access = 1;
static int initialized = 0;
static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

// Logging socket
static int log_socket = -1;
static struct sockaddr_un log_addr;

// Forward declarations
static void load_real_functions(void);
static void load_policy(void);
static int match_glob(const char* str, const char* pattern);
static int is_blocked(const char* name);
static int is_allowed(const char* name);
static int is_sensitive(const char* name);
static void emit_event(const char* var, const char* op, int allowed, int sensitive);
static void init_logging(void);

// String helper: uppercase
static void to_upper(char* dest, const char* src, size_t len) {
    size_t i;
    for (i = 0; i < len - 1 && src[i]; i++) {
        dest[i] = toupper((unsigned char)src[i]);
    }
    dest[i] = '\0';
}

// Glob pattern matching (supports * wildcard)
static int match_glob(const char* str, const char* pattern) {
    while (*pattern) {
        if (*pattern == '*') {
            pattern++;
            if (!*pattern) return 1;  // Trailing * matches everything
            while (*str) {
                if (match_glob(str, pattern)) return 1;
                str++;
            }
            return 0;
        }
        // Case-insensitive comparison
        if (tolower((unsigned char)*str) != tolower((unsigned char)*pattern)) return 0;
        str++;
        pattern++;
    }
    return !*str;
}

// Check if variable matches any blocked pattern
static int is_blocked(const char* name) {
    for (int i = 0; i < blocked_patterns.count; i++) {
        if (match_glob(name, blocked_patterns.patterns[i])) {
            return 1;
        }
    }
    return 0;
}

// Check if variable matches any allowed pattern
static int is_allowed(const char* name) {
    // Always block if in blocklist (blocklist takes precedence)
    if (is_blocked(name)) {
        return 0;
    }

    // In blocklist mode, allow anything not blocked
    if (!policy_mode_allowlist) {
        return 1;
    }

    // In allowlist mode, must match an allowed pattern
    for (int i = 0; i < allowed_patterns.count; i++) {
        if (match_glob(name, allowed_patterns.patterns[i])) {
            return 1;
        }
    }
    return 0;
}

// Check if variable is sensitive (for logging purposes)
static int is_sensitive(const char* name) {
    char upper[MAX_PATTERN_LEN];
    to_upper(upper, name, sizeof(upper));

    for (int i = 0; i < sensitive_patterns.count; i++) {
        char pattern_upper[MAX_PATTERN_LEN];
        to_upper(pattern_upper, sensitive_patterns.patterns[i], sizeof(pattern_upper));
        if (strstr(upper, pattern_upper)) {
            return 1;
        }
    }
    return 0;
}

// Initialize logging socket
static void init_logging(void) {
    const char* socket_path = real_getenv ? real_getenv(SOCKET_PATH_ENV) : getenv(SOCKET_PATH_ENV);
    if (!socket_path || !*socket_path) {
        socket_path = DEFAULT_SOCKET;
    }

    log_socket = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (log_socket < 0) return;

    memset(&log_addr, 0, sizeof(log_addr));
    log_addr.sun_family = AF_UNIX;
    strncpy(log_addr.sun_path, socket_path, sizeof(log_addr.sun_path) - 1);
}

// Emit event to agentsh daemon
static void emit_event(const char* var, const char* op, int allowed, int sensitive) {
    if (log_socket < 0 || !log_access) return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Determine event type
    const char* event_type;
    if (strcmp(op, "read") == 0) event_type = "env_read";
    else if (strcmp(op, "list") == 0) event_type = "env_list";
    else if (strcmp(op, "write") == 0) event_type = "env_write";
    else if (strcmp(op, "delete") == 0) event_type = "env_delete";
    else event_type = "env_access";

    char msg[1024];
    int len = snprintf(msg, sizeof(msg),
        "{"
        "\"type\":\"%s\","
        "\"timestamp\":%ld.%09ld,"
        "\"decision\":\"%s\","
        "\"platform\":\"linux-ld-preload\","
        "\"metadata\":{"
            "\"variable\":\"%s\","
            "\"operation\":\"%s\","
            "\"sensitive\":%s,"
            "\"pid\":%d"
        "}"
        "}",
        event_type,
        (long)ts.tv_sec, ts.tv_nsec,
        allowed ? "allow" : "deny",
        var ? var : "*",
        op,
        sensitive ? "true" : "false",
        getpid()
    );

    if (len > 0 && len < (int)sizeof(msg)) {
        sendto(log_socket, msg, len, MSG_DONTWAIT,
               (struct sockaddr*)&log_addr, sizeof(log_addr));
    }
}

// Add pattern to list
static void add_pattern(PatternList* list, const char* pattern) {
    if (list->count >= MAX_PATTERNS) return;
    strncpy(list->patterns[list->count], pattern, MAX_PATTERN_LEN - 1);
    list->patterns[list->count][MAX_PATTERN_LEN - 1] = '\0';
    list->count++;
}

// Parse comma-separated patterns
static void parse_patterns(PatternList* list, const char* str) {
    char buf[4096];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char* token = strtok(buf, ",");
    while (token) {
        // Trim whitespace
        while (*token && isspace((unsigned char)*token)) token++;
        char* end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) *end-- = '\0';

        if (*token) {
            add_pattern(list, token);
        }
        token = strtok(NULL, ",");
    }
}

// Load policy from file
static void load_policy(void) {
    if (policy_loaded) return;

    const char* policy_file = real_getenv ? real_getenv(POLICY_FILE_ENV) : getenv(POLICY_FILE_ENV);
    if (!policy_file || !*policy_file) {
        policy_file = DEFAULT_POLICY_FILE;
    }

    FILE* f = fopen(policy_file, "r");
    if (!f) {
        // No policy file - use permissive defaults (allow all, log access)
        policy_mode_allowlist = 0;
        policy_loaded = 1;
        return;
    }

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        // Skip comments and empty lines
        char* p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p || *p == '#') continue;

        // Remove trailing newline
        char* nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        // Parse key=value
        char* eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char* key = p;
        char* value = eq + 1;

        // Trim key
        char* key_end = eq - 1;
        while (key_end > key && isspace((unsigned char)*key_end)) *key_end-- = '\0';

        // Trim value
        while (*value && isspace((unsigned char)*value)) value++;

        if (strcasecmp(key, "mode") == 0) {
            policy_mode_allowlist = (strcasecmp(value, "allowlist") == 0);
        } else if (strcasecmp(key, "allowlist") == 0 || strcasecmp(key, "allowed") == 0) {
            parse_patterns(&allowed_patterns, value);
        } else if (strcasecmp(key, "blocklist") == 0 || strcasecmp(key, "blocked") == 0) {
            parse_patterns(&blocked_patterns, value);
        } else if (strcasecmp(key, "sensitive_patterns") == 0 || strcasecmp(key, "sensitive") == 0) {
            parse_patterns(&sensitive_patterns, value);
        } else if (strcasecmp(key, "log_access") == 0) {
            log_access = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
        }
    }

    fclose(f);
    policy_loaded = 1;
}

// Load original functions
static void load_real_functions(void) {
    real_getenv = dlsym(RTLD_NEXT, "getenv");
    real_putenv = dlsym(RTLD_NEXT, "putenv");
    real_setenv = dlsym(RTLD_NEXT, "setenv");
    real_unsetenv = dlsym(RTLD_NEXT, "unsetenv");
    real_secure_getenv = dlsym(RTLD_NEXT, "secure_getenv");
}

// Initialization (called on library load)
__attribute__((constructor))
static void shim_init(void) {
    pthread_mutex_lock(&init_mutex);
    if (!initialized) {
        load_real_functions();
        load_policy();
        init_logging();
        initialized = 1;
    }
    pthread_mutex_unlock(&init_mutex);
}

// Cleanup
__attribute__((destructor))
static void shim_cleanup(void) {
    if (log_socket >= 0) {
        close(log_socket);
        log_socket = -1;
    }
}

// === Intercepted functions ===

char* getenv(const char* name) {
    if (!initialized) shim_init();
    if (!name) return NULL;

    int sensitive = is_sensitive(name);
    int allowed = is_allowed(name);

    emit_event(name, "read", allowed, sensitive);

    if (!allowed) {
        return NULL;  // Behave as if variable doesn't exist
    }

    return real_getenv ? real_getenv(name) : NULL;
}

char* secure_getenv(const char* name) {
    if (!initialized) shim_init();
    if (!name) return NULL;

    int sensitive = is_sensitive(name);
    int allowed = is_allowed(name);

    emit_event(name, "read", allowed, sensitive);

    if (!allowed) {
        return NULL;
    }

    // Use secure_getenv if available, fall back to getenv
    if (real_secure_getenv) {
        return real_secure_getenv(name);
    }
    return real_getenv ? real_getenv(name) : NULL;
}

int setenv(const char* name, const char* value, int overwrite) {
    if (!initialized) shim_init();
    if (!name) {
        errno = EINVAL;
        return -1;
    }

    int sensitive = is_sensitive(name);
    int allowed = is_allowed(name);

    emit_event(name, "write", allowed, sensitive);

    if (!allowed) {
        errno = EPERM;
        return -1;
    }

    return real_setenv ? real_setenv(name, value, overwrite) : -1;
}

int putenv(char* string) {
    if (!initialized) shim_init();
    if (!string) {
        errno = EINVAL;
        return -1;
    }

    // Extract variable name
    char name[MAX_PATTERN_LEN];
    const char* eq = strchr(string, '=');
    if (eq) {
        size_t len = eq - string;
        if (len >= sizeof(name)) len = sizeof(name) - 1;
        strncpy(name, string, len);
        name[len] = '\0';
    } else {
        strncpy(name, string, sizeof(name) - 1);
        name[sizeof(name) - 1] = '\0';
    }

    int sensitive = is_sensitive(name);
    int allowed = is_allowed(name);

    emit_event(name, "write", allowed, sensitive);

    if (!allowed) {
        errno = EPERM;
        return -1;
    }

    return real_putenv ? real_putenv(string) : -1;
}

int unsetenv(const char* name) {
    if (!initialized) shim_init();
    if (!name) {
        errno = EINVAL;
        return -1;
    }

    int sensitive = is_sensitive(name);

    // Always allow unset, but log it
    emit_event(name, "delete", 1, sensitive);

    return real_unsetenv ? real_unsetenv(name) : -1;
}
