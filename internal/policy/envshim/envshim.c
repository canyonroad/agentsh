//go:build ignore

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char **blocked_environ = (char *[]) { NULL };
static char **real_environ = NULL;
static char ***real_environ_sym = NULL;
static int (*real_putenv)(char *) = NULL;
static int (*real_setenv)(const char *, const char *, int) = NULL;
static int (*real_unsetenv)(const char *) = NULL;
static char *(*real_getenv)(const char *) = NULL;

// Refer to libc's environ (do not define it ourselves).
extern char **environ;

static void init(void) __attribute__((constructor));

static void init(void) {
    real_putenv = dlsym(RTLD_NEXT, "putenv");
    real_setenv = dlsym(RTLD_NEXT, "setenv");
    real_unsetenv = dlsym(RTLD_NEXT, "unsetenv");
    real_getenv = dlsym(RTLD_NEXT, "getenv");
    real_environ_sym = (char ***)dlsym(RTLD_DEFAULT, "environ");
    if (real_environ_sym && *real_environ_sym) {
        real_environ = *real_environ_sym;
    } else if (environ) {
        real_environ = environ;
    }

    const char *flag = real_getenv ? real_getenv("AGENTSH_ENV_BLOCK_ITERATION") : getenv("AGENTSH_ENV_BLOCK_ITERATION");
    int block = (flag && strcmp(flag, "1") == 0);
    char **target = block ? blocked_environ : (real_environ ? real_environ : blocked_environ);

    if (real_environ_sym) {
        *real_environ_sym = target;
    }
    environ = target;
}

int putenv(char *string) {
    if (!real_putenv) init();
    return real_putenv(string);
}

int setenv(const char *name, const char *value, int overwrite) {
    if (!real_setenv) init();
    return real_setenv(name, value, overwrite);
}

int unsetenv(const char *name) {
    if (!real_unsetenv) init();
    return real_unsetenv(name);
}

char *getenv(const char *name) {
    if (!real_getenv) init();
    return real_getenv(name);
}
