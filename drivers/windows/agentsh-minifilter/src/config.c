// config.c - Driver configuration
#include "driver.h"
#include "config.h"

// Global configuration (protected by lock)
static EX_PUSH_LOCK gConfigLock;
static AGENTSH_CONFIG gConfig;

VOID AgentshInitializeConfig(VOID)
{
    ExInitializePushLock(&gConfigLock);

    RtlZeroMemory(&gConfig, sizeof(gConfig));
    gConfig.FailMode = DEFAULT_FAIL_MODE;
    gConfig.PolicyQueryTimeoutMs = DEFAULT_POLICY_TIMEOUT_MS;
    gConfig.MaxConsecutiveFailures = DEFAULT_MAX_CONSECUTIVE_FAIL;
    gConfig.CacheMaxEntries = DEFAULT_CACHE_MAX_ENTRIES;
    gConfig.CacheDefaultTTLMs = DEFAULT_CACHE_TTL_MS;

    DbgPrint("AgentSH: Configuration initialized (FailMode=%d, Timeout=%lu)\n",
             gConfig.FailMode, gConfig.PolicyQueryTimeoutMs);
}

VOID AgentshGetConfig(_Out_ PAGENTSH_CONFIG config)
{
    ExAcquirePushLockShared(&gConfigLock);
    RtlCopyMemory(config, &gConfig, sizeof(AGENTSH_CONFIG));
    ExReleasePushLockShared(&gConfigLock);
}

NTSTATUS AgentshSetConfig(_In_ PAGENTSH_CONFIG config)
{
    // Validate FailMode enum
    if (config->FailMode != FAIL_MODE_OPEN && config->FailMode != FAIL_MODE_CLOSED) {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate configuration values
    if (config->PolicyQueryTimeoutMs < 100 || config->PolicyQueryTimeoutMs > 60000) {
        return STATUS_INVALID_PARAMETER;
    }
    if (config->MaxConsecutiveFailures < 1 || config->MaxConsecutiveFailures > 1000) {
        return STATUS_INVALID_PARAMETER;
    }
    if (config->CacheMaxEntries < 100 || config->CacheMaxEntries > 100000) {
        return STATUS_INVALID_PARAMETER;
    }
    if (config->CacheDefaultTTLMs < 100 || config->CacheDefaultTTLMs > 3600000) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&gConfigLock);

    gConfig.FailMode = config->FailMode;
    gConfig.PolicyQueryTimeoutMs = config->PolicyQueryTimeoutMs;
    gConfig.MaxConsecutiveFailures = config->MaxConsecutiveFailures;
    gConfig.CacheMaxEntries = config->CacheMaxEntries;
    gConfig.CacheDefaultTTLMs = config->CacheDefaultTTLMs;

    ExReleasePushLockExclusive(&gConfigLock);

    DbgPrint("AgentSH: Configuration updated (FailMode=%d, Timeout=%lu, MaxFail=%lu)\n",
             config->FailMode, config->PolicyQueryTimeoutMs, config->MaxConsecutiveFailures);

    return STATUS_SUCCESS;
}

AGENTSH_FAIL_MODE AgentshGetFailMode(VOID)
{
    AGENTSH_FAIL_MODE mode;
    ExAcquirePushLockShared(&gConfigLock);
    mode = gConfig.FailMode;
    ExReleasePushLockShared(&gConfigLock);
    return mode;
}

ULONG AgentshGetPolicyTimeoutMs(VOID)
{
    ULONG timeout;
    ExAcquirePushLockShared(&gConfigLock);
    timeout = gConfig.PolicyQueryTimeoutMs;
    ExReleasePushLockShared(&gConfigLock);
    return timeout;
}

ULONG AgentshGetMaxConsecutiveFailures(VOID)
{
    ULONG maxFail;
    ExAcquirePushLockShared(&gConfigLock);
    maxFail = gConfig.MaxConsecutiveFailures;
    ExReleasePushLockShared(&gConfigLock);
    return maxFail;
}

ULONG AgentshGetCacheMaxEntries(VOID)
{
    ULONG maxEntries;
    ExAcquirePushLockShared(&gConfigLock);
    maxEntries = gConfig.CacheMaxEntries;
    ExReleasePushLockShared(&gConfigLock);
    return maxEntries;
}

ULONG AgentshGetCacheDefaultTTLMs(VOID)
{
    ULONG ttl;
    ExAcquirePushLockShared(&gConfigLock);
    ttl = gConfig.CacheDefaultTTLMs;
    ExReleasePushLockShared(&gConfigLock);
    return ttl;
}
