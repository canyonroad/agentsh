// cache.h - Policy cache definitions
#ifndef _AGENTSH_CACHE_H_
#define _AGENTSH_CACHE_H_

#include <fltKernel.h>
#include "protocol.h"

// Pool tag for cache allocations
#define AGENTSH_TAG_CACHE 'acGA'

// Cache configuration
#define CACHE_BUCKET_COUNT 256
#define CACHE_BUCKET_MASK (CACHE_BUCKET_COUNT - 1)
#define CACHE_MAX_ENTRIES 4096
#define CACHE_DEFAULT_TTL_MS 5000

// Cache entry
typedef struct _CACHE_ENTRY {
    LIST_ENTRY HashEntry;           // Hash bucket chain
    LIST_ENTRY LruEntry;            // LRU list
    ULONG64 SessionToken;
    AGENTSH_FILE_OP Operation;
    AGENTSH_DECISION Decision;
    LARGE_INTEGER ExpiryTime;
    ULONG PathHash;
    WCHAR Path[AGENTSH_MAX_PATH];
} CACHE_ENTRY, *PCACHE_ENTRY;

// Policy cache
typedef struct _POLICY_CACHE {
    EX_PUSH_LOCK Lock;
    LIST_ENTRY Buckets[CACHE_BUCKET_COUNT];
    LIST_ENTRY LruHead;             // Most recent at head
    volatile LONG EntryCount;
    volatile LONG HitCount;
    volatile LONG MissCount;
} POLICY_CACHE;

// Initialize the policy cache
NTSTATUS
AgentshInitializeCache(
    VOID
    );

// Shutdown the policy cache
VOID
AgentshShutdownCache(
    VOID
    );

// Lookup a cached decision
BOOLEAN
AgentshCacheLookup(
    _In_ ULONG64 SessionToken,
    _In_ AGENTSH_FILE_OP Operation,
    _In_ PCWSTR Path,
    _Out_ PAGENTSH_DECISION Decision
    );

// Insert a decision into the cache
VOID
AgentshCacheInsert(
    _In_ ULONG64 SessionToken,
    _In_ AGENTSH_FILE_OP Operation,
    _In_ PCWSTR Path,
    _In_ AGENTSH_DECISION Decision,
    _In_ ULONG TTLMs
    );

// Invalidate all entries for a session
VOID
AgentshCacheInvalidateSession(
    _In_ ULONG64 SessionToken
    );

// Get cache statistics
VOID
AgentshCacheGetStats(
    _Out_ PLONG HitCount,
    _Out_ PLONG MissCount,
    _Out_ PLONG EntryCount
    );

#endif // _AGENTSH_CACHE_H_
