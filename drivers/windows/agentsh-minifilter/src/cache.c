// cache.c - Policy cache implementation
#include "driver.h"
#include "cache.h"

// Global cache
static POLICY_CACHE gCache;

// Hash function for path
static ULONG HashPath(PCWSTR Path)
{
    ULONG hash = 5381;
    while (*Path) {
        // Case-insensitive hash (Windows paths are case-insensitive)
        WCHAR c = *Path++;
        if (c >= L'A' && c <= L'Z') c += 32;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Initialize the policy cache
NTSTATUS
AgentshInitializeCache(
    VOID
    )
{
    ULONG i;

    ExInitializePushLock(&gCache.Lock);
    InitializeListHead(&gCache.LruHead);

    for (i = 0; i < CACHE_BUCKET_COUNT; i++) {
        InitializeListHead(&gCache.Buckets[i]);
    }

    gCache.EntryCount = 0;
    gCache.HitCount = 0;
    gCache.MissCount = 0;

    DbgPrint("AgentSH: Policy cache initialized\n");
    return STATUS_SUCCESS;
}

// Shutdown the policy cache
VOID
AgentshShutdownCache(
    VOID
    )
{
    PLIST_ENTRY entry;
    PCACHE_ENTRY cacheEntry;

    ExAcquirePushLockExclusive(&gCache.Lock);

    // Free all entries via LRU list (more efficient than walking buckets)
    while (!IsListEmpty(&gCache.LruHead)) {
        entry = RemoveHeadList(&gCache.LruHead);
        cacheEntry = CONTAINING_RECORD(entry, CACHE_ENTRY, LruEntry);
        ExFreePoolWithTag(cacheEntry, AGENTSH_TAG_CACHE);
    }

    gCache.EntryCount = 0;

    ExReleasePushLockExclusive(&gCache.Lock);

    DbgPrint("AgentSH: Policy cache shutdown (hits=%ld, misses=%ld)\n",
             gCache.HitCount, gCache.MissCount);
}

// Check if entry is expired
static BOOLEAN IsExpired(PCACHE_ENTRY Entry)
{
    LARGE_INTEGER now;
    KeQuerySystemTimePrecise(&now);
    return now.QuadPart >= Entry->ExpiryTime.QuadPart;
}

// Lookup a cached decision
BOOLEAN
AgentshCacheLookup(
    _In_ ULONG64 SessionToken,
    _In_ AGENTSH_FILE_OP Operation,
    _In_ PCWSTR Path,
    _Out_ PAGENTSH_DECISION Decision
    )
{
    ULONG hash = HashPath(Path);
    ULONG bucket = hash & CACHE_BUCKET_MASK;
    PLIST_ENTRY entry;
    PCACHE_ENTRY cacheEntry;
    BOOLEAN found = FALSE;

    ExAcquirePushLockShared(&gCache.Lock);

    for (entry = gCache.Buckets[bucket].Flink;
         entry != &gCache.Buckets[bucket];
         entry = entry->Flink)
    {
        cacheEntry = CONTAINING_RECORD(entry, CACHE_ENTRY, HashEntry);

        if (cacheEntry->SessionToken == SessionToken &&
            cacheEntry->Operation == Operation &&
            cacheEntry->PathHash == hash &&
            _wcsicmp(cacheEntry->Path, Path) == 0)
        {
            if (!IsExpired(cacheEntry)) {
                *Decision = cacheEntry->Decision;
                found = TRUE;
                InterlockedIncrement(&gCache.HitCount);
            }
            break;
        }
    }

    if (!found) {
        InterlockedIncrement(&gCache.MissCount);
    }

    ExReleasePushLockShared(&gCache.Lock);
    return found;
}

// Evict oldest entry if at capacity
static VOID EvictIfNeeded(VOID)
{
    PCACHE_ENTRY oldest;

    if (gCache.EntryCount < CACHE_MAX_ENTRIES) {
        return;
    }

    // Remove from LRU tail (oldest)
    if (!IsListEmpty(&gCache.LruHead)) {
        oldest = CONTAINING_RECORD(gCache.LruHead.Blink, CACHE_ENTRY, LruEntry);
        RemoveEntryList(&oldest->LruEntry);
        RemoveEntryList(&oldest->HashEntry);
        ExFreePoolWithTag(oldest, AGENTSH_TAG_CACHE);
        InterlockedDecrement(&gCache.EntryCount);
    }
}

// Insert a decision into the cache
VOID
AgentshCacheInsert(
    _In_ ULONG64 SessionToken,
    _In_ AGENTSH_FILE_OP Operation,
    _In_ PCWSTR Path,
    _In_ AGENTSH_DECISION Decision,
    _In_ ULONG TTLMs
    )
{
    ULONG hash = HashPath(Path);
    ULONG bucket = hash & CACHE_BUCKET_MASK;
    PCACHE_ENTRY newEntry;
    LARGE_INTEGER now;
    SIZE_T pathLen;

    newEntry = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(CACHE_ENTRY),
        AGENTSH_TAG_CACHE
        );

    if (newEntry == NULL) {
        return;
    }

    // Initialize entry
    newEntry->SessionToken = SessionToken;
    newEntry->Operation = Operation;
    newEntry->Decision = Decision;
    newEntry->PathHash = hash;

    // Copy path (ensure null termination)
    pathLen = wcslen(Path);
    if (pathLen >= AGENTSH_MAX_PATH) {
        pathLen = AGENTSH_MAX_PATH - 1;
    }
    RtlCopyMemory(newEntry->Path, Path, pathLen * sizeof(WCHAR));
    newEntry->Path[pathLen] = L'\0';

    // Set expiry time
    KeQuerySystemTimePrecise(&now);
    // Convert ms to 100ns units
    newEntry->ExpiryTime.QuadPart = now.QuadPart + ((LONGLONG)TTLMs * 10000);

    ExAcquirePushLockExclusive(&gCache.Lock);

    // Evict if at capacity
    EvictIfNeeded();

    // Insert into hash bucket
    InsertHeadList(&gCache.Buckets[bucket], &newEntry->HashEntry);

    // Insert at LRU head (most recently used)
    InsertHeadList(&gCache.LruHead, &newEntry->LruEntry);

    InterlockedIncrement(&gCache.EntryCount);

    ExReleasePushLockExclusive(&gCache.Lock);
}

// Invalidate all entries for a session
VOID
AgentshCacheInvalidateSession(
    _In_ ULONG64 SessionToken
    )
{
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    PCACHE_ENTRY cacheEntry;

    ExAcquirePushLockExclusive(&gCache.Lock);

    // Walk LRU list and remove matching entries
    for (entry = gCache.LruHead.Flink; entry != &gCache.LruHead; entry = next) {
        next = entry->Flink;
        cacheEntry = CONTAINING_RECORD(entry, CACHE_ENTRY, LruEntry);

        if (cacheEntry->SessionToken == SessionToken) {
            RemoveEntryList(&cacheEntry->LruEntry);
            RemoveEntryList(&cacheEntry->HashEntry);
            ExFreePoolWithTag(cacheEntry, AGENTSH_TAG_CACHE);
            InterlockedDecrement(&gCache.EntryCount);
        }
    }

    ExReleasePushLockExclusive(&gCache.Lock);
}

// Get cache statistics
VOID
AgentshCacheGetStats(
    _Out_ PLONG HitCount,
    _Out_ PLONG MissCount,
    _Out_ PLONG EntryCount
    )
{
    *HitCount = gCache.HitCount;
    *MissCount = gCache.MissCount;
    *EntryCount = gCache.EntryCount;
}
