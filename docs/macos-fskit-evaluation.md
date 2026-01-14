# macOS FSKit Evaluation

**Date:** 2026-01-14
**Status:** Not Adopted
**Decision:** Continue using FUSE-T for macOS filesystem enforcement

## Summary

Apple introduced FSKit in macOS 26 as a native userspace filesystem API, eliminating the need for kernel extensions (kexts). This document evaluates FSKit as a potential replacement for FUSE-T and explains why we chose not to adopt it.

## What is FSKit?

FSKit is Apple's official API for implementing filesystems in userspace without kernel extensions. It was introduced to address the deprecation of kexts and provide a supported path for third-party filesystem implementations.

**Benefits:**
- No kernel extension required
- Apple-supported API
- No need to boot into Recovery Mode to enable
- Used internally by Apple (ExFAT, FAT32 now use FSKit)

## FSKit Limitations (as of macOS 26)

| Feature | Linux FUSE | FUSE-T | FSKit |
|---------|------------|--------|-------|
| Process attribution (PID) | Yes | Yes (via NFS) | **No** |
| Kernel caching (entry/attr) | Yes | Yes | **No** |
| Negative lookup caching | Yes | Yes | **No** |
| Readdir caching | Yes | Yes | **No** |
| Sandbox-friendly | N/A | Yes | **Limited** |

### Critical Missing Features

#### 1. No Process Attribution

FSKit does not provide the Process ID (PID) of the process making filesystem requests. Linux FUSE provides this via `fuse_in_header.pid`.

**Impact on agentsh:** Process attribution is fundamental to our security model. We need to know *which process* is accessing files to:
- Apply per-process policies
- Track parent-child relationships
- Generate accurate audit logs
- Make approval decisions

Without PID information, we cannot implement policy enforcement.

#### 2. No Kernel Caching

FSKit lacks the kernel-level caching that FUSE provides:
- **Entry caching** (`entry_timeout`): Cache directory entry lookups
- **Attribute caching** (`attr_timeout`): Cache file metadata
- **Negative lookup caching**: Cache "file not found" results
- **Readdir caching**: Cache directory listings

**Impact on agentsh:** Testing shows ~121μs overhead per `getdirentries` syscall due to FSKit-to-kernel communication. This overhead would significantly impact filesystem performance during normal development workflows.

#### 3. Sandbox Restrictions

Accessing user-provided file paths from FSKit extensions requires privileged helpers, adding complexity and reducing performance.

**Impact on agentsh:** Our architecture requires mounting user directories. The sandbox restrictions would complicate deployment and potentially require additional privileged components.

## Why FUSE-T Works

FUSE-T implements FUSE semantics using NFS as the transport layer:

```
Application → NFS Client (kernel) → NFS Server (userspace, FUSE-T) → FUSE filesystem
```

This architecture:
1. **Preserves PID information** - NFS requests include process context
2. **Leverages NFS caching** - Kernel NFS client provides caching
3. **No kext required** - Pure userspace implementation
4. **FUSE API compatible** - Existing FUSE filesystems work with minimal changes

## Decision

**We will continue using FUSE-T** for macOS filesystem enforcement because:

1. **Process attribution is required** for policy enforcement
2. **Performance is acceptable** with NFS caching
3. **Mature and stable** - actively maintained, production-ready
4. **No kext required** - same benefit as FSKit

## Future Considerations

We will re-evaluate FSKit when Apple addresses:

- [ ] Process attribution (PID in filesystem requests)
- [ ] Kernel caching support (entry/attr/readdir)
- [ ] Improved sandbox story for user directories

macFUSE 4.x already supports FSKit as a backend, so migration would be straightforward once these limitations are resolved.

## References

- [Which local file systems does macOS 26 support?](https://eclecticlight.co/2025/11/18/which-local-file-systems-does-macos-26-support/)
- [FSKit - Apple Developer Forums](https://developer.apple.com/forums/tags/fskit)
- [FUSE-T](https://www.fuse-t.org/)
- [macFUSE](https://macfuse.github.io/)
- [FSKit questions and clarifications](https://developer.apple.com/forums/thread/766793)
