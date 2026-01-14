// macos/SysExt/ProcessHierarchy.swift
import Foundation

/// Tracks parent-child process relationships for policy inheritance.
/// Uses observed fork/exit events and falls back to sysctl for processes
/// not in our tracking (e.g., started before we began monitoring).
class ProcessHierarchy {
    /// Shared singleton instance
    static let shared = ProcessHierarchy()

    /// Maps child PID to parent PID
    private var parentMap: [pid_t: pid_t] = [:]

    /// Maps parent PID to set of child PIDs
    private var childrenMap: [pid_t: Set<pid_t>] = [:]

    /// Serial queue for thread-safe access
    private let queue = DispatchQueue(label: "com.agentsh.processhierarchy")

    private init() {}

    // MARK: - Public API

    /// Records a fork event, establishing parent-child relationship.
    /// - Parameters:
    ///   - parentPID: The PID of the parent process
    ///   - childPID: The PID of the newly forked child process
    func recordFork(parentPID: pid_t, childPID: pid_t) {
        queue.sync {
            parentMap[childPID] = parentPID

            if childrenMap[parentPID] == nil {
                childrenMap[parentPID] = Set()
            }
            childrenMap[parentPID]?.insert(childPID)
        }
    }

    /// Records a process exit, cleaning up tracking data.
    /// - Parameter pid: The PID of the exiting process
    func recordExit(pid: pid_t) {
        queue.sync {
            // Remove from parent's children set
            if let parentPID = parentMap[pid] {
                childrenMap[parentPID]?.remove(pid)
                if childrenMap[parentPID]?.isEmpty == true {
                    childrenMap.removeValue(forKey: parentPID)
                }
            }

            // Remove this process's parent mapping
            parentMap.removeValue(forKey: pid)

            // Note: We don't remove children mappings here.
            // Children of an exited process remain tracked until they exit.
            // Their parentMap entries remain valid (pointing to the now-dead parent).
        }
    }

    /// Gets the parent PID of a process.
    /// First checks our tracking, then falls back to sysctl.
    /// - Parameter pid: The PID to look up
    /// - Returns: The parent PID, or nil if not found
    func getParent(pid: pid_t) -> pid_t? {
        // Check our tracking first
        if let parent = queue.sync(execute: { parentMap[pid] }) {
            return parent
        }

        // Fall back to sysctl for processes not in our tracking
        return getParentFromKernel(pid: pid)
    }

    /// Gets the ancestry chain from immediate parent up to root (PID 1 or 0).
    /// - Parameter pid: The PID to get ancestors for
    /// - Returns: Array of ancestor PIDs, from immediate parent to root
    func getAncestors(pid: pid_t) -> [pid_t] {
        var ancestors: [pid_t] = []
        var currentPID = pid
        var visited = Set<pid_t>()

        // Walk up the tree until we hit root or a cycle
        while let parentPID = getParent(pid: currentPID) {
            // Prevent infinite loops (shouldn't happen, but be safe)
            if visited.contains(parentPID) {
                break
            }

            ancestors.append(parentPID)
            visited.insert(parentPID)

            // Stop at init (PID 1) or kernel (PID 0)
            if parentPID <= 1 {
                break
            }

            currentPID = parentPID
        }

        return ancestors
    }

    /// Gets the immediate children of a process.
    /// - Parameter pid: The parent PID
    /// - Returns: Array of child PIDs
    func getChildren(pid: pid_t) -> [pid_t] {
        return queue.sync {
            Array(childrenMap[pid] ?? Set())
        }
    }

    /// Checks if a process is a descendant of another process.
    /// - Parameters:
    ///   - pid: The potential descendant PID
    ///   - ancestorPID: The potential ancestor PID
    /// - Returns: true if pid is a descendant of ancestorPID
    func isDescendant(pid: pid_t, of ancestorPID: pid_t) -> Bool {
        let ancestors = getAncestors(pid: pid)
        return ancestors.contains(ancestorPID)
    }

    // MARK: - Private Helpers

    /// Gets parent PID from kernel via sysctl KERN_PROC.
    /// - Parameter pid: The PID to look up
    /// - Returns: The parent PID, or nil if lookup fails
    private func getParentFromKernel(pid: pid_t) -> pid_t? {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size

        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)

        guard result == 0, size > 0 else {
            return nil
        }

        let ppid = info.kp_eproc.e_ppid
        return ppid > 0 ? ppid : nil
    }
}
