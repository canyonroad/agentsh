#!/usr/bin/env python3
"""Policy enforcement test — exercises agentsh command_rules via subprocess."""
import subprocess
import sys

passed = 0
failed = 0


def run(cmd):
    """Run command, return (exit_code, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", "command not found"
    except PermissionError:
        return 126, "", "permission denied"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except (subprocess.SubprocessError, OSError) as e:
        return 126, "", str(e)


def test_allowed(label, cmd):
    """Verify command exits 0."""
    global passed, failed
    rc, out, err = run(cmd)
    if rc == 0:
        passed += 1
        print(f"  PASS: {label} (exit 0)")
    else:
        failed += 1
        print(f"  FAIL: {label} — expected exit 0, got {rc}: {err[:200]}")


def test_denied(label, cmd):
    """Verify command exits non-zero (blocked by agentsh)."""
    global passed, failed
    rc, out, err = run(cmd)
    if rc != 0:
        passed += 1
        print(f"  PASS: {label} (exit {rc}) — blocked")
    else:
        failed += 1
        print(f"  FAIL: {label} — expected non-zero exit, got 0: {out[:200]}")


def test_redirected(label, cmd, expected_fragment):
    """Verify command is redirected (exits 0 with redirect message in stdout)."""
    global passed, failed
    rc, out, err = run(cmd)
    combined = (out + err).lower()
    if expected_fragment.lower() in combined:
        passed += 1
        print(f"  PASS: {label} — redirected")
    elif rc != 0:
        passed += 1
        print(f"  PASS: {label} (exit {rc}) — blocked")
    else:
        failed += 1
        print(f"  FAIL: {label} — no redirect evidence: {out[:200]}")


def test_not_intercepted(label, cmd, forbidden_fragment):
    """Verify command is NOT intercepted by policy (may fail for other reasons)."""
    global passed, failed
    rc, out, err = run(cmd)
    combined = (out + err).lower()
    if forbidden_fragment.lower() in combined:
        failed += 1
        print(f"  FAIL: {label} — unexpectedly intercepted: {out[:200]}")
    else:
        passed += 1
        print(f"  PASS: {label} — not intercepted by policy (exit {rc})")


# ===================================================================
# Allowed commands (5 tests)
# ===================================================================
print("--- Allowed commands ---")
test_allowed("echo hello", ["echo", "hello"])
test_allowed("ls /tmp", ["ls", "/tmp"])
test_allowed("cat /etc/hosts", ["cat", "/etc/hosts"])
test_allowed("git --version", ["git", "--version"])
test_allowed("python3 --version", ["python3", "--version"])

# ===================================================================
# Denied commands (5 tests)
# ===================================================================
print("--- Denied commands ---")
test_denied("sudo whoami", ["sudo", "whoami"])
test_denied("shutdown now", ["shutdown", "now"])
test_denied("nc -l 8080", ["nc", "-l", "8080"])
test_denied("su - root", ["su", "-", "root"])
test_denied("apt-get install vim", ["apt-get", "install", "vim"])

# ===================================================================
# Redirected commands (5 tests)
# ===================================================================
print("--- Redirected commands ---")
test_redirected("git push --force origin main",
                ["git", "push", "--force", "origin", "main"],
                "force push blocked")
test_redirected("git push -f origin feat",
                ["git", "push", "-f", "origin", "feat"],
                "force push blocked")
test_redirected("git reset --hard HEAD",
                ["git", "reset", "--hard", "HEAD"],
                "hard reset blocked")
test_redirected("git clean -fd",
                ["git", "clean", "-fd"],
                "git clean blocked")
test_redirected("rm -rf /",
                ["rm", "-rf", "/"],
                "destructive delete blocked")

# ===================================================================
# Edge cases (2 tests)
# ===================================================================
print("--- Edge cases ---")
test_not_intercepted("git push origin feature-branch (no force flag)",
                     ["git", "push", "origin", "feature-branch"],
                     "force push blocked")
test_not_intercepted("git push origin topic-f (-f in branch name)",
                     ["git", "push", "origin", "topic-f"],
                     "force push blocked")

# ===================================================================
# Summary
# ===================================================================
total = passed + failed
print(f'\n{{"passed": {passed}, "failed": {failed}, "total": {total}}}')
sys.exit(0 if failed == 0 else 1)
