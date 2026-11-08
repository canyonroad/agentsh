# Adjudication of adversarial-review-2026-11.md

Adjudicator: `openai-codex/gpt-6.1-sol`, thinking xhigh, 5 read-only shards (rows 1-13, 14-25, 26-40,
41-52, 53-65). Each row was checked against the real code (call sites, config defaults, mode gating,
attacker preconditions). Per-shard raw tables were kept locally, not committed. Parent re-checked the three
REFUTED rows and the disputed evidence itself (notes marked "parent").

## Tally

| Verdict | Count | Meaning |
|---|---|---|
| REAL (confirmed) | 19 | code does what the row says; attack as described works |
| NOT REAL (refuted) | 3 | #10, #21, #62 — the code does not behave as claimed |
| REAL BUT OVERSTATED (partial) | 43 | mechanism exists, but a detail, precondition or the severity is wrong |
| — of which need a runtime/env probe to settle | 12 | #1,#9,#12,#17,#19,#20,#40,#43,#47,#51,#55,#57 |

Adjusted severity after adjudication: **Critical 4, High 11, Medium 22, Low 28.**

## Refuted (not real)

- **#10 `AGENTSH_SECCOMP_CONFIG` shadowing** — REFUTED. `exec.Cmd` dedups `Env` with **last value
  winning** (Go `os/exec` `dedupEnv`), and the authoritative `AGENTSH_*` values are appended last
  (`shim/kernelinstall/install_linux.go:235-237`, `cli/wrap.go:141-145`). The server value wins;
  `os.Getenv` first-match reasoning was wrong. → drop.
- **#21 `fexecve(431)` untrapped** — REFUTED. x86-64 syscall 431 is `SYS_FSCONFIG`
  (`.gomodcache/.../zsysnum_linux_amd64.go:352`, same for arm64); `fexecve` is not a syscall there —
  glibc uses `execveat`, which is trapped and resolves `AT_EMPTY_PATH`
  (`netmonitor/unix/handler.go:901-912`). parent-confirmed. → drop.
- **#62 `IsRealPathUnder(path,"/")` always true** — REFUTED as a bypass (parent: mechanism true,
  impact wrong → PARTIAL/Low). `/` legitimately contains every resolved path and
  `fsmonitor/fuse.go:550` still applies policy to the resolved target; the illustrated symlink read
  is already covered by #31/#1.

## New issues found during adjudication (not in the review)

- **HIGH — PTY exec skips all kernel enforcement** (parent-verified). `api/pty_core.go:158,187-198`
  calls `pty.Start` → `exec.CommandContext` (`pty/engine_unix.go:114-141`) with **no**
  `setupSeccompWrapper` and **no** ptrace `AttachPID`; the file has no seccomp/ptrace/Landlock
  reference at all. So `agentsh exec --pty` and the PTY-WS endpoint run the command with only FUSE in
  front of it, while the non-PTY exec path installs both. Compare `core.go:1086,1112`,
  `exec_stream.go:198,206`, `grpc.go:401`.
- **MEDIUM — ptrace detaches children when prefilter injection fails.** `ptrace/tracer.go:880-887,1738-1765`:
  without an installed prefilter the tracer lets children run free (no `CLONE_UNTRACED` needed).

## Row-by-row

`orig` = severity in the review, `new` = severity after adjudication.

| # | orig | verdict | new | evidence / note |
|---|---|---|---|---|
| 1 | Crit | PARTIAL | High | lexical path only; `/proc/*/fd` aliases *are* resolved (`file_handler.go:104-112`); symlink case real, not a DAC bypass |
| 2 | Crit | PARTIAL | High | FUSE **does** check truncate as write (`fuse.go:310-326,468-470`); seccomp/ptrace omit it → needs a uid-writable target (`~/.ssh/authorized_keys`, not `/etc/hosts`) |
| 3 | Crit | PARTIAL | High | unchecked ops confirmed (`fuse.go:69-71,330`); `default_permissions` on (`mount.go:117`), root-only mknod/CAP examples overreach; hardlink laundering real |
| 4 | Crit | CONFIRMED | Crit | no approvals in hooks (`linux/filesystem.go:259-275`), `fuse.go:588-594`, callers block only on deny; holds even with approvals enabled |
| 5 | Crit | PARTIAL | High | only caller is the test-only hook (`landlock_exec.go:79`); matters only for a privileged daemon (`process_unix.go:46` does not change creds) |
| 6 | Crit | PARTIAL | High | bypass confirmed (`main.go:71-81,392-410`), but at *shim entry* only: cannot remove enforcement already inherited |
| 7 | Crit | PARTIAL | High | no role check (`grpc.go:752-775,925-956`); `config.yml:20` ships `grpc.enabled: false` |
| 8 | Crit | PARTIAL | High | `core.go:647-687` trusts the request; `project_root:"/"` literal → `//**` does not match `/**` (`vars.go:16-39`), so that example is wrong; `home:` example stands |
| 9 | Crit | PARTIAL | High | ring syscalls absent (`ptrace/syscalls.go:61-95`), prefilter default allow; needs io_uring available + ptrace-only mode; seccomp blocks it when configured |
| 10 | Crit | **REFUTED** | — | last-value-wins env; server values win |
| 11 | Crit | PARTIAL | High | `shellparse.go:449-464` falls back without `-c` (`engine.go:699`); real only while execve interception is off (default) |
| 12 | Crit | PARTIAL | High | `netns_linux.go:30-44,128-143` as claimed; `config.yml:195` ships transparent mode off (root host) |
| 13 | Crit | PARTIAL | High | `llmproxy.go:74` registers no tools; event bridge exists (`server.go:1025-1030`) but its only producer `isMCPCommand` is never called → policy inert in practice (parent-verified) |
| 14 | High | PARTIAL | Medium | early `Clean` (`handle_file.go:141`) but opened FDs are re-checked and denied (`tracer.go:1409-1457`); residual on legacy open/mutations |
| 15 | High | CONFIRMED | High | only `fc.Path` evaluated (`ptrace_handlers.go:195`); `Path2` ignored |
| 16 | High | PARTIAL | Medium | `fchmodat2` **is** in ptrace (`syscalls.go:15`) and `mknodat` in seccomp (`seccomp_linux.go:665`); remaining gaps: `renameat`, `utimensat` |
| 17 | High | CONFIRMED | High | arch dropped (`syscall_context.go:89-92`), unmatched nr allowed (`tracer.go:1360`), x32 falls through; needs the ABI enabled |
| 18 | High | PARTIAL | High | `handle_network.go:130-132` allows non-connect/bind; 129-byte DNS trick unproven; plain `sendmsg`/`sendto` gap real |
| 19 | High | PARTIAL | High | allow-on-read-failure real (`handler.go:305-317`); needs an alias that also matches an allow rule and Yama blocking the read |
| 20 | High | PARTIAL | High | `pidfd` missing (`signal/seccomp_linux.go:23-27`), ptrace allows all (`ptrace_handlers.go:364`); limited by UID permissions |
| 21 | High | **REFUTED** | — | 431 = fsconfig; fexecve goes through trapped `execveat` |
| 22 | High | PARTIAL | High | rules support absolute paths (`engine.go:254-268`); the copy trick only defeats basename-only rules (which the shipped policies use) |
| 23 | High | PARTIAL | Medium | shebang contents unread (`handler.go:416-425`) but the env→python exec is re-trapped as execveat; needs execve interception off |
| 24 | High | CONFIRMED | High | `main.go:71` + `:415-436` miss `&`/`>(`; known-C1 |
| 25 | High | PARTIAL | High | numeric scalars skipped (`dlp.go:207-240`) — real; `\u`-escape claim false (JSON unmarshalled first, `:183`); base64 gap real |
| 26 | High | CONFIRMED | High | substitution over all headers (`credshook.go:44-49`), log keeps them (`declared_service.go:732-733`) |
| 27 | High | PARTIAL | Medium | `sidecar_missing` rotation is recorded (`integrity_wrapper.go:137,529`); tail completeness still has no external anchor |
| 28 | High | CONFIRMED | High | `core.go:633-636,695-696`; allowlist only guards `AGENTSH_POLICY_NAME` (`manager.go:35-44`) |
| 29 | High | CONFIRMED | High | `app.go:321-340,796-811,1400-1415` — no ownership checks |
| 30 | High | CONFIRMED | High | prompt only for `local_tty` (`manager.go:240-250`); API resolve needs no second factor |
| 31 | High | PARTIAL | Medium | link checked, not target (`fuse.go:346-357,450-452`); overlaps #1, mode-dependent |
| 32 | High | PARTIAL | High | fail-open paths real (`core.go:114-128`, `session_policy.go:69-77`); `unixwrap` exit-without-exec is not an execution bypass |
| 33 | High | PARTIAL | Medium | ancestor grants survive (`ruleset.go:219-260,410-419`); opt-in layer, PoC needs extra perms |
| 34 | High | PARTIAL | Medium | `.npmrc` origin mismatch real (`resolver/npm.go:87,124-134`); `npm ci` **is** classified under `all_installs` (`interceptor.go:125-136`); skipped packages still reach local providers (`orchestrator.go:193-196`) |
| 35 | High | PARTIAL | Medium | error swallow real (`mcp_bridge.go:35`) but the wrapper has no production callers; dormant |
| 36 | High | PARTIAL | High | empty policy at `pty_core.go:158`, `exec_stream.go:297`; host env is pre-filtered (`exec.go:699-708`), so only session/request vars escape |
| 37 | High | PARTIAL | Medium | exec rules omitted (`policysock/handler.go:180-192`); macwrap profile is deny-default (`profile.go:15`); socket loss changes connectivity, not cached sessions; macOS Alpha / WSL2 unwired |
| 38 | High | PARTIAL | High | port-80 check vs dialed port confirmed (`proxy.go:325,433`); CONNECT **does** check CIDRs (`engine.go:1186-1212`) |
| 39 | High | PARTIAL | Medium | cache substitution (`transparent_tcp.go:125-131`) but CIDR rules still evaluated in order (`engine.go:586-610`); needs DNS control |
| 40 | High | CONFIRMED | High | full-width compare (`seccomp_linux.go:428-432,762-768`); needs a 64-bit host and AF_ALG present |
| 41 | Med | PARTIAL | Medium | encoding preserved (`declared_service.go:196,345-346`) but `/api/*` is single-segment (`http_service_compile.go:83`) → needs an `/api/**` rule |
| 42 | Med | CONFIRMED | High | silent caps (`memory.go:321-341`, `tracer.go:1945`) |
| 43 | Med | PARTIAL | Medium | fork-event reliance (`tracer.go:632-645,1586-1645`); prefilter enabled by default (`config/ptrace.go:53`) |
| 44 | Med | PARTIAL | Medium | mapper emits `open` (`file_syscalls.go:294-344`), FUSE evaluates read/list (`fuse.go:248,365`); strict-policy read rules that omit `open` still break |
| 45 | Med | CONFIRMED | Medium | byte-exact globs (`engine.go:187,935`), unnormalized source paths (`platform/fuse/ops.go:34-38`); mac/win only |
| 46 | Med | CONFIRMED | Medium | fields accepted (`model.go:266-269`), only commands evaluated (`context_eval.go:72-150,374-460`) |
| 47 | Med | CONFIRMED | Medium | `policy_adapter.go:31-36` + `ops.go:169-174,274-278`; darwin/win FUSE |
| 48 | Med | CONFIRMED | Medium | `proxy.go:329-332`, `declared_service.go:140,235`; cannot select another policy engine |
| 49 | Med | PARTIAL | Low | cache returns before approval/audit (`manager.go:274-277`, `cache.go:87-89`); `pkg/secrets` has no CLI/production wiring (`cli/root.go:28-54`) |
| 50 | Med | PARTIAL | Medium | ID accepted (`session_id.go:42-43,99-104`), workspace normalized; in-session guard `main.go:163`; overlaps #29 |
| 51 | Med | CONFIRMED | High | uid-0 skip, PID existence only, unrestricted `BindSession` (`wrap_linux.go:377,410,427`, `tracer.go:538-554`); needs ptrace deployments |
| 52 | Med | PARTIAL | Medium | sink nil, `strict` vacuous (`linux/filesystem.go:283-290`, `fsmonitor/policy.go:59-60`); divert emits its own event; trash 0640 in 0755 (`trash.go:351-359`) |
| 53 | Low | PARTIAL | Low | five symbols interposed (`envshim.c:361-501`); server pre-filters (`exec.go:186,750`), so it is not a filter bypass |
| 54 | Low | CONFIRMED | Low | 0755/0644 incl. rotation (`jsonl.go:79,83,225`) |
| 55 | Low | PARTIAL | Low | allocator reset (`composite.go:57`); normal runs get a new identity (`wtp.go:156-158`) |
| 56 | Low | CONFIRMED | Low | only `SKILL.md` triggers (`watcher.go:207-219`), tree hash at scan (`loader.go:108`); opt-in scanner |
| 57 | Low | PARTIAL | Low | unsafe PF writes (`darwin/network.go:69,103`) but PF setup has no production caller; cached denies still drop flows (`FilterDataProvider.swift:128-135`) |
| 58 | Low | PARTIAL | Low | no core suppression (`unixwrap/main.go:259`); destination host-dependent |
| 59 | Low | CONFIRMED | Low | net handling dropped when both perms true (`ruleset.go:193,387`) |
| 60 | Low | PARTIAL | Low | stateless TOTP (`totp.go:27`); prompt only in `local_tty`; overlaps #30 |
| 61 | Low | PARTIAL | Low | plaintext compare (`identity/agent.go:226`), no production imports |
| 62 | Low | **REFUTED** | Low | `/` contains everything; policy still applied to the resolved target (`fuse.go:550`) — downgraded, not a bypass |
| 63 | Low | PARTIAL | Low | detector already sorts highest-first (`detector.go:87-88`); >1 MiB line drop (`mcp_exec.go:249-254`) dormant |
| 64 | Low | PARTIAL | Low | chown/time skipped (`fuse.go:330`); `fchmodat2` audited in ptrace (`ptrace_handlers.go:200-210`); duplicates #3/#16/#52 |
| 65 | Low | CONFIRMED | Low | no `mcp-server` in `cli/root.go:28-54`; windows native import (`api/platform_windows.go:6`); `intercept_mode` unread (`config.go:442`) |

## What survives as the real priority list

Critical after adjudication (4): **#4** (approve never gates), **#1** (symlink path bypass, symlink case),
plus the two that stay Critical only in their stated mode — **#2**/#3 are High with uid-writable targets.
So the defensible top five: **#4, #1, #15, #17/#24, #29/#30** and the new **PTY finding**.

## Not checked

Builds, tests, exploit execution, kernel/libseccomp/FUSE/macOS/WSL2 runtime behaviour, and deployment
permissions. Rows tagged probe-dependent above remain open until one runtime PoC each is run.
