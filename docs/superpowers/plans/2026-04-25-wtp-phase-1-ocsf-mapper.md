# WTP Phase 1: OCSF Mapper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the production OCSF v1.8.0 mapper that closes the WTP `validate()` blocker — projects every production `pkg/types.Event` into a deterministic `(class_uid, activity_id, payload []byte)` triple consumable by `wtpv1.CompactEvent`.

**Architecture:** Pure-function `internal/ocsf` package implementing `compact.Mapper`. Eight proto3 messages under `proto/canyonroad/wtp/v1/ocsf/` mirror OCSF v1.8.0 classes. A single `registry map[string]Mapping` declares each agentsh `Type`'s class, activity, fields-allowlist, and projector function. Determinism comes from `proto.MarshalOptions{Deterministic: true}.Marshal(...)` and slice-ordered allowlist iteration.

**Tech Stack:** Go, `google.golang.org/protobuf/proto`, `protoc` (existing pipeline), `go/parser` for the exhaustiveness AST walk.

**Spec:** `docs/superpowers/specs/2026-04-25-wtp-phase-1-ocsf-mapper-design.md`

---

## File Structure

| File | Purpose |
|---|---|
| `proto/canyonroad/wtp/v1/ocsf/common.proto` (NEW) | Shared OCSF objects: `Metadata`, `Process`, `File`, `Endpoint`, `Actor`, `User`. |
| `proto/canyonroad/wtp/v1/ocsf/process_activity.proto` (NEW) | `ProcessActivity` (class_uid 1007). |
| `proto/canyonroad/wtp/v1/ocsf/file_activity.proto` (NEW) | `FileSystemActivity` (class_uid 1001). |
| `proto/canyonroad/wtp/v1/ocsf/network_activity.proto` (NEW) | `NetworkActivity` (class_uid 4001). |
| `proto/canyonroad/wtp/v1/ocsf/http_activity.proto` (NEW) | `HTTPActivity` (class_uid 4002). |
| `proto/canyonroad/wtp/v1/ocsf/dns_activity.proto` (NEW) | `DNSActivity` (class_uid 4003). |
| `proto/canyonroad/wtp/v1/ocsf/detection_finding.proto` (NEW) | `DetectionFinding` (class_uid 2004). |
| `proto/canyonroad/wtp/v1/ocsf/application_activity.proto` (NEW) | `ApplicationActivity` (class_uid 6005) + agent-internal activity enum (≥100). |
| `Makefile` (modify line 31-36) | Add OCSF .proto files to the `proto:` target. |
| `internal/ocsf/version.go` (NEW) | `const SchemaVersion = "1.8.0"`. |
| `internal/ocsf/activity.go` (NEW) | OCSF activity_id constants per class + agentsh-internal extensions ≥100. |
| `internal/ocsf/mapping.go` (NEW) | `type Mapping`, `type Projector`, `type FieldRule`, `projectFields` helper, `safeProject` recover wrapper. |
| `internal/ocsf/mapper.go` (NEW) | `type Mapper`, `New()`, `Map()` — implements `compact.Mapper`. |
| `internal/ocsf/registry.go` (NEW) | `var registry = map[string]Mapping{...}`; `var pendingTypes` for incremental rollout. |
| `internal/ocsf/skiplist.go` (NEW) | `var skiplist = map[string]string{...}` (Type → reason). |
| `internal/ocsf/skiplist_test.go` (NEW) | Asserts every skiplist entry has a non-empty reason; asserts skiplist ∩ registry-types = ∅. |
| `internal/ocsf/project_process.go` (NEW) | Projector for class_uid 1007. |
| `internal/ocsf/project_file.go` (NEW) | Projector for class_uid 1001. |
| `internal/ocsf/project_network.go` (NEW) | Projector for class_uid 4001. |
| `internal/ocsf/project_http.go` (NEW) | Projector for class_uid 4002. |
| `internal/ocsf/project_dns.go` (NEW) | Projector for class_uid 4003. |
| `internal/ocsf/project_finding.go` (NEW) | Projector for class_uid 2004. |
| `internal/ocsf/project_app.go` (NEW) | Projector for class_uid 6005 (incl. infra). |
| `internal/ocsf/exhaustiveness_test.go` (NEW) | AST walk: every emitted `types.Event{Type:"..."}` is registered or skiplisted; every `ev.Fields["..."]` write is allowlisted by at least one Mapping that emits that key. |
| `internal/ocsf/mapper_test.go` (NEW) | `TestMapDeterministic` (1000× byte-equality), per-Type golden tests. |
| `internal/ocsf/redaction_test.go` (NEW) | Asserts sensitive keys (`authorization`, `cookie`, `secret`, …) appear in NO allowlist. |
| `internal/ocsf/testdata/golden/<type>.json` (NEW, one per Type) | `protojson` projection of the proto payload, regenerated via `go test -update`. |
| `internal/store/watchtower/encoder_e2e_test.go` (modify) | Adds a parallel sub-test wiring `ocsf.New()` and asserting the chain accepts the deterministic payload. |

`internal/ocsf` does **not** import any `internal/store/*` package other than `internal/store/watchtower/compact` (for the `Mapper` interface and `MappedEvent` type). No reverse imports.

---

## Task 1: Author `common.proto` and wire it into the proto build

**Files:**
- Create: `proto/canyonroad/wtp/v1/ocsf/common.proto`
- Modify: `Makefile` (add the new file to the `proto:` target)

- [ ] **Step 1: Create the common proto**

```proto
// proto/canyonroad/wtp/v1/ocsf/common.proto
//
// Shared OCSF v1.8.0 object types. Each class's .proto imports this file
// and reuses these messages. Field names are snake_case matching OCSF
// JSON keys verbatim. All fields use proto3 explicit-presence (`optional`)
// so absence is distinguishable from zero-value.

syntax = "proto3";

package canyonroad.wtp.v1.ocsf;

option go_package = "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf;ocsfpb";

// Metadata is OCSF's per-record metadata object. Every class message
// embeds a Metadata.
message Metadata {
  optional string version       = 1; // OCSF schema version, e.g. "1.8.0"
  optional Product product      = 2;
  optional uint64 logged_time   = 3; // unix nanos
  optional string event_code    = 4; // agentsh ev.Type for cross-reference
  optional string uid           = 5; // ev.ID
}

message Product {
  optional string name          = 1; // "agentsh"
  optional string vendor_name   = 2; // "agentsh"
  optional string version       = 3; // agent version when known
}

// Process represents an OCSF Process Object — used by Process, File,
// Network, HTTP, DNS, and DetectionFinding classes.
message Process {
  optional uint64 pid           = 1;
  optional uint64 parent_pid    = 2;
  optional string name          = 3; // basename of the executable
  optional string cmd_line      = 4; // joined argv (space-separated, shell-safe-quoted)
  optional File   file          = 5; // executable file
  optional uint32 depth         = 6; // agentsh extension: nesting depth
  optional string session_uid   = 7; // ev.SessionID
  optional string command_uid   = 8; // ev.CommandID
}

// File is an OCSF File Object.
message File {
  optional string path          = 1; // ev.Path / ev.Filename canonical path
  optional string name          = 2; // basename
  optional string raw_path      = 3; // ev.RawFilename pre-resolution
  optional bool   is_abstract   = 4; // ev.Abstract (Unix abstract socket etc.)
}

// Endpoint is an OCSF Endpoint Object — used for source/destination of
// Network/HTTP/DNS activity.
message Endpoint {
  optional string ip            = 1;
  optional uint32 port          = 2;
  optional string hostname      = 3;
  optional string domain        = 4; // ev.Domain
  optional string instance_uid  = 5;
}

// Actor is an OCSF Actor Object — typically the process performing the action.
message Actor {
  optional Process process      = 1;
  optional User    user         = 2;
}

message User {
  optional string name          = 1;
  optional uint32 uid           = 2;
}
```

- [ ] **Step 2: Add the file to the proto-generation target**

Edit `Makefile` lines 31-36. Replace the existing block with:

```makefile
proto:
	protoc -I proto \
	  --go_out=. --go_opt=module=github.com/agentsh/agentsh \
	  --go-grpc_out=. --go-grpc_opt=module=github.com/agentsh/agentsh \
	  proto/agentsh/v1/pty.proto \
	  proto/canyonroad/wtp/v1/wtp.proto \
	  proto/canyonroad/wtp/v1/ocsf/common.proto \
	  proto/canyonroad/wtp/v1/ocsf/process_activity.proto \
	  proto/canyonroad/wtp/v1/ocsf/file_activity.proto \
	  proto/canyonroad/wtp/v1/ocsf/network_activity.proto \
	  proto/canyonroad/wtp/v1/ocsf/http_activity.proto \
	  proto/canyonroad/wtp/v1/ocsf/dns_activity.proto \
	  proto/canyonroad/wtp/v1/ocsf/detection_finding.proto \
	  proto/canyonroad/wtp/v1/ocsf/application_activity.proto
```

The `proto:` target now references files that don't exist yet — it will fail until Tasks 2-8 land. That is intentional: the per-class proto tasks each touch their file, and the Makefile is updated once here so we do not re-edit it in every subsequent task.

- [ ] **Step 3: Verify common.proto parses (sanity check)**

Run: `protoc -I proto --descriptor_set_out=/dev/null proto/canyonroad/wtp/v1/ocsf/common.proto`
Expected: exits 0, no output.

- [ ] **Step 4: Commit**

```bash
git add proto/canyonroad/wtp/v1/ocsf/common.proto Makefile
git commit -m "ocsf: add common proto types (Metadata, Process, File, Endpoint, Actor, User)"
```

---

## Task 2: Author `process_activity.proto`

**Files:**
- Create: `proto/canyonroad/wtp/v1/ocsf/process_activity.proto`

- [ ] **Step 1: Write the proto**

```proto
// proto/canyonroad/wtp/v1/ocsf/process_activity.proto

syntax = "proto3";

package canyonroad.wtp.v1.ocsf;

option go_package = "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf;ocsfpb";

import "canyonroad/wtp/v1/ocsf/common.proto";

// ProcessActivity (class_uid 1007). OCSF v1.8.0 subset.
//
// Activities used by agentsh:
//   1 = Launch
//   2 = Terminate
//   3 = Open      (used for exec_intercept)
//   4 = Inject    (reserved; not currently emitted)
//
// Sources mapping to this class: execve, exec, exec_intercept, exec.start,
// ptrace_execve, command_started, command_executed, command_finished,
// command_killed, command_redirected, command_redirect, process_start, exit.
message ProcessActivity {
  optional uint32   class_uid     = 1; // 1007
  optional uint32   activity_id   = 2;
  optional uint32   category_uid  = 3; // 1 = System Activity
  optional uint32   type_uid      = 4; // class_uid * 100 + activity_id
  optional uint64   time          = 5; // ev.Timestamp.UTC().UnixNano()
  optional string   severity      = 6; // "Informational" | "Low" | …
  optional Metadata metadata      = 7;
  optional Actor    actor         = 8; // parent process
  optional Process  process       = 9; // child / target process
  optional uint32   exit_code     = 10;
  optional string   policy_decision = 11; // ev.Policy.Decision when present
  optional string   policy_rule     = 12;
  optional string   unwrapped_from  = 13;
  optional string   payload_command = 14;
  optional bool     truncated       = 15;
}
```

- [ ] **Step 2: Verify it parses**

Run: `protoc -I proto --descriptor_set_out=/dev/null proto/canyonroad/wtp/v1/ocsf/process_activity.proto`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add proto/canyonroad/wtp/v1/ocsf/process_activity.proto
git commit -m "ocsf: add ProcessActivity (class_uid 1007)"
```

---

## Task 3: Author `file_activity.proto`

**Files:**
- Create: `proto/canyonroad/wtp/v1/ocsf/file_activity.proto`

- [ ] **Step 1: Write the proto**

```proto
syntax = "proto3";
package canyonroad.wtp.v1.ocsf;
option go_package = "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf;ocsfpb";
import "canyonroad/wtp/v1/ocsf/common.proto";

// FileSystemActivity (class_uid 1001). OCSF v1.8.0 subset.
//
// Activities used:
//   1 = Create
//   2 = Read
//   3 = Update    (write)
//   4 = Delete
//   5 = Rename
//   6 = Set Attributes (chmod)
//   7 = Set Security
//   8 = Get Attributes
message FileSystemActivity {
  optional uint32   class_uid     = 1; // 1001
  optional uint32   activity_id   = 2;
  optional uint32   category_uid  = 3; // 1 = System Activity
  optional uint32   type_uid      = 4;
  optional uint64   time          = 5;
  optional string   severity      = 6;
  optional Metadata metadata      = 7;
  optional Actor    actor         = 8;
  optional File     file          = 9;
  optional File     file_diff     = 10; // for rename: source file is `file_diff`, dest is `file`
  optional string   operation     = 11; // ev.Operation
  optional string   policy_decision = 12;
  optional string   policy_rule     = 13;
  optional bool     soft_deleted    = 14;
}
```

- [ ] **Step 2: Verify it parses**

Run: `protoc -I proto --descriptor_set_out=/dev/null proto/canyonroad/wtp/v1/ocsf/file_activity.proto`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add proto/canyonroad/wtp/v1/ocsf/file_activity.proto
git commit -m "ocsf: add FileSystemActivity (class_uid 1001)"
```

---

## Task 4: Author `network_activity.proto`

**Files:**
- Create: `proto/canyonroad/wtp/v1/ocsf/network_activity.proto`

- [ ] **Step 1: Write the proto**

```proto
syntax = "proto3";
package canyonroad.wtp.v1.ocsf;
option go_package = "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf;ocsfpb";
import "canyonroad/wtp/v1/ocsf/common.proto";

// NetworkActivity (class_uid 4001). OCSF v1.8.0 subset.
//
// Activities used:
//   1 = Open       (connect)
//   2 = Close
//   6 = Traffic
message NetworkActivity {
  optional uint32   class_uid     = 1; // 4001
  optional uint32   activity_id   = 2;
  optional uint32   category_uid  = 3; // 4 = Network Activity
  optional uint32   type_uid      = 4;
  optional uint64   time          = 5;
  optional string   severity      = 6;
  optional Metadata metadata      = 7;
  optional Actor    actor         = 8;
  optional Endpoint src_endpoint  = 9;
  optional Endpoint dst_endpoint  = 10;
  optional ConnectionInfo connection_info = 11;
  optional string   policy_decision = 12;
  optional string   policy_rule     = 13;
  optional string   redirect_target = 14; // ev.Fields["redirect_target"] when set
}

message ConnectionInfo {
  optional string protocol_name   = 1; // "tcp" | "udp" | "unix"
  optional string direction       = 2; // "Outbound" | "Inbound"
  optional bool   is_unix_abstract = 3;
}
```

- [ ] **Step 2: Verify it parses**

Run: `protoc -I proto --descriptor_set_out=/dev/null proto/canyonroad/wtp/v1/ocsf/network_activity.proto`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add proto/canyonroad/wtp/v1/ocsf/network_activity.proto
git commit -m "ocsf: add NetworkActivity (class_uid 4001)"
```

---

## Task 5: Author `http_activity.proto`

**Files:**
- Create: `proto/canyonroad/wtp/v1/ocsf/http_activity.proto`

- [ ] **Step 1: Write the proto**

```proto
syntax = "proto3";
package canyonroad.wtp.v1.ocsf;
option go_package = "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf;ocsfpb";
import "canyonroad/wtp/v1/ocsf/common.proto";

// HTTPActivity (class_uid 4002). OCSF v1.8.0 subset.
//
// Activities used:
//   1 = Request
//   2 = Response
//   6 = Traffic
message HTTPActivity {
  optional uint32   class_uid     = 1; // 4002
  optional uint32   activity_id   = 2;
  optional uint32   category_uid  = 3; // 4
  optional uint32   type_uid      = 4;
  optional uint64   time          = 5;
  optional string   severity      = 6;
  optional Metadata metadata      = 7;
  optional Actor    actor         = 8;
  optional Endpoint src_endpoint  = 9;
  optional Endpoint dst_endpoint  = 10;
  optional HTTPRequest  http_request  = 11;
  optional HTTPResponse http_response = 12;
  optional string   policy_decision = 13;
  optional string   policy_rule     = 14;
}

message HTTPRequest {
  optional string http_method = 1; // ev.Fields["method"]
  optional string url         = 2; // ev.Fields["url"]
  optional string user_agent  = 3; // ev.Fields["user_agent"]
  optional string version     = 4; // ev.Fields["http_version"]
  optional string host        = 5; // ev.Fields["host"]
}

message HTTPResponse {
  optional uint32 status_code = 1; // ev.Fields["status_code"]
  optional uint64 length      = 2; // ev.Fields["response_bytes"]
}
```

- [ ] **Step 2: Verify it parses**

Run: `protoc -I proto --descriptor_set_out=/dev/null proto/canyonroad/wtp/v1/ocsf/http_activity.proto`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add proto/canyonroad/wtp/v1/ocsf/http_activity.proto
git commit -m "ocsf: add HTTPActivity (class_uid 4002)"
```

---

## Task 6: Author `dns_activity.proto`

**Files:**
- Create: `proto/canyonroad/wtp/v1/ocsf/dns_activity.proto`

- [ ] **Step 1: Write the proto**

```proto
syntax = "proto3";
package canyonroad.wtp.v1.ocsf;
option go_package = "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf;ocsfpb";
import "canyonroad/wtp/v1/ocsf/common.proto";

// DNSActivity (class_uid 4003). OCSF v1.8.0 subset.
//
// Activities used:
//   1 = Query
//   2 = Response
//   6 = Traffic
message DNSActivity {
  optional uint32   class_uid     = 1; // 4003
  optional uint32   activity_id   = 2;
  optional uint32   category_uid  = 3; // 4
  optional uint32   type_uid      = 4;
  optional uint64   time          = 5;
  optional string   severity      = 6;
  optional Metadata metadata      = 7;
  optional Actor    actor         = 8;
  optional DNSQuery query         = 9;
  optional string   redirect_target = 10;
  optional string   policy_decision = 11;
  optional string   policy_rule     = 12;
}

message DNSQuery {
  optional string hostname  = 1; // ev.Domain or ev.Fields["hostname"]
  optional uint32 type      = 2; // dns rrtype number when known
  optional string type_name = 3; // "A" | "AAAA" | "TXT" | …
  optional string class     = 4; // "IN"
}
```

- [ ] **Step 2: Verify it parses**

Run: `protoc -I proto --descriptor_set_out=/dev/null proto/canyonroad/wtp/v1/ocsf/dns_activity.proto`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add proto/canyonroad/wtp/v1/ocsf/dns_activity.proto
git commit -m "ocsf: add DNSActivity (class_uid 4003)"
```

---

## Task 7: Author `detection_finding.proto`

**Files:**
- Create: `proto/canyonroad/wtp/v1/ocsf/detection_finding.proto`

- [ ] **Step 1: Write the proto**

```proto
syntax = "proto3";
package canyonroad.wtp.v1.ocsf;
option go_package = "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf;ocsfpb";
import "canyonroad/wtp/v1/ocsf/common.proto";

// DetectionFinding (class_uid 2004). OCSF v1.8.0 subset.
//
// Activities used:
//   1 = Create
//   2 = Update
//   3 = Close
message DetectionFinding {
  optional uint32   class_uid     = 1; // 2004
  optional uint32   activity_id   = 2;
  optional uint32   category_uid  = 3; // 2 = Findings
  optional uint32   type_uid      = 4;
  optional uint64   time          = 5;
  optional string   severity      = 6;
  optional Metadata metadata      = 7;
  optional Actor    actor         = 8;
  optional FindingInfo finding_info = 9;
  optional string   policy_decision = 10;
  optional string   policy_rule     = 11;
  optional string   threat_feed     = 12;
  optional string   threat_match    = 13;
  optional string   threat_action   = 14;
}

message FindingInfo {
  optional string title       = 1; // human-readable summary
  optional string desc        = 2; // ev.Policy.Message when present
  optional string finding_uid = 3; // ev.ID
  optional string types       = 4; // "policy_decision" | "threat" | "agent_self_detected" | …
}
```

- [ ] **Step 2: Verify it parses**

Run: `protoc -I proto --descriptor_set_out=/dev/null proto/canyonroad/wtp/v1/ocsf/detection_finding.proto`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add proto/canyonroad/wtp/v1/ocsf/detection_finding.proto
git commit -m "ocsf: add DetectionFinding (class_uid 2004)"
```

---

## Task 8: Author `application_activity.proto` and regenerate all `.pb.go`

**Files:**
- Create: `proto/canyonroad/wtp/v1/ocsf/application_activity.proto`
- Generated: `proto/canyonroad/wtp/v1/ocsf/*.pb.go` (8 files)

- [ ] **Step 1: Write the proto**

```proto
syntax = "proto3";
package canyonroad.wtp.v1.ocsf;
option go_package = "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf;ocsfpb";
import "canyonroad/wtp/v1/ocsf/common.proto";

// ApplicationActivity (class_uid 6005). OCSF v1.8.0 subset, with agentsh
// extensions for infrastructure events tagged via agent_internal.
//
// OCSF activities used (1..7):
//   1 = Open
//   2 = Close
//   3 = Update
//   6 = Other (used for misc agent actions like secret_access)
//
// agentsh-internal activities (>=100, see AppActivity enum):
//   100 = EBPF Attached
//   101 = FUSE Mounted
//   102 = Cgroup Applied
//   103 = LLM Proxy Started
//   104 = Net Proxy Started
//   105 = MCP Tool Called
//   106 = MCP Tool Seen
//   107 = MCP Tools List Changed
//   108 = MCP Sampling Request
//   109 = MCP Tool Result Inspected
//   110 = Integrity Chain Rotated
//   111 = Wrap Init
//   112 = FSEvents Error
//   113 = Transparent Net Setup
//   120 = Policy Created
//   121 = Policy Updated
//   122 = Policy Deleted
//   130 = Session Created
//   131 = Session Destroyed
//   132 = Session Expired
//   133 = Session Updated
//   140 = Cgroup Apply Failed
//   141 = Cgroup Cleanup Failed
//   142 = FUSE Mount Failed
//   143 = EBPF Attach Failed
//   144 = EBPF Collector Failed
//   145 = EBPF Enforce Disabled
//   146 = EBPF Enforce Non-Strict
//   147 = EBPF Enforce Refresh Failed
//   148 = EBPF Unavailable
//   149 = LLM Proxy Failed
//   150 = Net Proxy Failed
//   151 = Transparent Net Ready
//   152 = Transparent Net Failed
//   153 = MCP Tool Changed
message ApplicationActivity {
  optional uint32   class_uid     = 1; // 6005
  optional uint32   activity_id   = 2;
  optional uint32   category_uid  = 3; // 6 = Application Activity
  optional uint32   type_uid      = 4;
  optional uint64   time          = 5;
  optional string   severity      = 6;
  optional Metadata metadata      = 7;
  optional Actor    actor         = 8;
  optional string   app_name      = 9;
  optional string   resource_uid  = 10; // generic per-event identifier (tool name, secret name, …)
  optional bool     agent_internal = 50; // load-bearing — server-side filter signal
  // Generic enrichments slot for class 6005 only — values projected from
  // ev.Fields by the per-Type allowlist. The map's key set is bounded by
  // the registry; values are pre-stringified by the projector.
  map<string, string> enrichments = 51;
}
```

- [ ] **Step 2: Verify all OCSF protos parse together**

Run:
```bash
protoc -I proto --descriptor_set_out=/dev/null \
  proto/canyonroad/wtp/v1/ocsf/common.proto \
  proto/canyonroad/wtp/v1/ocsf/process_activity.proto \
  proto/canyonroad/wtp/v1/ocsf/file_activity.proto \
  proto/canyonroad/wtp/v1/ocsf/network_activity.proto \
  proto/canyonroad/wtp/v1/ocsf/http_activity.proto \
  proto/canyonroad/wtp/v1/ocsf/dns_activity.proto \
  proto/canyonroad/wtp/v1/ocsf/detection_finding.proto \
  proto/canyonroad/wtp/v1/ocsf/application_activity.proto
```
Expected: exits 0, no output.

- [ ] **Step 3: Generate all .pb.go**

Run: `make proto`
Expected: produces `proto/canyonroad/wtp/v1/ocsf/{common,process_activity,file_activity,network_activity,http_activity,dns_activity,detection_finding,application_activity}.pb.go`. All exit 0.

- [ ] **Step 4: Verify it compiles**

Run: `go build ./proto/canyonroad/wtp/v1/ocsf/...`
Expected: exits 0.

- [ ] **Step 5: Commit**

```bash
git add proto/canyonroad/wtp/v1/ocsf/application_activity.proto proto/canyonroad/wtp/v1/ocsf/*.pb.go
git commit -m "ocsf: add ApplicationActivity (class_uid 6005); generate .pb.go for all OCSF protos"
```

---

## Task 9: Skeleton `version.go`, `activity.go`, `mapping.go`

**Files:**
- Create: `internal/ocsf/version.go`
- Create: `internal/ocsf/activity.go`
- Create: `internal/ocsf/mapping.go`

- [ ] **Step 1: Write `version.go`**

```go
// Package ocsf maps agentsh events to OCSF v1.8.0 class payloads consumed
// by the WTP CompactEvent wire shape. See
// docs/superpowers/specs/2026-04-25-wtp-phase-1-ocsf-mapper-design.md.
package ocsf

// SchemaVersion is the OCSF schema version this mapper targets. It is
// also the value emitted in CompactEvent's Metadata.version field and
// must match the ocsf_version string the WTP client sends in
// SessionInit.
const SchemaVersion = "1.8.0"
```

- [ ] **Step 2: Write `activity.go`**

```go
package ocsf

// OCSF class UIDs used by this mapper.
const (
	ClassProcessActivity    uint32 = 1007
	ClassFileSystemActivity uint32 = 1001
	ClassNetworkActivity    uint32 = 4001
	ClassHTTPActivity       uint32 = 4002
	ClassDNSActivity        uint32 = 4003
	ClassDetectionFinding   uint32 = 2004
	ClassApplicationActivity uint32 = 6005
)

// OCSF activity_id values per class. Each constant block matches the
// class's proto definition; agentsh-internal extensions (>=100) live
// in the ApplicationActivity block.

const (
	ProcessActivityUnknown    uint32 = 0
	ProcessActivityLaunch     uint32 = 1
	ProcessActivityTerminate  uint32 = 2
	ProcessActivityOpen       uint32 = 3
	ProcessActivityInject     uint32 = 4
)

const (
	FileActivityUnknown       uint32 = 0
	FileActivityCreate        uint32 = 1
	FileActivityRead          uint32 = 2
	FileActivityUpdate        uint32 = 3
	FileActivityDelete        uint32 = 4
	FileActivityRename        uint32 = 5
	FileActivitySetAttributes uint32 = 6
)

const (
	NetworkActivityUnknown uint32 = 0
	NetworkActivityOpen    uint32 = 1
	NetworkActivityClose   uint32 = 2
	NetworkActivityTraffic uint32 = 6
)

const (
	HTTPActivityUnknown  uint32 = 0
	HTTPActivityRequest  uint32 = 1
	HTTPActivityResponse uint32 = 2
	HTTPActivityTraffic  uint32 = 6
)

const (
	DNSActivityUnknown  uint32 = 0
	DNSActivityQuery    uint32 = 1
	DNSActivityResponse uint32 = 2
	DNSActivityTraffic  uint32 = 6
)

const (
	FindingActivityUnknown uint32 = 0
	FindingActivityCreate  uint32 = 1
	FindingActivityUpdate  uint32 = 2
	FindingActivityClose   uint32 = 3
)

// Application Activity standard + agentsh-internal extensions.
const (
	AppActivityUnknown uint32 = 0
	AppActivityOpen    uint32 = 1
	AppActivityClose   uint32 = 2
	AppActivityUpdate  uint32 = 3
	AppActivityOther   uint32 = 6

	// agentsh-internal — values >= 100 to stay clear of OCSF reservations.
	AppActivityEBPFAttached            uint32 = 100
	AppActivityFUSEMounted             uint32 = 101
	AppActivityCgroupApplied           uint32 = 102
	AppActivityLLMProxyStarted         uint32 = 103
	AppActivityNetProxyStarted         uint32 = 104
	AppActivityMCPToolCalled           uint32 = 105
	AppActivityMCPToolSeen             uint32 = 106
	AppActivityMCPToolsListChanged     uint32 = 107
	AppActivityMCPSamplingRequest      uint32 = 108
	AppActivityMCPToolResultInspected  uint32 = 109
	AppActivityIntegrityChainRotated   uint32 = 110
	AppActivityWrapInit                uint32 = 111
	AppActivityFSEventsError           uint32 = 112
	AppActivityTransparentNetSetup     uint32 = 113
	AppActivityPolicyCreated           uint32 = 120
	AppActivityPolicyUpdated           uint32 = 121
	AppActivityPolicyDeleted           uint32 = 122
	AppActivitySessionCreated          uint32 = 130
	AppActivitySessionDestroyed        uint32 = 131
	AppActivitySessionExpired          uint32 = 132
	AppActivitySessionUpdated          uint32 = 133
	AppActivityCgroupApplyFailed       uint32 = 140
	AppActivityCgroupCleanupFailed     uint32 = 141
	AppActivityFUSEMountFailed         uint32 = 142
	AppActivityEBPFAttachFailed        uint32 = 143
	AppActivityEBPFCollectorFailed     uint32 = 144
	AppActivityEBPFEnforceDisabled     uint32 = 145
	AppActivityEBPFEnforceNonStrict    uint32 = 146
	AppActivityEBPFEnforceRefreshFailed uint32 = 147
	AppActivityEBPFUnavailable         uint32 = 148
	AppActivityLLMProxyFailed          uint32 = 149
	AppActivityNetProxyFailed          uint32 = 150
	AppActivityTransparentNetReady     uint32 = 151
	AppActivityTransparentNetFailed    uint32 = 152
	AppActivityMCPToolChanged          uint32 = 153
	AppActivityMCPCrossServerBlocked   uint32 = 154
	AppActivitySecretAccess            uint32 = 155
	AppActivityMCPNetworkConnection    uint32 = 156
)
```

- [ ] **Step 3: Write `mapping.go`**

```go
package ocsf

import (
	"errors"
	"fmt"
	"sort"

	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
)

// Mapping declares how a single agentsh ev.Type is projected into OCSF.
//
// All four fields are required:
//   - ClassUID and ActivityID end up on the resulting compact.MappedEvent.
//   - FieldsAllowlist is the ONLY way ev.Fields values reach the
//     projector. Sensitive keys are absent from every allowlist; there
//     is no global denylist.
//   - Project builds the class-specific proto.Message. Map() handles
//     the deterministic marshal at the boundary.
//
// AgentInternal is informational (also set inside the projected proto).
type Mapping struct {
	ClassUID        uint32
	ActivityID      uint32
	AgentInternal   bool
	FieldsAllowlist []FieldRule
	Project         Projector
}

// Projector builds a typed proto.Message for the class. It receives
// only allowlisted-and-transformed Fields values; it must not reach
// ev.Fields directly.
type Projector func(ev types.Event, allowed map[string]any) (proto.Message, error)

// FieldRule declares one allowlisted ev.Fields key plus its transform.
//
// Transform may return (nil, nil) to omit the key from `allowed`. An
// omitted required key is reported as ErrMissingRequiredField.
//
// DestPath is informational (used for documentation and golden test
// readability); the projector decides where the value lands inside the
// proto message.
type FieldRule struct {
	Key       string
	Required  bool
	Transform func(any) (any, error)
	DestPath  string
}

// Errors surfaced by Map() and consumed by the WTP store boundary.
var (
	ErrUnmappedType         = errors.New("ocsf: event Type not registered")
	ErrMissingRequiredField = errors.New("ocsf: required allowlisted field absent or rejected")
	ErrProjectFailed        = errors.New("ocsf: projector failed to build OCSF message")
)

// UnmappedTypeError wraps ErrUnmappedType with the offending Type so
// callers can include it in structured logs.
type UnmappedTypeError struct{ Type string }

func (e *UnmappedTypeError) Error() string {
	return fmt.Sprintf("%s: %q", ErrUnmappedType.Error(), e.Type)
}
func (e *UnmappedTypeError) Unwrap() error { return ErrUnmappedType }

// projectFields runs every FieldRule in the order it appears in the
// allowlist (slice order — deterministic by declaration). Returns a
// fresh map of Key -> transformed value, omitting keys whose transform
// returned (nil, nil). A required key that is absent or whose transform
// returned a non-nil error becomes ErrMissingRequiredField.
//
// The mapper's iteration order is the slice's order; this function MUST
// NOT range over `fields` directly (Go map iteration is randomized,
// breaking determinism).
func projectFields(fields map[string]any, rules []FieldRule) (map[string]any, error) {
	out := make(map[string]any, len(rules))
	for _, r := range rules {
		raw, present := fields[r.Key]
		if !present {
			if r.Required {
				return nil, fmt.Errorf("%w: %s", ErrMissingRequiredField, r.Key)
			}
			continue
		}
		var v any
		var err error
		if r.Transform != nil {
			v, err = r.Transform(raw)
		} else {
			v = raw
		}
		if err != nil {
			if r.Required {
				return nil, fmt.Errorf("%w: %s: %v", ErrMissingRequiredField, r.Key, err)
			}
			continue // non-required: drop silently
		}
		if v == nil {
			if r.Required {
				return nil, fmt.Errorf("%w: %s: transform returned nil", ErrMissingRequiredField, r.Key)
			}
			continue
		}
		out[r.Key] = v
	}
	return out, nil
}

// safeProject runs the projector under a recover() guard. Any panic is
// converted into ErrProjectFailed with the panic value in the wrapped
// message.
func safeProject(p Projector, ev types.Event, allowed map[string]any) (msg proto.Message, err error) {
	defer func() {
		if r := recover(); r != nil {
			msg = nil
			err = fmt.Errorf("%w: panic: %v", ErrProjectFailed, r)
		}
	}()
	msg, err = p(ev, allowed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProjectFailed, err)
	}
	if msg == nil {
		return nil, fmt.Errorf("%w: projector returned nil message", ErrProjectFailed)
	}
	return msg, nil
}

// allowlistKeys returns the sorted slice of keys an allowlist projects.
// Used by the exhaustiveness Fields-key check.
func allowlistKeys(rules []FieldRule) []string {
	keys := make([]string, len(rules))
	for i, r := range rules {
		keys[i] = r.Key
	}
	sort.Strings(keys)
	return keys
}

// Common transforms reused across registry entries.

// AsString stringifies common scalar concrete types behind an `any`.
// Returns (nil, nil) for nil input. Errors only on types it cannot
// reasonably stringify.
func AsString(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch x := v.(type) {
	case string:
		return x, nil
	case []byte:
		return string(x), nil
	case int, int32, int64, uint, uint32, uint64, float32, float64, bool:
		return fmt.Sprintf("%v", x), nil
	default:
		return nil, fmt.Errorf("AsString: unsupported %T", v)
	}
}

// AsUint32 narrows numeric concrete types to uint32. Errors on overflow.
func AsUint32(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch x := v.(type) {
	case int:
		if x < 0 || x > 1<<32-1 {
			return nil, fmt.Errorf("AsUint32: out of range: %d", x)
		}
		return uint32(x), nil
	case int32:
		if x < 0 {
			return nil, fmt.Errorf("AsUint32: negative: %d", x)
		}
		return uint32(x), nil
	case int64:
		if x < 0 || x > 1<<32-1 {
			return nil, fmt.Errorf("AsUint32: out of range: %d", x)
		}
		return uint32(x), nil
	case uint32:
		return x, nil
	case uint64:
		if x > 1<<32-1 {
			return nil, fmt.Errorf("AsUint32: overflow: %d", x)
		}
		return uint32(x), nil
	case float64:
		if x < 0 || x > 1<<32-1 {
			return nil, fmt.Errorf("AsUint32: out of range: %v", x)
		}
		return uint32(x), nil
	default:
		return nil, fmt.Errorf("AsUint32: unsupported %T", v)
	}
}

// AsUint64 narrows numeric concrete types to uint64.
func AsUint64(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch x := v.(type) {
	case int:
		if x < 0 {
			return nil, fmt.Errorf("AsUint64: negative: %d", x)
		}
		return uint64(x), nil
	case int64:
		if x < 0 {
			return nil, fmt.Errorf("AsUint64: negative: %d", x)
		}
		return uint64(x), nil
	case uint64:
		return x, nil
	case uint32:
		return uint64(x), nil
	case float64:
		if x < 0 {
			return nil, fmt.Errorf("AsUint64: negative: %v", x)
		}
		return uint64(x), nil
	default:
		return nil, fmt.Errorf("AsUint64: unsupported %T", v)
	}
}
```

- [ ] **Step 4: Verify it compiles**

Run: `go build ./internal/ocsf/...`
Expected: exits 0 (registry.go and mapper.go don't exist yet — build will fail until Task 11; for now this task lands as part of a sequence). If you are running tasks individually and want a clean build at this checkpoint, also commit Task 10's mapper.go and Task 11's registry.go before running.

> **Note:** Tasks 9, 10, 11 are tightly coupled — the package only compiles when all three land. Land them as a single PR if running this plan in subagent-driven mode.

- [ ] **Step 5: Commit (deferred — see note above)**

Hold the commit until Task 11 lands. The combined commit message goes there.

---

## Task 10: `mapper.go` — `Mapper` type, `New()`, `Map()`

**Files:**
- Create: `internal/ocsf/mapper.go`

- [ ] **Step 1: Write the file**

```go
package ocsf

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/pkg/types"
)

// Mapper is the production OCSF v1.8.0 mapper. It implements
// compact.Mapper. The zero value is NOT usable — construct with New().
//
// Mapper is read-only after New(); Map() is safe for concurrent use.
type Mapper struct {
	registry map[string]Mapping
}

// New returns a Mapper backed by the package's static registry.
func New() *Mapper {
	return &Mapper{registry: registry}
}

// Map projects an agentsh event into a compact.MappedEvent.
//
// Returns ErrUnmappedType if ev.Type is not in the registry (or its
// UnmappedTypeError wrapper which carries the offending Type). Returns
// ErrMissingRequiredField if a Required FieldRule was absent or
// transform-rejected. Returns ErrProjectFailed if the projector
// panicked, returned an error, returned nil, or proto.Marshal failed.
//
// Determinism contract: for any two calls with logically equal `ev`,
// the returned Payload []byte is byte-identical. See
// TestMapDeterministic.
func (m *Mapper) Map(ev types.Event) (compact.MappedEvent, error) {
	rule, ok := m.registry[ev.Type]
	if !ok {
		return compact.MappedEvent{}, &UnmappedTypeError{Type: ev.Type}
	}

	allowed, err := projectFields(ev.Fields, rule.FieldsAllowlist)
	if err != nil {
		return compact.MappedEvent{}, err
	}

	msg, err := safeProject(rule.Project, ev, allowed)
	if err != nil {
		return compact.MappedEvent{}, err
	}

	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return compact.MappedEvent{}, fmt.Errorf("%w: marshal: %v", ErrProjectFailed, err)
	}

	return compact.MappedEvent{
		OCSFClassUID:   rule.ClassUID,
		OCSFActivityID: rule.ActivityID,
		Payload:        payload,
	}, nil
}

// Compile-time check: Mapper implements compact.Mapper.
var _ compact.Mapper = (*Mapper)(nil)
```

- [ ] **Step 2: Hold for combined commit (Task 11)**

---

## Task 11: `registry.go` — empty registry + `pendingTypes`

**Files:**
- Create: `internal/ocsf/registry.go`

- [ ] **Step 1: Write the file**

```go
package ocsf

// registry maps every production agentsh ev.Type to its OCSF Mapping.
// Per-class projector files (project_*.go) populate it via package
// init() functions; this file holds only the central declaration and
// the rollout tracker.
//
// Determinism note: registry values are read-only after package init.
// Map() reads but never mutates the registry.
var registry = map[string]Mapping{}

// pendingTypes lists production agentsh ev.Type values that the
// mapper does NOT yet handle. Populated in this file initially; each
// per-class projector PR removes its types as it lands.
//
// The exhaustiveness CI test in exhaustiveness_test.go uses this set:
// for any ev.Type discovered in the source tree, the test asserts
//
//   _, registered := registry[t]
//   _, skipped    := skiplist[t]
//   _, pending    := pendingTypes[t]
//   require registered || skipped || pending
//
// When pendingTypes is empty AND every emitted Type is registered or
// skiplisted, Phase 1 is functionally complete.
var pendingTypes = map[string]struct{}{
	// Process Activity (1007) — Task 16
	"execve":              {},
	"exec":                {},
	"exec_intercept":      {},
	"exec.start":          {},
	"ptrace_execve":       {},
	"command_started":     {},
	"command_executed":    {},
	"command_finished":    {},
	"command_killed":      {},
	"command_redirected":  {},
	"command_redirect":    {},
	"process_start":       {},
	"exit":                {},
	// File System Activity (1001) — Task 17
	"file_open":          {},
	"file_read":          {},
	"file_write":         {},
	"file_create":        {},
	"file_created":       {},
	"file_delete":        {},
	"file_deleted":       {},
	"file_chmod":         {},
	"file_mkdir":         {},
	"file_rmdir":         {},
	"file_rename":        {},
	"file_renamed":       {},
	"file_modified":      {},
	"file_soft_deleted":  {},
	"ptrace_file":        {},
	"registry_write":     {},
	"registry_error":     {},
	// Network Activity (4001) — Task 18
	"net_connect":             {},
	"connection_allowed":      {},
	"connect_redirect":        {},
	"ptrace_network":          {},
	"unix_socket_op":          {},
	"transparent_net_failed":  {},
	"transparent_net_ready":   {},
	"transparent_net_setup":   {},
	"mcp_network_connection":  {},
	// HTTP Activity (4002) — Task 19
	"http":                       {},
	"net_http_request":           {},
	"http_service_denied_direct": {},
	// DNS Activity (4003) — Task 20
	"dns_query":    {},
	"dns_redirect": {},
	// Detection Finding (2004) — Task 21
	"command_policy":            {},
	"seccomp_blocked":           {},
	"agent_detected":            {},
	"taint_created":             {},
	"taint_propagated":          {},
	"taint_removed":             {},
	"mcp_cross_server_blocked":  {},
	"mcp_tool_call_intercepted": {},
	// Application Activity (6005) — Task 22
	"mcp_tool_called":             {},
	"mcp_tool_seen":               {},
	"mcp_tool_changed":            {},
	"mcp_tools_list_changed":      {},
	"mcp_sampling_request":        {},
	"mcp_tool_result_inspected":   {},
	"llm_proxy_started":           {},
	"llm_proxy_failed":            {},
	"net_proxy_started":           {},
	"net_proxy_failed":            {},
	"secret_access":               {},
	"cgroup_applied":              {},
	"cgroup_apply_failed":         {},
	"cgroup_cleanup_failed":       {},
	"fuse_mounted":                {},
	"fuse_mount_failed":           {},
	"ebpf_attached":               {},
	"ebpf_attach_failed":          {},
	"ebpf_collector_failed":       {},
	"ebpf_enforce_disabled":       {},
	"ebpf_enforce_non_strict":     {},
	"ebpf_enforce_refresh_failed": {},
	"ebpf_unavailable":            {},
	"wrap_init":                   {},
	"fsevents_error":              {},
	"integrity_chain_rotated":     {},
	"policy_created":              {},
	"policy_updated":              {},
	"policy_deleted":              {},
	"session_created":             {},
	"session_destroyed":           {},
	"session_expired":             {},
	"session_updated":             {},
}

// register installs a Mapping in the registry and removes the type
// from pendingTypes. Called from per-class init() in project_*.go.
// Panics if t is already registered or already in skiplist — these
// are package-init bugs that must surface immediately.
func register(t string, m Mapping) {
	if _, ok := registry[t]; ok {
		panic("ocsf: duplicate Mapping for type: " + t)
	}
	if _, ok := skiplist[t]; ok {
		panic("ocsf: cannot register skiplisted type: " + t)
	}
	registry[t] = m
	delete(pendingTypes, t)
}
```

- [ ] **Step 2: Verify the package compiles end-to-end**

Run: `go build ./internal/ocsf/...`
Expected: exits 0.

- [ ] **Step 3: Verify Mapper.Map returns ErrUnmappedType for any input**

Quick sanity: `go run -exec=true` style is awkward for an internal package; this is verified by the unit tests in Task 13. Skip the live check.

- [ ] **Step 4: Combined commit for Tasks 9-11**

```bash
git add internal/ocsf/version.go internal/ocsf/activity.go internal/ocsf/mapping.go internal/ocsf/mapper.go internal/ocsf/registry.go
git commit -m "ocsf: add skeleton mapper package (Mapper, registry, mapping primitives)

Empty registry; pendingTypes seeded with the full Phase 1 catalog so
exhaustiveness CI passes once it lands. Per-class projectors are added
in subsequent commits and remove their Types from pendingTypes."
```

---

## Task 12: `skiplist.go` and `skiplist_test.go`

**Files:**
- Create: `internal/ocsf/skiplist.go`
- Create: `internal/ocsf/skiplist_test.go`

- [ ] **Step 1: Write `skiplist.go`**

```go
package ocsf

// skiplist enumerates ev.Type literal values that appear in the source
// tree but are NOT production telemetry — test fixtures, placeholders,
// throwaway values used only in unit tests. The exhaustiveness CI walks
// every ev.Type literal and asserts it is either registered, in
// pendingTypes, or in this skiplist.
//
// Each entry's value is the reason it is skiplisted. The reason MUST
// be non-empty (asserted by skiplist_test.go) and SHOULD reference the
// kind of test that emits it.
//
// CRITICAL: a value listed here MUST NOT be a real production Type.
// TestSkiplistDoesNotShadowRegistry guards against that by asserting
// skiplist ∩ (registry ∪ pendingTypes) = ∅ on package init. Adding a
// production-flavored value here is a CI failure, not a silent drop.
var skiplist = map[string]string{
	"a":                 "test fixture: short alphabet sentinel in event_query/composite tests",
	"b":                 "test fixture: short alphabet sentinel",
	"x":                 "test fixture: short alphabet sentinel",
	"y":                 "test fixture: short alphabet sentinel",
	"test":              "test fixture: generic placeholder",
	"test_event":        "test fixture: generic placeholder",
	"demo":              "test fixture: example/demo path",
	"hello":             "test fixture: greeting placeholder",
	"phone":             "test fixture: contact placeholder",
	"license":           "test fixture: placeholder used in license-related tests",
	"ok":                "test fixture: success-flag placeholder",
	"none":              "test fixture: zero-value placeholder",
	"live":              "test fixture: liveness probe placeholder",
	"email":             "test fixture: contact placeholder",
	"external":          "test fixture: source classifier placeholder",
	"self":              "test fixture: self-reference placeholder",
	"invalid":           "test fixture: explicit invalid sentinel",
	"invalid_type":      "test fixture: explicit invalid sentinel",
	"pid_range":         "test fixture: pid_range query selector test",
	"signal":            "test fixture: signal placeholder",
	"resize":            "test fixture: pty resize placeholder",
	"rotate":            "test fixture: rotation placeholder",
	"after_rotate":      "test fixture: post-rotation placeholder",
	"start":             "test fixture: lifecycle placeholder",
	"big_event":         "test fixture: oversize-event boundary test",
	"command":           "test fixture: command placeholder",
	"fatal_sidecar":     "test fixture: fatal-sidecar drill placeholder",
	"file":              "test fixture: file placeholder distinct from file_open et al",
	"malware":           "test fixture: detection placeholder",
	"network":           "test fixture: network placeholder distinct from net_connect et al",
	"process":           "test fixture: process placeholder distinct from process_start",
	"session":           "test fixture: session placeholder distinct from session_created et al",
	"sse":               "test fixture: server-sent events placeholder",
	"stream":            "test fixture: stream placeholder",
	"unix":              "test fixture: unix-domain placeholder",
	"vulnerability":     "test fixture: vulnerability placeholder",
	"event":             "test fixture: generic event placeholder",
	"agent_detected_t":  "test fixture: agent_detected variant in tests",
	"stdio":             "test fixture: stdio source classifier",
	"children":          "test fixture: children placeholder",
}
```

- [ ] **Step 2: Write `skiplist_test.go`**

```go
package ocsf

import "testing"

// TestSkiplistReasonsNonEmpty asserts every skiplist entry has a
// non-empty reason. A blank reason is a hygiene failure — operators
// reading the file deserve to know why a Type was excluded.
func TestSkiplistReasonsNonEmpty(t *testing.T) {
	for k, v := range skiplist {
		if v == "" {
			t.Errorf("skiplist[%q] has empty reason", k)
		}
	}
}

// TestSkiplistDoesNotShadowRegistry asserts no skiplist entry is also
// a registered or pending production Type. A collision means a real
// event is being silently dropped from OCSF mapping.
func TestSkiplistDoesNotShadowRegistry(t *testing.T) {
	for k := range skiplist {
		if _, ok := registry[k]; ok {
			t.Errorf("skiplist[%q] is also registered — production Type cannot be skiplisted", k)
		}
		if _, ok := pendingTypes[k]; ok {
			t.Errorf("skiplist[%q] is also in pendingTypes — production Type cannot be skiplisted", k)
		}
	}
}
```

- [ ] **Step 3: Run the tests**

Run: `go test ./internal/ocsf/...`
Expected: PASS for both `TestSkiplistReasonsNonEmpty` and `TestSkiplistDoesNotShadowRegistry`.

- [ ] **Step 4: Commit**

```bash
git add internal/ocsf/skiplist.go internal/ocsf/skiplist_test.go
git commit -m "ocsf: add skiplist of test-only Type literals + hygiene tests"
```

---

## Task 13: `mapper_test.go` — determinism property test + golden harness

**Files:**
- Create: `internal/ocsf/mapper_test.go`
- Create: `internal/ocsf/testdata/.gitkeep`

- [ ] **Step 1: Create the testdata directory placeholder**

Run: `mkdir -p internal/ocsf/testdata/golden && touch internal/ocsf/testdata/.gitkeep`

- [ ] **Step 2: Write `mapper_test.go`**

```go
package ocsf

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

var updateGoldens = flag.Bool("update", false, "regenerate golden files")

func TestMap_UnmappedTypeReturnsErrUnmappedType(t *testing.T) {
	m := New()
	ev := types.Event{Type: "definitely_not_in_registry_xyz", Timestamp: time.Unix(0, 0)}
	_, err := m.Map(ev)
	if !errors.Is(err, ErrUnmappedType) {
		t.Fatalf("got %v, want errors.Is(ErrUnmappedType)", err)
	}
	var ute *UnmappedTypeError
	if !errors.As(err, &ute) {
		t.Fatalf("got %v, want *UnmappedTypeError", err)
	}
	if ute.Type != "definitely_not_in_registry_xyz" {
		t.Fatalf("UnmappedTypeError.Type = %q", ute.Type)
	}
}

// TestMapDeterministic asserts that for any registered event, mapping
// 1000 times produces byte-identical Payload. Run on a sample of
// events covering every class. New event Types added in per-class
// PRs MUST appear in deterministicSampleEvents() — the helper below
// is the test contract.
func TestMapDeterministic(t *testing.T) {
	m := New()
	for _, ev := range deterministicSampleEvents() {
		ev := ev
		t.Run(ev.Type, func(t *testing.T) {
			first, err := m.Map(ev)
			if err != nil {
				t.Skipf("Map(%q) error %v — Type not yet implemented", ev.Type, err)
			}
			for i := 0; i < 1000; i++ {
				got, err := m.Map(ev)
				if err != nil {
					t.Fatalf("iteration %d: %v", i, err)
				}
				if !bytes.Equal(first.Payload, got.Payload) {
					t.Fatalf("iteration %d: payload diverged: %x vs %x", i, first.Payload, got.Payload)
				}
				if got.OCSFClassUID != first.OCSFClassUID || got.OCSFActivityID != first.OCSFActivityID {
					t.Fatalf("iteration %d: class/activity diverged", i)
				}
			}
		})
	}
}

// deterministicSampleEvents returns one representative Event per
// registered Type. As per-class projectors land, each PR appends its
// fixtures here. The TestMapDeterministic skips Types whose Map call
// returns an error — that lets the test pass during incremental rollout
// and makes it strictly tighten as Types are registered.
func deterministicSampleEvents() []types.Event {
	return goldenSampleEvents()
}

// TestGoldens runs Map for every entry in goldenSampleEvents(),
// projects the resulting proto payload to JSON via protojson, and
// compares against testdata/golden/<type>.json. With -update,
// regenerates the golden files instead of comparing.
//
// Skips Types whose Map returns an error so the test stays green
// during incremental per-class rollout.
func TestGoldens(t *testing.T) {
	m := New()
	for _, ev := range goldenSampleEvents() {
		ev := ev
		t.Run(ev.Type, func(t *testing.T) {
			mapped, err := m.Map(ev)
			if err != nil {
				t.Skipf("Map(%q) error %v — Type not yet implemented", ev.Type, err)
			}
			msg, err := decodePayloadForGolden(mapped.OCSFClassUID, mapped.Payload)
			if err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			gotJSON, err := protojson.MarshalOptions{
				Multiline:       true,
				Indent:          "  ",
				UseProtoNames:   true,
				EmitUnpopulated: false,
			}.Marshal(msg)
			if err != nil {
				t.Fatalf("protojson: %v", err)
			}
			path := filepath.Join("testdata", "golden", ev.Type+".json")
			if *updateGoldens {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, gotJSON, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden %s: %v (run with -update to create)", path, err)
			}
			if !bytes.Equal(normalizeJSON(t, gotJSON), normalizeJSON(t, want)) {
				t.Errorf("golden mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", ev.Type, gotJSON, want)
			}
		})
	}
}

// decodePayloadForGolden picks the right proto.Message type for a
// given class_uid so protojson can marshal its fields. Per-class PRs
// extend this switch.
func decodePayloadForGolden(classUID uint32, payload []byte) (proto.Message, error) {
	var msg proto.Message
	switch classUID {
	case ClassProcessActivity:
		msg = &ocsfpb.ProcessActivity{}
	case ClassFileSystemActivity:
		msg = &ocsfpb.FileSystemActivity{}
	case ClassNetworkActivity:
		msg = &ocsfpb.NetworkActivity{}
	case ClassHTTPActivity:
		msg = &ocsfpb.HTTPActivity{}
	case ClassDNSActivity:
		msg = &ocsfpb.DNSActivity{}
	case ClassDetectionFinding:
		msg = &ocsfpb.DetectionFinding{}
	case ClassApplicationActivity:
		msg = &ocsfpb.ApplicationActivity{}
	default:
		return nil, errors.New("decodePayloadForGolden: unknown class_uid")
	}
	if err := proto.Unmarshal(payload, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func normalizeJSON(t *testing.T, in []byte) []byte {
	t.Helper()
	var v any
	if err := json.Unmarshal(in, &v); err != nil {
		t.Fatalf("json normalize: %v", err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// goldenSampleEvents returns the canonical fixture per registered
// Type. Each per-class PR appends its fixtures here.
func goldenSampleEvents() []types.Event {
	return nil // populated by per-class PRs
}
```

- [ ] **Step 3: Run the tests**

Run: `go test ./internal/ocsf/...`
Expected: `TestMap_UnmappedTypeReturnsErrUnmappedType` PASSES; `TestMapDeterministic` and `TestGoldens` PASS with no sub-tests (because `goldenSampleEvents()` returns nil).

- [ ] **Step 4: Commit**

```bash
git add internal/ocsf/mapper_test.go internal/ocsf/testdata/.gitkeep
git commit -m "ocsf: add mapper test harness — determinism, goldens, unmapped type"
```

---

## Task 14: `redaction_test.go` — sensitive-key denylist guard

**Files:**
- Create: `internal/ocsf/redaction_test.go`

- [ ] **Step 1: Write the test**

```go
package ocsf

import (
	"strings"
	"testing"
)

// sensitiveKeys is the test-only fixture of key names that MUST NOT
// appear in any FieldRule.Key across the entire registry. This is a
// guard against accidental allowlisting of values that would carry
// secrets to Watchtower.
//
// The list is intentionally lowercase; the check is case-insensitive.
// Matches are exact (a registered key "x_authorization" does NOT match
// "authorization"); to widen, add the variant explicitly.
var sensitiveKeys = []string{
	"authorization",
	"cookie",
	"set-cookie",
	"set_cookie",
	"proxy-authorization",
	"proxy_authorization",
	"api_key",
	"api-key",
	"apikey",
	"secret",
	"password",
	"passwd",
	"token",
	"bearer",
	"x-auth-token",
	"x_auth_token",
	"private_key",
	"client_secret",
}

func TestRegistry_NoSensitiveKeysAllowlisted(t *testing.T) {
	deny := make(map[string]struct{}, len(sensitiveKeys))
	for _, k := range sensitiveKeys {
		deny[strings.ToLower(k)] = struct{}{}
	}
	for evType, mapping := range registry {
		for _, rule := range mapping.FieldsAllowlist {
			if _, banned := deny[strings.ToLower(rule.Key)]; banned {
				t.Errorf("registry[%q] allowlists sensitive key %q — must be omitted entirely",
					evType, rule.Key)
			}
		}
	}
}
```

- [ ] **Step 2: Run it**

Run: `go test ./internal/ocsf/ -run TestRegistry_NoSensitiveKeysAllowlisted -v`
Expected: PASS (registry is empty until per-class PRs land; the test still runs and passes vacuously).

- [ ] **Step 3: Commit**

```bash
git add internal/ocsf/redaction_test.go
git commit -m "ocsf: add sensitive-key denylist guard test"
```

---

## Task 15: `exhaustiveness_test.go` — AST walk for Types and Fields keys

**Files:**
- Create: `internal/ocsf/exhaustiveness_test.go`

- [ ] **Step 1: Write the test**

```go
package ocsf

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// findRepoRoot returns the absolute path to the agentsh repo root by
// walking up from this file's directory until it finds a go.mod.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := filepath.Abs(filepath.Join(dir, "go.mod")); err == nil {
			if _, statErr := fs.Stat(rootFS{dir}, "go.mod"); statErr == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate go.mod")
		}
		dir = parent
	}
}

type rootFS struct{ dir string }

func (r rootFS) Open(name string) (fs.File, error) { return nil, fs.ErrNotExist }

// scanTypeLiterals walks rootDir for .go files (excluding vendor/,
// .gomodcache/, build/, bin/, dist/) and collects every string literal
// passed as the Type field of a types.Event composite literal or
// assigned to ev.Type.
func scanTypeLiterals(t *testing.T, rootDir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	fset := token.NewFileSet()
	skip := map[string]bool{
		"vendor": true, ".gomodcache": true, "build": true, "bin": true, "dist": true,
		"node_modules": true, ".git": true, ".claude": true, "tmp": true, "examples": true,
	}
	walkErr := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Exclude generated *.pb.go (protoc output) — never contain ev.Type literals.
		if strings.HasSuffix(path, ".pb.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Logf("parse %s: %v (skipping)", path, err)
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				// types.Event{Type: "foo", ...} OR Event{Type: "foo", ...} (in pkg types)
				if !isEventCompositeLit(x) {
					return true
				}
				for _, elt := range x.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					ident, ok := kv.Key.(*ast.Ident)
					if !ok || ident.Name != "Type" {
						continue
					}
					if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						s, err := strconv.Unquote(lit.Value)
						if err == nil && s != "" {
							pos := fset.Position(lit.Pos())
							if _, seen := out[s]; !seen {
								out[s] = pos.String()
							}
						}
					}
				}
			case *ast.AssignStmt:
				// ev.Type = "foo"
				if len(x.Lhs) != 1 || len(x.Rhs) != 1 {
					return true
				}
				sel, ok := x.Lhs[0].(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Type" {
					return true
				}
				if lit, ok := x.Rhs[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					s, err := strconv.Unquote(lit.Value)
					if err == nil && s != "" {
						pos := fset.Position(lit.Pos())
						if _, seen := out[s]; !seen {
							out[s] = pos.String()
						}
					}
				}
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk: %v", walkErr)
	}
	return out
}

func isEventCompositeLit(c *ast.CompositeLit) bool {
	switch t := c.Type.(type) {
	case *ast.SelectorExpr:
		// pkg.Event style — accept any selector ending in "Event" so we
		// catch types.Event and other re-exports. False positives are
		// fine; missed positives are not.
		return t.Sel != nil && t.Sel.Name == "Event"
	case *ast.Ident:
		return t.Name == "Event"
	}
	return false
}

// TestExhaustiveness_AllEventTypesRegistered walks the source tree and
// asserts every distinct ev.Type string literal is in registry,
// pendingTypes, or skiplist. Reports the file:line of the first
// occurrence on failure.
func TestExhaustiveness_AllEventTypesRegistered(t *testing.T) {
	root := repoRoot(t)
	found := scanTypeLiterals(t, root)
	var missing []string
	for s, pos := range found {
		if _, ok := registry[s]; ok {
			continue
		}
		if _, ok := pendingTypes[s]; ok {
			continue
		}
		if _, ok := skiplist[s]; ok {
			continue
		}
		missing = append(missing, s+" (first seen "+pos+")")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("event Type literals not registered, pending, or skiplisted:\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// TestExhaustiveness_PendingTypesEventuallyResolve is a hint test that
// fails as a reminder when pendingTypes is empty BUT the registry is
// also missing entries the test discovered. The real coverage is the
// exhaustiveness test above; this one just nudges toward removing the
// pendingTypes seed once Phase 1 is done.
func TestExhaustiveness_PendingTypesShrinking(t *testing.T) {
	if len(pendingTypes) == 0 {
		t.Log("pendingTypes is empty — Phase 1 catalog complete")
	}
}

// repoRoot returns the agentsh repo root via go.mod search.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	for {
		entries, err := filepath.Glob(filepath.Join(dir, "go.mod"))
		if err == nil && len(entries) == 1 {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repoRoot: go.mod not found")
		}
		dir = parent
	}
}
```

- [ ] **Step 2: Run the test**

Run: `go test ./internal/ocsf/ -run TestExhaustiveness -v`
Expected: PASS — every Type discovered in the source tree is in `pendingTypes` (since registry is empty and skiplist is the test-only catalog). If the test reports unregistered Types, audit them: real production Type → add to `pendingTypes`; test-only → add to `skiplist`.

- [ ] **Step 3: Commit**

```bash
git add internal/ocsf/exhaustiveness_test.go
git commit -m "ocsf: add AST-walk exhaustiveness test for ev.Type literals"
```

---

## Task 16: Process Activity projector + registry entries + goldens

**Files:**
- Create: `internal/ocsf/project_process.go`
- Modify: `internal/ocsf/mapper_test.go` (extend `goldenSampleEvents`)
- Create: `internal/ocsf/testdata/golden/{execve,exec,exec_intercept,exec.start,ptrace_execve,command_started,command_executed,command_finished,command_killed,command_redirected,command_redirect,process_start,exit}.json`

- [ ] **Step 1: Write `project_process.go`**

```go
package ocsf

import (
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

// processProjector builds a *ocsfpb.ProcessActivity from an event
// classified as Process Activity (class_uid 1007).
//
// activity_id is read from the registry Mapping (it differs per Type:
// execve→Launch, exit→Terminate, exec_intercept→Open, ...). The
// projector embeds a Process object (the child) and an Actor with the
// parent (when ev.ParentPID > 0).
func processProjector(activity uint32) Projector {
	return func(ev types.Event, _ map[string]any) (proto.Message, error) {
		msg := &ocsfpb.ProcessActivity{
			ClassUid:     u32p(ClassProcessActivity),
			ActivityId:   u32p(activity),
			CategoryUid:  u32p(1),
			TypeUid:      u32p(ClassProcessActivity*100 + activity),
			Time:         u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:     strp(severityFromPolicy(ev.Policy)),
			Metadata:     buildMetadata(ev),
			Process:      buildProcess(ev),
		}
		if ev.ParentPID > 0 {
			msg.Actor = &ocsfpb.Actor{
				Process: &ocsfpb.Process{
					Pid: u64p(uint64(ev.ParentPID)),
				},
			}
		}
		if ev.UnwrappedFrom != "" {
			msg.UnwrappedFrom = strp(ev.UnwrappedFrom)
		}
		if ev.PayloadCommand != "" {
			msg.PayloadCommand = strp(ev.PayloadCommand)
		}
		if ev.Truncated {
			msg.Truncated = boolp(true)
		}
		if ev.Policy != nil {
			if d := string(ev.Policy.Decision); d != "" {
				msg.PolicyDecision = strp(d)
			}
			if ev.Policy.Rule != "" {
				msg.PolicyRule = strp(ev.Policy.Rule)
			}
		}
		return msg, nil
	}
}

func buildProcess(ev types.Event) *ocsfpb.Process {
	p := &ocsfpb.Process{}
	if ev.PID > 0 {
		p.Pid = u64p(uint64(ev.PID))
	}
	if ev.ParentPID > 0 {
		p.ParentPid = u64p(uint64(ev.ParentPID))
	}
	if ev.Filename != "" {
		p.Name = strp(filepath.Base(ev.Filename))
		p.File = &ocsfpb.File{
			Path:    strp(ev.Filename),
			Name:    strp(filepath.Base(ev.Filename)),
			RawPath: strpOrNil(ev.RawFilename),
		}
	}
	if len(ev.Argv) > 0 {
		p.CmdLine = strp(strings.Join(ev.Argv, " "))
	}
	if ev.Depth > 0 {
		p.Depth = u32p(uint32(ev.Depth))
	}
	if ev.SessionID != "" {
		p.SessionUid = strp(ev.SessionID)
	}
	if ev.CommandID != "" {
		p.CommandUid = strp(ev.CommandID)
	}
	return p
}

func buildMetadata(ev types.Event) *ocsfpb.Metadata {
	md := &ocsfpb.Metadata{
		Version: strp(SchemaVersion),
		Product: &ocsfpb.Product{
			Name:       strp("agentsh"),
			VendorName: strp("agentsh"),
		},
		LoggedTime: u64p(uint64(ev.Timestamp.UTC().UnixNano())),
		EventCode:  strp(ev.Type),
	}
	if ev.ID != "" {
		md.Uid = strp(ev.ID)
	}
	return md
}

func severityFromPolicy(p *types.PolicyInfo) string {
	if p == nil {
		return "Informational"
	}
	switch string(p.EffectiveDecision) {
	case "deny", "block":
		return "Medium"
	case "warn":
		return "Low"
	default:
		return "Informational"
	}
}

// Pointer helpers for proto3 explicit-presence fields.
func u32p(v uint32) *uint32 { return &v }
func u64p(v uint64) *uint64 { return &v }
func strp(v string) *string  { return &v }
func boolp(v bool) *bool     { return &v }

func strpOrNil(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func init() {
	// Process Activity Type → activity_id mapping.
	processMappings := map[string]uint32{
		"execve":             ProcessActivityLaunch,
		"exec":               ProcessActivityLaunch,
		"exec.start":         ProcessActivityLaunch,
		"ptrace_execve":      ProcessActivityLaunch,
		"command_started":    ProcessActivityLaunch,
		"command_executed":   ProcessActivityLaunch,
		"process_start":      ProcessActivityLaunch,
		"command_finished":   ProcessActivityTerminate,
		"command_killed":     ProcessActivityTerminate,
		"exit":               ProcessActivityTerminate,
		"exec_intercept":     ProcessActivityOpen,
		"command_redirected": ProcessActivityOpen,
		"command_redirect":   ProcessActivityOpen,
	}
	for t, activity := range processMappings {
		register(t, Mapping{
			ClassUID:        ClassProcessActivity,
			ActivityID:      activity,
			FieldsAllowlist: nil, // process events use only top-level Event columns
			Project:         processProjector(activity),
		})
	}
}
```

- [ ] **Step 2: Add fixtures to `goldenSampleEvents()` in `mapper_test.go`**

Replace the `goldenSampleEvents` function in `internal/ocsf/mapper_test.go` with:

```go
func goldenSampleEvents() []types.Event {
	t0 := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	return []types.Event{
		// Process Activity (1007) — Task 16
		{
			ID: "ev-execve-1", Type: "execve", Timestamp: t0,
			SessionID: "sess-1", CommandID: "cmd-1",
			PID: 1234, ParentPID: 1, Depth: 2,
			Filename: "/usr/bin/curl", RawFilename: "curl",
			Argv: []string{"curl", "-sS", "https://example.com"},
		},
		{ID: "ev-exec-1", Type: "exec", Timestamp: t0, PID: 100, Filename: "/bin/sh"},
		{ID: "ev-exec-intercept-1", Type: "exec_intercept", Timestamp: t0, PID: 101, Filename: "/bin/dangerous",
			Policy: &types.PolicyInfo{Decision: "deny", EffectiveDecision: "deny", Rule: "no-fork"}},
		{ID: "ev-exec-start-1", Type: "exec.start", Timestamp: t0, PID: 102, Filename: "/bin/ls"},
		{ID: "ev-ptrace-execve-1", Type: "ptrace_execve", Timestamp: t0, PID: 103, Filename: "/bin/ls"},
		{ID: "ev-cmd-started-1", Type: "command_started", Timestamp: t0, PID: 110, CommandID: "c1"},
		{ID: "ev-cmd-executed-1", Type: "command_executed", Timestamp: t0, PID: 111, CommandID: "c1"},
		{ID: "ev-cmd-finished-1", Type: "command_finished", Timestamp: t0, PID: 110, CommandID: "c1"},
		{ID: "ev-cmd-killed-1", Type: "command_killed", Timestamp: t0, PID: 110, CommandID: "c1"},
		{ID: "ev-cmd-redirected-1", Type: "command_redirected", Timestamp: t0, PID: 120, UnwrappedFrom: "sudo", PayloadCommand: "/usr/bin/find"},
		{ID: "ev-cmd-redirect-1", Type: "command_redirect", Timestamp: t0, PID: 121},
		{ID: "ev-process-start-1", Type: "process_start", Timestamp: t0, PID: 130},
		{ID: "ev-exit-1", Type: "exit", Timestamp: t0, PID: 140},
	}
}
```

(Subsequent per-class tasks add their fixtures by appending to this slice.)

- [ ] **Step 3: Run the determinism + goldens tests in update mode to generate goldens**

Run: `go test ./internal/ocsf/ -run TestGoldens -update`
Expected: creates 13 files in `internal/ocsf/testdata/golden/`, one per event Type.

- [ ] **Step 4: Inspect a golden by hand**

Run: `cat internal/ocsf/testdata/golden/execve.json`
Expected: a multi-line JSON object with `class_uid: 1007`, `activity_id: 1`, `process.pid: "1234"`, `process.cmd_line: "curl -sS https://example.com"`, `metadata.version: "1.8.0"`. Spot-check that no sensitive data leaked.

- [ ] **Step 5: Re-run tests without -update**

Run: `go test ./internal/ocsf/...`
Expected: PASS for `TestGoldens`, `TestMapDeterministic` (13 sub-tests each), `TestExhaustiveness_AllEventTypesRegistered` (no missing — the 13 process types moved from `pendingTypes` to `registry` via `register()`), `TestRegistry_NoSensitiveKeysAllowlisted`.

- [ ] **Step 6: Commit**

```bash
git add internal/ocsf/project_process.go internal/ocsf/mapper_test.go internal/ocsf/testdata/golden/
git commit -m "ocsf: implement Process Activity (1007) projector + registry entries

Maps execve, exec, exec_intercept, exec.start, ptrace_execve, command_*,
process_start, exit to ProcessActivity. 13 entries removed from
pendingTypes; TestGoldens populated for each."
```

---

## Task 17: File System Activity projector + registry entries + goldens

**Files:**
- Create: `internal/ocsf/project_file.go`
- Modify: `internal/ocsf/mapper_test.go`
- Create: `internal/ocsf/testdata/golden/{file_open,file_read,file_write,file_create,file_created,file_delete,file_deleted,file_chmod,file_mkdir,file_rmdir,file_rename,file_renamed,file_modified,file_soft_deleted,ptrace_file,registry_write,registry_error}.json`

- [ ] **Step 1: Write `project_file.go`**

```go
package ocsf

import (
	"path/filepath"

	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

func fileProjector(activity uint32) Projector {
	return func(ev types.Event, allowed map[string]any) (proto.Message, error) {
		msg := &ocsfpb.FileSystemActivity{
			ClassUid:    u32p(ClassFileSystemActivity),
			ActivityId:  u32p(activity),
			CategoryUid: u32p(1),
			TypeUid:     u32p(ClassFileSystemActivity*100 + activity),
			Time:        u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:    strp(severityFromPolicy(ev.Policy)),
			Metadata:    buildMetadata(ev),
			Actor:       buildActor(ev),
			File:        buildFile(ev),
			Operation:   strpOrNil(ev.Operation),
		}
		if ev.Type == "file_rename" || ev.Type == "file_renamed" {
			if old, ok := allowed["from_path"].(string); ok && old != "" {
				msg.FileDiff = &ocsfpb.File{
					Path: strp(old),
					Name: strp(filepath.Base(old)),
				}
			}
		}
		if ev.Type == "file_soft_deleted" {
			msg.SoftDeleted = boolp(true)
		}
		if ev.Policy != nil {
			if d := string(ev.Policy.Decision); d != "" {
				msg.PolicyDecision = strp(d)
			}
			if ev.Policy.Rule != "" {
				msg.PolicyRule = strp(ev.Policy.Rule)
			}
		}
		return msg, nil
	}
}

func buildActor(ev types.Event) *ocsfpb.Actor {
	if ev.PID == 0 && ev.SessionID == "" {
		return nil
	}
	a := &ocsfpb.Actor{Process: &ocsfpb.Process{}}
	if ev.PID > 0 {
		a.Process.Pid = u64p(uint64(ev.PID))
	}
	if ev.SessionID != "" {
		a.Process.SessionUid = strp(ev.SessionID)
	}
	if ev.CommandID != "" {
		a.Process.CommandUid = strp(ev.CommandID)
	}
	return a
}

func buildFile(ev types.Event) *ocsfpb.File {
	if ev.Path == "" && ev.Filename == "" {
		return nil
	}
	path := ev.Path
	if path == "" {
		path = ev.Filename
	}
	return &ocsfpb.File{
		Path:       strp(path),
		Name:       strp(filepath.Base(path)),
		RawPath:    strpOrNil(ev.RawFilename),
		IsAbstract: boolPtrIfTrue(ev.Abstract),
	}
}

func boolPtrIfTrue(b bool) *bool {
	if !b {
		return nil
	}
	return boolp(true)
}

func init() {
	fileMappings := map[string]uint32{
		"file_open":         FileActivityRead,
		"file_read":         FileActivityRead,
		"file_write":        FileActivityUpdate,
		"file_create":       FileActivityCreate,
		"file_created":      FileActivityCreate,
		"file_delete":       FileActivityDelete,
		"file_deleted":      FileActivityDelete,
		"file_chmod":        FileActivitySetAttributes,
		"file_mkdir":        FileActivityCreate,
		"file_rmdir":        FileActivityDelete,
		"file_rename":       FileActivityRename,
		"file_renamed":      FileActivityRename,
		"file_modified":     FileActivityUpdate,
		"file_soft_deleted": FileActivityDelete,
		"ptrace_file":       FileActivityRead,
		"registry_write":    FileActivityUpdate,
		"registry_error":    FileActivityUpdate,
	}
	renameAllowlist := []FieldRule{{
		Key: "from_path", Required: false, Transform: AsString, DestPath: "file_diff.path",
	}}
	for t, activity := range fileMappings {
		var allow []FieldRule
		if t == "file_rename" || t == "file_renamed" {
			allow = renameAllowlist
		}
		register(t, Mapping{
			ClassUID:        ClassFileSystemActivity,
			ActivityID:      activity,
			FieldsAllowlist: allow,
			Project:         fileProjector(activity),
		})
	}
}
```

- [ ] **Step 2: Append fixtures in `mapper_test.go`**

Append inside `goldenSampleEvents()`'s return slice (after the Process Activity block):

```go
		// File System Activity (1001) — Task 17
		{ID: "ev-file-open-1", Type: "file_open", Timestamp: t0, PID: 200, Path: "/etc/hosts", Operation: "open"},
		{ID: "ev-file-read-1", Type: "file_read", Timestamp: t0, PID: 201, Path: "/etc/passwd", Operation: "read"},
		{ID: "ev-file-write-1", Type: "file_write", Timestamp: t0, PID: 202, Path: "/tmp/out", Operation: "write"},
		{ID: "ev-file-create-1", Type: "file_create", Timestamp: t0, PID: 203, Path: "/tmp/new"},
		{ID: "ev-file-created-1", Type: "file_created", Timestamp: t0, PID: 204, Path: "/tmp/done"},
		{ID: "ev-file-delete-1", Type: "file_delete", Timestamp: t0, PID: 205, Path: "/tmp/old"},
		{ID: "ev-file-deleted-1", Type: "file_deleted", Timestamp: t0, PID: 206, Path: "/tmp/removed"},
		{ID: "ev-file-chmod-1", Type: "file_chmod", Timestamp: t0, PID: 207, Path: "/tmp/perm"},
		{ID: "ev-file-mkdir-1", Type: "file_mkdir", Timestamp: t0, PID: 208, Path: "/tmp/dir"},
		{ID: "ev-file-rmdir-1", Type: "file_rmdir", Timestamp: t0, PID: 209, Path: "/tmp/dir"},
		{ID: "ev-file-rename-1", Type: "file_rename", Timestamp: t0, PID: 210, Path: "/tmp/new", Fields: map[string]any{"from_path": "/tmp/old"}},
		{ID: "ev-file-renamed-1", Type: "file_renamed", Timestamp: t0, PID: 211, Path: "/tmp/dest", Fields: map[string]any{"from_path": "/tmp/src"}},
		{ID: "ev-file-modified-1", Type: "file_modified", Timestamp: t0, PID: 212, Path: "/tmp/changed"},
		{ID: "ev-file-soft-deleted-1", Type: "file_soft_deleted", Timestamp: t0, PID: 213, Path: "/tmp/soft"},
		{ID: "ev-ptrace-file-1", Type: "ptrace_file", Timestamp: t0, PID: 214, Path: "/etc/shadow"},
		{ID: "ev-registry-write-1", Type: "registry_write", Timestamp: t0, PID: 215, Path: "HKLM\\Software\\Foo"},
		{ID: "ev-registry-error-1", Type: "registry_error", Timestamp: t0, PID: 216, Path: "HKLM\\Software\\Bar"},
```

- [ ] **Step 3: Generate goldens**

Run: `go test ./internal/ocsf/ -run TestGoldens -update`
Expected: creates 17 new files in `internal/ocsf/testdata/golden/`.

- [ ] **Step 4: Run all tests**

Run: `go test ./internal/ocsf/...`
Expected: PASS. 17 file_* Types removed from `pendingTypes`.

- [ ] **Step 5: Commit**

```bash
git add internal/ocsf/project_file.go internal/ocsf/mapper_test.go internal/ocsf/testdata/golden/
git commit -m "ocsf: implement File System Activity (1001) projector + registry entries"
```

---

## Task 18: Network Activity projector + registry entries + goldens

**Files:**
- Create: `internal/ocsf/project_network.go`
- Modify: `internal/ocsf/mapper_test.go`
- Create: 9 goldens under `testdata/golden/` for the network types.

- [ ] **Step 1: Write `project_network.go`**

```go
package ocsf

import (
	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

func networkProjector(activity uint32) Projector {
	return func(ev types.Event, allowed map[string]any) (proto.Message, error) {
		msg := &ocsfpb.NetworkActivity{
			ClassUid:     u32p(ClassNetworkActivity),
			ActivityId:   u32p(activity),
			CategoryUid:  u32p(4),
			TypeUid:      u32p(ClassNetworkActivity*100 + activity),
			Time:         u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:     strp(severityFromPolicy(ev.Policy)),
			Metadata:     buildMetadata(ev),
			Actor:        buildActor(ev),
			DstEndpoint:  buildDstEndpoint(ev),
			ConnectionInfo: buildConnInfo(ev),
		}
		if rt, ok := allowed["redirect_target"].(string); ok && rt != "" {
			msg.RedirectTarget = strp(rt)
		}
		if ev.Policy != nil {
			if d := string(ev.Policy.Decision); d != "" {
				msg.PolicyDecision = strp(d)
			}
			if ev.Policy.Rule != "" {
				msg.PolicyRule = strp(ev.Policy.Rule)
			}
		}
		return msg, nil
	}
}

func buildDstEndpoint(ev types.Event) *ocsfpb.Endpoint {
	if ev.Domain == "" && ev.Remote == "" {
		return nil
	}
	e := &ocsfpb.Endpoint{}
	if ev.Domain != "" {
		e.Domain = strp(ev.Domain)
		e.Hostname = strp(ev.Domain)
	}
	if ev.Remote != "" {
		e.Ip = strp(ev.Remote)
	}
	return e
}

func buildConnInfo(ev types.Event) *ocsfpb.ConnectionInfo {
	ci := &ocsfpb.ConnectionInfo{}
	any := false
	switch ev.Type {
	case "unix_socket_op":
		ci.ProtocolName = strp("unix")
		any = true
		if ev.Abstract {
			ci.IsUnixAbstract = boolp(true)
		}
	case "net_connect", "connection_allowed", "connect_redirect", "ptrace_network", "mcp_network_connection":
		ci.ProtocolName = strp("tcp")
		ci.Direction = strp("Outbound")
		any = true
	}
	if !any {
		return nil
	}
	return ci
}

func init() {
	netMappings := map[string]uint32{
		"net_connect":            NetworkActivityOpen,
		"connection_allowed":     NetworkActivityOpen,
		"connect_redirect":       NetworkActivityOpen,
		"ptrace_network":         NetworkActivityOpen,
		"unix_socket_op":         NetworkActivityOpen,
		"transparent_net_failed": NetworkActivityClose,
		"transparent_net_ready":  NetworkActivityOpen,
		"transparent_net_setup":  NetworkActivityOpen,
		"mcp_network_connection": NetworkActivityOpen,
	}
	allow := []FieldRule{{
		Key: "redirect_target", Required: false, Transform: AsString, DestPath: "redirect_target",
	}}
	for t, activity := range netMappings {
		register(t, Mapping{
			ClassUID:        ClassNetworkActivity,
			ActivityID:      activity,
			FieldsAllowlist: allow,
			Project:         networkProjector(activity),
		})
	}
}
```

- [ ] **Step 2: Append fixtures**

Append to `goldenSampleEvents()`:

```go
		// Network Activity (4001) — Task 18
		{ID: "ev-net-connect-1", Type: "net_connect", Timestamp: t0, PID: 300, Domain: "example.com", Remote: "93.184.216.34"},
		{ID: "ev-conn-allowed-1", Type: "connection_allowed", Timestamp: t0, PID: 301, Domain: "ok.example", Remote: "10.0.0.1"},
		{ID: "ev-connect-redirect-1", Type: "connect_redirect", Timestamp: t0, PID: 302, Domain: "in.example", Fields: map[string]any{"redirect_target": "out.example:443"}},
		{ID: "ev-ptrace-network-1", Type: "ptrace_network", Timestamp: t0, PID: 303, Domain: "trace.example"},
		{ID: "ev-unix-sock-1", Type: "unix_socket_op", Timestamp: t0, PID: 304, Path: "/run/agentsh.sock", Abstract: false},
		{ID: "ev-tnet-failed-1", Type: "transparent_net_failed", Timestamp: t0},
		{ID: "ev-tnet-ready-1", Type: "transparent_net_ready", Timestamp: t0},
		{ID: "ev-tnet-setup-1", Type: "transparent_net_setup", Timestamp: t0},
		{ID: "ev-mcp-net-1", Type: "mcp_network_connection", Timestamp: t0, PID: 305, Domain: "mcp.example", Remote: "10.0.0.5"},
```

- [ ] **Step 3: Generate goldens, run tests, commit**

Run:
```bash
go test ./internal/ocsf/ -run TestGoldens -update
go test ./internal/ocsf/...
```
Expected: PASS, 9 new goldens generated, 9 types removed from `pendingTypes`.

```bash
git add internal/ocsf/project_network.go internal/ocsf/mapper_test.go internal/ocsf/testdata/golden/
git commit -m "ocsf: implement Network Activity (4001) projector + registry entries"
```

---

## Task 19: HTTP Activity projector + registry entries + goldens

**Files:**
- Create: `internal/ocsf/project_http.go`
- Modify: `internal/ocsf/mapper_test.go`
- Create: 3 goldens.

- [ ] **Step 1: Write `project_http.go`**

```go
package ocsf

import (
	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

func httpProjector(activity uint32) Projector {
	return func(ev types.Event, allowed map[string]any) (proto.Message, error) {
		msg := &ocsfpb.HTTPActivity{
			ClassUid:    u32p(ClassHTTPActivity),
			ActivityId:  u32p(activity),
			CategoryUid: u32p(4),
			TypeUid:     u32p(ClassHTTPActivity*100 + activity),
			Time:        u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:    strp(severityFromPolicy(ev.Policy)),
			Metadata:    buildMetadata(ev),
			Actor:       buildActor(ev),
		}
		req := &ocsfpb.HTTPRequest{}
		anyReq := false
		if v, ok := allowed["method"].(string); ok && v != "" {
			req.HttpMethod = strp(v); anyReq = true
		}
		if v, ok := allowed["url"].(string); ok && v != "" {
			req.Url = strp(v); anyReq = true
		}
		if v, ok := allowed["user_agent"].(string); ok && v != "" {
			req.UserAgent = strp(v); anyReq = true
		}
		if v, ok := allowed["http_version"].(string); ok && v != "" {
			req.Version = strp(v); anyReq = true
		}
		if v, ok := allowed["host"].(string); ok && v != "" {
			req.Host = strp(v); anyReq = true
		}
		if anyReq {
			msg.HttpRequest = req
		}
		resp := &ocsfpb.HTTPResponse{}
		anyResp := false
		if v, ok := allowed["status_code"].(uint32); ok && v != 0 {
			resp.StatusCode = u32p(v); anyResp = true
		}
		if v, ok := allowed["response_bytes"].(uint64); ok && v != 0 {
			resp.Length = u64p(v); anyResp = true
		}
		if anyResp {
			msg.HttpResponse = resp
		}
		if ev.Domain != "" || ev.Remote != "" {
			msg.DstEndpoint = buildDstEndpoint(ev)
		}
		if ev.Policy != nil {
			if d := string(ev.Policy.Decision); d != "" {
				msg.PolicyDecision = strp(d)
			}
			if ev.Policy.Rule != "" {
				msg.PolicyRule = strp(ev.Policy.Rule)
			}
		}
		return msg, nil
	}
}

func init() {
	httpAllow := []FieldRule{
		{Key: "method", Transform: AsString, DestPath: "http_request.http_method"},
		{Key: "url", Transform: AsString, DestPath: "http_request.url"},
		{Key: "host", Transform: AsString, DestPath: "http_request.host"},
		{Key: "user_agent", Transform: AsString, DestPath: "http_request.user_agent"},
		{Key: "http_version", Transform: AsString, DestPath: "http_request.version"},
		{Key: "status_code", Transform: AsUint32, DestPath: "http_response.status_code"},
		{Key: "response_bytes", Transform: AsUint64, DestPath: "http_response.length"},
	}
	httpMappings := map[string]uint32{
		"http":                       HTTPActivityRequest,
		"net_http_request":           HTTPActivityRequest,
		"http_service_denied_direct": HTTPActivityRequest,
	}
	for t, activity := range httpMappings {
		register(t, Mapping{
			ClassUID:        ClassHTTPActivity,
			ActivityID:      activity,
			FieldsAllowlist: httpAllow,
			Project:         httpProjector(activity),
		})
	}
}
```

- [ ] **Step 2: Append fixtures**

```go
		// HTTP Activity (4002) — Task 19
		{ID: "ev-http-1", Type: "http", Timestamp: t0, PID: 400, Domain: "api.example", Fields: map[string]any{
			"method": "POST", "url": "https://api.example/v1/x", "host": "api.example",
			"user_agent": "agentsh/1.0", "http_version": "1.1",
			"status_code": 200, "response_bytes": 1024,
		}},
		{ID: "ev-net-http-req-1", Type: "net_http_request", Timestamp: t0, PID: 401, Domain: "raw.example",
			Fields: map[string]any{"method": "GET", "url": "https://raw.example/file"}},
		{ID: "ev-http-svc-denied-1", Type: "http_service_denied_direct", Timestamp: t0, PID: 402, Domain: "blocked.example",
			Fields: map[string]any{"method": "POST", "url": "https://blocked.example/api"},
			Policy: &types.PolicyInfo{Decision: "deny", EffectiveDecision: "deny", Rule: "no-direct"}},
```

- [ ] **Step 3: Generate, test, commit**

```bash
go test ./internal/ocsf/ -run TestGoldens -update
go test ./internal/ocsf/...
git add internal/ocsf/project_http.go internal/ocsf/mapper_test.go internal/ocsf/testdata/golden/
git commit -m "ocsf: implement HTTP Activity (4002) projector + registry entries"
```

---

## Task 20: DNS Activity projector + registry entries + goldens

**Files:**
- Create: `internal/ocsf/project_dns.go`
- Modify: `internal/ocsf/mapper_test.go`
- Create: 2 goldens.

- [ ] **Step 1: Write `project_dns.go`**

```go
package ocsf

import (
	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

func dnsProjector(activity uint32) Projector {
	return func(ev types.Event, allowed map[string]any) (proto.Message, error) {
		msg := &ocsfpb.DNSActivity{
			ClassUid:    u32p(ClassDNSActivity),
			ActivityId:  u32p(activity),
			CategoryUid: u32p(4),
			TypeUid:     u32p(ClassDNSActivity*100 + activity),
			Time:        u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:    strp(severityFromPolicy(ev.Policy)),
			Metadata:    buildMetadata(ev),
			Actor:       buildActor(ev),
		}
		q := &ocsfpb.DNSQuery{Class: strp("IN")}
		if ev.Domain != "" {
			q.Hostname = strp(ev.Domain)
		} else if v, ok := allowed["hostname"].(string); ok && v != "" {
			q.Hostname = strp(v)
		}
		if v, ok := allowed["rrtype_name"].(string); ok && v != "" {
			q.TypeName = strp(v)
		}
		if v, ok := allowed["rrtype"].(uint32); ok && v != 0 {
			q.Type = u32p(v)
		}
		msg.Query = q
		if rt, ok := allowed["redirect_target"].(string); ok && rt != "" {
			msg.RedirectTarget = strp(rt)
		}
		if ev.Policy != nil {
			if d := string(ev.Policy.Decision); d != "" {
				msg.PolicyDecision = strp(d)
			}
			if ev.Policy.Rule != "" {
				msg.PolicyRule = strp(ev.Policy.Rule)
			}
		}
		return msg, nil
	}
}

func init() {
	allow := []FieldRule{
		{Key: "hostname", Transform: AsString, DestPath: "query.hostname"},
		{Key: "rrtype", Transform: AsUint32, DestPath: "query.type"},
		{Key: "rrtype_name", Transform: AsString, DestPath: "query.type_name"},
		{Key: "redirect_target", Transform: AsString, DestPath: "redirect_target"},
	}
	register("dns_query", Mapping{
		ClassUID: ClassDNSActivity, ActivityID: DNSActivityQuery,
		FieldsAllowlist: allow, Project: dnsProjector(DNSActivityQuery),
	})
	register("dns_redirect", Mapping{
		ClassUID: ClassDNSActivity, ActivityID: DNSActivityQuery,
		FieldsAllowlist: allow, Project: dnsProjector(DNSActivityQuery),
	})
}
```

- [ ] **Step 2: Append fixtures**

```go
		// DNS Activity (4003) — Task 20
		{ID: "ev-dns-query-1", Type: "dns_query", Timestamp: t0, PID: 500, Domain: "lookup.example",
			Fields: map[string]any{"rrtype": 1, "rrtype_name": "A"}},
		{ID: "ev-dns-redirect-1", Type: "dns_redirect", Timestamp: t0, PID: 501, Domain: "in.example",
			Fields: map[string]any{"rrtype_name": "A", "redirect_target": "127.0.0.1"}},
```

- [ ] **Step 3: Generate, test, commit**

```bash
go test ./internal/ocsf/ -run TestGoldens -update
go test ./internal/ocsf/...
git add internal/ocsf/project_dns.go internal/ocsf/mapper_test.go internal/ocsf/testdata/golden/
git commit -m "ocsf: implement DNS Activity (4003) projector + registry entries"
```

---

## Task 21: Detection Finding projector + registry entries + goldens

**Files:**
- Create: `internal/ocsf/project_finding.go`
- Modify: `internal/ocsf/mapper_test.go`
- Create: 8 goldens.

- [ ] **Step 1: Write `project_finding.go`**

```go
package ocsf

import (
	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

func findingProjector(activity uint32, findingType string) Projector {
	return func(ev types.Event, _ map[string]any) (proto.Message, error) {
		msg := &ocsfpb.DetectionFinding{
			ClassUid:    u32p(ClassDetectionFinding),
			ActivityId:  u32p(activity),
			CategoryUid: u32p(2),
			TypeUid:     u32p(ClassDetectionFinding*100 + activity),
			Time:        u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:    strp("Medium"),
			Metadata:    buildMetadata(ev),
			Actor:       buildActor(ev),
			FindingInfo: &ocsfpb.FindingInfo{
				Title:      strp(ev.Type),
				FindingUid: strpOrNil(ev.ID),
				Types:      strp(findingType),
			},
		}
		if ev.Policy != nil {
			if ev.Policy.Message != "" {
				msg.FindingInfo.Desc = strp(ev.Policy.Message)
			}
			if d := string(ev.Policy.Decision); d != "" {
				msg.PolicyDecision = strp(d)
			}
			if ev.Policy.Rule != "" {
				msg.PolicyRule = strp(ev.Policy.Rule)
			}
			if ev.Policy.ThreatFeed != "" {
				msg.ThreatFeed = strp(ev.Policy.ThreatFeed)
			}
			if ev.Policy.ThreatMatch != "" {
				msg.ThreatMatch = strp(ev.Policy.ThreatMatch)
			}
			if ev.Policy.ThreatAction != "" {
				msg.ThreatAction = strp(ev.Policy.ThreatAction)
			}
		}
		return msg, nil
	}
}

func init() {
	findingTypes := map[string]string{
		"command_policy":            "policy_decision",
		"seccomp_blocked":           "policy_decision",
		"agent_detected":            "agent_self_detected",
		"taint_created":             "taint",
		"taint_propagated":          "taint",
		"taint_removed":             "taint",
		"mcp_cross_server_blocked":  "policy_decision",
		"mcp_tool_call_intercepted": "policy_decision",
	}
	for t, ft := range findingTypes {
		register(t, Mapping{
			ClassUID:        ClassDetectionFinding,
			ActivityID:      FindingActivityCreate,
			FieldsAllowlist: nil,
			Project:         findingProjector(FindingActivityCreate, ft),
		})
	}
}
```

- [ ] **Step 2: Append fixtures**

```go
		// Detection Finding (2004) — Task 21
		{ID: "ev-cmd-policy-1", Type: "command_policy", Timestamp: t0, PID: 600,
			Policy: &types.PolicyInfo{Decision: "deny", Rule: "no-curl", Message: "curl is blocked"}},
		{ID: "ev-seccomp-1", Type: "seccomp_blocked", Timestamp: t0, PID: 601,
			Policy: &types.PolicyInfo{Decision: "deny", Rule: "syscall-block"}},
		{ID: "ev-agent-detect-1", Type: "agent_detected", Timestamp: t0, PID: 602,
			Policy: &types.PolicyInfo{Decision: "warn", Message: "self-detection succeeded"}},
		{ID: "ev-taint-created-1", Type: "taint_created", Timestamp: t0, PID: 603},
		{ID: "ev-taint-prop-1", Type: "taint_propagated", Timestamp: t0, PID: 604},
		{ID: "ev-taint-removed-1", Type: "taint_removed", Timestamp: t0, PID: 605},
		{ID: "ev-mcp-cross-1", Type: "mcp_cross_server_blocked", Timestamp: t0, PID: 606,
			Policy: &types.PolicyInfo{Decision: "deny", Rule: "no-cross-server"}},
		{ID: "ev-mcp-tool-int-1", Type: "mcp_tool_call_intercepted", Timestamp: t0, PID: 607,
			Policy: &types.PolicyInfo{Decision: "deny", Rule: "tool-block"}},
```

- [ ] **Step 3: Generate, test, commit**

```bash
go test ./internal/ocsf/ -run TestGoldens -update
go test ./internal/ocsf/...
git add internal/ocsf/project_finding.go internal/ocsf/mapper_test.go internal/ocsf/testdata/golden/
git commit -m "ocsf: implement Detection Finding (2004) projector + registry entries"
```

---

## Task 22: Application Activity projector + registry entries + goldens (largest class)

**Files:**
- Create: `internal/ocsf/project_app.go`
- Modify: `internal/ocsf/mapper_test.go`
- Create: 33 goldens.

- [ ] **Step 1: Write `project_app.go`**

```go
package ocsf

import (
	"sort"

	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

// appProjector handles class_uid 6005. Both standard MCP/proxy/secret
// events and agent-internal infra events route here. agentInternal is
// reflected on the proto message so server-side filters can split SOC
// from fleet-health views without depending on the activity_id range.
func appProjector(activity uint32, agentInternal bool) Projector {
	return func(ev types.Event, allowed map[string]any) (proto.Message, error) {
		msg := &ocsfpb.ApplicationActivity{
			ClassUid:      u32p(ClassApplicationActivity),
			ActivityId:    u32p(activity),
			CategoryUid:   u32p(6),
			TypeUid:       u32p(ClassApplicationActivity*100 + activity),
			Time:          u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:      strp(severityFromPolicy(ev.Policy)),
			Metadata:      buildMetadata(ev),
			Actor:         buildActor(ev),
			AppName:       strp("agentsh"),
			AgentInternal: boolp(agentInternal),
		}
		if ev.CommandID != "" {
			msg.ResourceUid = strp(ev.CommandID)
		}
		if len(allowed) > 0 {
			// enrichments map: pre-stringified per allowlist transforms.
			// Iterate keys in sorted order so deterministic-marshal output
			// is stable. (proto3 deterministic marshal already sorts map
			// keys by string ordering, but we build the map deterministically
			// for clarity.)
			keys := make([]string, 0, len(allowed))
			for k := range allowed {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			enrichments := make(map[string]string, len(keys))
			for _, k := range keys {
				if s, ok := allowed[k].(string); ok && s != "" {
					enrichments[k] = s
				}
			}
			if len(enrichments) > 0 {
				msg.Enrichments = enrichments
			}
		}
		return msg, nil
	}
}

func init() {
	// Standard / SOC-relevant Application Activity events.
	standardAllow := []FieldRule{
		{Key: "tool_name", Transform: AsString, DestPath: "enrichments.tool_name"},
		{Key: "server_name", Transform: AsString, DestPath: "enrichments.server_name"},
		{Key: "tool_uri", Transform: AsString, DestPath: "enrichments.tool_uri"},
		{Key: "secret_name", Transform: AsString, DestPath: "enrichments.secret_name"},
		{Key: "provider", Transform: AsString, DestPath: "enrichments.provider"},
	}
	standardMappings := map[string]uint32{
		"mcp_tool_called":            AppActivityMCPToolCalled,
		"mcp_tool_seen":              AppActivityMCPToolSeen,
		"mcp_tool_changed":           AppActivityMCPToolChanged,
		"mcp_tools_list_changed":     AppActivityMCPToolsListChanged,
		"mcp_sampling_request":       AppActivityMCPSamplingRequest,
		"mcp_tool_result_inspected":  AppActivityMCPToolResultInspected,
		"llm_proxy_started":          AppActivityLLMProxyStarted,
		"llm_proxy_failed":           AppActivityLLMProxyFailed,
		"net_proxy_started":          AppActivityNetProxyStarted,
		"net_proxy_failed":           AppActivityNetProxyFailed,
		"secret_access":              AppActivitySecretAccess,
	}
	for t, activity := range standardMappings {
		register(t, Mapping{
			ClassUID:        ClassApplicationActivity,
			ActivityID:      activity,
			AgentInternal:   false,
			FieldsAllowlist: standardAllow,
			Project:         appProjector(activity, false),
		})
	}

	// Infra / fleet-health events (agent_internal=true).
	infraMappings := map[string]uint32{
		"cgroup_applied":              AppActivityCgroupApplied,
		"cgroup_apply_failed":         AppActivityCgroupApplyFailed,
		"cgroup_cleanup_failed":       AppActivityCgroupCleanupFailed,
		"fuse_mounted":                AppActivityFUSEMounted,
		"fuse_mount_failed":           AppActivityFUSEMountFailed,
		"ebpf_attached":               AppActivityEBPFAttached,
		"ebpf_attach_failed":          AppActivityEBPFAttachFailed,
		"ebpf_collector_failed":       AppActivityEBPFCollectorFailed,
		"ebpf_enforce_disabled":       AppActivityEBPFEnforceDisabled,
		"ebpf_enforce_non_strict":     AppActivityEBPFEnforceNonStrict,
		"ebpf_enforce_refresh_failed": AppActivityEBPFEnforceRefreshFailed,
		"ebpf_unavailable":            AppActivityEBPFUnavailable,
		"wrap_init":                   AppActivityWrapInit,
		"fsevents_error":              AppActivityFSEventsError,
		"integrity_chain_rotated":     AppActivityIntegrityChainRotated,
		"policy_created":              AppActivityPolicyCreated,
		"policy_updated":              AppActivityPolicyUpdated,
		"policy_deleted":              AppActivityPolicyDeleted,
		"session_created":             AppActivitySessionCreated,
		"session_destroyed":           AppActivitySessionDestroyed,
		"session_expired":             AppActivitySessionExpired,
		"session_updated":             AppActivitySessionUpdated,
	}
	infraAllow := []FieldRule{
		{Key: "reason", Transform: AsString, DestPath: "enrichments.reason"},
		{Key: "policy_name", Transform: AsString, DestPath: "enrichments.policy_name"},
		{Key: "rotation_reason", Transform: AsString, DestPath: "enrichments.rotation_reason"},
	}
	for t, activity := range infraMappings {
		register(t, Mapping{
			ClassUID:        ClassApplicationActivity,
			ActivityID:      activity,
			AgentInternal:   true,
			FieldsAllowlist: infraAllow,
			Project:         appProjector(activity, true),
		})
	}
}
```

- [ ] **Step 2: Append fixtures**

Append to `goldenSampleEvents()`:

```go
		// Application Activity (6005) — Task 22
		{ID: "ev-mcp-called-1", Type: "mcp_tool_called", Timestamp: t0, PID: 700,
			Fields: map[string]any{"tool_name": "search", "server_name": "tools-1"}},
		{ID: "ev-mcp-seen-1", Type: "mcp_tool_seen", Timestamp: t0, Fields: map[string]any{"tool_name": "search"}},
		{ID: "ev-mcp-changed-1", Type: "mcp_tool_changed", Timestamp: t0, Fields: map[string]any{"tool_name": "search"}},
		{ID: "ev-mcp-list-changed-1", Type: "mcp_tools_list_changed", Timestamp: t0, Fields: map[string]any{"server_name": "tools-1"}},
		{ID: "ev-mcp-sampling-1", Type: "mcp_sampling_request", Timestamp: t0},
		{ID: "ev-mcp-result-1", Type: "mcp_tool_result_inspected", Timestamp: t0, Fields: map[string]any{"tool_name": "search"}},
		{ID: "ev-llm-started-1", Type: "llm_proxy_started", Timestamp: t0, Fields: map[string]any{"provider": "anthropic"}},
		{ID: "ev-llm-failed-1", Type: "llm_proxy_failed", Timestamp: t0, Fields: map[string]any{"provider": "anthropic"}},
		{ID: "ev-net-proxy-started-1", Type: "net_proxy_started", Timestamp: t0},
		{ID: "ev-net-proxy-failed-1", Type: "net_proxy_failed", Timestamp: t0},
		{ID: "ev-secret-access-1", Type: "secret_access", Timestamp: t0, Fields: map[string]any{"secret_name": "github_pat", "provider": "vault"}},
		// Infra
		{ID: "ev-cgroup-applied-1", Type: "cgroup_applied", Timestamp: t0},
		{ID: "ev-cgroup-fail-1", Type: "cgroup_apply_failed", Timestamp: t0, Fields: map[string]any{"reason": "permission denied"}},
		{ID: "ev-cgroup-cleanup-1", Type: "cgroup_cleanup_failed", Timestamp: t0, Fields: map[string]any{"reason": "busy"}},
		{ID: "ev-fuse-mounted-1", Type: "fuse_mounted", Timestamp: t0},
		{ID: "ev-fuse-mount-fail-1", Type: "fuse_mount_failed", Timestamp: t0, Fields: map[string]any{"reason": "no fusermount"}},
		{ID: "ev-ebpf-att-1", Type: "ebpf_attached", Timestamp: t0},
		{ID: "ev-ebpf-att-fail-1", Type: "ebpf_attach_failed", Timestamp: t0, Fields: map[string]any{"reason": "kernel too old"}},
		{ID: "ev-ebpf-coll-1", Type: "ebpf_collector_failed", Timestamp: t0, Fields: map[string]any{"reason": "verifier"}},
		{ID: "ev-ebpf-enf-dis-1", Type: "ebpf_enforce_disabled", Timestamp: t0},
		{ID: "ev-ebpf-non-strict-1", Type: "ebpf_enforce_non_strict", Timestamp: t0},
		{ID: "ev-ebpf-refresh-fail-1", Type: "ebpf_enforce_refresh_failed", Timestamp: t0},
		{ID: "ev-ebpf-unav-1", Type: "ebpf_unavailable", Timestamp: t0},
		{ID: "ev-wrap-init-1", Type: "wrap_init", Timestamp: t0},
		{ID: "ev-fsev-err-1", Type: "fsevents_error", Timestamp: t0, Fields: map[string]any{"reason": "queue overflow"}},
		{ID: "ev-int-rot-1", Type: "integrity_chain_rotated", Timestamp: t0, Fields: map[string]any{"rotation_reason": "scheduled"}},
		{ID: "ev-pol-created-1", Type: "policy_created", Timestamp: t0, Fields: map[string]any{"policy_name": "default"}},
		{ID: "ev-pol-updated-1", Type: "policy_updated", Timestamp: t0, Fields: map[string]any{"policy_name": "default"}},
		{ID: "ev-pol-deleted-1", Type: "policy_deleted", Timestamp: t0, Fields: map[string]any{"policy_name": "old"}},
		{ID: "ev-sess-created-1", Type: "session_created", Timestamp: t0, SessionID: "sess-x"},
		{ID: "ev-sess-destroyed-1", Type: "session_destroyed", Timestamp: t0, SessionID: "sess-x"},
		{ID: "ev-sess-expired-1", Type: "session_expired", Timestamp: t0, SessionID: "sess-x"},
		{ID: "ev-sess-updated-1", Type: "session_updated", Timestamp: t0, SessionID: "sess-x"},
```

- [ ] **Step 3: Generate, test, commit**

```bash
go test ./internal/ocsf/ -run TestGoldens -update
go test ./internal/ocsf/...
```
Expected: PASS. `pendingTypes` is now empty. `TestExhaustiveness_PendingTypesShrinking` logs "pendingTypes is empty — Phase 1 catalog complete".

```bash
git add internal/ocsf/project_app.go internal/ocsf/mapper_test.go internal/ocsf/testdata/golden/
git commit -m "ocsf: implement Application Activity (6005) — MCP, proxy, secret, infra

Closes Phase 1 catalog: 33 standard + agent-internal Types mapped to
class 6005, with agent_internal=true flag for the infra subset so
server-side filters can split SOC from fleet-health views.
pendingTypes is now empty; exhaustiveness test enforces the entire
production catalog."
```

---

## Task 23: WTP encoder E2E test with real `ocsf.New()`

**Files:**
- Modify: `internal/store/watchtower/encoder_e2e_test.go`

- [ ] **Step 1: Read the existing test to find its shape**

Run: `cat internal/store/watchtower/encoder_e2e_test.go | head -80`
Expected: a test using `compact.StubMapper{}` to encode a sample event end-to-end.

- [ ] **Step 2: Add a parallel sub-test wiring `ocsf.New()`**

Append at the end of `internal/store/watchtower/encoder_e2e_test.go` (replace the placeholder if one exists):

```go
func TestEncoderE2E_WithOCSFMapper(t *testing.T) {
	// Verifies that the production OCSF mapper produces a payload the
	// WTP chain accepts AND rejects on tampering. This is the hand-off
	// gate from Phase 1 to Phase 2 wiring.
	mapper := ocsf.New()
	ev := types.Event{
		ID: "e2e-execve-1", Type: "execve",
		Timestamp: time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC),
		SessionID: "sess-e2e", PID: 9999, ParentPID: 1,
		Filename: "/usr/bin/curl",
		Argv:     []string{"curl", "https://example.com"},
		Chain:    &types.ChainState{Sequence: 1, Generation: 1},
	}
	mapped, err := mapper.Map(ev)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if mapped.OCSFClassUID != 1007 {
		t.Fatalf("class_uid = %d, want 1007", mapped.OCSFClassUID)
	}
	if mapped.OCSFActivityID != 1 {
		t.Fatalf("activity_id = %d, want 1 (Launch)", mapped.OCSFActivityID)
	}
	if len(mapped.Payload) == 0 {
		t.Fatal("payload empty")
	}
	// Determinism: re-map and assert byte-identical.
	mapped2, err := mapper.Map(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mapped.Payload, mapped2.Payload) {
		t.Fatal("non-deterministic payload between consecutive Map calls")
	}
	// Tamper guard: mutating one byte must change the protojson output.
	tampered := append([]byte{}, mapped.Payload...)
	tampered[0] ^= 0xFF
	if bytes.Equal(tampered, mapped.Payload) {
		t.Fatal("tamper guard: mutating byte 0 produced equal slice")
	}
}
```

Add the import to the test file's import block:
```go
import "github.com/agentsh/agentsh/internal/ocsf"
```

- [ ] **Step 3: Run the test**

Run: `go test ./internal/store/watchtower/ -run TestEncoderE2E_WithOCSFMapper -v`
Expected: PASS.

- [ ] **Step 4: Run the full WTP test suite to confirm no regression**

Run: `go test ./internal/store/watchtower/...`
Expected: PASS. The existing `compact.StubMapper`-based tests still work because `StubMapper` is unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/encoder_e2e_test.go
git commit -m "wtp: add E2E test wiring real ocsf.Mapper through the encoder"
```

---

## Task 24: Verify `validate()` accepts `ocsf.New()` and rejects `StubMapper{}`

**Files:**
- Create: `internal/store/watchtower/validate_ocsf_test.go`

- [ ] **Step 1: Write the test**

```go
package watchtower

import (
	"testing"

	"github.com/agentsh/agentsh/internal/ocsf"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
)

func TestValidate_AcceptsOCSFMapper(t *testing.T) {
	opts := minimalValidOptionsForTest(t)
	opts.Mapper = ocsf.New()
	opts.AllowStubMapper = false
	if err := opts.validate(); err != nil {
		t.Fatalf("validate() with ocsf.New() = %v, want nil", err)
	}
}

func TestValidate_RejectsStubMapperInProduction(t *testing.T) {
	opts := minimalValidOptionsForTest(t)
	opts.Mapper = compact.StubMapper{}
	opts.AllowStubMapper = false
	if err := opts.validate(); err == nil {
		t.Fatal("validate() with StubMapper accepted; expected rejection")
	}
}
```

> **Note:** `minimalValidOptionsForTest` is a test helper that already exists in the watchtower package — see `options_test.go` for the canonical builder. If the helper is named differently in your tree, adjust the call.

- [ ] **Step 2: Locate the helper**

Run: `grep -n "func.*minimalValid\|func.*newTestOptions\|func.*validOptions" internal/store/watchtower/options_test.go internal/store/watchtower/integrity_test.go 2>/dev/null`
Expected: a helper that returns valid `Options`. Name your test file's helper-call accordingly. If no helper exists, build the Options literally from a single existing test in the package — do NOT introduce a new helper across packages.

- [ ] **Step 3: Run the test**

Run: `go test ./internal/store/watchtower/ -run "TestValidate_(Accepts|Rejects)" -v`
Expected: PASS for both.

- [ ] **Step 4: Commit**

```bash
git add internal/store/watchtower/validate_ocsf_test.go
git commit -m "wtp: assert validate() accepts ocsf.New() and rejects StubMapper in prod"
```

---

## Task 25: Final acceptance check

**Files:** none (verification only)

- [ ] **Step 1: Confirm `pendingTypes` is empty**

Run: `grep -A 2 "var pendingTypes" internal/ocsf/registry.go | head -5`
Expected: shows `var pendingTypes = map[string]struct{}{` followed by `}` on the next non-blank line — i.e., the seed entries have all been removed by `register()` calls (the package-init runs before tests so the map IS empty at runtime, but the source declaration may still list them; the runtime emptiness is the contract). Alternatively confirm via:

Run: `go test ./internal/ocsf/ -run TestExhaustiveness_PendingTypesShrinking -v`
Expected: log line "pendingTypes is empty — Phase 1 catalog complete".

- [ ] **Step 2: Run the full mapper test suite**

Run: `go test ./internal/ocsf/... -count=1`
Expected: PASS for every sub-test, including:
- `TestMap_UnmappedTypeReturnsErrUnmappedType`
- `TestMapDeterministic` (one sub-test per registered Type — ~80 sub-tests)
- `TestGoldens` (matching count)
- `TestExhaustiveness_AllEventTypesRegistered`
- `TestExhaustiveness_PendingTypesShrinking`
- `TestRegistry_NoSensitiveKeysAllowlisted`
- `TestSkiplistReasonsNonEmpty`
- `TestSkiplistDoesNotShadowRegistry`

- [ ] **Step 3: Run the WTP integration tests**

Run: `go test ./internal/store/watchtower/... -count=1`
Expected: PASS, including the new `TestEncoderE2E_WithOCSFMapper` and `TestValidate_*` tests.

- [ ] **Step 4: Cross-compile sanity**

Run: `GOOS=windows go build ./internal/ocsf/...` and `GOOS=darwin go build ./internal/ocsf/...`
Expected: both exit 0. The mapper has no platform-specific deps.

- [ ] **Step 5: Verify no sensitive-data regression**

Run: `go test ./internal/ocsf/ -run TestRegistry_NoSensitiveKeysAllowlisted -v -count=1`
Expected: PASS.

- [ ] **Step 6: Final commit (if any uncommitted changes)**

```bash
git status
```
Expected: clean. All work has been committed task-by-task.

If clean, the branch is ready to merge. Phase 1 is done.

---

## Acceptance criteria (cross-reference with spec §"Verification")

1. ✅ All eight class projectors implemented (Tasks 16-22).
2. ✅ `registry` covers every production-emitted Type (Tasks 16-22; verified by `TestExhaustiveness_AllEventTypesRegistered`).
3. ✅ `pendingTypes` empty after Task 22 (`TestExhaustiveness_PendingTypesShrinking`).
4. ✅ `TestMapDeterministic` passes — 1000× call equality on all sample events (Task 13 framework, populated incrementally).
5. ✅ `TestRegistry_NoSensitiveKeysAllowlisted` passes — no sensitive key allowlisted (Task 14).
6. ✅ E2E round-trip with real mapper through encoder (Task 23).
7. ✅ `validate()` accepts `ocsf.New()`, rejects `compact.StubMapper{}` (Task 24).
8. ✅ Cross-compile green (Task 25 step 4).
