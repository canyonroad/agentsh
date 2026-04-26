// Package ocsf maps agentsh events to OCSF v1.8.0 class payloads consumed
// by the WTP CompactEvent wire shape. See
// docs/superpowers/specs/2026-04-25-wtp-phase-1-ocsf-mapper-design.md.
package ocsf

// SchemaVersion is the OCSF schema version this mapper targets. It is
// also the value emitted in CompactEvent's Metadata.version field and
// must match the ocsf_version string the WTP client sends in
// SessionInit.
const SchemaVersion = "1.8.0"
