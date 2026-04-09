// Package credsub implements the per-session credential substitution
// table that maps fake credentials (the bytes an agent sees in its
// environment) to real credentials (the bytes sent upstream).
//
// A Table is created at session start, populated with one entry per
// configured service, and zeroed at session close. It exposes byte-level
// substitution in both directions:
//
//   - ReplaceFakeToReal is used on outbound request bodies, headers,
//     query strings, and URL paths before they leave agentsh.
//   - ReplaceRealToFake is used on inbound response bodies before they
//     reach the agent (when the matched service has scrub_response: true).
//
// Table enforces length preservation (len(fake) == len(real)) and
// basic collision invariants at Add time; it does NOT enforce that
// one fake cannot be a substring of another. Callers are responsible
// for generating fakes with sufficient entropy (the design spec
// mandates ≥24 random base62 characters) so accidental substring
// collisions are astronomically unlikely.
//
// Plan 2 of the external-secrets roadmap lands this package in
// isolation. Providers, session wiring, and the egress flow are
// implemented in later plans.
package credsub
