// Package vault implements secrets.SecretProvider using HashiCorp
// Vault's KV v2 secrets engine. It wraps github.com/hashicorp/vault/api.
//
// Vault URIs take the form
//
//	vault://<mount>/<path>[#<field>]
//
// where <mount> is the KV v2 mount name, <path> is the secret path
// within the mount, and the optional <field> selects one key from
// the KV data map.
//
// The vault/api KV v2 helper adds the "data/" prefix internally.
// If a URI path starts with "data/", the provider strips it for
// compatibility with the parent spec format (e.g.
// vault://kv/data/github → vault://kv/github).
//
// OpenBao is a wire-compatible Vault fork. This provider works
// with OpenBao by pointing Address at the OpenBao server. No code
// changes are needed.
//
// Supported auth methods: token, approle, kubernetes.
//
// Auth chaining is supported: bootstrap credentials (e.g. the
// Vault token) can be fetched from another provider via the
// RefResolver passed to New.
package vault
