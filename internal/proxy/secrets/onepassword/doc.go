// Package onepassword implements secrets.SecretProvider using the
// 1Password Connect API. It wraps github.com/1Password/connect-sdk-go.
//
// 1Password URIs take the form
//
//	op://<vault>/<item>[#<field>]
//
// where <vault> is the vault name (URI host), <item> is the item
// title (URI path), and the optional <field> selects one field by
// label within the item.
//
// Auth requires a Connect API key, provided either as a literal
// config value (api_key) or chained from another provider via the
// RefResolver passed to New (api_key_ref).
package onepassword
