// Package keyring implements secrets.SecretProvider using the OS
// keyring: macOS Keychain, Linux Secret Service (via libsecret and
// D-Bus), or Windows Credential Manager. It wraps
// github.com/zalando/go-keyring.
//
// Keyring URIs take the form
//
//	keyring://<service>/<user>
//
// where <service> is the OS keyring service name and <user> is the
// OS keyring account name. Keyring entries are scalar, so a
// SecretRef with a non-empty Field is rejected with
// secrets.ErrFieldNotSupported.
//
// The provider performs an availability probe at construction. If
// the OS keyring backend is unreachable (headless Linux without a
// running Secret Service, Windows Credential Manager subsystem
// down, macOS Keychain inaccessible), New returns
// secrets.ErrKeyringUnavailable. Operators must either set up the
// keyring or use a different provider — there is no "optional
// keyring" mode.
package keyring
