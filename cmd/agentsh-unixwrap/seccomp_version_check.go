//go:build linux && cgo

package main

// Duplicate of internal/netmonitor/unix/seccomp_version_check.go.
// Kept here independently so the wrapper binary fails to build even if
// the import graph changes and this package stops pulling in the unix
// package's CGo compilation unit.

// #cgo pkg-config: libseccomp
// #include <seccomp.h>
// #if SCMP_VER_MAJOR < 2 || (SCMP_VER_MAJOR == 2 && SCMP_VER_MINOR < 6)
// #error "libseccomp >= 2.6.0 required for SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (Layer 1 SIGURG fix). Run scripts/build-libseccomp.sh and set PKG_CONFIG_PATH=/opt/libseccomp/<arch>/lib/pkgconfig."
// #endif
import "C"
