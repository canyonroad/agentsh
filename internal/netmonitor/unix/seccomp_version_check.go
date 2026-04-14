//go:build linux && cgo

package unix

// Compile-time assertion that libseccomp >= 2.6.0 headers are in use.
//
// Why this matters: libseccomp-golang v0.11.0 contains a preprocessor
// fallback that remaps SCMP_FLTATR_CTL_WAITKILL to _SCMP_FLTATR_MIN (a
// no-op sentinel) when built against pre-2.6 headers. In that state the
// Go-level SetWaitKill(true) call silently succeeds but sets no real
// kernel flag — Layer 1 of the SIGURG preemption fix dies silently.
//
// This #error ensures any build against pre-2.6 headers fails loudly
// with an actionable message pointing at scripts/build-libseccomp.sh.

// #cgo pkg-config: libseccomp
// #include <seccomp.h>
// #if SCMP_VER_MAJOR < 2 || (SCMP_VER_MAJOR == 2 && SCMP_VER_MINOR < 6)
// #error "libseccomp >= 2.6.0 required for SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (Layer 1 SIGURG fix). Run scripts/build-libseccomp.sh and set PKG_CONFIG_PATH=/opt/libseccomp/<arch>/lib/pkgconfig."
// #endif
import "C"
