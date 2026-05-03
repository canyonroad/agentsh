//go:build linux && cgo

package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
)

// landlockSupported returns true when the host kernel supports Landlock ABI v1+.
func landlockSupported(t *testing.T) bool {
	t.Helper()
	result := capabilities.DetectLandlock()
	return result.Available
}

// seccompUserNotifySupported returns true when the kernel supports
// SECCOMP_RET_USER_NOTIF (required by agentsh-unixwrap).
func seccompUserNotifySupported(t *testing.T) bool {
	t.Helper()
	r := capabilities.CheckAll(&config.Config{
		Sandbox: config.SandboxConfig{
			UnixSockets: config.SandboxUnixSocketsConfig{
				Enabled: func(b bool) *bool { return &b }(true),
			},
		},
	})
	return r == nil
}

// cgoAvailable returns true when cgo is available in the current build
// environment (needed to compile agentsh-unixwrap).
func cgoAvailable() bool {
	// The simplest check: try to find a C compiler. go build with CGO_ENABLED=1
	// fails fast if cc isn't available, so we can also just attempt the build
	// and t.Skip on error. This is just an early-out.
	if os.Getenv("CGO_ENABLED") == "0" {
		return false
	}
	_, err := exec.LookPath("cc")
	return err == nil
}

// repoRoot returns the repository root by walking up from the test package dir.
func repoRoot(t *testing.T) string {
	t.Helper()
	// When running go test, the working directory is set to the package directory.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repository root from %s", wd)
		}
		dir = parent
	}
}

// shimInstallTestServerSpec holds everything the sibling-process integration
// test needs from the server setup step.
type shimInstallTestServerSpec struct {
	srv           *httptest.Server
	sessionID     string
	mgr           *session.Manager
	wrapInitCalls *atomic.Int32 // counts successful POST /…/wrap-init requests
}

// startTestServerWithLandlockDeny starts an in-process agentsh HTTP server
// with Landlock enabled and a deny rule for denyPath (or its parent directory).
// It also pre-creates a session with the returned sessionID so the shim's
// wrap-init call finds an existing session.
func startTestServerWithLandlockDeny(t *testing.T, denyPath string) *shimInstallTestServerSpec {
	return startTestServerWithLandlockDenyOpts(t, denyPath, nil)
}

// startTestServerWithLandlockDenyOpts is like startTestServerWithLandlockDeny
// but accepts extra AllowExecute directories (e.g., the shim's tempdir for
// the nested-install test so the inner shim binary can be exec'd).
func startTestServerWithLandlockDenyOpts(t *testing.T, denyPath string, extraAllowExecute []string) *shimInstallTestServerSpec {
	t.Helper()

	llResult := capabilities.DetectLandlock()
	if !llResult.Available {
		t.Skip("Landlock not available — cannot configure deny rules")
	}

	// Determine which paths to deny. Deny the parent directory of the target
	// file so Landlock blocks the entire directory tree, not just the file
	// (file-level Landlock rules are harder to get right — dir-level is robust).
	denyDir := filepath.Dir(denyPath)

	// Enable unix sockets so the wrap-init path succeeds.
	enabled := true
	wrapperBin := "agentsh-unixwrap" // resolved from PATH during the test

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = wrapperBin

	// Landlock: enable and deny the directory containing the target file.
	// AllowExecute / AllowRead are deliberately minimal — the test only needs
	// to verify that the deny target is blocked.  The allow lists let bash and
	// cat find their shared libraries; they do NOT include denyDir.
	cfg.Landlock.Enabled = true
	cfg.Landlock.DenyPaths = []string{denyDir}
	cfg.Landlock.AllowExecute = append([]string{
		"/bin",
		"/usr/bin",
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
	}, extraAllowExecute...)
	cfg.Landlock.AllowRead = []string{
		"/bin",
		"/usr/bin",
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
		"/etc/ld.so.cache",
		"/etc/ld.so.conf",
		"/proc/self",
		"/proc/self/maps",
		"/dev/null",
		"/dev/urandom",
	}
	// Allow network for the wrapper's seccomp-notify handshake with the server.
	connectTCP := true
	bindTCP := false
	cfg.Landlock.Network.AllowConnectTCP = &connectTCP
	cfg.Landlock.Network.AllowBindTCP = &bindTCP

	mgr := session.NewManager(10)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()

	app := NewApp(cfg, mgr, store, nil, broker, nil, nil, nil, nil, nil, nil)

	// Pre-create the session so wrap-init finds it.
	ws := t.TempDir()
	sessID := "test-shim-install"
	s, err := mgr.CreateWithID(sessID, ws, "default")
	if err != nil {
		t.Fatalf("create test session: %v", err)
	}
	_ = s

	// Wrap the app's router with a middleware that counts wrap-init requests.
	var counter atomic.Int32
	counted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/wrap-init") {
			counter.Add(1)
		}
		app.Router().ServeHTTP(w, r)
	})

	srv := newHTTPTestServerOrSkip(t, counted)
	t.Cleanup(srv.Close)

	return &shimInstallTestServerSpec{
		srv:           srv,
		sessionID:     sessID,
		mgr:           mgr,
		wrapInitCalls: &counter,
	}
}

// buildShimBinary compiles agentsh-shell-shim with the -tags shimtest flag and
// returns the path to the binary.  The binary is named "bash" so the shim
// internally resolves the real shell as "bash.real".
func buildShimBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("shim binary is Linux-only")
	}
	binDir := t.TempDir()
	shimBin := filepath.Join(binDir, "bash")
	cmd := exec.Command("go", "build", "-tags", "shimtest", "-o", shimBin,
		"./cmd/agentsh-shell-shim")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build agentsh-shell-shim: %v\n%s", err, out)
	}
	return shimBin
}

// buildWrapBinary compiles agentsh-unixwrap (requires cgo) and returns the
// path to the binary.
func buildWrapBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("agentsh-unixwrap is Linux-only")
	}
	binDir := t.TempDir()
	wrapBin := filepath.Join(binDir, "agentsh-unixwrap")
	cmd := exec.Command("go", "build", "-o", wrapBin, "./cmd/agentsh-unixwrap")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("build agentsh-unixwrap output:\n%s", out)
		// If cgo isn't available, skip rather than fail.
		if isNoCGOError(string(out)) {
			t.Skip("cgo not available — cannot build agentsh-unixwrap")
		}
		t.Fatalf("build agentsh-unixwrap: %v\n%s", err, out)
	}
	return wrapBin
}

// isNoCGOError returns true when the build failure is attributable to a
// missing C compiler or disabled CGO rather than a code error.
func isNoCGOError(output string) bool {
	patterns := []string{
		"C compiler",
		"cgo",
		"CGO_ENABLED",
		"exec: \"cc\"",
		"exec: \"gcc\"",
	}
	for _, p := range patterns {
		if len(output) > 0 {
			for i := 0; i <= len(output)-len(p); i++ {
				if output[i:i+len(p)] == p {
					return true
				}
			}
		}
	}
	return false
}
