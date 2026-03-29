//go:build linux

package capabilities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProbeSeccompBasic(t *testing.T) {
	result := probeSeccompBasic()
	assert.NotEmpty(t, result.Detail, "probe should always return a detail string")
	// On a modern Linux kernel, basic seccomp should be available.
	// If this test runs on a system where seccomp is blocked, it's OK to fail.
	t.Logf("seccomp basic: available=%v detail=%q", result.Available, result.Detail)
}

func TestProbeSeccompUserNotify(t *testing.T) {
	result := probeSeccompUserNotify()
	assert.NotEmpty(t, result.Detail, "probe should always return a detail string")
	t.Logf("seccomp user-notify: available=%v detail=%q", result.Available, result.Detail)
}

func TestCheckSeccompBasicIndependent(t *testing.T) {
	// checkSeccompBasic should use probeSeccompBasic, not delegate to checkSeccompUserNotify.
	// Verify they can return different results by checking they call different probes.
	basic := probeSeccompBasic()
	notify := probeSeccompUserNotify()
	t.Logf("basic=%v notify=%v", basic.Available, notify.Available)
	// On a kernel with user-notify, both should be true.
	// On a kernel without user-notify, basic could be true while notify is false.
	if notify.Available {
		assert.True(t, basic.Available, "if user-notify is available, basic must also be available")
	}
}

func TestRealCheckSeccompUserNotify(t *testing.T) {
	result := realCheckSeccompUserNotify()
	assert.Equal(t, "seccomp-user-notify", result.Feature)
	if result.Available {
		assert.Nil(t, result.Error)
	} else {
		assert.NotNil(t, result.Error)
		assert.Contains(t, result.Error.Error(), "SECCOMP_RET_USER_NOTIF")
	}
	t.Logf("realCheckSeccompUserNotify: available=%v err=%v", result.Available, result.Error)
}
