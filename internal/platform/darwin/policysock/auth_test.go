//go:build darwin

package policysock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateCodeSignature_InvalidPath(t *testing.T) {
	err := validateCodeSignature("/nonexistent/binary", "WCKWMMKJ35")
	assert.Error(t, err, "should fail for nonexistent binary")
}

func TestValidateCodeSignature_UnsignedBinary(t *testing.T) {
	// /usr/bin/true is Apple-signed, not our team ID
	err := validateCodeSignature("/usr/bin/true", "WCKWMMKJ35")
	assert.Error(t, err, "should fail for binary signed by different team")
}

func TestResolvePIDPath_Self(t *testing.T) {
	// Our own process should resolve
	path, err := resolvePIDPath(int32(os.Getpid()))
	assert.NoError(t, err)
	assert.NotEmpty(t, path)
}

func TestResolvePIDPath_InvalidPID(t *testing.T) {
	_, err := resolvePIDPath(-1)
	assert.Error(t, err)
}
