//go:build darwin

package fuse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckAvailable_AlwaysFalse(t *testing.T) {
	assert.False(t, checkAvailable(), "FUSE is not used on macOS")
}

func TestDetectImplementation_AlwaysNone(t *testing.T) {
	assert.Equal(t, "none", detectImplementation(), "FUSE implementation should be none on macOS")
}
