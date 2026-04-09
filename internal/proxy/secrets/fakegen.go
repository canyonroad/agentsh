package secrets

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	// ErrInvalidFakeFormat is returned by ParseFormat when the
	// format template is syntactically invalid (empty, missing
	// {rand:N} placeholder, placeholder not at end, etc.).
	ErrInvalidFakeFormat = errors.New("secrets: invalid fake format template")

	// ErrFakeLengthMismatch is returned by GenerateFake when the
	// total length produced by the format (len(prefix) + randLen)
	// does not equal the real secret's length.
	ErrFakeLengthMismatch = errors.New("secrets: fake format length does not match real secret length")

	// ErrFakeEntropyTooLow is returned by ParseFormat when the
	// random portion of the format has fewer than 24 characters,
	// which would make collisions or brute-force feasible.
	ErrFakeEntropyTooLow = errors.New("secrets: fake format has fewer than 24 random characters")
)

// minFakeEntropy is the minimum number of random base62 characters
// required in a fake credential format. 24 base62 chars provide
// ~143 bits of entropy.
const minFakeEntropy = 24

// base62 is the alphabet used for random portions of fake credentials.
const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// ParseFormat validates a fake credential format template and returns
// its components. The format syntax is "<prefix>{rand:<count>}" where
// prefix is a literal string (may be empty) and {rand:N} emits N
// random base62 characters. The {rand:N} placeholder must appear
// exactly once and must be the last element in the format string.
//
// Returns ErrInvalidFakeFormat for syntactic problems and
// ErrFakeEntropyTooLow when count is below minFakeEntropy (24).
func ParseFormat(format string) (prefix string, randLen int, err error) {
	if format == "" {
		return "", 0, ErrInvalidFakeFormat
	}

	idx := strings.Index(format, "{rand:")
	if idx < 0 {
		return "", 0, ErrInvalidFakeFormat
	}

	// Exactly one {rand:...} placeholder allowed.
	if strings.Count(format, "{rand:") != 1 {
		return "", 0, ErrInvalidFakeFormat
	}

	// Must end with closing brace.
	if !strings.HasSuffix(format, "}") {
		return "", 0, ErrInvalidFakeFormat
	}

	// Extract the count between "{rand:" and the closing "}".
	inner := format[idx+len("{rand:") : len(format)-1]
	if inner == "" {
		return "", 0, ErrInvalidFakeFormat
	}

	n, parseErr := strconv.Atoi(inner)
	if parseErr != nil || n <= 0 {
		return "", 0, ErrInvalidFakeFormat
	}

	if n < minFakeEntropy {
		return "", 0, fmt.Errorf("%w: got %d, minimum %d", ErrFakeEntropyTooLow, n, minFakeEntropy)
	}

	// Verify placeholder is at the very end (no trailing suffix).
	closingIdx := idx + len("{rand:") + len(inner) + 1
	if closingIdx != len(format) {
		return "", 0, ErrInvalidFakeFormat
	}

	return format[:idx], n, nil
}

// GenerateFake produces a fake credential from a format template.
// The generated credential has the same length as realLen (the real
// secret's byte length) with the literal prefix preserved and the
// random portion filled with crypto/rand base62 characters.
//
// Returns ErrFakeLengthMismatch when len(prefix)+randLen != realLen.
func GenerateFake(format string, realLen int) ([]byte, error) {
	prefix, randLen, err := ParseFormat(format)
	if err != nil {
		return nil, err
	}

	if len(prefix)+randLen != realLen {
		return nil, fmt.Errorf("%w: format produces %d bytes, real secret is %d bytes",
			ErrFakeLengthMismatch, len(prefix)+randLen, realLen)
	}

	out := make([]byte, realLen)
	copy(out, prefix)

	randBytes := make([]byte, randLen)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, fmt.Errorf("secrets: crypto/rand failed: %w", err)
	}
	for i, b := range randBytes {
		out[len(prefix)+i] = base62[int(b)%len(base62)]
	}

	return out, nil
}
