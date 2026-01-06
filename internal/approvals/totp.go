package approvals

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"strings"

	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

// GenerateTOTPSecret generates a new 20-byte (160-bit) TOTP secret.
// Returns the secret as a base32-encoded string.
func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.EncodeToString(secret), nil
}

// ValidateTOTPCode validates a 6-digit TOTP code against the given secret.
// Uses standard TOTP parameters: SHA1, 6 digits, 30-second period, ±1 period skew.
func ValidateTOTPCode(code, secret string) bool {
	return totp.Validate(code, secret)
}

// FormatTOTPURI creates an otpauth:// URI for the given session and secret.
func FormatTOTPURI(sessionID, secret string) string {
	// Use first 8 chars of session ID as label
	label := sessionID
	if len(label) > 8 {
		label = label[:8]
	}
	return fmt.Sprintf("otpauth://totp/agentsh:%s?secret=%s&issuer=agentsh", label, secret)
}

// DisplayTOTPSetup writes the TOTP setup screen (QR code + manual secret) to the writer.
func DisplayTOTPSetup(w io.Writer, sessionID, secret string) error {
	uri := FormatTOTPURI(sessionID, secret)

	// Generate QR code as ASCII art
	qr, err := qrcode.New(uri, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("generate QR code: %w", err)
	}
	qrASCII := qr.ToSmallString(false)

	// Display setup screen
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "╔══════════════════════════════════════════════════════════╗")
	fmt.Fprintln(w, "║              TOTP Setup for Session                      ║")
	fmt.Fprintln(w, "╠══════════════════════════════════════════════════════════╣")
	fmt.Fprintln(w, "║  Scan this QR code with your authenticator app:          ║")
	fmt.Fprintln(w, "║                                                          ║")

	// Print QR code with padding
	for _, line := range strings.Split(qrASCII, "\n") {
		if line != "" {
			fmt.Fprintf(w, "║  %s\n", line)
		}
	}

	fmt.Fprintln(w, "║                                                          ║")
	fmt.Fprintln(w, "║  Or enter manually:                                      ║")
	fmt.Fprintf(w, "║  Secret: %s\n", secret)
	fmt.Fprintln(w, "║                                                          ║")
	fmt.Fprintln(w, "╚══════════════════════════════════════════════════════════╝")
	fmt.Fprintln(w, "")

	return nil
}
