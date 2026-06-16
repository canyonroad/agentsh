package watchtower

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type erroringCredentialSource struct{}

func (erroringCredentialSource) Bearer(context.Context) (string, error) {
	return "", errors.New("kms unavailable")
}

func TestDial_CredentialResolutionErrorIsSurfaced(t *testing.T) {
	t.Parallel()
	d := &productionDialer{opts: Options{
		Endpoint:         "127.0.0.1:0", // never actually dialed; Bearer() fails first
		CredentialSource: erroringCredentialSource{},
	}}
	_, err := d.Dial(context.Background())
	if err == nil {
		t.Fatal("expected Dial to fail when CredentialSource errors")
	}
	if !strings.Contains(err.Error(), "resolve credential") {
		t.Fatalf("err = %v, want 'resolve credential'", err)
	}
}
