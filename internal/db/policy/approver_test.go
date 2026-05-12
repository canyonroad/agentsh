package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestNopApprover_Timeout_ReturnsFalseNoError(t *testing.T) {
	a := NopApprover{}
	approved, err := a.Decide(context.Background(), effects.ClassifiedStatement{}, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("Decide err: %v", err)
	}
	if approved {
		t.Error("NopApprover must always deny on timeout")
	}
}

func TestNopApprover_CtxCancel_ReturnsCtxErr(t *testing.T) {
	a := NopApprover{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	approved, err := a.Decide(ctx, effects.ClassifiedStatement{}, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err=%v want context.Canceled", err)
	}
	if approved {
		t.Error("approved should be false on ctx cancel")
	}
}

func TestErrApproverNotConfigured(t *testing.T) {
	if ErrApproverNotConfigured == nil {
		t.Fatal("ErrApproverNotConfigured should not be nil")
	}
}
