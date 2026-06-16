package metrics

import "testing"

func TestSessionFailureReason_AuthRejectedIsValid(t *testing.T) {
	if _, ok := wtpSessionFailureReasonsValid[WTPSessionFailureReasonAuthRejected]; !ok {
		t.Fatal("auth_rejected must be in wtpSessionFailureReasonsValid")
	}
	if WTPSessionFailureReasonAuthRejected != "auth_rejected" {
		t.Fatalf("value = %q, want %q", WTPSessionFailureReasonAuthRejected, "auth_rejected")
	}
	found := false
	for _, r := range wtpSessionFailureReasonsEmitOrder {
		if r == WTPSessionFailureReasonAuthRejected {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("auth_rejected must be in wtpSessionFailureReasonsEmitOrder")
	}
}
