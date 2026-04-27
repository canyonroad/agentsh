package wal

import "testing"

func TestLossReasonConstants_StableValues(t *testing.T) {
	cases := []struct {
		name     string
		got      string
		expected string
	}{
		{"Overflow", LossReasonOverflow, "overflow"},
		{"CRCCorruption", LossReasonCRCCorruption, "crc_corruption"},
		{"AckRegressionAfterGC", LossReasonAckRegressionAfterGC, "ack_regression_after_gc"},
		{"MapperFailure", LossReasonMapperFailure, "mapper_failure"},
		{"InvalidMapper", LossReasonInvalidMapper, "invalid_mapper"},
		{"InvalidTimestamp", LossReasonInvalidTimestamp, "invalid_timestamp"},
		{"InvalidUTF8", LossReasonInvalidUTF8, "invalid_utf8"},
		{"SequenceOverflow", LossReasonSequenceOverflow, "sequence_overflow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.expected {
				t.Fatalf("%s = %q, want %q (on-disk-stable; do NOT change)", tc.name, tc.got, tc.expected)
			}
		})
	}
}
