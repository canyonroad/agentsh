package transport

import (
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// ===== Test #9 =====
// TestComputeReplayStart_PartialGCdGapEmitsLoss — Case A in the decision
// tree. Append seqs 1..100 in gen=1, GC the lower seqs by raising the
// MarkAcked HW high enough; remoteReplayCursor=(20, 1) with persistedAck=(80, 1).
// The helper should emit a LossRecord covering [21, earliest-1] and open
// the reader at earliest.
func TestComputeReplayStart_PartialGCdGapEmitsLoss(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 80, Generation: 1, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

	// Override EarliestDataSequence(1) to return (51, true, nil) so the
	// case-A branch fires: gapStart=21 > 51 false, but we want
	// earliestOnDisk > gapStart → 51 > 21 → true → Case A.
	SetWALEarliestDataSequenceFnForTest(env.tr, func(gen uint32) (uint64, bool, error) {
		if gen != 1 {
			t.Errorf("EarliestDataSequence: got gen=%d, want 1", gen)
		}
		return 51, true, nil
	})

	prefixLoss, readerStart, err := ComputeReplayStartForTest(env.tr,
		AckCursor{Sequence: 20, Generation: 1},
		AckCursor{Sequence: 80, Generation: 1})
	if err != nil {
		t.Fatalf("computeReplayStart: %v", err)
	}
	if prefixLoss == nil {
		t.Fatal("prefixLoss: got nil, want non-nil for Case A")
	}
	want := wal.LossRecord{
		FromSequence: 21,
		ToSequence:   50,
		Generation:   1,
		Reason:       "ack_regression_after_gc",
	}
	if *prefixLoss != want {
		t.Fatalf("prefixLoss: got %+v, want %+v", *prefixLoss, want)
	}
	if readerStart != 51 {
		t.Fatalf("readerStart: got %d, want 51 (earliestOnDisk)", readerStart)
	}

	// INFO log entry must be present at compute-time.
	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "INFO"); got != 1 {
		t.Fatalf("INFO entries: got %d, want 1: %+v", got, entries)
	}
	infoEntry := firstLevel(entries, "INFO")
	if v, ok := infoEntry.Attrs["from_seq"].(float64); !ok || uint64(v) != 21 {
		t.Fatalf("INFO from_seq: got %v, want 21", infoEntry.Attrs["from_seq"])
	}
	if v, ok := infoEntry.Attrs["to_seq"].(float64); !ok || uint64(v) != 50 {
		t.Fatalf("INFO to_seq: got %v, want 50", infoEntry.Attrs["to_seq"])
	}
	if v, ok := infoEntry.Attrs["earliest_on_disk_present"].(bool); !ok || !v {
		t.Fatalf("INFO earliest_on_disk_present: got %v, want true", infoEntry.Attrs["earliest_on_disk_present"])
	}
	if v, ok := infoEntry.Attrs["earliest_on_disk_seq"].(float64); !ok || uint64(v) != 51 {
		t.Fatalf("INFO earliest_on_disk_seq: got %v, want 51", infoEntry.Attrs["earliest_on_disk_seq"])
	}
	// Counter is NOT incremented at compute-time (Round-13 Finding 5: emit-time only).
	if env.metrics.ackRegressionLoss != 0 {
		t.Fatalf("ackRegressionLoss counter: got %d at compute-time, want 0 (emit-time only)",
			env.metrics.ackRegressionLoss)
	}
}

// ===== Test #10 =====
// TestComputeReplayStart_NoGapWhenSteadyState — Case B in the decision
// tree. EarliestDataSequence returns (51, true), but gapStart=71, so
// 51 <= 71 → no synthetic loss; readerStart = gapStart = 71.
func TestComputeReplayStart_NoGapWhenSteadyState(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 80, Generation: 1, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

	SetWALEarliestDataSequenceFnForTest(env.tr, func(gen uint32) (uint64, bool, error) {
		if gen != 1 {
			t.Errorf("EarliestDataSequence: got gen=%d, want 1", gen)
		}
		return 51, true, nil
	})

	prefixLoss, readerStart, err := ComputeReplayStartForTest(env.tr,
		AckCursor{Sequence: 70, Generation: 1},
		AckCursor{Sequence: 80, Generation: 1})
	if err != nil {
		t.Fatalf("computeReplayStart: %v", err)
	}
	if prefixLoss != nil {
		t.Fatalf("prefixLoss: got %+v, want nil for Case B (no gap)", *prefixLoss)
	}
	if readerStart != 71 {
		t.Fatalf("readerStart: got %d, want 71 (gapStart)", readerStart)
	}
	entries := parseLogBuffer(t, env.logBuf)
	if len(entries) != 0 {
		t.Fatalf("unexpected log entries on Case B (no gap): %+v", entries)
	}
	if env.metrics.ackRegressionLoss != 0 {
		t.Fatalf("ackRegressionLoss counter: got %d, want 0 on no-gap path", env.metrics.ackRegressionLoss)
	}
}

// ===== Test #11 =====
// TestComputeReplayStart_FullyGCdServerBehindPersistedAck_EmitsLoss — Case C
// in the decision tree. EarliestDataSequence returns (0, false, nil) (fully
// GC'd) and gapStart <= persistedAck.Sequence. Loss covers
// [gapStart, persistedAck.Sequence].
func TestComputeReplayStart_FullyGCdServerBehindPersistedAck_EmitsLoss(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 100, Generation: 1, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

	SetWALEarliestDataSequenceFnForTest(env.tr, func(gen uint32) (uint64, bool, error) {
		return 0, false, nil
	})

	prefixLoss, readerStart, err := ComputeReplayStartForTest(env.tr,
		AckCursor{Sequence: 20, Generation: 1},
		AckCursor{Sequence: 100, Generation: 1})
	if err != nil {
		t.Fatalf("computeReplayStart: %v", err)
	}
	if prefixLoss == nil {
		t.Fatal("prefixLoss: got nil, want non-nil for Case C")
	}
	want := wal.LossRecord{
		FromSequence: 21,
		ToSequence:   100, // persistedAck.Sequence
		Generation:   1,
		Reason:       "ack_regression_after_gc",
	}
	if *prefixLoss != want {
		t.Fatalf("prefixLoss: got %+v, want %+v", *prefixLoss, want)
	}
	if readerStart != 21 {
		t.Fatalf("readerStart: got %d, want 21 (gapStart)", readerStart)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "INFO"); got != 1 {
		t.Fatalf("INFO entries: got %d, want 1", got)
	}
	infoEntry := firstLevel(entries, "INFO")
	if v, ok := infoEntry.Attrs["earliest_on_disk_present"].(bool); !ok || v {
		t.Fatalf("INFO earliest_on_disk_present: got %v, want false", infoEntry.Attrs["earliest_on_disk_present"])
	}
	if v, ok := infoEntry.Attrs["to_seq"].(float64); !ok || uint64(v) != 100 {
		t.Fatalf("INFO to_seq: got %v, want 100", infoEntry.Attrs["to_seq"])
	}
	// Counter NOT incremented at compute-time.
	if env.metrics.ackRegressionLoss != 0 {
		t.Fatalf("ackRegressionLoss counter: got %d at compute-time, want 0", env.metrics.ackRegressionLoss)
	}
}

// ===== Test #11a =====
// TestComputeReplayStart_FullyGCdServerAtOrPastPersistedAckIsNoOp — Case D
// (defensive). Two sub-cases: (a) gapStart == persistedAck.Sequence + 1
// (the normal collapsed reconnect); (b) gapStart > persistedAck.Sequence + 1.
// Both should return prefixLoss == nil.
func TestComputeReplayStart_FullyGCdServerAtOrPastPersistedAckIsNoOp(t *testing.T) {
	cases := []struct {
		name              string
		remoteReplayCsr   AckCursor
		persistedAckCsr   AckCursor
		wantReaderStart   uint64
	}{
		{
			name:            "boundary_gapStart_equals_persistedAck_plus_1",
			remoteReplayCsr: AckCursor{Sequence: 100, Generation: 1},
			persistedAckCsr: AckCursor{Sequence: 100, Generation: 1},
			wantReaderStart: 101,
		},
		{
			name:            "defensive_gapStart_far_past_persistedAck",
			remoteReplayCsr: AckCursor{Sequence: 150, Generation: 1},
			persistedAckCsr: AckCursor{Sequence: 100, Generation: 1},
			wantReaderStart: 151,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			env := newClampTestEnv(t, Options{
				InitialAckTuple: &AckTuple{
					Sequence:   tc.persistedAckCsr.Sequence,
					Generation: tc.persistedAckCsr.Generation,
					Present:    true,
				},
			})
			SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

			SetWALEarliestDataSequenceFnForTest(env.tr, func(gen uint32) (uint64, bool, error) {
				return 0, false, nil
			})

			prefixLoss, readerStart, err := ComputeReplayStartForTest(env.tr,
				tc.remoteReplayCsr, tc.persistedAckCsr)
			if err != nil {
				t.Fatalf("computeReplayStart: %v", err)
			}
			if prefixLoss != nil {
				t.Fatalf("prefixLoss: got %+v, want nil for Case D", *prefixLoss)
			}
			if readerStart != tc.wantReaderStart {
				t.Fatalf("readerStart: got %d, want %d", readerStart, tc.wantReaderStart)
			}
			entries := parseLogBuffer(t, env.logBuf)
			if len(entries) != 0 {
				t.Fatalf("unexpected log entries on Case D: %+v", entries)
			}
			if env.metrics.ackRegressionLoss != 0 {
				t.Fatalf("ackRegressionLoss counter: got %d, want 0", env.metrics.ackRegressionLoss)
			}
		})
	}
}

// ===== Test #11b =====
// TestComputeReplayStart_MixedGenerationsOnDisk_DetectsLossInOlderGeneration
// — round-12 Finding 2 regression test. The helper MUST pass
// persistedAck.Generation to EarliestDataSequence so a higher-gen
// segment's low earliest is NOT mistaken for the older gen's gap.
//
// Sub-case (a): replay gen=1, gen=1 fully GC'd, gen=2 still has data.
// EarliestDataSequence(1) returns (0, false), so the helper hits Case C
// and emits loss.
//
// Sub-case (b): replay gen=2, gen=2 has data starting at seq=1.
// EarliestDataSequence(2) returns (1, true). gapStart=1, earliestOnDisk=1,
// so 1 > 1 false → Case B (no gap).
func TestComputeReplayStart_MixedGenerationsOnDisk_DetectsLossInOlderGeneration(t *testing.T) {
	type accessorCall struct{ gen uint32 }

	tests := []struct {
		name              string
		replayCursor      AckCursor
		persistedCursor   AckCursor
		walEarliest       func(gen uint32) (uint64, bool, error)
		wantPrefixLoss    *wal.LossRecord
		wantReaderStart   uint64
		wantCalledWithGen uint32
		wantInfoCount     int
	}{
		{
			name:            "replay_older_gen_fully_GCd_emits_loss",
			replayCursor:    AckCursor{Sequence: 20, Generation: 1},
			persistedCursor: AckCursor{Sequence: 50, Generation: 1},
			walEarliest: func(gen uint32) (uint64, bool, error) {
				switch gen {
				case 1:
					return 0, false, nil
				case 2:
					return 1, true, nil
				}
				return 0, false, errors.New("unexpected gen")
			},
			wantPrefixLoss: &wal.LossRecord{
				FromSequence: 21,
				ToSequence:   50,
				Generation:   1,
				Reason:       "ack_regression_after_gc",
			},
			wantReaderStart:   21,
			wantCalledWithGen: 1,
			wantInfoCount:     1,
		},
		{
			name:            "replay_newer_gen_at_earliest_no_gap",
			replayCursor:    AckCursor{Sequence: 0, Generation: 2},
			persistedCursor: AckCursor{Sequence: 5, Generation: 2},
			walEarliest: func(gen uint32) (uint64, bool, error) {
				switch gen {
				case 1:
					return 0, false, nil
				case 2:
					return 1, true, nil
				}
				return 0, false, errors.New("unexpected gen")
			},
			wantPrefixLoss:    nil,
			wantReaderStart:   1,
			wantCalledWithGen: 2,
			wantInfoCount:     0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			env := newClampTestEnv(t, Options{
				InitialAckTuple: &AckTuple{
					Sequence:   tc.persistedCursor.Sequence,
					Generation: tc.persistedCursor.Generation,
					Present:    true,
				},
			})
			SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

			var calls []accessorCall
			SetWALEarliestDataSequenceFnForTest(env.tr, func(gen uint32) (uint64, bool, error) {
				calls = append(calls, accessorCall{gen: gen})
				return tc.walEarliest(gen)
			})

			prefixLoss, readerStart, err := ComputeReplayStartForTest(env.tr,
				tc.replayCursor, tc.persistedCursor)
			if err != nil {
				t.Fatalf("computeReplayStart: %v", err)
			}

			// Confirm the helper called EarliestDataSequence with persistedAck.Generation.
			if len(calls) == 0 {
				t.Fatal("EarliestDataSequence was NOT called")
			}
			if got := calls[0].gen; got != tc.wantCalledWithGen {
				t.Fatalf("EarliestDataSequence called with gen=%d, want %d", got, tc.wantCalledWithGen)
			}

			if tc.wantPrefixLoss == nil {
				if prefixLoss != nil {
					t.Fatalf("prefixLoss: got %+v, want nil", *prefixLoss)
				}
			} else {
				if prefixLoss == nil {
					t.Fatalf("prefixLoss: got nil, want %+v", *tc.wantPrefixLoss)
				}
				if *prefixLoss != *tc.wantPrefixLoss {
					t.Fatalf("prefixLoss: got %+v, want %+v", *prefixLoss, *tc.wantPrefixLoss)
				}
			}

			if readerStart != tc.wantReaderStart {
				t.Fatalf("readerStart: got %d, want %d", readerStart, tc.wantReaderStart)
			}

			entries := parseLogBuffer(t, env.logBuf)
			if got := countLevel(entries, "INFO"); got != tc.wantInfoCount {
				t.Fatalf("INFO entries: got %d, want %d (entries=%+v)", got, tc.wantInfoCount, entries)
			}
		})
	}
}

// ===== Test #12 =====
// TestComputeReplayPlan_MultiGenerationCoversLaterGens — round-14 Finding 2
// regression. The orchestrator MUST emit one stage per generation that has
// data on disk, in strictly ascending order, starting from
// persistedAck.Generation. Without this, a reconnect that lands when the
// agent has already rolled to a newer generation drops the later-gen
// backlog because the Replaying state would only drain
// persistedAck.Generation before handing off to Live.
//
// Sub-cases:
//
//  1. happy_multi_gen_three_stages: persistedAck=(50, 1), gen=2 has data,
//     gen=3 is empty (header only), gen=4 has data, gen=5 is the high gen
//     with data. Expect 4 stages: (gen=1,start=51), (gen=2,start=0),
//     (gen=4,start=0), (gen=5,start=0). gen=3 is skipped because
//     WrittenDataHighWater(3) reports ok=false. The first stage's
//     PrefixLoss is nil (Case B no-gap on gen=1 — earliestOnDisk=1 <=
//     gapStart=51).
//
//  2. only_persisted_gen_no_later: HighGeneration() == persistedAck.Generation.
//     Expect exactly one stage covering persistedAck.Generation.
//
//  3. wal_failure_on_later_gen_propagates: WrittenDataHighWater(2) returns
//     an error. Expect computeReplayPlan to return that error wrapped.
func TestComputeReplayPlan_MultiGenerationCoversLaterGens(t *testing.T) {
	t.Run("happy_multi_gen_three_stages", func(t *testing.T) {
		env := newClampTestEnv(t, Options{
			InitialAckTuple: &AckTuple{Sequence: 50, Generation: 1, Present: true},
		})
		SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

		// First-stage decision tree: Case B (no gap).
		SetWALEarliestDataSequenceFnForTest(env.tr, func(gen uint32) (uint64, bool, error) {
			if gen != 1 {
				t.Errorf("EarliestDataSequence: got gen=%d, want 1 (first stage only)", gen)
			}
			return 1, true, nil
		})
		// Multi-gen probe: gen=2 has data, gen=3 is empty (header only),
		// gen=4 has data, gen=5 has data. Track call ordering to confirm
		// the iteration goes in strictly ascending generation order.
		var probedGens []uint32
		SetWALWrittenDataHighWaterFnForTest(env.tr, func(gen uint32) (uint64, bool, error) {
			probedGens = append(probedGens, gen)
			switch gen {
			case 2:
				return 100, true, nil
			case 3:
				return 0, false, nil
			case 4:
				return 75, true, nil
			case 5:
				return 25, true, nil
			}
			return 0, false, errors.New("unexpected gen")
		})
		SetWALHighGenerationFnForTest(env.tr, func() uint32 { return 5 })

		stages, err := ComputeReplayPlanForTest(env.tr,
			AckCursor{Sequence: 50, Generation: 1},
			AckCursor{Sequence: 50, Generation: 1})
		if err != nil {
			t.Fatalf("computeReplayPlan: %v", err)
		}
		if len(stages) != 4 {
			t.Fatalf("stages: got %d, want 4 (gen=1, 2, 4, 5; gen=3 skipped): %+v", len(stages), stages)
		}

		want := []ReplayStage{
			{Generation: 1, StartSeq: 51, PrefixLoss: nil},
			{Generation: 2, StartSeq: 0, PrefixLoss: nil},
			{Generation: 4, StartSeq: 0, PrefixLoss: nil},
			{Generation: 5, StartSeq: 0, PrefixLoss: nil},
		}
		for i, w := range want {
			if stages[i].Generation != w.Generation {
				t.Errorf("stage[%d].Generation: got %d, want %d", i, stages[i].Generation, w.Generation)
			}
			if stages[i].StartSeq != w.StartSeq {
				t.Errorf("stage[%d].StartSeq: got %d, want %d", i, stages[i].StartSeq, w.StartSeq)
			}
			if stages[i].PrefixLoss != nil {
				t.Errorf("stage[%d].PrefixLoss: got %+v, want nil", i, *stages[i].PrefixLoss)
			}
		}

		// Probe order must be strictly ascending past persistedAck.Generation.
		wantProbed := []uint32{2, 3, 4, 5}
		if len(probedGens) != len(wantProbed) {
			t.Fatalf("probedGens: got %v, want %v", probedGens, wantProbed)
		}
		for i, g := range wantProbed {
			if probedGens[i] != g {
				t.Errorf("probedGens[%d]: got %d, want %d", i, probedGens[i], g)
			}
		}
	})

	t.Run("only_persisted_gen_no_later", func(t *testing.T) {
		env := newClampTestEnv(t, Options{
			InitialAckTuple: &AckTuple{Sequence: 50, Generation: 7, Present: true},
		})
		SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

		SetWALEarliestDataSequenceFnForTest(env.tr, func(uint32) (uint64, bool, error) {
			return 1, true, nil
		})
		// HighGeneration == persistedAck.Generation: no later-gen probe should fire.
		SetWALWrittenDataHighWaterFnForTest(env.tr, func(gen uint32) (uint64, bool, error) {
			t.Errorf("WrittenDataHighWater MUST NOT be called when HighGeneration == persistedAck.Generation; got gen=%d", gen)
			return 0, false, nil
		})
		SetWALHighGenerationFnForTest(env.tr, func() uint32 { return 7 })

		stages, err := ComputeReplayPlanForTest(env.tr,
			AckCursor{Sequence: 50, Generation: 7},
			AckCursor{Sequence: 50, Generation: 7})
		if err != nil {
			t.Fatalf("computeReplayPlan: %v", err)
		}
		if len(stages) != 1 {
			t.Fatalf("stages: got %d, want 1: %+v", len(stages), stages)
		}
		if stages[0].Generation != 7 {
			t.Fatalf("stage[0].Generation: got %d, want 7", stages[0].Generation)
		}
		if stages[0].StartSeq != 51 {
			t.Fatalf("stage[0].StartSeq: got %d, want 51", stages[0].StartSeq)
		}
	})

	t.Run("wal_failure_on_later_gen_propagates", func(t *testing.T) {
		env := newClampTestEnv(t, Options{
			InitialAckTuple: &AckTuple{Sequence: 50, Generation: 1, Present: true},
		})
		SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

		SetWALEarliestDataSequenceFnForTest(env.tr, func(uint32) (uint64, bool, error) {
			return 1, true, nil
		})
		injErr := errors.New("simulated wal failure on gen=2")
		SetWALWrittenDataHighWaterFnForTest(env.tr, func(gen uint32) (uint64, bool, error) {
			if gen == 2 {
				return 0, false, injErr
			}
			return 0, false, nil
		})
		SetWALHighGenerationFnForTest(env.tr, func() uint32 { return 5 })

		stages, err := ComputeReplayPlanForTest(env.tr,
			AckCursor{Sequence: 50, Generation: 1},
			AckCursor{Sequence: 50, Generation: 1})
		if err == nil {
			t.Fatalf("computeReplayPlan: got err=nil, stages=%+v; want wrapped wal failure", stages)
		}
		if !errors.Is(err, injErr) {
			t.Fatalf("computeReplayPlan: err does not wrap injected error: %v", err)
		}
		if stages != nil {
			t.Fatalf("stages: got %+v, want nil on error", stages)
		}
	})
}
