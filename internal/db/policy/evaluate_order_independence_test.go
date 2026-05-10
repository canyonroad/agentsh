package policy

import (
	"math/rand"
	"testing"
)

func TestEvaluate_R14OrderIndependent(t *testing.T) {
	// Build a fresh RuleSet on every permutation by reordering the slice
	// post-Decode. Doing this means we don't have to re-shuffle the YAML
	// itself — the evaluator must produce the same decision regardless of
	// statement[] slice order.
	rs := MustLoadSample()
	if len(rs.statement) < 2 {
		t.Fatal("need at least two rules to permute")
	}
	original := append([]*compiledStatementRule(nil), rs.statement...)
	defer func() { rs.statement = original }()

	const permutations = 8
	rng := rand.New(rand.NewSource(1234))

	for _, c := range cases() {
		c := c
		// Snapshot the baseline outcome.
		rs.statement = append([]*compiledStatementRule(nil), original...)
		baseline := Evaluate(c.stmt, rs, c.service)

		for p := 0; p < permutations; p++ {
			permuted := append([]*compiledStatementRule(nil), original...)
			rng.Shuffle(len(permuted), func(i, j int) { permuted[i], permuted[j] = permuted[j], permuted[i] })
			rs.statement = permuted
			got := Evaluate(c.stmt, rs, c.service)
			if got.Verb != baseline.Verb {
				t.Errorf("[%s] permutation %d: Verb=%v want %v (baseline rule=%q got rule=%q)", c.name, p, got.Verb, baseline.Verb, baseline.RuleName, got.RuleName)
			}
		}
	}
}
