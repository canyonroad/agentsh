package policy

import (
	"bytes"
	_ "embed"
	"fmt"

	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

//go:embed testdata/sample-policy.yaml
var sampleYAML []byte

// MustLoadSample returns a *RuleSet built from the embedded sample policy
// (testdata/sample-policy.yaml). Panics on any error — the file is part of
// the package and a parse failure indicates a development-time bug, not a
// runtime condition. Plan 03's golden corpus also calls this.
func MustLoadSample() *RuleSet {
	rs, _, err := loadSample()
	if err != nil {
		panic(fmt.Sprintf("MustLoadSample: %v", err))
	}
	return rs
}

func loadSample() (*RuleSet, []Warning, error) {
	p, err := rootpolicy.LoadFromBytes(bytes.Clone(sampleYAML))
	if err != nil {
		return nil, nil, fmt.Errorf("LoadFromBytes: %w", err)
	}
	return Decode(p)
}
