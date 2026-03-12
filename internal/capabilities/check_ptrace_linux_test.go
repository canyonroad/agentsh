//go:build linux

package capabilities

import "testing"

func TestReadCapEff(t *testing.T) {
	capEff, err := readCapEff()
	if err != nil {
		t.Fatalf("readCapEff() error: %v", err)
	}
	t.Logf("CapEff = 0x%016x", capEff)
}

func TestReadCapEffParsing(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint64
		wantErr bool
	}{
		{
			name:  "standard format",
			input: "Name:\ttest\nCapEff:\t000001ffffffffff\nPPid:\t1\n",
			want:  0x000001ffffffffff,
		},
		{
			name:    "missing CapEff",
			input:   "Name:\ttest\nPPid:\t1\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCapEff(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCapEff() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseCapEff() = 0x%x, want 0x%x", got, tt.want)
			}
		})
	}
}

func TestProbePtraceAttach(t *testing.T) {
	result := probePtraceAttach()
	t.Logf("probePtraceAttach() = %v", result)
}

func TestCheckPtraceCapability(t *testing.T) {
	result := checkPtraceCapability()
	t.Logf("checkPtraceCapability() = %v", result)
}
