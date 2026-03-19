package config

import "testing"

func TestSigningConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SigningConfig
		wantErr bool
	}{
		{"empty is valid", SigningConfig{}, false},
		{"off is valid", SigningConfig{Mode: "off"}, false},
		{"warn with trust store", SigningConfig{Mode: "warn", TrustStore: "/keys"}, false},
		{"enforce with trust store", SigningConfig{Mode: "enforce", TrustStore: "/keys"}, false},
		{"invalid mode", SigningConfig{Mode: "strict"}, true},
		{"enforce without trust store", SigningConfig{Mode: "enforce"}, true},
		{"warn without trust store", SigningConfig{Mode: "warn"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSigningConfig_SigningMode(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{"", "off"},
		{"off", "off"},
		{"warn", "warn"},
		{"enforce", "enforce"},
	}
	for _, tt := range tests {
		cfg := SigningConfig{Mode: tt.mode}
		if got := cfg.SigningMode(); got != tt.want {
			t.Errorf("SigningMode(%q) = %q, want %q", tt.mode, got, tt.want)
		}
	}
}
