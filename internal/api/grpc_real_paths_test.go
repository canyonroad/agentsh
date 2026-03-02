package api

import (
	"encoding/json"
	"testing"
)

func TestCreateSessionRequestCompat_RealPaths_TriState(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		wantNil  bool
		wantBool bool
	}{
		{
			name:    "absent (nil)",
			json:    `{"id":"s1","workspace":"/tmp","policy":"default"}`,
			wantNil: true,
		},
		{
			name:     "explicit true",
			json:     `{"id":"s1","workspace":"/tmp","policy":"default","real_paths":true}`,
			wantNil:  false,
			wantBool: true,
		},
		{
			name:     "explicit false",
			json:     `{"id":"s1","workspace":"/tmp","policy":"default","real_paths":false}`,
			wantNil:  false,
			wantBool: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var compat CreateSessionRequestCompat
			if err := json.Unmarshal([]byte(tt.json), &compat); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}

			if tt.wantNil {
				if compat.RealPaths != nil {
					t.Errorf("compat.RealPaths = %v, want nil", *compat.RealPaths)
				}
			} else {
				if compat.RealPaths == nil {
					t.Fatal("compat.RealPaths = nil, want non-nil")
				}
				if *compat.RealPaths != tt.wantBool {
					t.Errorf("compat.RealPaths = %v, want %v", *compat.RealPaths, tt.wantBool)
				}
			}

			// Verify ToTypes preserves the value
			req := compat.ToTypes()
			if tt.wantNil {
				if req.RealPaths != nil {
					t.Errorf("req.RealPaths = %v, want nil after ToTypes()", *req.RealPaths)
				}
			} else {
				if req.RealPaths == nil {
					t.Fatal("req.RealPaths = nil after ToTypes(), want non-nil")
				}
				if *req.RealPaths != tt.wantBool {
					t.Errorf("req.RealPaths = %v after ToTypes(), want %v", *req.RealPaths, tt.wantBool)
				}
			}
		})
	}
}
