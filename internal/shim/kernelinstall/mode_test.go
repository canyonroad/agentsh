package kernelinstall

import "testing"

func TestResolveMode(t *testing.T) {
	cases := []struct {
		name    string
		conf    string
		env     string
		want    Mode
		wantErr bool
	}{
		{name: "default", conf: "", env: "", want: ModeAuto},
		{name: "conf_auto", conf: "auto", env: "", want: ModeAuto},
		{name: "conf_on", conf: "on", env: "", want: ModeOn},
		{name: "conf_off", conf: "off", env: "", want: ModeOff},
		{name: "env_strengthens_auto_to_on", conf: "auto", env: "on", want: ModeOn},
		{name: "env_cannot_weaken_on_to_off", conf: "on", env: "off", want: ModeOn},
		{name: "env_cannot_weaken_on_to_auto", conf: "on", env: "auto", want: ModeOn},
		{name: "env_cannot_weaken_auto_to_off", conf: "auto", env: "off", want: ModeAuto},
		{name: "env_off_with_conf_off_stays_off", conf: "off", env: "off", want: ModeOff},
		{name: "env_invalid", conf: "auto", env: "maybe", wantErr: true},
		{name: "conf_invalid", conf: "yolo", env: "", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := ResolveMode(c.conf, c.env)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got mode=%v", m)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if m != c.want {
				t.Fatalf("got %v, want %v", m, c.want)
			}
		})
	}
}
