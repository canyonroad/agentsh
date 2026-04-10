package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ShimConf is the parsed shim configuration.
type ShimConf struct {
	Force     bool              // force=true|1
	ReadyGate bool              // ready_gate=true|1
	Raw       map[string]string // all key=value pairs for forward compat
}

// ShimConfPath returns the config file path under root.
func ShimConfPath(root string) string {
	if root == "" {
		root = "/"
	}
	return filepath.Join(root, "etc", "agentsh", "shim.conf")
}

// ReadShimConf reads the config file at ShimConfPath(root).
// Missing file (ENOENT) returns empty conf with nil error.
// Other read errors return empty conf and the error.
func ReadShimConf(root string) (ShimConf, error) {
	conf := ShimConf{Raw: make(map[string]string)}
	data, err := os.ReadFile(ShimConfPath(root))
	if err != nil {
		if os.IsNotExist(err) {
			return conf, nil
		}
		return conf, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		conf.Raw[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	conf.Force = conf.Raw["force"] == "true" || conf.Raw["force"] == "1"
	conf.ReadyGate = conf.Raw["ready_gate"] == "true" || conf.Raw["ready_gate"] == "1"
	// Strict validation: if "force" key is present but not a recognized value,
	// return an error to prevent silent fail-open from typos like "force=tru".
	if v, ok := conf.Raw["force"]; ok {
		switch v {
		case "true", "1", "false", "0":
			// valid
		default:
			return conf, fmt.Errorf("shim.conf: invalid force value %q (expected true, 1, false, or 0)", v)
		}
	}
	if v, ok := conf.Raw["ready_gate"]; ok {
		switch v {
		case "true", "1", "false", "0":
			// valid
		default:
			return conf, fmt.Errorf("shim.conf: invalid ready_gate value %q (expected true, 1, false, or 0)", v)
		}
	}
	return conf, nil
}

// WriteShimConf writes all keys from conf.Raw as key=value lines.
// Creates /etc/agentsh/ directory (mode 0o755) if needed.
// File is written atomically with mode 0o644.
func WriteShimConf(root string, conf ShimConf) error {
	keys := make([]string, 0, len(conf.Raw))
	for k := range conf.Raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf strings.Builder
	buf.WriteString("# Written by: agentsh shim install-shell\n")
	for _, k := range keys {
		fmt.Fprintf(&buf, "%s=%s\n", k, conf.Raw[k])
	}
	return writeFileAtomic(ShimConfPath(root), []byte(buf.String()), 0o644)
}
