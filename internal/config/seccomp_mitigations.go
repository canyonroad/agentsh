package config

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

//go:embed mitigations/*.yaml
var builtinMitigationFS embed.FS

var mitigationIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

type EffectiveSeccompRules struct {
	SocketRules           []SandboxSeccompSocketRuleConfig
	BlockedSocketFamilies []SandboxSeccompSocketFamilyConfig
	SyscallBlock          []string
	SyscallOnBlock        string
	LoadedMitigations     []MitigationLoadInfo
}

type MitigationLoadInfo struct {
	ID                    string
	Source                string
	Path                  string
	Checksum              string
	SocketRules           int
	BlockedSocketFamilies int
	Syscalls              int
}

type mitigationDocument struct {
	Version    int               `yaml:"version"`
	ID         string            `yaml:"id"`
	Title      string            `yaml:"title,omitempty"`
	References []string          `yaml:"references,omitempty"`
	Seccomp    mitigationSeccomp `yaml:"seccomp"`
}

type mitigationSeccomp struct {
	SocketRules           []SandboxSeccompSocketRuleConfig   `yaml:"socket_rules"`
	BlockedSocketFamilies []SandboxSeccompSocketFamilyConfig `yaml:"blocked_socket_families"`
	Syscalls              mitigationSyscalls                 `yaml:"syscalls"`
}

type mitigationSyscalls struct {
	Block   []string `yaml:"block"`
	OnBlock string   `yaml:"on_block"`
}

func EffectiveSeccompRulesForConfig(in SandboxSeccompConfig) (EffectiveSeccompRules, error) {
	out := EffectiveSeccompRules{
		SocketRules:           append([]SandboxSeccompSocketRuleConfig(nil), in.SocketRules...),
		BlockedSocketFamilies: append([]SandboxSeccompSocketFamilyConfig(nil), in.BlockedSocketFamilies...),
		SyscallBlock:          append([]string(nil), in.Syscalls.Block...),
		SyscallOnBlock:        in.Syscalls.OnBlock,
	}
	if out.SyscallOnBlock == "" {
		out.SyscallOnBlock = "errno"
	}

	requests, err := requestedMitigationSetIDs(in)
	if err != nil {
		return EffectiveSeccompRules{}, err
	}
	for _, request := range requests {
		doc, info, err := loadMitigationSet(request.id, in.MitigationDirs)
		if err != nil {
			return EffectiveSeccompRules{}, fmt.Errorf("%s[%d]: %w", request.field, request.index, err)
		}
		if doc.Seccomp.Syscalls.OnBlock != "" && doc.Seccomp.Syscalls.OnBlock != out.SyscallOnBlock {
			return EffectiveSeccompRules{}, fmt.Errorf("%s[%d] %q: seccomp.syscalls.on_block %q conflicts with effective sandbox.seccomp.syscalls.on_block %q",
				request.field, request.index, request.id, doc.Seccomp.Syscalls.OnBlock, out.SyscallOnBlock)
		}
		out.SocketRules = append(out.SocketRules, doc.Seccomp.SocketRules...)
		out.BlockedSocketFamilies = append(out.BlockedSocketFamilies, doc.Seccomp.BlockedSocketFamilies...)
		out.SyscallBlock = append(out.SyscallBlock, doc.Seccomp.Syscalls.Block...)
		out.LoadedMitigations = append(out.LoadedMitigations, info)
	}
	return out, nil
}

type requestedMitigationSet struct {
	field string
	index int
	id    string
}

func requestedMitigationSetIDs(in SandboxSeccompConfig) ([]requestedMitigationSet, error) {
	requests := make([]requestedMitigationSet, 0, len(in.MitigationSets)+len(in.HardeningProfiles))
	seen := map[string]struct{}{}
	for _, source := range []struct {
		field string
		vals  []string
	}{
		{field: "mitigation_sets", vals: in.MitigationSets},
		{field: "hardening_profiles", vals: in.HardeningProfiles},
	} {
		for i, id := range source.vals {
			if !mitigationIDPattern.MatchString(id) {
				return nil, fmt.Errorf("%s[%d]: invalid mitigation set id %q", source.field, i, id)
			}
			if _, ok := seen[id]; ok {
				return nil, fmt.Errorf("duplicate mitigation set %q", id)
			}
			seen[id] = struct{}{}
			requests = append(requests, requestedMitigationSet{
				field: source.field,
				index: i,
				id:    id,
			})
		}
	}
	return requests, nil
}

func loadMitigationSet(id string, dirs []string) (mitigationDocument, MitigationLoadInfo, error) {
	builtinData, builtinFound, err := readBuiltinMitigation(id)
	if err != nil {
		return mitigationDocument{}, MitigationLoadInfo{}, err
	}
	externalData, externalPath, externalFound, err := readExternalMitigation(id, dirs)
	if err != nil {
		return mitigationDocument{}, MitigationLoadInfo{}, err
	}
	if builtinFound && externalFound {
		return mitigationDocument{}, MitigationLoadInfo{}, fmt.Errorf("%q exists as both built-in and external mitigation %q", id, externalPath)
	}
	if !builtinFound && !externalFound {
		return mitigationDocument{}, MitigationLoadInfo{}, fmt.Errorf("unknown mitigation set %q", id)
	}

	source := "builtin"
	path := mitigationFSPath(id)
	data := builtinData
	if externalFound {
		source = "external"
		path = externalPath
		data = externalData
	}
	doc, err := decodeMitigation(id, data, path)
	if err != nil {
		return mitigationDocument{}, MitigationLoadInfo{}, err
	}
	sum := sha256.Sum256(data)
	info := MitigationLoadInfo{
		ID:                    id,
		Source:                source,
		Path:                  path,
		Checksum:              "sha256:" + hex.EncodeToString(sum[:]),
		SocketRules:           len(doc.Seccomp.SocketRules),
		BlockedSocketFamilies: len(doc.Seccomp.BlockedSocketFamilies),
		Syscalls:              len(doc.Seccomp.Syscalls.Block),
	}
	return doc, info, nil
}

func readBuiltinMitigation(id string) ([]byte, bool, error) {
	data, err := builtinMitigationFS.ReadFile(mitigationFSPath(id))
	if err == nil {
		return data, true, nil
	}
	if errorsIsNotExist(err) {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("read built-in mitigation %q: %w", id, err)
}

func readExternalMitigation(id string, dirs []string) ([]byte, string, bool, error) {
	var foundPath string
	for _, dir := range dirs {
		for _, name := range []string{id + ".yaml", id + ".yml"} {
			candidate := filepath.Join(dir, name)
			if _, err := os.Stat(candidate); err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, "", false, fmt.Errorf("stat external mitigation %q: %w", candidate, err)
			}
			if foundPath != "" {
				return nil, "", false, fmt.Errorf("mitigation set %q found in multiple external files: %q and %q", id, foundPath, candidate)
			}
			foundPath = candidate
		}
	}
	if foundPath == "" {
		return nil, "", false, nil
	}
	if err := validateMitigationPathPermissions(foundPath); err != nil {
		return nil, "", false, err
	}
	data, err := os.ReadFile(foundPath)
	if err != nil {
		return nil, "", false, fmt.Errorf("read external mitigation %q: %w", foundPath, err)
	}
	return data, foundPath, true, nil
}

func decodeMitigation(requestedID string, data []byte, source string) (mitigationDocument, error) {
	var doc mitigationDocument
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return mitigationDocument{}, fmt.Errorf("parse mitigation %q: %w", source, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != nil {
		if !errors.Is(err, io.EOF) {
			return mitigationDocument{}, fmt.Errorf("parse mitigation %q: %w", source, err)
		}
	} else {
		return mitigationDocument{}, fmt.Errorf("mitigation %q: multiple YAML documents are not allowed", source)
	}
	if doc.Version != 1 {
		return mitigationDocument{}, fmt.Errorf("mitigation %q: version must be 1", source)
	}
	if doc.ID != requestedID {
		return mitigationDocument{}, fmt.Errorf("mitigation %q: id %q does not match requested id %q", source, doc.ID, requestedID)
	}
	if len(doc.Seccomp.SocketRules) == 0 &&
		len(doc.Seccomp.BlockedSocketFamilies) == 0 &&
		len(doc.Seccomp.Syscalls.Block) == 0 {
		return mitigationDocument{}, fmt.Errorf("mitigation %q: empty mitigations are not allowed", source)
	}
	return doc, nil
}

func mitigationFSPath(id string) string {
	return filepath.ToSlash(filepath.Join("mitigations", id+".yaml"))
}

func errorsIsNotExist(err error) bool {
	return os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist)
}
