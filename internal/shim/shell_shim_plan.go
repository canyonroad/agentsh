package shim

import (
	"fmt"
	"os"
	"path/filepath"
)

type ShellShimAction struct {
	Op   string `json:"op"`             // "skip" | "rename" | "write" | "remove" | "note"
	Path string `json:"path,omitempty"` // primary target path
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	Note string `json:"note,omitempty"`
}

type ShellShimPlan struct {
	Root    string            `json:"root"`
	Shim    string            `json:"shim,omitempty"`
	Actions []ShellShimAction `json:"actions"`
}

func PlanInstallShellShim(opts InstallShellShimOptions) (*ShellShimPlan, error) {
	root := filepath.Clean(opts.Root)
	if root == "" {
		root = "/"
	}
	if opts.ShimPath == "" {
		return nil, fmt.Errorf("shim path is required")
	}
	shimBytes, err := os.ReadFile(opts.ShimPath)
	if err != nil {
		return nil, fmt.Errorf("read shim: %w", err)
	}

	var actions []ShellShimAction
	if !opts.BashOnly {
		actions = append(actions, planInstallOne(root, "sh", shimBytes)...)
	}
	if opts.InstallBash {
		actions = append(actions, planInstallOne(root, "bash", shimBytes)...)
	}
	return &ShellShimPlan{Root: root, Shim: opts.ShimPath, Actions: actions}, nil
}

func PlanUninstallShellShim(opts InstallShellShimOptions) (*ShellShimPlan, error) {
	root := filepath.Clean(opts.Root)
	if root == "" {
		root = "/"
	}
	var actions []ShellShimAction
	actions = append(actions, planUninstallOne(root, "sh")...)
	if opts.InstallBash {
		actions = append(actions, planUninstallOne(root, "bash")...)
	}
	return &ShellShimPlan{Root: root, Actions: actions}, nil
}

func planInstallOne(root, name string, shimBytes []byte) []ShellShimAction {
	target := filepath.Join(root, "bin", name)
	real := target + ".real"

	if _, err := os.Lstat(target); err != nil {
		if os.IsNotExist(err) {
			return []ShellShimAction{{Op: "skip", Path: target, Note: "target missing"}}
		}
		return []ShellShimAction{{Op: "note", Path: target, Note: fmt.Sprintf("stat failed: %v", err)}}
	}

	actions := []ShellShimAction{}
	realExists := true
	if _, err := os.Lstat(real); err != nil {
		if os.IsNotExist(err) {
			realExists = false
		} else {
			actions = append(actions, ShellShimAction{Op: "note", Path: real, Note: fmt.Sprintf("stat failed: %v", err)})
		}
	}

	if !realExists {
		if sameFileContents(target, shimBytes) {
			actions = append(actions, ShellShimAction{
				Op:   "note",
				Path: target,
				Note: "already shimmed but missing .real; leaving untouched",
			})
			return actions
		}
		actions = append(actions, ShellShimAction{Op: "rename", From: target, To: real})
	}

	if sameFileContents(target, shimBytes) {
		actions = append(actions, ShellShimAction{Op: "note", Path: target, Note: "shim already installed"})
		return actions
	}
	actions = append(actions, ShellShimAction{Op: "write", Path: target, Note: "write shim bytes"})
	return actions
}

func planUninstallOne(root, name string) []ShellShimAction {
	target := filepath.Join(root, "bin", name)
	real := target + ".real"

	if _, err := os.Lstat(real); err != nil {
		if os.IsNotExist(err) {
			return []ShellShimAction{{Op: "skip", Path: real, Note: ".real missing"}}
		}
		return []ShellShimAction{{Op: "note", Path: real, Note: fmt.Sprintf("stat failed: %v", err)}}
	}
	return []ShellShimAction{
		{Op: "remove", Path: target, Note: "remove current target (best effort)"},
		{Op: "rename", From: real, To: target},
	}
}
