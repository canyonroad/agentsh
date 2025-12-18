package shim

import (
	"fmt"
	"os"
	"path/filepath"
)

type ShellShimTargetStatus struct {
	Name       string `json:"name"`
	TargetPath string `json:"target_path"`
	RealPath   string `json:"real_path"`

	// State is a convenience summary derived from the other fields:
	// - "missing": target doesn't exist
	// - "installed": target matches shim and .real exists
	// - "partial_missing_real": target matches shim but .real is missing
	// - "not_installed": target exists but does not match shim (or shim not provided)
	State string `json:"state"`

	TargetExists bool   `json:"target_exists"`
	TargetMode   uint32 `json:"target_mode,omitempty"`
	TargetType   string `json:"target_type,omitempty"` // "file" | "symlink" | "other"
	TargetLink   string `json:"target_link,omitempty"`

	RealExists bool   `json:"real_exists"`
	RealMode   uint32 `json:"real_mode,omitempty"`
	RealType   string `json:"real_type,omitempty"`
	RealLink   string `json:"real_link,omitempty"`

	ShimMatches bool `json:"shim_matches"` // only true when shim bytes provided and target is a regular file
}

type ShellShimStatus struct {
	Root string `json:"root"`

	ShimPath string `json:"shim_path,omitempty"`

	Sh   ShellShimTargetStatus  `json:"sh"`
	Bash *ShellShimTargetStatus `json:"bash,omitempty"`
}

func GetShellShimStatus(root string, shimPath string, includeBash bool) (ShellShimStatus, error) {
	root = filepath.Clean(root)
	if root == "" {
		root = "/"
	}

	var shimBytes []byte
	var err error
	if shimPath != "" {
		shimBytes, err = os.ReadFile(shimPath)
		if err != nil {
			return ShellShimStatus{}, fmt.Errorf("read shim: %w", err)
		}
	}

	sh, err := getTargetStatus(root, "sh", shimBytes)
	if err != nil {
		return ShellShimStatus{}, err
	}

	var bash *ShellShimTargetStatus
	if includeBash {
		b, err := getTargetStatus(root, "bash", shimBytes)
		if err != nil {
			return ShellShimStatus{}, err
		}
		bash = &b
	}

	return ShellShimStatus{
		Root:     root,
		ShimPath: shimPath,
		Sh:       sh,
		Bash:     bash,
	}, nil
}

func getTargetStatus(root, name string, shimBytes []byte) (ShellShimTargetStatus, error) {
	target := filepath.Join(root, "bin", name)
	real := target + ".real"

	out := ShellShimTargetStatus{
		Name:       name,
		TargetPath: target,
		RealPath:   real,
	}

	if fi, err := os.Lstat(target); err == nil {
		out.TargetExists = true
		out.TargetMode = uint32(fi.Mode())
		switch {
		case fi.Mode().IsRegular():
			out.TargetType = "file"
			if len(shimBytes) > 0 && sameFileContents(target, shimBytes) {
				out.ShimMatches = true
			}
		case fi.Mode()&os.ModeSymlink != 0:
			out.TargetType = "symlink"
			if link, err := os.Readlink(target); err == nil {
				out.TargetLink = link
			}
		default:
			out.TargetType = "other"
		}
	} else if !os.IsNotExist(err) {
		return ShellShimTargetStatus{}, fmt.Errorf("stat %s: %w", target, err)
	}

	if fi, err := os.Lstat(real); err == nil {
		out.RealExists = true
		out.RealMode = uint32(fi.Mode())
		switch {
		case fi.Mode().IsRegular():
			out.RealType = "file"
		case fi.Mode()&os.ModeSymlink != 0:
			out.RealType = "symlink"
			if link, err := os.Readlink(real); err == nil {
				out.RealLink = link
			}
		default:
			out.RealType = "other"
		}
	} else if !os.IsNotExist(err) {
		return ShellShimTargetStatus{}, fmt.Errorf("stat %s: %w", real, err)
	}

	// Compute State last.
	switch {
	case !out.TargetExists:
		out.State = "missing"
	case len(shimBytes) == 0:
		out.State = "not_installed"
	case out.ShimMatches && out.RealExists:
		out.State = "installed"
	case out.ShimMatches && !out.RealExists:
		out.State = "partial_missing_real"
	default:
		out.State = "not_installed"
	}

	return out, nil
}
