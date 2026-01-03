//go:build darwin

package platform

import (
	"encoding/json"
	"os/exec"
)

// limaInstance represents a Lima VM instance from limactl list --json.
type limaInstance struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// isLimaAvailable checks if Lima is installed and has a running VM.
// Lima provides full Linux capabilities on macOS via a lightweight VM.
func isLimaAvailable() bool {
	// Check if limactl is installed
	limactlPath, err := exec.LookPath("limactl")
	if err != nil {
		return false
	}

	// Check for running instances
	cmd := exec.Command(limactlPath, "list", "--json")
	out, err := cmd.Output()
	if err != nil {
		return false
	}

	// Parse JSON output
	var instances []limaInstance
	if err := json.Unmarshal(out, &instances); err != nil {
		return false
	}

	// Check if any instance is running
	for _, inst := range instances {
		if inst.Status == "Running" {
			return true
		}
	}

	return false
}

// getLimaDefaultInstance returns the name of the default or first running Lima instance.
func getLimaDefaultInstance() string {
	limactlPath, err := exec.LookPath("limactl")
	if err != nil {
		return "default"
	}

	cmd := exec.Command(limactlPath, "list", "--json")
	out, err := cmd.Output()
	if err != nil {
		return "default"
	}

	var instances []limaInstance
	if err := json.Unmarshal(out, &instances); err != nil {
		return "default"
	}

	// Return first running instance, or "default" if none
	for _, inst := range instances {
		if inst.Status == "Running" {
			return inst.Name
		}
	}

	return "default"
}
