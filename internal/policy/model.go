package policy

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	Version     int    `yaml:"version"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	FileRules    []FileRule       `yaml:"file_rules"`
	NetworkRules []NetworkRule    `yaml:"network_rules"`
	CommandRules []CommandRule    `yaml:"command_rules"`
	UnixRules    []UnixSocketRule `yaml:"unix_socket_rules"`

	ResourceLimits ResourceLimits `yaml:"resource_limits"`
}

type FileRule struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Paths       []string `yaml:"paths"`
	Operations  []string `yaml:"operations"`
	Decision    string   `yaml:"decision"`
	Message     string   `yaml:"message"`
	Timeout     duration `yaml:"timeout"`
}

type NetworkRule struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Domains     []string `yaml:"domains"`
	Ports       []int    `yaml:"ports"`
	CIDRs       []string `yaml:"cidrs"`
	Decision    string   `yaml:"decision"`
	Message     string   `yaml:"message"`
	Timeout     duration `yaml:"timeout"`
}

type CommandRule struct {
	Name         string           `yaml:"name"`
	Description  string           `yaml:"description"`
	Commands     []string         `yaml:"commands"`
	ArgsPatterns []string         `yaml:"args_patterns"`
	Decision     string           `yaml:"decision"`
	Message      string           `yaml:"message"`
	RedirectTo   *CommandRedirect `yaml:"redirect_to,omitempty"`
}

type CommandRedirect struct {
	Command string   `yaml:"command"`
	Args    []string `yaml:"args,omitempty"`
}

// UnixSocketRule controls AF_UNIX socket operations such as connect/bind/listen.
// Paths refer to filesystem socket paths; abstract namespace sockets use "@name" (no leading slash).
type UnixSocketRule struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Paths       []string `yaml:"paths"`
	Operations  []string `yaml:"operations"` // connect|bind|listen|sendto; empty = all
	Decision    string   `yaml:"decision"`   // allow|deny|approve
	Message     string   `yaml:"message"`
	Timeout     duration `yaml:"timeout"`
}

type ResourceLimits struct {
	MaxMemoryMB      int      `yaml:"max_memory_mb"`
	MemorySwapMaxMB  int      `yaml:"memory_swap_max_mb"`
	CPUQuotaPercent  int      `yaml:"cpu_quota_percent"`
	DiskReadBpsMax   int64    `yaml:"disk_read_bps_max"`
	DiskWriteBpsMax  int64    `yaml:"disk_write_bps_max"`
	NetBandwidthMbps int      `yaml:"net_bandwidth_mbps"`
	PidsMax          int      `yaml:"pids_max"`
	CommandTimeout   duration `yaml:"command_timeout"`
	SessionTimeout   duration `yaml:"session_timeout"`
	IdleTimeout      duration `yaml:"idle_timeout"`
}

type duration struct{ time.Duration }

func (d *duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be scalar")
	}
	dd, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	d.Duration = dd
	return nil
}
