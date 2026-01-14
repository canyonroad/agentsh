// Quick test to run PNACL monitor with eBPF
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/netmonitor/ebpf"
	"github.com/agentsh/agentsh/internal/netmonitor/pnacl"
)

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("Must run as root to load eBPF programs")
	}

	// Load PNACL config - use SUDO_USER's home if running with sudo
	configPath := os.Getenv("HOME") + "/.config/agentsh/network-acl.yml"
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		// Running with sudo - use original user's config
		configPath = "/home/" + sudoUser + "/.config/agentsh/network-acl.yml"
	}
	// Allow override via command line arg
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}
	config, err := pnacl.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create policy engine
	engine, err := pnacl.NewPolicyEngine(config)
	if err != nil {
		log.Fatalf("Failed to create policy engine: %v", err)
	}

	// Create process filter
	filter := ebpf.NewProcessFilter(engine)
	defer filter.Close()

	// Set up callbacks for logging
	filter.SetOnAllow(func(ev *ebpf.ConnectionEvent) {
		procName := "unknown"
		if ev.Process != nil {
			procName = ev.Process.Name
		}
		fmt.Printf("✅ ALLOW: %s (pid:%d) -> %s:%d (%s)\n",
			procName, ev.PID, ev.Host, ev.DstPort, ev.Protocol)
	})

	filter.SetOnDeny(func(ev *ebpf.ConnectionEvent) {
		procName := "unknown"
		if ev.Process != nil {
			procName = ev.Process.Name
		}
		fmt.Printf("❌ DENY: %s (pid:%d) -> %s:%d (%s)\n",
			procName, ev.PID, ev.Host, ev.DstPort, ev.Protocol)
	})

	filter.SetOnAudit(func(ev *ebpf.ConnectionEvent) {
		procName := "unknown"
		if ev.Process != nil {
			procName = ev.Process.Name
		}
		fmt.Printf("📝 AUDIT: %s (pid:%d) -> %s:%d (%s)\n",
			procName, ev.PID, ev.Host, ev.DstPort, ev.Protocol)
	})

	// Load and attach eBPF programs to root cgroup
	cgroupPath := "/sys/fs/cgroup"
	coll, cleanup, err := ebpf.AttachConnectToCgroup(cgroupPath)
	if err != nil {
		log.Fatalf("Failed to attach eBPF programs: %v", err)
	}
	defer cleanup()

	// Start the event collector
	collector, err := ebpf.StartCollector(coll, 1024)
	if err != nil {
		log.Fatalf("Failed to start collector: %v", err)
	}
	defer collector.Close()

	fmt.Println("PNACL Monitor started - watching network connections...")
	fmt.Println("Config:", configPath)
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Process events
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	// Process events from collector
	eventCh := collector.Events()
	filterConfig := &ebpf.ProcessFilterConfig{
		ApprovalTimeout:  30 * time.Second,
		DefaultOnTimeout: pnacl.DecisionDeny,
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-eventCh:
			if !ok {
				return
			}
			filter.ProcessEvent(ctx, &ev, filterConfig)
		}
	}
}
