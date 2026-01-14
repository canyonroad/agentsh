//go:build linux

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// AttachConnectToCgroup loads the connect programs and attaches them to the given cgroup path.
// Returns the collection (caller must not close it until done) and a detach func.
func AttachConnectToCgroup(cgroupPath string) (*ebpf.Collection, func() error, error) {
	coll, err := LoadConnectProgram()
	if err != nil {
		return nil, nil, err
	}
	if len(coll.Programs) == 0 {
		coll.Close()
		return nil, nil, fmt.Errorf("ebpf connect object has no programs")
	}

	var links []link.Link
	attach := func(progName string, attachType ebpf.AttachType) error {
		prog, ok := coll.Programs[progName]
		if !ok {
			return fmt.Errorf("program %s not found", progName)
		}
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  attachType,
			Program: prog,
		})
		if err != nil {
			return err
		}
		links = append(links, l)
		return nil
	}

	if err := attach("handle_connect4", ebpf.AttachCGroupInet4Connect); err != nil {
		closeLinks(links)
		coll.Close()
		return nil, nil, fmt.Errorf("attach connect4: %w", err)
	}
	if err := attach("handle_connect6", ebpf.AttachCGroupInet6Connect); err != nil {
		closeLinks(links)
		coll.Close()
		return nil, nil, fmt.Errorf("attach connect6: %w", err)
	}

	// Attach UDP sendmsg hooks for capturing outbound UDP traffic
	if err := attach("handle_sendmsg4", ebpf.AttachCGroupUDP4Sendmsg); err != nil {
		closeLinks(links)
		coll.Close()
		return nil, nil, fmt.Errorf("attach sendmsg4: %w", err)
	}
	if err := attach("handle_sendmsg6", ebpf.AttachCGroupUDP6Sendmsg); err != nil {
		closeLinks(links)
		coll.Close()
		return nil, nil, fmt.Errorf("attach sendmsg6: %w", err)
	}

	return coll, func() error {
		closeLinks(links)
		coll.Close()
		return nil
	}, nil
}

func closeLinks(ls []link.Link) {
	for _, l := range ls {
		_ = l.Close()
	}
}
