//go:build linux

package ebpf

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/cilium/ebpf"
)

var (
	lastAllowCgroup    uint64
	lastDenyCgroup     uint64
	lastLpmAllowCgroup uint64
	lastLpmDenyCgroup  uint64
	lastAllowTotal     uint64
	lastDenyTotal      uint64
	lastLpmAllowTotal  uint64
	lastLpmDenyTotal   uint64
)

// MapCounts is a best-effort snapshot from the last PopulateAllowlist call.
type MapCounts struct {
	AllowCgroup    uint64
	AllowTotal     uint64
	DenyCgroup     uint64
	DenyTotal      uint64
	LpmAllowCgroup uint64
	LpmAllowTotal  uint64
	LpmDenyCgroup  uint64
	LpmDenyTotal   uint64
}

func GetLastMapCounts() MapCounts {
	return MapCounts{
		AllowCgroup:    atomic.LoadUint64(&lastAllowCgroup),
		AllowTotal:     atomic.LoadUint64(&lastAllowTotal),
		DenyCgroup:     atomic.LoadUint64(&lastDenyCgroup),
		DenyTotal:      atomic.LoadUint64(&lastDenyTotal),
		LpmAllowCgroup: atomic.LoadUint64(&lastLpmAllowCgroup),
		LpmAllowTotal:  atomic.LoadUint64(&lastLpmAllowTotal),
		LpmDenyCgroup:  atomic.LoadUint64(&lastLpmDenyCgroup),
		LpmDenyTotal:   atomic.LoadUint64(&lastLpmDenyTotal),
	}
}

// PopulateAllowlist loads allowed/denied endpoints, CIDRs, and default_deny into the collection maps.
func PopulateAllowlist(coll *ebpf.Collection, cgroupID uint64, allow []AllowKey, allowCIDRs []AllowCIDR, deny []AllowKey, denyCIDRs []AllowCIDR, defaultDeny bool) error {
	if coll == nil {
		return fmt.Errorf("nil collection")
	}
	allowMap, ok := coll.Maps["allowlist"]
	if !ok {
		return fmt.Errorf("allowlist map missing")
	}
	denyMap, ok := coll.Maps["denylist"]
	if !ok {
		return fmt.Errorf("denylist map missing")
	}
	defdeny, ok := coll.Maps["default_deny"]
	if !ok {
		return fmt.Errorf("default_deny map missing")
	}
	lpm4 := coll.Maps["lpm4_allow"]
	lpm6 := coll.Maps["lpm6_allow"]
	lpm4deny := coll.Maps["lpm4_deny"]
	lpm6deny := coll.Maps["lpm6_deny"]

	// Clear existing LPM entries for this cgroup.
	if lpm4 != nil {
		type lpm4Key struct {
			Prefixlen uint32
			CgroupID  uint64
			Addr      [4]byte
			Dport     uint16
		}
		iter := lpm4.Iterate()
		var k lpm4Key
		var v uint8
		for iter.Next(&k, &v) {
			if k.CgroupID == cgroupID {
				_ = lpm4.Delete(k)
			}
		}
		if err := iter.Err(); err != nil {
			return fmt.Errorf("iterate lpm4: %w", err)
		}
	}
	if lpm6 != nil {
		type lpm6Key struct {
			Prefixlen uint32
			CgroupID  uint64
			Addr      [16]byte
			Dport     uint16
		}
		iter := lpm6.Iterate()
		var k lpm6Key
		var v uint8
		for iter.Next(&k, &v) {
			if k.CgroupID == cgroupID {
				_ = lpm6.Delete(k)
			}
		}
		if err := iter.Err(); err != nil {
			return fmt.Errorf("iterate lpm6: %w", err)
		}
	}

	// Remove existing entries for this cgroup first to avoid stale allows after policy changes.
	iter := allowMap.Iterate()
	var k AllowKey
	var v uint8
	var allowInserted uint64
	var denyInserted uint64
	var lpmAllowInserted uint64
	var lpmDenyInserted uint64
	var allowRemoved uint64
	var denyRemoved uint64
	var allowTotalBefore uint64
	var denyTotalBefore uint64
	var lpmAllowTotal uint64
	var lpmDenyTotal uint64
	for iter.Next(&k, &v) {
		allowTotalBefore++
		if k.CgroupID == cgroupID {
			_ = allowMap.Delete(k) // best effort
			allowRemoved++
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate allowlist: %w", err)
	}

	// Clear deny exact map
	iter = denyMap.Iterate()
	for iter.Next(&k, &v) {
		denyTotalBefore++
		if k.CgroupID == cgroupID {
			_ = denyMap.Delete(k)
			denyRemoved++
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate denylist: %w", err)
	}

	for _, e := range allow {
		key := e
		key.CgroupID = cgroupID
		val := uint8(1)
		if err := allowMap.Put(key, val); err != nil {
			return fmt.Errorf("put allowlist: %w", err)
		}
		allowInserted++
	}

	for _, e := range deny {
		key := e
		key.CgroupID = cgroupID
		val := uint8(1)
		if err := denyMap.Put(key, val); err != nil {
			return fmt.Errorf("put denylist: %w", err)
		}
		denyInserted++
	}

	// Load CIDRs into LPM tries.
	for _, c := range allowCIDRs {
		if c.Family == 2 && lpm4 != nil {
			type lpm4Key struct {
				Prefixlen uint32
				CgroupID  uint64
				Addr      [4]byte
				Dport     uint16
			}
			var key lpm4Key
			if c.Dport != 0 {
				key.Prefixlen = 64 + c.PrefixLen + 16
			} else {
				key.Prefixlen = 64 + c.PrefixLen
			}
			key.CgroupID = cgroupID
			copy(key.Addr[:], c.Addr[:4])
			key.Dport = c.Dport
			val := uint8(1)
			if err := lpm4.Put(key, val); err != nil {
				return fmt.Errorf("put lpm4 allow: %w", err)
			}
			lpmAllowInserted++
		} else if c.Family == 10 && lpm6 != nil {
			type lpm6Key struct {
				Prefixlen uint32
				CgroupID  uint64
				Addr      [16]byte
				Dport     uint16
			}
			var key lpm6Key
			if c.Dport != 0 {
				key.Prefixlen = 64 + c.PrefixLen + 16
			} else {
				key.Prefixlen = 64 + c.PrefixLen
			}
			key.CgroupID = cgroupID
			copy(key.Addr[:], c.Addr[:])
			key.Dport = c.Dport
			val := uint8(1)
			if err := lpm6.Put(key, val); err != nil {
				return fmt.Errorf("put lpm6 allow: %w", err)
			}
			lpmAllowInserted++
		}
	}
	// Count LPM allow totals after insertion (best effort, may race)
	if lpm4 != nil {
		type lpm4Key struct {
			Prefixlen uint32
			CgroupID  uint64
			Addr      [4]byte
			Dport     uint16
		}
		iter := lpm4.Iterate()
		var k lpm4Key
		var v uint8
		for iter.Next(&k, &v) {
			lpmAllowTotal++
		}
	}
	if lpm6 != nil {
		type lpm6Key struct {
			Prefixlen uint32
			CgroupID  uint64
			Addr      [16]byte
			Dport     uint16
		}
		iter := lpm6.Iterate()
		var k lpm6Key
		var v uint8
		for iter.Next(&k, &v) {
			lpmAllowTotal++
		}
	}
	for _, c := range denyCIDRs {
		if c.Family == 2 && lpm4deny != nil {
			type lpm4Key struct {
				Prefixlen uint32
				CgroupID  uint64
				Addr      [4]byte
				Dport     uint16
			}
			var key lpm4Key
			if c.Dport != 0 {
				key.Prefixlen = 64 + c.PrefixLen + 16
			} else {
				key.Prefixlen = 64 + c.PrefixLen
			}
			key.CgroupID = cgroupID
			copy(key.Addr[:], c.Addr[:4])
			key.Dport = c.Dport
			val := uint8(1)
			if err := lpm4deny.Put(key, val); err != nil {
				return fmt.Errorf("put lpm4 deny: %w", err)
			}
			lpmDenyInserted++
		} else if c.Family == 10 && lpm6deny != nil {
			type lpm6Key struct {
				Prefixlen uint32
				CgroupID  uint64
				Addr      [16]byte
				Dport     uint16
			}
			var key lpm6Key
			if c.Dport != 0 {
				key.Prefixlen = 64 + c.PrefixLen + 16
			} else {
				key.Prefixlen = 64 + c.PrefixLen
			}
			key.CgroupID = cgroupID
			copy(key.Addr[:], c.Addr[:])
			key.Dport = c.Dport
			val := uint8(1)
			if err := lpm6deny.Put(key, val); err != nil {
				return fmt.Errorf("put lpm6 deny: %w", err)
			}
			lpmDenyInserted++
		}
	}
	if lpm4deny != nil {
		type lpm4Key struct {
			Prefixlen uint32
			CgroupID  uint64
			Addr      [4]byte
			Dport     uint16
		}
		iter := lpm4deny.Iterate()
		var k lpm4Key
		var v uint8
		for iter.Next(&k, &v) {
			lpmDenyTotal++
		}
	}
	if lpm6deny != nil {
		type lpm6Key struct {
			Prefixlen uint32
			CgroupID  uint64
			Addr      [16]byte
			Dport     uint16
		}
		iter := lpm6deny.Iterate()
		var k lpm6Key
		var v uint8
		for iter.Next(&k, &v) {
			lpmDenyTotal++
		}
	}

	// default_deny keyed by cgroup id
	var defVal uint8 = 0
	if defaultDeny {
		defVal = 1
	}
	if err := defdeny.Put(cgroupID, defVal); err != nil {
		return fmt.Errorf("set default_deny: %w", err)
	}

	allowTotal := allowTotalBefore - allowRemoved + allowInserted
	denyTotal := denyTotalBefore - denyRemoved + denyInserted
	atomic.StoreUint64(&lastAllowCgroup, allowInserted)
	atomic.StoreUint64(&lastDenyCgroup, denyInserted)
	atomic.StoreUint64(&lastLpmAllowCgroup, lpmAllowInserted)
	atomic.StoreUint64(&lastLpmDenyCgroup, lpmDenyInserted)
	atomic.StoreUint64(&lastAllowTotal, allowTotal)
	atomic.StoreUint64(&lastDenyTotal, denyTotal)
	atomic.StoreUint64(&lastLpmAllowTotal, lpmAllowTotal)
	atomic.StoreUint64(&lastLpmDenyTotal, lpmDenyTotal)
	return nil
}

// CleanupAllowlist removes allowlist entries and default-deny flag for a cgroup.
func CleanupAllowlist(coll *ebpf.Collection, cgroupID uint64) error {
	if coll == nil {
		return nil
	}
	allow, ok := coll.Maps["allowlist"]
	if ok {
		iter := allow.Iterate()
		var k AllowKey
		var v uint8
		for iter.Next(&k, &v) {
			if k.CgroupID == cgroupID {
				_ = allow.Delete(k) // best effort
			}
		}
		if err := iter.Err(); err != nil {
			return err
		}
	}
	if lpm4, ok := coll.Maps["lpm4_allow"]; ok {
		type lpm4Key struct {
			Prefixlen uint32
			CgroupID  uint64
			Addr      [4]byte
			Dport     uint16
		}
		iter := lpm4.Iterate()
		var k lpm4Key
		var v uint8
		for iter.Next(&k, &v) {
			if k.CgroupID == cgroupID {
				_ = lpm4.Delete(k)
			}
		}
		if err := iter.Err(); err != nil {
			return err
		}
	}
	if lpm6, ok := coll.Maps["lpm6_allow"]; ok {
		type lpm6Key struct {
			Prefixlen uint32
			CgroupID  uint64
			Addr      [16]byte
			Dport     uint16
		}
		iter := lpm6.Iterate()
		var k lpm6Key
		var v uint8
		for iter.Next(&k, &v) {
			if k.CgroupID == cgroupID {
				_ = lpm6.Delete(k)
			}
		}
		if err := iter.Err(); err != nil {
			return err
		}
	}
	if defdeny, ok := coll.Maps["default_deny"]; ok {
		_ = defdeny.Delete(cgroupID)
	}
	return nil
}

func isNoEntry(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "no such file or directory") || strings.Contains(err.Error(), "not found")
}
