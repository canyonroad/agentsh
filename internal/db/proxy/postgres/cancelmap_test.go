//go:build linux

package postgres

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestCancelMap_RegisterLookupAndRelease(t *testing.T) {
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	cm := newCancelMap(cancelMapConfig{
		Max:         10,
		GraceWindow: 5 * time.Minute,
		Now:         func() time.Time { return now },
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 1001, secret: []byte{0, 0, 0, 7}},
		}),
	})

	reg, err := cm.Register(cancelMeta{
		ServiceName:     "appdb",
		UpstreamAddr:    "127.0.0.1:15432",
		ClientIdentity:  "uid:1000",
		DBUser:          "alice",
		Database:        "app",
		ApplicationName: "psql",
		PeerUID:         1000,
	}, 42, []byte{0, 0, 0, 99})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if reg.SyntheticPID != 1001 || !bytes.Equal(reg.SyntheticSecret, []byte{0, 0, 0, 7}) {
		t.Fatalf("synthetic key = (%d,%x), want (1001,00000007)", reg.SyntheticPID, reg.SyntheticSecret)
	}

	entry, status := cm.Lookup(1001, []byte{0, 0, 0, 7})
	if status != cancelLookupFound {
		t.Fatalf("Lookup status = %v, want found", status)
	}
	if entry.RealPID != 42 || !bytes.Equal(entry.RealSecret, []byte{0, 0, 0, 99}) {
		t.Fatalf("real key = (%d,%x), want (42,00000063)", entry.RealPID, entry.RealSecret)
	}
	if entry.ServiceName != "appdb" || entry.DBUser != "alice" || entry.ClientIdentity != "uid:1000" {
		t.Fatalf("metadata not preserved: %+v", entry)
	}

	reg.Release()
	reg.Release()
	entry, status = cm.Lookup(1001, []byte{0, 0, 0, 7})
	if status != cancelLookupFound {
		t.Fatalf("Lookup after release status = %v, want found within grace", status)
	}
	if entry.DisconnectedAt.IsZero() {
		t.Fatal("DisconnectedAt was not set by Release")
	}

	now = now.Add(6 * time.Minute)
	_, status = cm.Lookup(1001, []byte{0, 0, 0, 7})
	if status != cancelLookupExpired {
		t.Fatalf("Lookup after grace status = %v, want expired", status)
	}
}

func TestCancelMap_CollisionRetryAndExhaustion(t *testing.T) {
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	cm := newCancelMap(cancelMapConfig{
		Max:         10,
		GraceWindow: time.Minute,
		Now:         func() time.Time { return now },
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 1, secret: []byte{1}},
			{pid: 1, secret: []byte{1}},
			{pid: 2, secret: []byte{2}},
		}),
	})
	if _, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 10, []byte{10}); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	reg, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 20, []byte{20})
	if err != nil {
		t.Fatalf("second Register: %v", err)
	}
	if reg.SyntheticPID != 2 || !bytes.Equal(reg.SyntheticSecret, []byte{2}) {
		t.Fatalf("second synthetic key = (%d,%x), want (2,02)", reg.SyntheticPID, reg.SyntheticSecret)
	}

	exhaust := newCancelMap(cancelMapConfig{
		Max:         10,
		GraceWindow: time.Minute,
		Now:         func() time.Time { return now },
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
		}),
	})
	if _, err := exhaust.Register(cancelMeta{ServiceName: "appdb"}, 1, []byte{1}); err != nil {
		t.Fatalf("seed Register: %v", err)
	}
	if _, err := exhaust.Register(cancelMeta{ServiceName: "appdb"}, 2, []byte{2}); !errors.Is(err, errBackendKeyGenerationFailed) {
		t.Fatalf("collision exhaustion err = %v, want errBackendKeyGenerationFailed", err)
	}
}

func TestCancelMap_CapPrunesOnlyPastGrace(t *testing.T) {
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	cm := newCancelMap(cancelMapConfig{
		Max:         2,
		GraceWindow: 5 * time.Minute,
		Now:         func() time.Time { return now },
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 1, secret: []byte{1}},
			{pid: 2, secret: []byte{2}},
			{pid: 3, secret: []byte{3}},
			{pid: 4, secret: []byte{4}},
		}),
	})
	reg1, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 11, []byte{11})
	if err != nil {
		t.Fatalf("reg1: %v", err)
	}
	if _, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 22, []byte{22}); err != nil {
		t.Fatalf("reg2: %v", err)
	}

	reg1.Release()
	if _, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 33, []byte{33}); !errors.Is(err, errBackendKeyTableFull) {
		t.Fatalf("within-grace cap err = %v, want errBackendKeyTableFull", err)
	}

	now = now.Add(6 * time.Minute)
	reg3, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 33, []byte{33})
	if err != nil {
		t.Fatalf("after-grace Register: %v", err)
	}
	if reg3.SyntheticPID != 3 {
		t.Fatalf("synthetic pid = %d, want 3", reg3.SyntheticPID)
	}
	if _, status := cm.Lookup(reg1.SyntheticPID, reg1.SyntheticSecret); status != cancelLookupMiss {
		t.Fatalf("expired pruned lookup status = %v, want miss", status)
	}
}

func TestCancelMap_RegisterClassifiesGeneratorErrors(t *testing.T) {
	generateErr := errors.New("entropy unavailable")
	cm := newCancelMap(cancelMapConfig{
		Max:         10,
		GraceWindow: time.Minute,
		Generate: func() (uint32, []byte, error) {
			return 0, nil, generateErr
		},
	})

	_, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 10, []byte{10})
	if !errors.Is(err, errBackendKeyGenerationFailed) {
		t.Fatalf("Register err = %v, want errBackendKeyGenerationFailed", err)
	}
	if !errors.Is(err, generateErr) {
		t.Fatalf("Register err = %v, want wrapped generator error", err)
	}
}

func TestCancelMap_ClonesSecrets(t *testing.T) {
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	realSecret := []byte{0, 0, 0, 99}
	cm := newCancelMap(cancelMapConfig{
		Max:         10,
		GraceWindow: time.Minute,
		Now:         func() time.Time { return now },
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 1001, secret: []byte{0, 0, 0, 7}},
		}),
	})

	reg, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 42, realSecret)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	realSecret[3] = 1
	reg.SyntheticSecret[3] = 1

	entry, status := cm.Lookup(1001, []byte{0, 0, 0, 7})
	if status != cancelLookupFound {
		t.Fatalf("Lookup status = %v, want found", status)
	}
	if !bytes.Equal(entry.RealSecret, []byte{0, 0, 0, 99}) {
		t.Fatalf("stored real secret = %x, want 00000063", entry.RealSecret)
	}
	if !bytes.Equal(entry.SyntheticSecret, []byte{0, 0, 0, 7}) {
		t.Fatalf("stored synthetic secret = %x, want 00000007", entry.SyntheticSecret)
	}

	entry.RealSecret[3] = 2
	entry.SyntheticSecret[3] = 2

	entry, status = cm.Lookup(1001, []byte{0, 0, 0, 7})
	if status != cancelLookupFound {
		t.Fatalf("second Lookup status = %v, want found", status)
	}
	if !bytes.Equal(entry.RealSecret, []byte{0, 0, 0, 99}) {
		t.Fatalf("stored real secret after lookup mutation = %x, want 00000063", entry.RealSecret)
	}
	if !bytes.Equal(entry.SyntheticSecret, []byte{0, 0, 0, 7}) {
		t.Fatalf("stored synthetic secret after lookup mutation = %x, want 00000007", entry.SyntheticSecret)
	}
}

func TestCancelMap_GenerateCancelKeyReturnsFourByteSecret(t *testing.T) {
	_, secret, err := generateCancelKey()
	if err != nil {
		t.Fatalf("generateCancelKey: %v", err)
	}
	if len(secret) != 4 {
		t.Fatalf("secret length = %d, want 4", len(secret))
	}
}

type generatedCancelKey struct {
	pid    uint32
	secret []byte
}

func fixedCancelKeyGenerator(keys []generatedCancelKey) func() (uint32, []byte, error) {
	i := 0
	return func() (uint32, []byte, error) {
		if i >= len(keys) {
			return 0, nil, errors.New("test key generator exhausted")
		}
		k := keys[i]
		i++
		return k.pid, append([]byte(nil), k.secret...), nil
	}
}
