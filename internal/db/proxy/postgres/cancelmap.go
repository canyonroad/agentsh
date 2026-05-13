//go:build linux

package postgres

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	defaultCancelMappingMax    = 100000
	defaultCancelGraceWindow   = 5 * time.Minute
	cancelKeyGenerationRetries = 8
)

var (
	errBackendKeyGenerationFailed = errors.New("BACKEND_KEY_GENERATION_FAILED")
	errBackendKeyTableFull        = errors.New("BACKEND_KEY_TABLE_FULL")
)

type cancelLookupStatus uint8

const (
	cancelLookupMiss cancelLookupStatus = iota
	cancelLookupExpired
	cancelLookupFound
)

type cancelMapConfig struct {
	Max         int
	GraceWindow time.Duration
	Now         func() time.Time
	Generate    func() (uint32, []byte, error)
}

type cancelMeta struct {
	AgentSessionID  string
	ServiceName     string
	UpstreamAddr    string
	ClientIdentity  string
	DBUser          string
	Database        string
	ApplicationName string
	PeerUID         uint32
}

type cancelEntry struct {
	cancelMeta
	RealPID         uint32
	RealSecret      []byte
	SyntheticPID    uint32
	SyntheticSecret []byte
	CreatedAt       time.Time
	DisconnectedAt  time.Time
}

type cancelRegistration struct {
	SyntheticPID    uint32
	SyntheticSecret []byte

	once    sync.Once
	release func()
}

func (r *cancelRegistration) Release() {
	if r == nil || r.release == nil {
		return
	}
	r.once.Do(r.release)
}

type cancelKey struct {
	pid    uint32
	secret string
}

func newCancelKey(pid uint32, secret []byte) cancelKey {
	return cancelKey{
		pid:    pid,
		secret: string(append([]byte(nil), secret...)),
	}
}

type cancelMap struct {
	mu          sync.Mutex
	entries     map[cancelKey]*cancelEntry
	max         int
	graceWindow time.Duration
	now         func() time.Time
	generate    func() (uint32, []byte, error)
}

func newCancelMap(cfg cancelMapConfig) *cancelMap {
	if cfg.Max <= 0 {
		cfg.Max = defaultCancelMappingMax
	}
	if cfg.GraceWindow <= 0 {
		cfg.GraceWindow = defaultCancelGraceWindow
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Generate == nil {
		cfg.Generate = generateCancelKey
	}

	return &cancelMap{
		entries:     make(map[cancelKey]*cancelEntry),
		max:         cfg.Max,
		graceWindow: cfg.GraceWindow,
		now:         cfg.Now,
		generate:    cfg.Generate,
	}
}

func (m *cancelMap) Register(meta cancelMeta, realPID uint32, realSecret []byte) (cancelRegistration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	if len(m.entries) >= m.max {
		m.pruneExpiredLocked(now)
	}
	if len(m.entries) >= m.max {
		return cancelRegistration{}, errBackendKeyTableFull
	}

	for i := 0; i < cancelKeyGenerationRetries; i++ {
		pid, secret, err := m.generate()
		if err != nil {
			return cancelRegistration{}, errors.Join(errBackendKeyGenerationFailed, err)
		}

		key := newCancelKey(pid, secret)
		if _, exists := m.entries[key]; exists {
			continue
		}

		entry := &cancelEntry{
			cancelMeta:      meta,
			RealPID:         realPID,
			RealSecret:      cloneBytes(realSecret),
			SyntheticPID:    pid,
			SyntheticSecret: cloneBytes(secret),
			CreatedAt:       now,
		}
		m.entries[key] = entry

		reg := cancelRegistration{
			SyntheticPID:    pid,
			SyntheticSecret: cloneBytes(secret),
		}
		reg.release = func() {
			m.MarkDisconnected(key)
		}
		return reg, nil
	}

	return cancelRegistration{}, errBackendKeyGenerationFailed
}

func (m *cancelMap) Lookup(pid uint32, secret []byte) (cancelEntry, cancelLookupStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := newCancelKey(pid, secret)
	entry, ok := m.entries[key]
	if !ok {
		return cancelEntry{}, cancelLookupMiss
	}
	if !entry.DisconnectedAt.IsZero() && !m.withinGraceLocked(*entry, m.now()) {
		return cloneCancelEntry(entry), cancelLookupExpired
	}
	return cloneCancelEntry(entry), cancelLookupFound
}

func (m *cancelMap) MarkDisconnected(key cancelKey) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, ok := m.entries[key]; ok && entry.DisconnectedAt.IsZero() {
		entry.DisconnectedAt = m.now()
	}
}

func (m *cancelMap) PruneExpired(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.pruneExpiredLocked(now)
}

func (m *cancelMap) pruneExpiredLocked(now time.Time) int {
	var removed int
	for key, entry := range m.entries {
		if !entry.DisconnectedAt.IsZero() && !m.withinGraceLocked(*entry, now) {
			delete(m.entries, key)
			removed++
		}
	}
	return removed
}

func (m *cancelMap) withinGraceLocked(entry cancelEntry, now time.Time) bool {
	return entry.DisconnectedAt.IsZero() || now.Sub(entry.DisconnectedAt) <= m.graceWindow
}

func cloneCancelEntry(entry *cancelEntry) cancelEntry {
	out := *entry
	out.RealSecret = cloneBytes(entry.RealSecret)
	out.SyntheticSecret = cloneBytes(entry.SyntheticSecret)
	return out
}

func cloneBytes(in []byte) []byte {
	return append([]byte(nil), in...)
}

func generateCancelKey() (uint32, []byte, error) {
	var pidBytes [4]byte
	var secret [4]byte
	if _, err := rand.Read(pidBytes[:]); err != nil {
		return 0, nil, err
	}
	if _, err := rand.Read(secret[:]); err != nil {
		return 0, nil, err
	}

	pid := binary.BigEndian.Uint32(pidBytes[:])
	if pid == 0 {
		pid = 1
	}
	return pid, cloneBytes(secret[:]), nil
}
