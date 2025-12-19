//go:build linux

package ebpf

import (
	"errors"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// ConnectEvent matches the struct emitted by the BPF program.
type ConnectEvent struct {
	TsNs     uint64
	Cookie   uint64
	PID      uint32
	TGID     uint32
	Sport    uint16
	Dport    uint16
	Family   uint8
	Protocol uint8
	_        [6]byte
	DstIPv4  uint32
	DstIPv6  [16]byte
	Blocked  uint8
	_pad     [7]byte
}

// Collector reads events from the BPF ring buffer.
type Collector struct {
	mu     sync.Mutex
	rd     *ringbuf.Reader
	events chan ConnectEvent
	done   chan struct{}

	onDrop func()
}

// StartCollector starts reading events from the "events" ring buffer map.
// Caller is responsible for closing the returned collector.
func StartCollector(coll *ebpf.Collection, bufSize int) (*Collector, error) {
	if coll == nil {
		return nil, errors.New("collection nil")
	}
	if bufSize <= 0 {
		bufSize = 1024
	}
	m, ok := coll.Maps["events"]
	if !ok {
		return nil, errors.New("events map not found")
	}
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, err
	}
	c := &Collector{
		rd:     rd,
		events: make(chan ConnectEvent, bufSize),
		done:   make(chan struct{}),
	}
	go c.loop()
	return c, nil
}

func (c *Collector) loop() {
	for {
		record, err := c.rd.Read()
		if err != nil {
			select {
			case <-c.done:
				return
			default:
			}
			// transient errors like ringbuf.ErrClosed handled by exit
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		var ev ConnectEvent
		if len(record.RawSample) >= 49 { // 49 bytes needed for blocked flag
			copyToEvent(&ev, record.RawSample)
			select {
			case c.events <- ev:
			default:
				if c.onDrop != nil {
					c.onDrop()
				}
			}
		}
	}
}

func copyToEvent(ev *ConnectEvent, data []byte) {
	// Layout matches struct in connect.bpf.c
	ev.TsNs = le64(data[0:])
	ev.Cookie = le64(data[8:])
	ev.PID = le32(data[16:])
	ev.TGID = le32(data[20:])
	ev.Sport = le16(data[24:])
	ev.Dport = le16(data[26:])
	ev.Family = data[28]
	ev.Protocol = data[29]
	if len(data) >= 48 {
		copy(ev.DstIPv6[:], data[32:48]) // always copy 16 bytes
		if len(data) >= 40 {
			ev.DstIPv4 = le32(data[36:]) // overlap ok for v4
		}
	}
	if len(data) > 48 {
		ev.Blocked = data[48]
	}
}

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func le64(b []byte) uint64 {
	return uint64(le32(b)) | uint64(le32(b[4:]))<<32
}

// Events channel for consumers.
func (c *Collector) Events() <-chan ConnectEvent { return c.events }

// SetOnDrop registers a callback invoked when an event is dropped due to backpressure.
func (c *Collector) SetOnDrop(fn func()) { c.onDrop = fn }

// Close stops reading and closes the ring buffer.
func (c *Collector) Close() error {
	c.mu.Lock()
	select {
	case <-c.done:
		c.mu.Unlock()
		return nil
	default:
		close(c.done)
	}
	c.mu.Unlock()
	_ = c.rd.Close()
	return nil
}
