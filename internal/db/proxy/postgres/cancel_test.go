//go:build linux

package postgres

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// captureCancelListener accepts one connection, reads up to 16 bytes,
// and sends them on the returned channel. Returns the listener address and
// a channel that receives the captured bytes.
func captureCancelListener(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- nil
			return
		}
		defer c.Close()
		buf := make([]byte, 16)
		_ = c.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _ := io.ReadFull(c, buf)
		ch <- buf[:n]
	}()
	return ln.Addr().String(), ch
}

func buildCancelPacket(pid, secret uint32) []byte {
	pkt := make([]byte, 16)
	binary.BigEndian.PutUint32(pkt[0:4], 16)
	binary.BigEndian.PutUint32(pkt[4:8], cancelRequestMagic)
	binary.BigEndian.PutUint32(pkt[8:12], pid)
	binary.BigEndian.PutUint32(pkt[12:16], secret)
	return pkt
}

func TestForwardCancel_WritesPayloadVerbatim(t *testing.T) {
	addr, ch := captureCancelListener(t)
	svc := Service{Upstream: addr, TLSMode: "terminate_reissue"}

	packet := buildCancelPacket(54321, 98765)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := forwardCancel(ctx, svc, packet); err != nil {
		t.Fatalf("forwardCancel: %v", err)
	}
	var got []byte
	select {
	case got = <-ch:
		if got == nil {
			t.Fatal("upstream did not capture cancel packet")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not capture cancel packet")
	}
	if len(got) != 16 {
		t.Fatalf("captured %d bytes, want 16", len(got))
	}
	for i := range packet {
		if got[i] != packet[i] {
			t.Errorf("byte %d: got %#x, want %#x", i, got[i], packet[i])
		}
	}
}

func TestForwardCancel_DialFailureReturnsError(t *testing.T) {
	svc := Service{Upstream: "127.0.0.1:1", TLSMode: "terminate_reissue"}
	packet := buildCancelPacket(1, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := forwardCancel(ctx, svc, packet); err == nil {
		t.Fatal("forwardCancel against unreachable upstream: want error, got nil")
	}
}
