//go:build linux

package postgres

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestBytePump_BothDirections(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	t.Cleanup(func() {
		_ = a1.Close()
		_ = a2.Close()
		_ = b1.Close()
		_ = b2.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- bytePump(ctx, a2, b1) }()

	// Write on a1 (client side), expect on b2 (upstream side).
	go func() { _, _ = a1.Write([]byte("hello")) }()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(b2, buf); err != nil {
		t.Fatalf("read upstream: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("upstream got %q, want hello", buf)
	}

	// Write on b2 (upstream side), expect on a1 (client side).
	go func() { _, _ = b2.Write([]byte("world")) }()
	if _, err := io.ReadFull(a1, buf); err != nil {
		t.Fatalf("read client: %v", err)
	}
	if string(buf) != "world" {
		t.Errorf("client got %q, want world", buf)
	}

	_ = a1.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			t.Errorf("bytePump returned %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("bytePump did not return after close")
	}
}

func TestBytePump_CtxCancel(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	t.Cleanup(func() {
		_ = a1.Close()
		_ = a2.Close()
		_ = b1.Close()
		_ = b2.Close()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bytePump(ctx, a2, b1) }()

	cancel()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("bytePump did not return after ctx cancel")
	}
}
