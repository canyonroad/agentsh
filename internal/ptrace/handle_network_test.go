//go:build linux

package ptrace

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseSockaddr_IPv4(t *testing.T) {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(buf[2:4], 8080)
	copy(buf[4:8], net.ParseIP("192.168.1.1").To4())

	family, addr, port, err := parseSockaddr(buf)
	if err != nil {
		t.Fatal(err)
	}
	if family != unix.AF_INET {
		t.Errorf("family = %d, want %d", family, unix.AF_INET)
	}
	if addr != "192.168.1.1" {
		t.Errorf("addr = %q, want %q", addr, "192.168.1.1")
	}
	if port != 8080 {
		t.Errorf("port = %d, want %d", port, 8080)
	}
}

func TestParseSockaddr_IPv6(t *testing.T) {
	buf := make([]byte, 28)
	binary.LittleEndian.PutUint16(buf[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(buf[2:4], 443)
	copy(buf[8:24], net.ParseIP("::1").To16())

	family, addr, port, err := parseSockaddr(buf)
	if err != nil {
		t.Fatal(err)
	}
	if family != unix.AF_INET6 {
		t.Errorf("family = %d, want %d", family, unix.AF_INET6)
	}
	if addr != "::1" {
		t.Errorf("addr = %q, want %q", addr, "::1")
	}
	if port != 443 {
		t.Errorf("port = %d, want %d", port, 443)
	}
}

func TestParseSockaddr_Unix(t *testing.T) {
	path := "/var/run/docker.sock"
	buf := make([]byte, 2+len(path)+1)
	binary.LittleEndian.PutUint16(buf[0:2], unix.AF_UNIX)
	copy(buf[2:], path)

	family, addr, port, err := parseSockaddr(buf)
	if err != nil {
		t.Fatal(err)
	}
	if family != unix.AF_UNIX {
		t.Errorf("family = %d, want %d", family, unix.AF_UNIX)
	}
	if addr != path {
		t.Errorf("addr = %q, want %q", addr, path)
	}
	if port != 0 {
		t.Errorf("port = %d, want 0", port)
	}
}

func TestParseSockaddr_UnixAbstract(t *testing.T) {
	name := "my-abstract-socket"
	buf := make([]byte, 2+1+len(name))
	binary.LittleEndian.PutUint16(buf[0:2], unix.AF_UNIX)
	buf[2] = 0
	copy(buf[3:], name)

	family, addr, _, err := parseSockaddr(buf)
	if err != nil {
		t.Fatal(err)
	}
	if family != unix.AF_UNIX {
		t.Errorf("family = %d, want %d", family, unix.AF_UNIX)
	}
	if addr != "@"+name {
		t.Errorf("addr = %q, want %q", addr, "@"+name)
	}
}

func TestParseSockaddr_TooShort(t *testing.T) {
	buf := []byte{0}
	_, _, _, err := parseSockaddr(buf)
	if err == nil {
		t.Error("expected error for short buffer")
	}
}

func TestParseSockaddr_AFUnspec(t *testing.T) {
	// AF_UNSPEC is used with connect() to disconnect datagram sockets.
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], unix.AF_UNSPEC)

	family, addr, port, err := parseSockaddr(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if family != unix.AF_UNSPEC {
		t.Errorf("family = %d, want %d", family, unix.AF_UNSPEC)
	}
	if addr != "" {
		t.Errorf("addr = %q, want empty", addr)
	}
	if port != 0 {
		t.Errorf("port = %d, want 0", port)
	}
}
