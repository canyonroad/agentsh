package netmonitor

import (
	"bytes"
	"testing"
)

func TestReadSocksConnect_Domain(t *testing.T) {
	// VER CMD RSV ATYP LEN "ab.onion" PORT(443)
	host := "ab.onion"
	buf := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	buf = append(buf, []byte(host)...)
	buf = append(buf, 0x01, 0xBB) // 443
	req, err := readSocksConnect(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if req.host != "ab.onion" || req.port != 443 || req.atyp != 0x03 {
		t.Fatalf("got host=%q port=%d atyp=%d", req.host, req.port, req.atyp)
	}
}

func TestReadSocksConnect_IPv4(t *testing.T) {
	buf := []byte{0x05, 0x01, 0x00, 0x01, 10, 0, 0, 7, 0x00, 0x50} // 10.0.0.7:80
	req, err := readSocksConnect(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if req.host != "10.0.0.7" || req.port != 80 {
		t.Fatalf("got host=%q port=%d", req.host, req.port)
	}
}

func TestReadSocksConnect_RejectsNonConnect(t *testing.T) {
	buf := []byte{0x05, 0x02, 0x00, 0x01, 1, 1, 1, 1, 0, 80} // CMD=2 (bind)
	if _, err := readSocksConnect(bytes.NewReader(buf)); err == nil {
		t.Fatal("expected error for non-CONNECT command")
	}
}

func TestEncodeConnectReq_RoundTrips(t *testing.T) {
	host := "x.onion"
	in := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	in = append(in, []byte(host)...)
	in = append(in, 0x01, 0xBB)
	req, err := readSocksConnect(bytes.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if got := encodeConnectReq(req); !bytes.Equal(got, in) {
		t.Fatalf("re-encode mismatch:\n got %v\nwant %v", got, in)
	}
}

func TestGreetingAndReply(t *testing.T) {
	greet := []byte{0x05, 0x01, 0x00} // 1 method: no-auth
	if err := readSocksGreeting(bytes.NewReader(greet)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeSocksReply(&out, socksRepNotAllowed); err != nil {
		t.Fatal(err)
	}
	want := []byte{0x05, socksRepNotAllowed, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("reply = %v, want %v", out.Bytes(), want)
	}
}
