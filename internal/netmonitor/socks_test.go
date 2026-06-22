package netmonitor

import (
	"bytes"
	"testing"
)

func TestReadSocksRequest_Domain(t *testing.T) {
	// VER CMD RSV ATYP LEN "ab.onion" PORT(443)
	host := "ab.onion"
	buf := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	buf = append(buf, []byte(host)...)
	buf = append(buf, 0x01, 0xBB) // 443
	req, err := readSocksRequest(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if req.host != "ab.onion" || req.port != 443 || req.atyp != 0x03 || req.cmd != 0x01 {
		t.Fatalf("got host=%q port=%d atyp=%d cmd=%d", req.host, req.port, req.atyp, req.cmd)
	}
}

func TestReadSocksRequest_IPv4(t *testing.T) {
	buf := []byte{0x05, 0x01, 0x00, 0x01, 10, 0, 0, 7, 0x00, 0x50} // 10.0.0.7:80
	req, err := readSocksRequest(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if req.host != "10.0.0.7" || req.port != 80 || req.cmd != 0x01 {
		t.Fatalf("got host=%q port=%d cmd=%d", req.host, req.port, req.cmd)
	}
}

func TestReadSocksRequest_AcceptsNonConnect(t *testing.T) {
	buf := []byte{0x05, 0x02, 0x00, 0x01, 1, 1, 1, 1, 0, 80} // CMD=2 (bind)
	req, err := readSocksRequest(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if req.cmd != 0x02 {
		t.Fatalf("expected readSocksRequest to accept non-CONNECT, got cmd=%d", req.cmd)
	}
}

func TestEncodeReq_RoundTrips(t *testing.T) {
	host := "x.onion"
	in := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	in = append(in, []byte(host)...)
	in = append(in, 0x01, 0xBB)
	req, err := readSocksRequest(bytes.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if got := encodeReq(req); !bytes.Equal(got, in) {
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
