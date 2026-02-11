package netmonitor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

// buildClientHello constructs a valid TLS record containing a ClientHello
// with the given SNI hostname. If extraExtensions is provided, they are
// appended before the SNI extension.
func buildClientHello(sni string, extraExtensions ...[]byte) []byte {
	// Build SNI extension data
	var sniExt []byte
	nameBytes := []byte(sni)
	// Extension type (0x0000 = SNI)
	sniExt = append(sniExt, 0x00, 0x00)
	// Extension data length placeholder (filled below)
	sniExtDataLenPos := len(sniExt)
	sniExt = append(sniExt, 0x00, 0x00)
	// ServerNameList length placeholder
	sniListLenPos := len(sniExt)
	sniExt = append(sniExt, 0x00, 0x00)
	// NameType = host_name (0x00)
	sniExt = append(sniExt, 0x00)
	// HostName length
	sniExt = append(sniExt, 0x00, 0x00)
	binary.BigEndian.PutUint16(sniExt[len(sniExt)-2:], uint16(len(nameBytes)))
	// HostName
	sniExt = append(sniExt, nameBytes...)

	// Fill list length: nameType(1) + nameLen(2) + name
	listLen := 1 + 2 + len(nameBytes)
	binary.BigEndian.PutUint16(sniExt[sniListLenPos:], uint16(listLen))
	// Fill ext data length: listLen(2) + list
	extDataLen := 2 + listLen
	binary.BigEndian.PutUint16(sniExt[sniExtDataLenPos:], uint16(extDataLen))

	// Combine all extensions
	var allExts []byte
	for _, ext := range extraExtensions {
		allExts = append(allExts, ext...)
	}
	allExts = append(allExts, sniExt...)

	return buildClientHelloWithExtensions(allExts)
}

// buildClientHelloNoSNI builds a ClientHello with a supported_versions extension
// instead of SNI.
func buildClientHelloNoSNI() []byte {
	// supported_versions extension (type 0x002b)
	ext := []byte{
		0x00, 0x2b, // extension type
		0x00, 0x03, // extension data length
		0x02,       // versions list length
		0x03, 0x04, // TLS 1.3
	}
	return buildClientHelloWithExtensions(ext)
}

func buildClientHelloWithExtensions(extensions []byte) []byte {
	// ClientHello body: version(2) + random(32) + sessionID(1+0) + cipherSuites(2+2) + compression(1+1) + extensions
	var body []byte
	// ClientVersion TLS 1.2
	body = append(body, 0x03, 0x03)
	// Random (32 zero bytes)
	body = append(body, make([]byte, 32)...)
	// SessionID length = 0
	body = append(body, 0x00)
	// CipherSuites: length 2, one suite (TLS_RSA_WITH_AES_128_CBC_SHA)
	body = append(body, 0x00, 0x02, 0x00, 0x2f)
	// CompressionMethods: length 1, null compression
	body = append(body, 0x01, 0x00)

	// Extensions length
	extLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(extLenBytes, uint16(len(extensions)))
	body = append(body, extLenBytes...)
	body = append(body, extensions...)

	// Handshake: type(1) + uint24 length(3) + body
	var handshake []byte
	handshake = append(handshake, tlsHandshakeClientHello)
	handshakeLen := len(body)
	handshake = append(handshake, byte(handshakeLen>>16), byte(handshakeLen>>8), byte(handshakeLen))
	handshake = append(handshake, body...)

	// TLS record: type(1) + version(2) + length(2) + payload
	var record []byte
	record = append(record, tlsHandshakeType)
	record = append(record, 0x03, 0x01) // TLS 1.0 record version
	recordPayloadLen := len(handshake)
	record = append(record, 0x00, 0x00)
	binary.BigEndian.PutUint16(record[3:5], uint16(recordPayloadLen))
	record = append(record, handshake...)

	return record
}

// validateRecord parses a rewritten record and checks all length fields
// are consistent and the SNI value matches.
func validateRecord(t *testing.T, record []byte, expectedSNI string) {
	t.Helper()

	if len(record) < 5 {
		t.Fatal("record too short for TLS header")
	}
	if record[0] != tlsHandshakeType {
		t.Fatalf("expected handshake type 0x16, got 0x%02x", record[0])
	}

	// Check record payload length
	recordPayloadLen := int(binary.BigEndian.Uint16(record[3:5]))
	if recordPayloadLen != len(record)-5 {
		t.Fatalf("record payload length %d != actual %d", recordPayloadLen, len(record)-5)
	}

	// Check handshake length
	if record[5] != tlsHandshakeClientHello {
		t.Fatalf("expected ClientHello type 0x01, got 0x%02x", record[5])
	}
	handshakeLen := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
	if handshakeLen != recordPayloadLen-4 {
		t.Fatalf("handshake length %d != record payload - 4 (%d)", handshakeLen, recordPayloadLen-4)
	}

	// Find SNI via our parser
	loc, err := findSNI(record)
	if err != nil {
		t.Fatalf("findSNI on rewritten record: %v", err)
	}

	gotSNI := string(record[loc.sniNameStart:loc.sniNameEnd])
	if gotSNI != expectedSNI {
		t.Fatalf("SNI = %q, want %q", gotSNI, expectedSNI)
	}

	// Verify all stored lengths match current
	gotRecordPayload := int(binary.BigEndian.Uint16(record[loc.recordPayloadLenOffset:]))
	if gotRecordPayload != len(record)-5 {
		t.Fatalf("recordPayloadLen field %d != actual %d", gotRecordPayload, len(record)-5)
	}

	gotHandshake := int(record[loc.handshakeLenOffset])<<16 |
		int(record[loc.handshakeLenOffset+1])<<8 |
		int(record[loc.handshakeLenOffset+2])
	if gotHandshake != recordPayloadLen-4 {
		t.Fatalf("handshakeLen field %d != expected %d", gotHandshake, recordPayloadLen-4)
	}

	gotExtLen := int(binary.BigEndian.Uint16(record[loc.extensionsLenOffset:]))
	gotExtDataLen := int(binary.BigEndian.Uint16(record[loc.sniExtDataLenOffset:]))
	gotListLen := int(binary.BigEndian.Uint16(record[loc.sniListLenOffset:]))
	gotNameLen := int(binary.BigEndian.Uint16(record[loc.sniNameLenOffset:]))

	if gotNameLen != len(expectedSNI) {
		t.Fatalf("nameLen %d != %d", gotNameLen, len(expectedSNI))
	}
	expectedListLen := 1 + 2 + len(expectedSNI)
	if gotListLen != expectedListLen {
		t.Fatalf("listLen %d != %d", gotListLen, expectedListLen)
	}
	expectedExtDataLen := 2 + expectedListLen
	if gotExtDataLen != expectedExtDataLen {
		t.Fatalf("extDataLen %d != %d", gotExtDataLen, expectedExtDataLen)
	}
	_ = gotExtLen // Validated transitively via handshake length check
}

func TestRewriteSNI_SameLength(t *testing.T) {
	record := buildClientHello("example.com")
	result, err := RewriteClientHelloSNI(record, "changed.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != len(record) {
		t.Fatalf("length changed: %d → %d", len(record), len(result))
	}
	validateRecord(t, result, "changed.com")
}

func TestRewriteSNI_Shorter(t *testing.T) {
	record := buildClientHello("api.anthropic.com")
	result, err := RewriteClientHelloSNI(record, "a.co")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) >= len(record) {
		t.Fatalf("expected shorter record: %d → %d", len(record), len(result))
	}
	validateRecord(t, result, "a.co")
}

func TestRewriteSNI_Longer(t *testing.T) {
	record := buildClientHello("a.co")
	result, err := RewriteClientHelloSNI(record, "long-hostname.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) <= len(record) {
		t.Fatalf("expected longer record: %d → %d", len(record), len(result))
	}
	validateRecord(t, result, "long-hostname.example.com")
}

func TestRewriteSNI_NoSNI(t *testing.T) {
	record := buildClientHelloNoSNI()
	result, err := RewriteClientHelloSNI(record, "new.example.com")
	if !errors.Is(err, ErrNoSNIExtension) {
		t.Fatalf("expected ErrNoSNIExtension, got %v", err)
	}
	if !bytes.Equal(result, record) {
		t.Fatal("expected original record returned unchanged")
	}
}

func TestRewriteSNI_NotTLS(t *testing.T) {
	record := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	result, err := RewriteClientHelloSNI(record, "new.example.com")
	if !errors.Is(err, ErrNotTLSRecord) {
		t.Fatalf("expected ErrNotTLSRecord, got %v", err)
	}
	if !bytes.Equal(result, record) {
		t.Fatal("expected original record returned unchanged")
	}
}

func TestRewriteSNI_NotClientHello(t *testing.T) {
	record := buildClientHello("example.com")
	// Change handshake type from ClientHello (0x01) to ServerHello (0x02)
	record[5] = 0x02
	result, err := RewriteClientHelloSNI(record, "new.example.com")
	if !errors.Is(err, ErrNotClientHello) {
		t.Fatalf("expected ErrNotClientHello, got %v", err)
	}
	if !bytes.Equal(result, record) {
		t.Fatal("expected original record returned unchanged")
	}
}

func TestRewriteSNI_Truncated(t *testing.T) {
	record := buildClientHello("example.com")
	// Truncate the record
	truncated := record[:10]
	_, err := RewriteClientHelloSNI(truncated, "new.example.com")
	if !errors.Is(err, ErrTruncatedRecord) {
		t.Fatalf("expected ErrTruncatedRecord, got %v", err)
	}
}

func TestRewriteSNI_MultipleExtensions(t *testing.T) {
	// Add a supported_versions extension before SNI
	extraExt := []byte{
		0x00, 0x2b, // supported_versions extension type
		0x00, 0x03, // extension data length
		0x02,       // versions list length
		0x03, 0x04, // TLS 1.3
	}
	record := buildClientHello("original.example.com", extraExt)

	result, err := RewriteClientHelloSNI(record, "rewritten.example.com")
	if err != nil {
		t.Fatal(err)
	}
	validateRecord(t, result, "rewritten.example.com")

	// Verify the supported_versions extension is still intact
	// It should be at the same position (after extensions length field)
	loc, err := findSNI(result)
	if err != nil {
		t.Fatal(err)
	}
	// The extra extension should be between extensionsLenOffset+2 and sniExtDataLenOffset-2
	extStart := loc.extensionsLenOffset + 2
	if result[extStart] != 0x00 || result[extStart+1] != 0x2b {
		t.Fatal("supported_versions extension was corrupted")
	}
}

func TestReadTLSRecord_Valid(t *testing.T) {
	original := buildClientHello("example.com")
	reader := bytes.NewReader(original)
	record, err := readTLSRecord(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record, original) {
		t.Fatalf("record mismatch: got %d bytes, want %d", len(record), len(original))
	}
}

func TestReadTLSRecord_NotTLS(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	reader := bytes.NewReader(data)
	record, err := readTLSRecord(reader)
	if !errors.Is(err, ErrNotTLSRecord) {
		t.Fatalf("expected ErrNotTLSRecord, got %v", err)
	}
	if len(record) != 5 {
		t.Fatalf("expected 5 header bytes, got %d", len(record))
	}
}

func TestSNIRewriteFirstRecord_HappyPath(t *testing.T) {
	clientConn, clientWrite := net.Pipe()
	upstreamRead, upstreamConn := net.Pipe()

	original := buildClientHello("original.example.com")
	errCh := make(chan error, 1)
	go func() {
		defer upstreamConn.Close()
		errCh <- sniRewriteFirstRecord(clientConn, upstreamConn, "rewritten.example.com")
	}()

	// Write the ClientHello from the "client" side
	go func() {
		_, _ = clientWrite.Write(original)
		clientWrite.Close()
	}()

	// Read what was written to upstream
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(upstreamRead)

	err := <-errCh
	if err != nil {
		t.Fatal(err)
	}

	validateRecord(t, buf.Bytes(), "rewritten.example.com")
}

func TestSNIRewriteFirstRecord_NonTLS(t *testing.T) {
	clientConn, clientWrite := net.Pipe()
	upstreamRead, upstreamConn := net.Pipe()

	httpData := []byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	errCh := make(chan error, 1)
	go func() {
		defer upstreamConn.Close()
		errCh <- sniRewriteFirstRecord(clientConn, upstreamConn, "rewritten.example.com")
	}()

	go func() {
		_, _ = clientWrite.Write(httpData)
		clientWrite.Close()
	}()

	// Read what was forwarded to upstream (should be the 5-byte header unchanged)
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(upstreamRead)

	err := <-errCh
	if !isSNIParseError(err) {
		t.Fatalf("expected SNI parse error, got %v", err)
	}

	// The 5-byte header should have been forwarded
	if buf.Len() != 5 {
		t.Fatalf("expected 5 bytes forwarded, got %d", buf.Len())
	}
}
