//go:build linux

package ptrace

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	errNotTLS         = errors.New("not a TLS record")
	errNotHandshake   = errors.New("not a handshake record")
	errNotClientHello = errors.New("not a ClientHello")
	errTruncated      = errors.New("truncated TLS record")
	errNoSNI          = errors.New("no SNI extension found")
)

// isClientHello returns true if buf starts with a TLS ClientHello record.
func isClientHello(buf []byte) bool {
	if len(buf) < 6 {
		return false
	}
	if buf[0] != 0x16 {
		return false
	}
	if buf[1] != 0x03 || buf[2] < 0x01 || buf[2] > 0x03 {
		return false
	}
	return buf[5] == 0x01
}

// parseSNI extracts the SNI server name from a TLS ClientHello record.
// Returns the server name, its byte offset within buf, its length, and any error.
func parseSNI(buf []byte) (serverName string, offset int, length int, err error) {
	if len(buf) < 6 {
		return "", 0, 0, errTruncated
	}
	if buf[0] != 0x16 {
		return "", 0, 0, errNotTLS
	}
	if buf[1] != 0x03 || buf[2] < 0x01 || buf[2] > 0x03 {
		return "", 0, 0, errNotTLS
	}
	if buf[5] != 0x01 {
		return "", 0, 0, errNotClientHello
	}

	if len(buf) < 9 {
		return "", 0, 0, errTruncated
	}
	handshakeLen := int(buf[6])<<16 | int(buf[7])<<8 | int(buf[8])
	handshakeEnd := 9 + handshakeLen
	if handshakeEnd > len(buf) {
		handshakeEnd = len(buf)
	}

	// ClientHello body: client_version(2) + random(32)
	pos := 9 + 34
	if pos >= handshakeEnd {
		return "", 0, 0, errTruncated
	}

	// Session ID
	sessionIDLen := int(buf[pos])
	pos += 1 + sessionIDLen
	if pos+2 > handshakeEnd {
		return "", 0, 0, errTruncated
	}

	// Cipher suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos+1 > handshakeEnd {
		return "", 0, 0, errTruncated
	}

	// Compression methods
	compressionLen := int(buf[pos])
	pos += 1 + compressionLen
	if pos+2 > handshakeEnd {
		return "", 0, 0, errTruncated
	}

	// Extensions
	extensionsLen := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
	pos += 2
	extensionsEnd := pos + extensionsLen
	if extensionsEnd > handshakeEnd {
		extensionsEnd = handshakeEnd
	}

	// Walk extensions looking for SNI (type 0x0000)
	for pos+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(buf[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(buf[pos+2 : pos+4]))
		pos += 4

		if extType == 0x0000 { // server_name
			if pos+5 > extensionsEnd {
				return "", 0, 0, errTruncated
			}
			nameType := buf[pos+2]
			if nameType != 0 {
				pos += extLen
				continue
			}
			nameLen := int(binary.BigEndian.Uint16(buf[pos+3 : pos+5]))
			nameOffset := pos + 5
			if nameOffset+nameLen > extensionsEnd {
				return "", 0, 0, errTruncated
			}
			return string(buf[nameOffset : nameOffset+nameLen]), nameOffset, nameLen, nil
		}
		pos += extLen
	}

	return "", 0, 0, errNoSNI
}

// rewriteSNI replaces the SNI server name in a TLS ClientHello with newName.
// Returns a new buffer with the rewritten ClientHello.
// Updates all length fields (TLS record, handshake, extensions total, SNI extension, server name list, host name).
func rewriteSNI(buf []byte, newName string) ([]byte, error) {
	_, nameOffset, nameLen, err := parseSNI(buf)
	if err != nil {
		return nil, fmt.Errorf("parseSNI: %w", err)
	}

	newNameBytes := []byte(newName)
	diff := len(newNameBytes) - nameLen

	// Build new buffer: before name + new name + after name
	result := make([]byte, 0, len(buf)+diff)
	result = append(result, buf[:nameOffset]...)
	result = append(result, newNameBytes...)
	result = append(result, buf[nameOffset+nameLen:]...)

	// Fix ALL length fields. All lengths increase/decrease by diff.

	// 1. TLS record length (bytes 3-4)
	recordLen := int(binary.BigEndian.Uint16(result[3:5])) + diff
	binary.BigEndian.PutUint16(result[3:5], uint16(recordLen))

	// 2. Handshake length (bytes 6-8): 3-byte big-endian
	handshakeLen := int(result[6])<<16 | int(result[7])<<8 | int(result[8])
	handshakeLen += diff
	result[6] = byte(handshakeLen >> 16)
	result[7] = byte(handshakeLen >> 8)
	result[8] = byte(handshakeLen)

	// 3. Host name length (2 bytes before name): nameOffset-2
	binary.BigEndian.PutUint16(result[nameOffset-2:nameOffset], uint16(len(newNameBytes)))

	// 4. Server name list length (2 bytes before name type): nameOffset-5
	listLen := int(binary.BigEndian.Uint16(buf[nameOffset-5:nameOffset-3])) + diff
	binary.BigEndian.PutUint16(result[nameOffset-5:nameOffset-3], uint16(listLen))

	// 5. SNI extension length (2 bytes before list length): nameOffset-7
	extLen := int(binary.BigEndian.Uint16(buf[nameOffset-7:nameOffset-5])) + diff
	binary.BigEndian.PutUint16(result[nameOffset-7:nameOffset-5], uint16(extLen))

	// 6. Extensions total length — re-parse to find offset
	epos := 9 + 34
	if epos < len(result) {
		sessionIDLen := int(result[epos])
		epos += 1 + sessionIDLen
		if epos+2 <= len(result) {
			cipherLen := int(binary.BigEndian.Uint16(result[epos : epos+2]))
			epos += 2 + cipherLen
			if epos+1 <= len(result) {
				compLen := int(result[epos])
				epos += 1 + compLen
				if epos+2 <= len(result) {
					extTotalLen := int(binary.BigEndian.Uint16(result[epos:epos+2])) + diff
					binary.BigEndian.PutUint16(result[epos:epos+2], uint16(extTotalLen))
				}
			}
		}
	}

	return result, nil
}
