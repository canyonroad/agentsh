//go:build linux

package postgres

import "encoding/binary"

// extractSNI parses a TLS ClientHello buffer and returns the SNI hostname
// (server_name extension, host_name field) when present. Best-effort:
// returns "" and nil error for malformed/fragmented inputs.
//
// Reference: RFC 5246 §7.4.1.2 + RFC 6066 §3 (server_name).
func extractSNI(buf []byte) (string, error) {
	// TLS record header: type(1) + version(2) + length(2)
	if len(buf) < 5 {
		return "", nil
	}
	if buf[0] != 22 { // 22 = handshake
		return "", nil
	}
	recLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if recLen+5 > len(buf) {
		return "", nil
	}
	hs := buf[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 1 { // 1 = ClientHello
		return "", nil
	}
	chBody := hs[4:]
	if len(chBody) < 2+32+1 {
		return "", nil
	}
	off := 2 + 32
	sidLen := int(chBody[off])
	off += 1 + sidLen
	if off+2 > len(chBody) {
		return "", nil
	}
	csLen := int(binary.BigEndian.Uint16(chBody[off : off+2]))
	off += 2 + csLen
	if off+1 > len(chBody) {
		return "", nil
	}
	compLen := int(chBody[off])
	off += 1 + compLen
	if off+2 > len(chBody) {
		return "", nil
	}
	extTotal := int(binary.BigEndian.Uint16(chBody[off : off+2]))
	off += 2
	if off+extTotal > len(chBody) {
		return "", nil
	}
	exts := chBody[off : off+extTotal]
	for len(exts) >= 4 {
		typ := binary.BigEndian.Uint16(exts[0:2])
		ln := int(binary.BigEndian.Uint16(exts[2:4]))
		if 4+ln > len(exts) {
			return "", nil
		}
		body := exts[4 : 4+ln]
		exts = exts[4+ln:]
		if typ != 0 {
			continue
		}
		if len(body) < 2 {
			return "", nil
		}
		listLen := int(binary.BigEndian.Uint16(body[0:2]))
		if 2+listLen > len(body) {
			return "", nil
		}
		entries := body[2 : 2+listLen]
		for len(entries) >= 3 {
			nameType := entries[0]
			nameLen := int(binary.BigEndian.Uint16(entries[1:3]))
			if 3+nameLen > len(entries) {
				return "", nil
			}
			name := entries[3 : 3+nameLen]
			entries = entries[3+nameLen:]
			if nameType == 0 {
				return string(name), nil
			}
		}
	}
	return "", nil
}
