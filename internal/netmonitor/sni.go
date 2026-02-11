package netmonitor

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	tlsRecordHeaderLen      = 5
	tlsHandshakeType        = 0x16
	tlsHandshakeClientHello = 0x01
	tlsExtensionSNI         = 0x0000
	sniHostNameType         = 0x00
	maxTLSRecordLen         = 16384 + 2048
)

var (
	ErrNotTLSRecord    = errors.New("sni: not a TLS handshake record")
	ErrNotClientHello  = errors.New("sni: not a ClientHello")
	ErrTruncatedRecord = errors.New("sni: truncated TLS record")
	ErrNoSNIExtension  = errors.New("sni: no SNI extension found")
	ErrMalformedSNI    = errors.New("sni: malformed SNI extension")
	ErrRecordTooLarge  = errors.New("sni: rewritten record exceeds max size")
)

// sniLocation holds byte offsets discovered during parsing of a TLS ClientHello.
type sniLocation struct {
	recordPayloadLenOffset int // always 3
	handshakeLenOffset     int // always 6
	extensionsLenOffset    int
	sniExtDataLenOffset    int
	sniListLenOffset       int
	sniNameLenOffset       int
	sniNameStart           int
	sniNameEnd             int
	origRecordPayloadLen   int
	origHandshakeLen       int
	origExtensionsLen      int
	origExtDataLen         int
	origListLen            int
}

// findSNI walks a TLS ClientHello record to locate the SNI host_name.
func findSNI(record []byte) (*sniLocation, error) {
	if len(record) < tlsRecordHeaderLen {
		return nil, ErrTruncatedRecord
	}

	// Validate TLS record header
	if record[0] != tlsHandshakeType {
		return nil, ErrNotTLSRecord
	}
	recordPayloadLen := int(binary.BigEndian.Uint16(record[3:5]))
	if len(record) < tlsRecordHeaderLen+recordPayloadLen {
		return nil, ErrTruncatedRecord
	}

	// Validate handshake type
	pos := tlsRecordHeaderLen
	if pos >= len(record) || record[pos] != tlsHandshakeClientHello {
		return nil, ErrNotClientHello
	}

	// Read uint24 handshake length
	if pos+4 > len(record) {
		return nil, ErrTruncatedRecord
	}
	handshakeLen := int(record[pos+1])<<16 | int(record[pos+2])<<8 | int(record[pos+3])
	handshakeEnd := pos + 4 + handshakeLen
	if handshakeEnd > len(record) {
		return nil, ErrTruncatedRecord
	}
	pos += 4

	// Skip ClientVersion (2 bytes)
	pos += 2
	if pos > handshakeEnd {
		return nil, ErrTruncatedRecord
	}

	// Skip Random (32 bytes)
	pos += 32
	if pos > handshakeEnd {
		return nil, ErrTruncatedRecord
	}

	// Skip SessionID (1 byte length + N bytes)
	if pos >= handshakeEnd {
		return nil, ErrTruncatedRecord
	}
	sessionIDLen := int(record[pos])
	pos += 1 + sessionIDLen
	if pos > handshakeEnd {
		return nil, ErrTruncatedRecord
	}

	// Skip CipherSuites (2 byte length + N bytes)
	if pos+2 > handshakeEnd {
		return nil, ErrTruncatedRecord
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(record[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos > handshakeEnd {
		return nil, ErrTruncatedRecord
	}

	// Skip CompressionMethods (1 byte length + N bytes)
	if pos >= handshakeEnd {
		return nil, ErrTruncatedRecord
	}
	compMethodsLen := int(record[pos])
	pos += 1 + compMethodsLen
	if pos > handshakeEnd {
		return nil, ErrTruncatedRecord
	}

	// No extensions
	if pos == handshakeEnd {
		return nil, ErrNoSNIExtension
	}

	// Read extensions total length (2 bytes)
	if pos+2 > handshakeEnd {
		return nil, ErrTruncatedRecord
	}
	extensionsLenOffset := pos
	extensionsLen := int(binary.BigEndian.Uint16(record[pos : pos+2]))
	pos += 2
	extensionsEnd := pos + extensionsLen
	if extensionsEnd > handshakeEnd {
		return nil, ErrTruncatedRecord
	}

	// Walk extensions
	for pos+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(record[pos : pos+2])
		extDataLenOffset := pos + 2
		extDataLen := int(binary.BigEndian.Uint16(record[extDataLenOffset : extDataLenOffset+2]))
		extDataStart := extDataLenOffset + 2
		extDataEnd := extDataStart + extDataLen
		if extDataEnd > extensionsEnd {
			return nil, ErrTruncatedRecord
		}

		if extType == tlsExtensionSNI {
			// Parse ServerNameList
			if extDataLen < 2 {
				return nil, ErrMalformedSNI
			}
			sniListLenOffset := extDataStart
			listLen := int(binary.BigEndian.Uint16(record[sniListLenOffset : sniListLenOffset+2]))
			listPos := sniListLenOffset + 2
			listEnd := listPos + listLen
			if listEnd > extDataEnd {
				return nil, ErrMalformedSNI
			}

			// Walk server name entries
			for listPos+3 <= listEnd {
				nameType := record[listPos]
				nameLenOffset := listPos + 1
				nameLen := int(binary.BigEndian.Uint16(record[nameLenOffset : nameLenOffset+2]))
				nameStart := nameLenOffset + 2
				nameEnd := nameStart + nameLen
				if nameEnd > listEnd {
					return nil, ErrMalformedSNI
				}

				if nameType == sniHostNameType {
					return &sniLocation{
						recordPayloadLenOffset: 3,
						handshakeLenOffset:     6,
						extensionsLenOffset:    extensionsLenOffset,
						sniExtDataLenOffset:    extDataLenOffset,
						sniListLenOffset:       sniListLenOffset,
						sniNameLenOffset:       nameLenOffset,
						sniNameStart:           nameStart,
						sniNameEnd:             nameEnd,
						origRecordPayloadLen:   recordPayloadLen,
						origHandshakeLen:       handshakeLen,
						origExtensionsLen:      extensionsLen,
						origExtDataLen:         extDataLen,
						origListLen:            listLen,
					}, nil
				}

				listPos = nameEnd
			}
			return nil, ErrMalformedSNI
		}

		pos = extDataEnd
	}

	return nil, ErrNoSNIExtension
}

// RewriteClientHelloSNI rewrites the SNI extension in a TLS ClientHello record.
// On parse error, it returns the original record unchanged along with the error.
func RewriteClientHelloSNI(record []byte, newSNI string) ([]byte, error) {
	loc, err := findSNI(record)
	if err != nil {
		return record, err
	}

	oldLen := loc.sniNameEnd - loc.sniNameStart
	delta := len(newSNI) - oldLen

	// Build new record: prefix + new SNI + suffix
	newRecord := make([]byte, 0, len(record)+delta)
	newRecord = append(newRecord, record[:loc.sniNameStart]...)
	newRecord = append(newRecord, []byte(newSNI)...)
	newRecord = append(newRecord, record[loc.sniNameEnd:]...)

	// Validate result size
	if len(newRecord) > tlsRecordHeaderLen+maxTLSRecordLen {
		return record, ErrRecordTooLarge
	}

	// Patch all 6 length fields (all are before sniNameStart, so offsets are stable)
	// 1. SNI name length
	binary.BigEndian.PutUint16(newRecord[loc.sniNameLenOffset:], uint16(len(newSNI)))
	// 2. SNI list length
	binary.BigEndian.PutUint16(newRecord[loc.sniListLenOffset:], uint16(loc.origListLen+delta))
	// 3. SNI extension data length
	binary.BigEndian.PutUint16(newRecord[loc.sniExtDataLenOffset:], uint16(loc.origExtDataLen+delta))
	// 4. Extensions total length
	binary.BigEndian.PutUint16(newRecord[loc.extensionsLenOffset:], uint16(loc.origExtensionsLen+delta))
	// 5. Handshake length (uint24 at bytes 6, 7, 8)
	newHandshakeLen := loc.origHandshakeLen + delta
	newRecord[loc.handshakeLenOffset] = byte(newHandshakeLen >> 16)
	newRecord[loc.handshakeLenOffset+1] = byte(newHandshakeLen >> 8)
	newRecord[loc.handshakeLenOffset+2] = byte(newHandshakeLen)
	// 6. Record payload length
	binary.BigEndian.PutUint16(newRecord[loc.recordPayloadLenOffset:], uint16(loc.origRecordPayloadLen+delta))

	return newRecord, nil
}

// readTLSRecord reads a single TLS record from the reader.
func readTLSRecord(r io.Reader) ([]byte, error) {
	var header [tlsRecordHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}

	if header[0] != tlsHandshakeType {
		return header[:], ErrNotTLSRecord
	}

	payloadLen := int(binary.BigEndian.Uint16(header[3:5]))
	if payloadLen > maxTLSRecordLen {
		return header[:], ErrRecordTooLarge
	}

	record := make([]byte, tlsRecordHeaderLen+payloadLen)
	copy(record, header[:])
	if _, err := io.ReadFull(r, record[tlsRecordHeaderLen:]); err != nil {
		return record[:tlsRecordHeaderLen], err
	}

	return record, nil
}

// sniRewriteFirstRecord reads the first TLS record from client, rewrites the
// SNI extension, and writes the (possibly modified) record to upstream.
// On any error, it still forwards whatever data was read.
func sniRewriteFirstRecord(client io.Reader, upstream io.Writer, newSNI string) error {
	record, err := readTLSRecord(client)
	if err != nil {
		// Forward whatever we managed to read
		if len(record) > 0 {
			_, _ = upstream.Write(record)
		}
		return err
	}

	modified, err := RewriteClientHelloSNI(record, newSNI)
	if err != nil {
		// Forward original record unchanged
		_, _ = upstream.Write(record)
		return err
	}

	_, writeErr := upstream.Write(modified)
	return writeErr
}

// isSNIParseError returns true if the error is a known SNI parsing error
// (as opposed to an I/O error).
func isSNIParseError(err error) bool {
	return errors.Is(err, ErrNotTLSRecord) ||
		errors.Is(err, ErrNotClientHello) ||
		errors.Is(err, ErrTruncatedRecord) ||
		errors.Is(err, ErrNoSNIExtension) ||
		errors.Is(err, ErrMalformedSNI)
}
