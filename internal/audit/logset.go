package audit

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// LogFile describes one member of a rotated audit log set.
type LogFile struct {
	Path     string
	Index    int
	IsBackup bool
}

// ParsedEntry is a reusable parsed audit line representation.
type ParsedEntry struct {
	Type             string
	Integrity        *IntegrityMetadata
	CanonicalPayload []byte
}

// DiscoverRotationSet returns audit log siblings in oldest-first order.
func DiscoverRotationSet(base string) ([]LogFile, error) {
	dir := filepath.Dir(base)
	baseName := filepath.Base(base)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read audit rotation dir: %w", err)
	}

	indexes := make([]int, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, baseName+".") {
			continue
		}
		suffix := strings.TrimPrefix(name, baseName+".")
		index, err := strconv.Atoi(suffix)
		if err != nil {
			continue
		}
		indexes = append(indexes, index)
	}

	sort.Ints(indexes)
	for i, index := range indexes {
		want := i + 1
		if index != want {
			return nil, fmt.Errorf("missing audit log file %s.%d", base, want)
		}
	}

	files := make([]LogFile, 0, len(indexes)+1)
	for i := len(indexes) - 1; i >= 0; i-- {
		files = append(files, LogFile{
			Path:     base + "." + strconv.Itoa(indexes[i]),
			Index:    indexes[i],
			IsBackup: true,
		})
	}
	if _, err := os.Stat(base); err == nil {
		files = append(files, LogFile{
			Path:     base,
			Index:    0,
			IsBackup: false,
		})
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat %s: %w", base, err)
	}

	return files, nil
}

// ReadLastNonEmptyLine returns the newest non-empty line across a rotation set.
func ReadLastNonEmptyLine(files []LogFile) (LogFile, []byte, error) {
	for i := len(files) - 1; i >= 0; i-- {
		data, err := os.ReadFile(files[i].Path)
		if err != nil {
			return LogFile{}, nil, fmt.Errorf("read %s: %w", files[i].Path, err)
		}

		lines := bytes.Split(data, []byte{'\n'})
		for j := len(lines) - 1; j >= 0; j-- {
			line := bytes.TrimSpace(lines[j])
			if len(line) == 0 {
				continue
			}
			return files[i], bytes.Clone(line), nil
		}
	}

	return LogFile{}, nil, os.ErrNotExist
}

// NewScanner returns a scanner sized for large JSONL audit entries.
func NewScanner(file *os.File) *bufio.Scanner {
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	return scanner
}

// ParseIntegrityEntry parses a JSONL audit line into reusable structured pieces.
func ParseIntegrityEntry(line []byte) (ParsedEntry, error) {
	raw, err := parseIntegrityPayloadUseNumber(line)
	if err != nil {
		return ParsedEntry{}, err
	}

	entry := ParsedEntry{}
	if typ, ok := raw["type"].(string); ok {
		entry.Type = typ
	}

	if value, ok := raw["integrity"]; ok {
		meta, ok := integrityMetadataFromMap(value)
		if !ok {
			return ParsedEntry{}, fmt.Errorf("parse payload: invalid integrity metadata")
		}
		entry.Integrity = &meta
		delete(raw, "integrity")
	}

	entry.CanonicalPayload, err = marshalCanonicalPayload(raw)
	if err != nil {
		return ParsedEntry{}, err
	}
	return entry, nil
}
