package audit

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
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
	baseExists := false
	for i := len(indexes) - 1; i >= 0; i-- {
		files = append(files, LogFile{
			Path:     base + "." + strconv.Itoa(indexes[i]),
			Index:    indexes[i],
			IsBackup: true,
		})
	}
	if _, err := os.Stat(base); err == nil {
		baseExists = true
		files = append(files, LogFile{
			Path:     base,
			Index:    0,
			IsBackup: false,
		})
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat %s: %w", base, err)
	}
	if len(indexes) > 0 && !baseExists {
		return nil, fmt.Errorf("missing audit log file %s", base)
	}

	return files, nil
}

// ReadLastNonEmptyLine returns the newest non-empty line across a rotation set.
func ReadLastNonEmptyLine(files []LogFile) (LogFile, []byte, error) {
	for i := len(files) - 1; i >= 0; i-- {
		line, err := readLastNonEmptyLineFromFile(files[i].Path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return LogFile{}, nil, fmt.Errorf("read %s: %w", files[i].Path, err)
		}
		return files[i], line, nil
	}

	return LogFile{}, nil, os.ErrNotExist
}

// ReadFirstNonEmptyLine returns the oldest visible non-empty line across a rotation set.
func ReadFirstNonEmptyLine(files []LogFile) (LogFile, []byte, error) {
	for _, file := range files {
		line, err := readFirstNonEmptyLineFromFile(file.Path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return LogFile{}, nil, fmt.Errorf("read %s: %w", file.Path, err)
		}
		return file, line, nil
	}

	return LogFile{}, nil, os.ErrNotExist
}

func readLastNonEmptyLineFromFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() == 0 {
		return nil, os.ErrNotExist
	}

	const chunkSize = 64 * 1024
	buf := make([]byte, chunkSize)
	tail := make([]byte, 0, chunkSize)
	end := info.Size()

	for end > 0 {
		readSize := int64(chunkSize)
		if end < readSize {
			readSize = end
		}
		start := end - readSize
		if _, err := file.ReadAt(buf[:readSize], start); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}

		data := make([]byte, 0, int(readSize)+len(tail))
		data = append(data, buf[:readSize]...)
		data = append(data, tail...)

		scanEnd := len(data)
		if end == info.Size() && scanEnd > 0 && data[scanEnd-1] == '\n' {
			scanEnd--
		}
		for i := scanEnd - 1; i >= 0; i-- {
			if data[i] != '\n' {
				continue
			}
			line := bytes.TrimSpace(data[i+1 : scanEnd])
			if len(line) > 0 {
				return bytes.Clone(line), nil
			}
			scanEnd = i
		}

		tail = append(tail[:0], data[:scanEnd]...)
		end = start
	}

	line := bytes.TrimSpace(tail)
	if len(line) == 0 {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(line), nil
}

func readFirstNonEmptyLineFromFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := NewScanner(file)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		return bytes.Clone(line), nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, os.ErrNotExist
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
