package config

import (
	"fmt"
	"strconv"
	"strings"
)

func ParseByteSize(s string) (int64, error) {
	in := strings.TrimSpace(s)
	if in == "" {
		return 0, fmt.Errorf("empty size")
	}
	in = strings.ReplaceAll(in, "_", "")
	upper := strings.ToUpper(in)

	mult := int64(1)
	numPart := upper
	switch {
	case strings.HasSuffix(upper, "KIB"):
		mult = 1024
		numPart = strings.TrimSuffix(upper, "KIB")
	case strings.HasSuffix(upper, "MIB"):
		mult = 1024 * 1024
		numPart = strings.TrimSuffix(upper, "MIB")
	case strings.HasSuffix(upper, "GIB"):
		mult = 1024 * 1024 * 1024
		numPart = strings.TrimSuffix(upper, "GIB")
	case strings.HasSuffix(upper, "KB"):
		mult = 1000
		numPart = strings.TrimSuffix(upper, "KB")
	case strings.HasSuffix(upper, "MB"):
		mult = 1000 * 1000
		numPart = strings.TrimSuffix(upper, "MB")
	case strings.HasSuffix(upper, "GB"):
		mult = 1000 * 1000 * 1000
		numPart = strings.TrimSuffix(upper, "GB")
	}

	numPart = strings.TrimSpace(numPart)
	if numPart == "" {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	n, err := strconv.ParseInt(numPart, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	if n > 0 && mult > 0 && n > (1<<63-1)/mult {
		return 0, fmt.Errorf("size overflow %q", s)
	}
	return n * mult, nil
}
