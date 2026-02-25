package threatfeed

import (
	"bufio"
	"io"
	"strings"
)

// Parser extracts domain names from a threat feed format.
type Parser interface {
	Parse(r io.Reader) ([]string, error)
}

// HostfileParser parses hosts-file format: "127.0.0.1 domain" or "0.0.0.0 domain".
type HostfileParser struct{}

func (p *HostfileParser) Parse(r io.Reader) ([]string, error) {
	seen := make(map[string]struct{})
	var domains []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		domain := strings.ToLower(fields[1])
		if domain == "localhost" || domain == "localhost.localdomain" ||
			domain == "broadcasthost" || domain == "local" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	return domains, scanner.Err()
}

// DomainListParser parses one-domain-per-line format.
type DomainListParser struct{}

func (p *DomainListParser) Parse(r io.Reader) ([]string, error) {
	seen := make(map[string]struct{})
	var domains []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain := strings.ToLower(line)
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	return domains, scanner.Err()
}

// ParserForFormat returns the appropriate parser for a feed format string.
func ParserForFormat(format string) Parser {
	switch strings.ToLower(format) {
	case "hostfile":
		return &HostfileParser{}
	default:
		return &DomainListParser{}
	}
}
