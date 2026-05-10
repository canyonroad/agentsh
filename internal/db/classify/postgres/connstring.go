// Package postgres — connstring.go owns the libpq connection-string parser
// used by external-IO DDL handlers (CREATE/ALTER SUBSCRIPTION). Plan 03 only
// needs host and port — those drive the ObjectExternalEndpoint that policies
// match on. Everything else (user, password, dbname, sslmode, …) is parsed
// far enough to skip but not retained.
//
// libpq accepts two on-the-wire forms (see PostgreSQL docs §34.1):
//
//   - URI form: postgresql://[user[:password]@][host[:port]][/dbname][?param=value&…]
//     (postgres:// is an accepted alias; multi-host is allowed in the host
//     component but Plan 03 keeps only the first).
//   - Keyword/value form: whitespace-separated key=value pairs, where values
//     may be wrapped in single quotes to embed spaces. Backslash-escaped quotes
//     (\') are preserved as part of the value rather than terminating it.
//
// The parser is deliberately tolerant — garbage input returns ("", 0) rather
// than an error. The classifier is best-effort metadata extraction and must
// not break the pipeline on malformed conninfo.
package postgres

import (
	"net/url"
	"strconv"
	"strings"
)

// libpqConn parses a libpq connection string and returns the (host, port)
// pair. Empty/invalid input returns ("", 0). Multi-host strings keep only
// the first host. URI form is preferred when the input begins with the
// postgresql:// or postgres:// scheme; otherwise the keyword/value parser
// runs.
func libpqConn(s string) (host string, port int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}
	if strings.HasPrefix(s, "postgresql://") || strings.HasPrefix(s, "postgres://") {
		return libpqURI(s)
	}
	return libpqKV(s)
}

// libpqURI parses the URI form. Returns ("", 0) on malformed URIs.
func libpqURI(s string) (host string, port int) {
	u, err := url.Parse(s)
	if err != nil {
		return "", 0
	}
	// url.Parse keeps the whole [user[:pw]@]hostlist[:port] segment in Host.
	// Hostname() / Port() handle a single host:port pair fine; for multi-host
	// inputs (e.g. host1,host2:5432) Hostname() returns the comma-joined list,
	// so trim down to the first.
	h := u.Hostname()
	if comma := strings.IndexByte(h, ','); comma >= 0 {
		h = h[:comma]
	}
	host = h
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	return
}

// libpqKV parses the keyword/value form. host=foo port=5432 user='bob smith'
// becomes ("foo", 5432). Multi-host is split on the first comma.
func libpqKV(s string) (host string, port int) {
	for _, tok := range splitKeywordValue(s) {
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(tok[:eq]))
		val := strings.TrimSpace(tok[eq+1:])
		val = unquoteKVValue(val)
		switch key {
		case "host":
			h := val
			if comma := strings.IndexByte(h, ','); comma >= 0 {
				h = h[:comma]
			}
			host = h
		case "port":
			p := val
			if comma := strings.IndexByte(p, ','); comma >= 0 {
				p = p[:comma]
			}
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		}
	}
	return
}

// splitKeywordValue splits a libpq keyword/value string into tokens, treating
// runs of whitespace as separators. Single-quoted regions span whitespace
// transparently; a backslash escapes the next byte (so \' inside quotes does
// not terminate the value).
func splitKeywordValue(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
		case c == '\'':
			inQuote = !inQuote
			cur.WriteByte(c)
		case (c == ' ' || c == '\t' || c == '\n' || c == '\r') && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// unquoteKVValue strips a single layer of surrounding single quotes from a
// keyword/value value and resolves backslash escapes inside the quoted run.
// A bare value is returned unchanged.
func unquoteKVValue(v string) string {
	if len(v) < 2 || v[0] != '\'' || v[len(v)-1] != '\'' {
		return v
	}
	inner := v[1 : len(v)-1]
	if !strings.ContainsRune(inner, '\\') {
		return inner
	}
	var b strings.Builder
	b.Grow(len(inner))
	for i := 0; i < len(inner); i++ {
		if inner[i] == '\\' && i+1 < len(inner) {
			b.WriteByte(inner[i+1])
			i++
			continue
		}
		b.WriteByte(inner[i])
	}
	return b.String()
}
