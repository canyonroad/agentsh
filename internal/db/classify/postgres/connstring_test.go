package postgres

import "testing"

func TestLibpqConn(t *testing.T) {
	cases := []struct {
		name string
		in   string
		host string
		port int
	}{
		{"empty", "", "", 0},
		{"whitespace only", "   \t\n", "", 0},
		{"uri host port", "postgresql://upstream.example:5433/mydb", "upstream.example", 5433},
		{"uri postgres scheme", "postgres://upstream.example:5432", "upstream.example", 5432},
		{"uri user pass host port", "postgresql://bob:secret@db.internal:6543/app", "db.internal", 6543},
		{"uri no port", "postgresql://only-host/dbname", "only-host", 0},
		{"uri only host no path", "postgresql://h.example", "h.example", 0},
		{"uri params", "postgresql://h.example:5432/db?sslmode=require", "h.example", 5432},
		{"uri multi-host first wins", "postgresql://a.example,b.example:5432/db", "a.example", 5432},
		{"uri malformed", "postgresql://%%%%bad", "", 0},
		{"kv host port", "host=foo port=5432", "foo", 5432},
		{"kv extras", "host=db.internal port=5433 user=bob password=qux dbname=app", "db.internal", 5433},
		{"kv quoted host with space", "host='db one' port=5432 user=bob", "db one", 5432},
		{"kv backslash escaped quote", `host='it\'s.fine' port=5432`, "it's.fine", 5432},
		{"kv multi host first wins", "host=a,b port=5432", "a", 5432},
		{"kv no port", "host=h.example", "h.example", 0},
		{"kv junk port ignored", "host=h port=NaN", "h", 0},
		{"kv unknown keys", "user=bob dbname=app sslmode=require", "", 0},
		{"kv whitespace separators", "host=h\tport=6543\nuser=u", "h", 6543},
		{"kv leading whitespace", "  host=h.example  port=7777  ", "h.example", 7777},
		{"garbage", "definitely not a connection string", "", 0},
		{"empty quotes", "host='' port=5432", "", 5432},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, p := libpqConn(c.in)
			if h != c.host || p != c.port {
				t.Fatalf("libpqConn(%q) = (%q, %d); want (%q, %d)",
					c.in, h, p, c.host, c.port)
			}
		})
	}
}

func TestSplitKeywordValue(t *testing.T) {
	tokens := splitKeywordValue("host='db one' port=5432  user=bob")
	want := []string{"host='db one'", "port=5432", "user=bob"}
	if len(tokens) != len(want) {
		t.Fatalf("token count: got %d want %d (%v)", len(tokens), len(want), tokens)
	}
	for i, w := range want {
		if tokens[i] != w {
			t.Fatalf("token[%d]: got %q want %q", i, tokens[i], w)
		}
	}
}

func TestUnquoteKVValue(t *testing.T) {
	cases := map[string]string{
		"":            "",
		"plain":       "plain",
		"'quoted'":    "quoted",
		"'with sp'":   "with sp",
		`'it\'s'`:     "it's",
		"'unterm":     "'unterm",
		`'\\path'`:    `\path`,
		`'\n is \\n'`: `n is \n`,
	}
	for in, want := range cases {
		if got := unquoteKVValue(in); got != want {
			t.Errorf("unquoteKVValue(%q) = %q; want %q", in, got, want)
		}
	}
}
