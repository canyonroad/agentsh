package shellparse

import (
	"testing"
)

// TestDerivePolicyTarget covers the public API: given a (command, args)
// pair as it would arrive at the server exec API, return the binary the
// policy pre-check should evaluate.
func TestDerivePolicyTarget(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		wantCmd string
		wantArg []string
		wantOK  bool
	}{
		// --- happy path: basic shell-c forms ---
		{"bare sh, simple cmd", "sh", []string{"-c", "shutdown now"}, "shutdown", []string{"now"}, true},
		{"absolute sh, simple cmd", "/bin/sh", []string{"-c", "shutdown now"}, "shutdown", []string{"now"}, true},
		{"relative sh", "./sh", []string{"-c", "ls"}, "ls", []string{}, true},
		{"backslash-separator windows-style sh path", `C:\bin\sh`, []string{"-c", "shutdown"}, "shutdown", []string{}, true},
		{"mixed-separator bash path", `/usr/local\bash`, []string{"-c", "ls"}, "ls", []string{}, true},
		{"uppercase shell basename (case-insensitive FS)", "/BIN/SH", []string{"-c", "ls"}, "ls", []string{}, true},
		{"bash, simple cmd", "bash", []string{"-c", "rm foo"}, "rm", []string{"foo"}, true},
		{"dash", "/bin/dash", []string{"-c", "whoami"}, "whoami", []string{}, true},
		{"ash (busybox shell on alpine)", "/bin/ash", []string{"-c", "id"}, "id", []string{}, true},
		{"ksh", "ksh", []string{"-c", "ps"}, "ps", []string{}, true},
		{"mksh", "mksh", []string{"-c", "date"}, "date", []string{}, true},

		// --- flag forms ---
		{"-ec (errexit + command)", "sh", []string{"-ec", "ls"}, "ls", []string{}, true},
		{"-ce (reversed cluster)", "sh", []string{"-ce", "ls"}, "ls", []string{}, true},
		{"-euxc (all safe shorts clustered)", "bash", []string{"-euxc", "shutdown"}, "shutdown", []string{}, true},
		{"-e -c (split safe + c)", "sh", []string{"-e", "-c", "shutdown"}, "shutdown", []string{}, true},
		{"-e -u -c (three split)", "bash", []string{"-e", "-u", "-c", "rm foo"}, "rm", []string{"foo"}, true},
		{"-ux -c (split with cluster)", "sh", []string{"-ux", "-c", "ls"}, "ls", []string{}, true},
		{"-f -c (noglob + c)", "sh", []string{"-f", "-c", "shutdown"}, "shutdown", []string{}, true},
		{"-x -c (xtrace + c)", "sh", []string{"-x", "-c", "shutdown"}, "shutdown", []string{}, true},
		{"-e -c script argv0 (positional after script)", "sh", []string{"-e", "-c", "shutdown", "argv0"}, "shutdown", []string{}, true},

		// --- transparent wrappers ---
		{"exec wrapper", "sh", []string{"-c", "exec shutdown now"}, "shutdown", []string{"now"}, true},
		{"command wrapper", "sh", []string{"-c", "command ls"}, "ls", []string{}, true},
		{"double exec", "sh", []string{"-c", "exec exec shutdown"}, "shutdown", []string{}, true},
		{"exec then command", "sh", []string{"-c", "exec command ls"}, "ls", []string{}, true},
		{"nohup wrapper stripped", "sh", []string{"-c", "nohup shutdown"}, "shutdown", []string{}, true},
		{"nice wrapper stripped", "sh", []string{"-c", "nice ls"}, "ls", []string{}, true},
		{"nohup exec chained", "sh", []string{"-c", "nohup exec shutdown"}, "shutdown", []string{}, true},
		{"exec nohup chained", "sh", []string{"-c", "exec nohup shutdown"}, "shutdown", []string{}, true},
		{"nice shutdown with arg", "sh", []string{"-c", "nice shutdown now"}, "shutdown", []string{"now"}, true},
		// --- time wrapper: shell reserved word / binary that times the
		// next command. Without this, `time shutdown` would classify as a
		// shell builtin (reserved word) and fall through to outer allow.
		{"time wrapper stripped", "sh", []string{"-c", "time shutdown"}, "shutdown", []string{}, true},
		{"time with arg passes through", "sh", []string{"-c", "time shutdown now"}, "shutdown", []string{"now"}, true},
		{"time then nohup chained", "sh", []string{"-c", "time nohup shutdown"}, "shutdown", []string{}, true},
		{"nice then time chained", "sh", []string{"-c", "nice time shutdown"}, "shutdown", []string{}, true},
		// --- env wrapper: runs the next command with (optionally modified)
		// environment. Without this, `env shutdown` would surface `env`
		// (bare name with no rule) and default-deny fails closed to outer
		// allow.
		{"env wrapper stripped", "sh", []string{"-c", "env shutdown"}, "shutdown", []string{}, true},
		{"env with arg", "sh", []string{"-c", "env shutdown now"}, "shutdown", []string{"now"}, true},
		{"env then nohup chained", "sh", []string{"-c", "env nohup shutdown"}, "shutdown", []string{}, true},
		{"exec env shutdown chained", "sh", []string{"-c", "exec env shutdown"}, "shutdown", []string{}, true},

		// --- rejected wrapper flag forms (deny rewrite via StatusBypass, NOT silent fallback) ---
		{"command -v (flag form)", "sh", []string{"-c", "command -v ls"}, "", nil, false},
		{"exec -a (flag form)", "sh", []string{"-c", "exec -a foo ls"}, "", nil, false},
		{"nohup with flag rejects", "sh", []string{"-c", "nohup -h shutdown"}, "", nil, false},
		{"nice -n N parsed (succeeds)", "sh", []string{"-c", "nice -n 19 shutdown"}, "shutdown", []string{}, true},
		{"nice -n -5 parsed (succeeds)", "sh", []string{"-c", "nice -n -5 shutdown"}, "shutdown", []string{}, true},
		{"nice -n +5 rejected (+ not in byte allowlist)", "sh", []string{"-c", "nice -n +5 shutdown"}, "", nil, false},
		{"nice -n bogus (non-numeric increment)", "sh", []string{"-c", "nice -n bogus shutdown"}, "", nil, false},
		{"nice --adjustment= rejects (= blocked by allowlist)", "sh", []string{"-c", "nice --adjustment=19 shutdown"}, "", nil, false},
		{"time -p CMD rejected (unknown time flag)", "sh", []string{"-c", "time -p shutdown"}, "", nil, false},
		{"time --help rejected", "sh", []string{"-c", "time --help shutdown"}, "", nil, false},
		{"env -i CMD rejected (unknown env flag)", "sh", []string{"-c", "env -i shutdown"}, "", nil, false},
		{"env -u VAR CMD rejected", "sh", []string{"-c", "env -u PATH shutdown"}, "", nil, false},
		{"env --chdir= rejected (= blocked by allowlist)", "sh", []string{"-c", "env --chdir=/tmp shutdown"}, "", nil, false},
		{"env VAR=val CMD rejected (= blocked in env wrapper form)", "sh", []string{"-c", "env VAR=val shutdown"}, "", nil, false},

		// --- zsh: treated as a known shell so allow bin=zsh + deny
		// bin=shutdown can't be bypassed via `zsh -c "shutdown"`.
		{"zsh simple cmd", "zsh", []string{"-c", "ls"}, "ls", []string{}, true},
		{"zsh absolute path", "/usr/bin/zsh", []string{"-c", "shutdown now"}, "shutdown", []string{"now"}, true},
		// --- unknown shells ---
		{"fish not supported", "/usr/bin/fish", []string{"-c", "ls"}, "", nil, false},
		{"busybox multicall not supported", "busybox", []string{"sh", "-c", "ls"}, "", nil, false},
		{"random binary with -c", "/usr/bin/python3", []string{"-c", "print('hi')"}, "", nil, false},
		{"empty command", "", []string{"-c", "ls"}, "", nil, false},

		// --- wrong flag forms ---
		{"no flag", "sh", []string{"ls"}, "", nil, false},
		{"-l (login)", "sh", []string{"-l", "-c", "ls"}, "", nil, false},
		{"--login", "bash", []string{"--login", "-c", "ls"}, "", nil, false},
		{"-lc cluster", "bash", []string{"-lc", "ls"}, "", nil, false},
		{"-i (interactive)", "bash", []string{"-i", "-c", "ls"}, "", nil, false},
		{"-p (privileged)", "bash", []string{"-p", "-c", "ls"}, "", nil, false},
		{"-a (allexport)", "sh", []string{"-a", "-c", "ls"}, "", nil, false},
		{"-s (read-stdin)", "sh", []string{"-s", "-c", "ls"}, "", nil, false},
		{"-o errexit (operand option rejected)", "bash", []string{"-o", "errexit", "-c", "ls"}, "", nil, false},
		{"+o (plus-form rejected)", "bash", []string{"+o", "noclobber", "-c", "ls"}, "", nil, false},
		{"--rcfile=file (profile source)", "bash", []string{"--rcfile=/tmp/rc", "-c", "ls"}, "", nil, false},
		{"--norc (long option)", "bash", []string{"--norc", "-c", "ls"}, "", nil, false},
		{"-- (end-of-options marker)", "sh", []string{"--", "-c", "ls"}, "", nil, false},
		{"empty args", "sh", nil, "", nil, false},
		{"single arg no script", "sh", []string{"-c"}, "", nil, false},
		// --- unsafe-option shapes with -c (treated as bypass, not fallback) ---
		{"-lc with script (bypass, not fallback)", "bash", []string{"-lc", "shutdown"}, "", nil, false},
		{"-rc cluster with script", "bash", []string{"-rc", "shutdown"}, "", nil, false},
		{"-l -c split (bypass)", "bash", []string{"-l", "-c", "shutdown"}, "", nil, false},
		{"-o errexit -c (bypass)", "bash", []string{"-o", "errexit", "-c", "shutdown"}, "", nil, false},
		{"--rcfile -c (bypass)", "bash", []string{"--rcfile=/tmp/rc", "-c", "shutdown"}, "", nil, false},
		{"--norc -c (bypass)", "bash", []string{"--norc", "-c", "shutdown"}, "", nil, false},
		// --- env-assignment-prefix parse-through: strip leading NAME=VALUE
		// tokens, derive the rest. Under `allow sh` + `deny shutdown` this
		// lets the inner deny fire instead of masking it behind the shell.
		{"assign + nohup (parse-through)", "sh", []string{"-c", "PATH=/tmp nohup shutdown"}, "shutdown", []string{}, true},
		{"assign + exec (parse-through)", "sh", []string{"-c", "VAR=x exec shutdown"}, "shutdown", []string{}, true},
		{"multiple assigns + nice -n N (parse-through)", "sh", []string{"-c", "FOO=1 BAR=2 nice -n 19 shutdown"}, "shutdown", []string{}, true},
		{"empty-value assign + nohup (parse-through)", "sh", []string{"-c", "FOO= nohup shutdown"}, "shutdown", []string{}, true},
		{"assign + plain binary (parse-through)", "sh", []string{"-c", "PATH=/tmp shutdown"}, "shutdown", []string{}, true},
		{"assign + plain binary with arg (parse-through)", "sh", []string{"-c", "FOO=bar shutdown now"}, "shutdown", []string{"now"}, true},
		// assign + inner bypass form (exec -a …) — strip leaves inner
		// still unparsable → bypass.
		{"assign + exec -a (inner bypass)", "sh", []string{"-c", "VAR=x exec -a foo shutdown"}, "", nil, false},
		// dirty VALUE (byte outside the narrow allowlist) is a bypass.
		{"assign with colon in VALUE", "sh", []string{"-c", "PATH=/tmp:/bin shutdown"}, "", nil, false},
		{"assign with glob in VALUE", "sh", []string{"-c", "PATH=*/bad nohup shutdown"}, "", nil, false},
		{"assign with dollar in VALUE", "sh", []string{"-c", "FOO=$VAR shutdown"}, "", nil, false},
		{"assign with equals in VALUE", "sh", []string{"-c", "FOO=a=b shutdown"}, "", nil, false},
		// digit-leading tokens are NOT valid assignments — shell would
		// try to exec them. Falls through to the byte-allowlist check
		// which rejects the `=` → statusFallback (not bypass).
		{"digit-leading token is not assign (fallback)", "sh", []string{"-c", "0FOO=bar nohup ls"}, "", nil, false},
		// All-assignment script: shell sets vars and exits, no command
		// to derive. Falls back to outer shell rule.
		{"only assignments (fallback)", "sh", []string{"-c", "FOO=1 BAR=2"}, "", nil, false},
		// --- three args ---
		{"three args", "sh", []string{"-c", "ls", "extra"}, "ls", []string{}, true},
		{"four args (argv0 + positional)", "sh", []string{"-c", "shutdown now", "argv0_name", "param1"}, "shutdown", []string{"now"}, true},
		{"many positional params", "bash", []string{"-c", "rm foo", "bash", "a", "b", "c"}, "rm", []string{"foo"}, true},
		{"-ec with argv0", "sh", []string{"-ec", "whoami", "myscript"}, "whoami", []string{}, true},

		// --- empty or whitespace scripts ---
		{"empty script", "sh", []string{"-c", ""}, "", nil, false},
		{"whitespace-only script", "sh", []string{"-c", "   \t  "}, "", nil, false},

		// --- rejected chars (shell metachars) ---
		{"pipe", "sh", []string{"-c", "ls | wc"}, "", nil, false},
		{"redirect >", "sh", []string{"-c", "echo hi > out"}, "", nil, false},
		{"redirect <", "sh", []string{"-c", "cat < in"}, "", nil, false},
		{"semicolon", "sh", []string{"-c", "ls; pwd"}, "", nil, false},
		{"ampersand", "sh", []string{"-c", "ls &"}, "", nil, false},
		{"backtick", "sh", []string{"-c", "echo `date`"}, "", nil, false},
		{"dollar expansion", "sh", []string{"-c", "echo $PWD"}, "", nil, false},
		{"parens (subshell)", "sh", []string{"-c", "(ls)"}, "", nil, false},
		{"double quotes", "sh", []string{"-c", "echo \"hi\""}, "", nil, false},
		{"single quotes", "sh", []string{"-c", "echo 'hi'"}, "", nil, false},
		{"backslash", "sh", []string{"-c", "echo \\n"}, "", nil, false},
		{"asterisk (glob)", "sh", []string{"-c", "ls *.go"}, "", nil, false},
		{"question glob", "sh", []string{"-c", "ls foo?"}, "", nil, false},
		{"bracket glob", "sh", []string{"-c", "ls foo[0-9]"}, "", nil, false},
		{"brace expansion", "sh", []string{"-c", "echo {a,b}"}, "", nil, false},
		{"tilde expansion", "sh", []string{"-c", "ls ~/foo"}, "", nil, false},
		{"hash (comment)", "sh", []string{"-c", "ls # comment"}, "", nil, false},
		{"percent (job ctrl)", "sh", []string{"-c", "fg %1"}, "", nil, false},
		{"newline", "sh", []string{"-c", "ls\npwd"}, "", nil, false},
		{"non-ascii", "sh", []string{"-c", "éls"}, "", nil, false},

		// --- builtins (first token blocked) ---
		{"echo (dual builtin)", "sh", []string{"-c", "echo hi"}, "", nil, false},
		{"printf (dual builtin)", "sh", []string{"-c", "printf hi"}, "", nil, false},
		{"pwd", "sh", []string{"-c", "pwd"}, "", nil, false},
		{"test", "sh", []string{"-c", "test -f foo"}, "", nil, false},
		{"[ builtin", "sh", []string{"-c", "[ -f foo ]"}, "", nil, false},
		{"true builtin", "sh", []string{"-c", "true"}, "", nil, false},
		{"false builtin", "sh", []string{"-c", "false"}, "", nil, false},
		{"cd", "sh", []string{"-c", "cd /tmp"}, "", nil, false},
		{"kill (builtin on bash)", "sh", []string{"-c", "kill 1"}, "", nil, false},
		{"ulimit (bash builtin)", "sh", []string{"-c", "ulimit -n 1024"}, "", nil, false},
		{"enable (bash builtin, used to re-enable kill)", "sh", []string{"-c", "enable kill"}, "", nil, false},
		{"hash", "sh", []string{"-c", "hash -r"}, "", nil, false},
		{"type", "sh", []string{"-c", "type ls"}, "", nil, false},
		{"let", "sh", []string{"-c", "let x=1"}, "", nil, false},

		// --- reserved words (first token blocked) ---
		{"if", "sh", []string{"-c", "if true"}, "", nil, false},
		{"while", "sh", []string{"-c", "while true"}, "", nil, false},
		{"for", "sh", []string{"-c", "for x in a"}, "", nil, false},
		{"function", "sh", []string{"-c", "function foo"}, "", nil, false},
		{"double-bracket", "sh", []string{"-c", "[[ -f foo ]]"}, "", nil, false},

		// --- builtin after stripping wrapper is also blocked ---
		{"exec echo (blocked via builtin)", "sh", []string{"-c", "exec echo hi"}, "", nil, false},
		{"command cd (blocked via builtin)", "sh", []string{"-c", "command cd /tmp"}, "", nil, false},

		// --- absolute path binaries ---
		{"absolute path binary", "sh", []string{"-c", "/usr/sbin/shutdown now"}, "/usr/sbin/shutdown", []string{"now"}, true},
		{"relative dot-slash", "sh", []string{"-c", "./script"}, "./script", []string{}, true},
		{"relative dotdot", "sh", []string{"-c", "../tool arg"}, "../tool", []string{"arg"}, true},

		// --- bare transparent wrapper ---
		{"exec alone", "sh", []string{"-c", "exec"}, "", nil, false},
		{"command alone", "sh", []string{"-c", "command"}, "", nil, false},
		// nohup/nice as bare tokens are valid external binaries in their own
		// right (they just wouldn't have anything to wrap); the policy layer
		// is free to have a rule named `nohup` or `nice`, so we return them
		// as-is rather than treating the missing operand as a parse error.
		{"nohup alone, bare binary", "sh", []string{"-c", "nohup"}, "nohup", []string{}, true},
		{"nice alone, bare binary", "sh", []string{"-c", "nice"}, "nice", []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCmd, gotArgs, gotOK := DerivePolicyTarget(tt.command, tt.args)
			if gotOK != tt.wantOK {
				t.Fatalf("ok: got %v, want %v (cmd=%q args=%v)", gotOK, tt.wantOK, gotCmd, gotArgs)
			}
			if !gotOK {
				if gotCmd != "" || gotArgs != nil {
					t.Errorf("expected zero returns on !ok, got cmd=%q args=%v", gotCmd, gotArgs)
				}
				return
			}
			if gotCmd != tt.wantCmd {
				t.Errorf("cmd: got %q, want %q", gotCmd, tt.wantCmd)
			}
			if !slicesEqual(gotArgs, tt.wantArg) {
				t.Errorf("args: got %v, want %v", gotArgs, tt.wantArg)
			}
		})
	}
}

// TestIsShellCBypassAttempt verifies the escape hatch for wrapper forms
// that DerivePolicyTarget won't rewrite but that we DO recognize as deny
// bypasses. The caller (policy engine) uses this to fail closed instead of
// falling through to the outer shell's allow rule.
func TestIsShellCBypassAttempt(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		want    bool
	}{
		// Bypass — flag forms we refuse to parse.
		{"exec -a NAME CMD", "sh", []string{"-c", "exec -a foo shutdown"}, true},
		{"command -v CMD", "sh", []string{"-c", "command -v shutdown"}, true},
		{"command -p CMD", "sh", []string{"-c", "command -p shutdown"}, true},
		{"nohup --help CMD", "sh", []string{"-c", "nohup --help shutdown"}, true},
		{"nohup -x CMD", "sh", []string{"-c", "nohup -x shutdown"}, true},
		{"nice -n bogus CMD (non-numeric)", "sh", []string{"-c", "nice -n bogus shutdown"}, true},
		{"nice -19 CMD (unsupported form)", "sh", []string{"-c", "nice -19 shutdown"}, true},
		// Byte allowlist evasion via wrapper long-option `=`.
		{"nice --adjustment=19 CMD", "sh", []string{"-c", "nice --adjustment=19 shutdown"}, true},
		{"nohup --preserve-status=1 CMD", "sh", []string{"-c", "nohup --preserve-status=1 shutdown"}, true},
		// time / env wrapper bypass (R15).
		{"time -p CMD", "sh", []string{"-c", "time -p shutdown"}, true},
		{"time --help CMD", "sh", []string{"-c", "time --help shutdown"}, true},
		{"env -i CMD", "sh", []string{"-c", "env -i shutdown"}, true},
		{"env -u VAR CMD", "sh", []string{"-c", "env -u PATH shutdown"}, true},
		{"env VAR=val CMD (byte-allowlist evasion)", "sh", []string{"-c", "env VAR=val shutdown"}, true},
		{"env --chdir=/tmp CMD (byte-allowlist evasion)", "sh", []string{"-c", "env --chdir=/tmp shutdown"}, true},

		// Bypass — unsafe shell options hiding -c.
		{"bash -lc shutdown", "bash", []string{"-lc", "shutdown"}, true},
		{"bash -l -c shutdown", "bash", []string{"-l", "-c", "shutdown"}, true},
		{"bash -o errexit -c shutdown", "bash", []string{"-o", "errexit", "-c", "shutdown"}, true},
		{"bash --rcfile=X -c shutdown", "bash", []string{"--rcfile=/tmp/rc", "-c", "shutdown"}, true},
		{"bash --norc -c shutdown", "bash", []string{"--norc", "-c", "shutdown"}, true},
		{"bash -ic shutdown (interactive+c)", "bash", []string{"-ic", "shutdown"}, true},
		{"sh -pc shutdown (privileged+c)", "sh", []string{"-pc", "shutdown"}, true},

		// Bypass — env-assignment prefix followed by a wrapper in an
		// UNPARSABLE flag form (inner bypass survives the parse-through).
		{"assign + exec -a", "sh", []string{"-c", "VAR=x exec -a foo shutdown"}, true},
		{"assign + command -v", "sh", []string{"-c", "FOO=1 command -v shutdown"}, true},
		{"assign + nohup --preserve-status", "sh", []string{"-c", "PATH=/tmp nohup --preserve-status=1 shutdown"}, true},

		// Bypass — env-assignment with a VALUE byte outside the narrow
		// allowlist. The shell would accept these, but our pure-string
		// check cannot safely reason about them, so fail closed.
		{"assign with colon in VALUE", "sh", []string{"-c", "PATH=/tmp:/bin shutdown"}, true},
		{"assign with glob in VALUE", "sh", []string{"-c", "PATH=*/bad nohup shutdown"}, true},
		{"assign with dollar in VALUE", "sh", []string{"-c", "FOO=$VAR shutdown"}, true},
		{"assign with equals in VALUE", "sh", []string{"-c", "FOO=a=b shutdown"}, true},

		// Not a bypass — assignment parse-through to a parseable inner.
		// DerivePolicyTarget succeeds (returns the inner binary) under
		// these, so the caller uses the derived target directly.
		{"assign + nohup (parses through)", "sh", []string{"-c", "PATH=/tmp nohup shutdown"}, false},
		{"assign + exec (parses through)", "sh", []string{"-c", "VAR=x exec shutdown"}, false},
		{"assign + nice (parses through)", "sh", []string{"-c", "FOO=1 nice shutdown"}, false},
		{"two assigns + nice -n N (parses through)", "sh", []string{"-c", "FOO=1 BAR=2 nice -n 19 shutdown"}, false},
		{"empty-value assign + nohup (parses through)", "sh", []string{"-c", "FOO= nohup shutdown"}, false},
		{"assign + plain binary (parses through)", "sh", []string{"-c", "PATH=/tmp shutdown"}, false},
		{"assign + plain binary with arg (parses through)", "sh", []string{"-c", "FOO=bar shutdown now"}, false},

		// Not a bypass — DerivePolicyTarget would succeed.
		{"nohup CMD", "sh", []string{"-c", "nohup shutdown"}, false},
		{"nice CMD", "sh", []string{"-c", "nice shutdown"}, false},
		{"nice -n 19 CMD", "sh", []string{"-c", "nice -n 19 shutdown"}, false},
		{"exec CMD", "sh", []string{"-c", "exec shutdown"}, false},
		{"time CMD", "sh", []string{"-c", "time shutdown"}, false},
		{"env CMD", "sh", []string{"-c", "env shutdown"}, false},
		{"time nohup CMD chained", "sh", []string{"-c", "time nohup shutdown"}, false},
		{"env nohup CMD chained", "sh", []string{"-c", "env nohup shutdown"}, false},

		// Not a bypass — plain shell-c that doesn't involve a wrapper.
		{"plain command", "sh", []string{"-c", "shutdown"}, false},
		{"builtin (fallback, not bypass)", "sh", []string{"-c", "echo hi"}, false},
		{"metachar (fallback)", "sh", []string{"-c", "ls | wc"}, false},

		// Not a bypass — assignment without wrapper (separate issue, out of scope).
		{"assign + plain binary (out of scope, fallback)", "sh", []string{"-c", "PATH=/tmp shutdown"}, false},
		{"digit-leading token (not a valid assign)", "sh", []string{"-c", "0FOO=bar nohup shutdown"}, false},

		// Not a bypass — unsafe option without -c.
		{"bash -l script.sh (no -c)", "bash", []string{"-l", "script.sh"}, false},
		{"bash --norc script.sh (no -c)", "bash", []string{"--norc", "script.sh"}, false},
		{"bash -- -c script (after --)", "bash", []string{"--", "-c", "script"}, false},

		// Not a known shell — never a bypass.
		{"python -c", "python3", []string{"-c", "exec -a foo shutdown"}, false},
		// zsh IS a known shell — the nice bypass form fails closed.
		{"zsh with nice -n bogus (bypass)", "zsh", []string{"-c", "nice -n bogus shutdown"}, true},

		// Malformed — no -c flag at all.
		{"no -c", "sh", []string{"shutdown"}, false},
		{"empty args", "sh", nil, false},
		{"empty command", "", []string{"-c", "exec -a foo shutdown"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsShellCBypassAttempt(tt.command, tt.args); got != tt.want {
				t.Errorf("IsShellCBypassAttempt(%q, %v) = %v, want %v", tt.command, tt.args, got, tt.want)
			}
		})
	}
}

func TestIsOpaqueShellC(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		want    bool
	}{
		// --- opaque cases: metachars, pipes, subshells, globs, quotes, expansions ---
		{"pipe", "sh", []string{"-c", "ls | wc"}, true},
		{"semicolon", "sh", []string{"-c", "foo; bar"}, true},
		{"and", "bash", []string{"-c", "foo && bar"}, true},
		{"or", "bash", []string{"-c", "foo || bar"}, true},
		{"redirect out", "sh", []string{"-c", "foo > out"}, true},
		{"redirect in", "sh", []string{"-c", "foo < in"}, true},
		{"subshell", "sh", []string{"-c", "(foo)"}, true},
		{"glob", "sh", []string{"-c", "ls *.go"}, true},
		{"double quote", "sh", []string{"-c", "echo \"hi\""}, true},
		{"single quote", "sh", []string{"-c", "echo 'hi'"}, true},
		{"dollar var", "sh", []string{"-c", "echo $X"}, true},
		{"backtick substitution", "sh", []string{"-c", "echo `date`"}, true},
		{"absolute shell path opaque", "/usr/bin/bash", []string{"-c", "foo | bar"}, true},
		{"zsh opaque", "zsh", []string{"-c", "foo; bar"}, true},

		// --- NOT opaque: bypass cases return statusBypass, not opaque ---
		{"exec -a bypass (not opaque)", "sh", []string{"-c", "exec -a foo shutdown"}, false},
		{"nohup --help bypass (not opaque)", "sh", []string{"-c", "nohup --help shutdown"}, false},
		{"bash -lc bypass (not opaque)", "bash", []string{"-lc", "shutdown"}, false},

		// --- NOT opaque: normal derivable scripts ---
		{"plain command", "sh", []string{"-c", "ls"}, false},
		{"command with safe args", "sh", []string{"-c", "shutdown now"}, false},
		{"wrapper + cmd", "bash", []string{"-c", "nohup shutdown"}, false},
		{"env assignment", "sh", []string{"-c", "PATH=/tmp shutdown"}, false},

		// --- NOT opaque: not a shell ---
		{"python -c pipe (not a shell)", "python3", []string{"-c", "ls | wc"}, false},
		{"python -c metachar", "python", []string{"-c", "a; b"}, false},

		// --- NOT opaque: no -c ---
		{"sh bare", "sh", []string{}, false},
		{"sh login", "sh", []string{"-l"}, false},

		// --- NOT opaque: empty command ---
		{"empty", "", []string{"-c", "foo | bar"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsOpaqueShellC(tt.command, tt.args); got != tt.want {
				t.Errorf("IsOpaqueShellC(%q, %v) = %v, want %v", tt.command, tt.args, got, tt.want)
			}
		})
	}
}

func TestIsKnownShell(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"sh", true},
		{"bash", true},
		{"dash", true},
		{"ash", true},
		{"mksh", true},
		{"ksh", true},
		{"zsh", true},
		{"fish", false},
		{"busybox", false},
		{"python", false},
		{"", false},
		{"sh.exe", false}, // Windows shells not in scope
		{"-sh", false},    // login-shell argv0 convention
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := isKnownShell(tt.in); got != tt.want {
				t.Errorf("isKnownShell(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
