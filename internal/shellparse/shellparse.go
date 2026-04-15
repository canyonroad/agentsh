// Package shellparse extracts the policy-relevant binary from a shell-wrapped
// invocation like `sh -c "shutdown now"`.
//
// Why: the server's policy pre-check runs CheckCommand(cmd, args). When the
// client invokes a shell with `-c`, the command is the shell binary and the
// script is opaque to the policy engine. A rule like `deny bin=shutdown`
// never fires for `sh -c "shutdown now"` unless we peek inside the script.
//
// This package implements that peek for the narrow case where the script is
// a single external command with no shell features (pipes, globs, redirects,
// builtins, quoting, compound operators, …). For anything more complex we
// return ok=false and the caller falls back to checking the shell itself —
// a safe default because the shell's own rule (or per-builtin rule via
// env_inject) still applies.
//
// This is a best-effort pre-check aid, NOT a sandbox. The actual exec still
// runs via the shell; seccomp/landlock/env_inject remain the primary
// enforcement layers. This package only widens what the policy pre-check
// can see.
package shellparse

import (
	"strings"
)

// DerivePolicyTarget reports the underlying binary and args that should be
// used for a policy pre-check when command+args represents a simple shell
// invocation of the form `<shell> -c "<simple-cmd>"`.
//
// Returns (derivedCmd, derivedArgs, true) for invocations the caller can
// safely substitute for policy evaluation, or ("", nil, false) otherwise —
// in which case the caller MUST use the original command/args UNLESS
// IsShellCBypassAttempt reports true, which indicates a known command-exec
// wrapper in a form we can't safely parse; the caller should fail closed.
//
// The input command may be an absolute path ("/bin/sh"), a relative path
// ("./sh"), or a bare name ("bash"); the basename is lowercased before
// matching the known-shell set so that case-insensitive filesystems
// (e.g. stock macOS) don't produce a bypass where `/BIN/SH` is recognized
// by the policy engine but not by this derivation. Both `/` and `\` are
// treated as path separators regardless of GOOS so cross-compiled Windows
// builds parse Unix-style exec paths the same way a Linux server would.
func DerivePolicyTarget(command string, args []string) (string, []string, bool) {
	if command == "" {
		return "", nil, false
	}
	if !isKnownShell(basenameLower(command)) {
		return "", nil, false
	}
	cmd, argv, status := parseSimpleShellC(args)
	if status == statusOK {
		return cmd, argv, true
	}
	return "", nil, false
}

// IsShellCBypassAttempt reports whether command+args is a shell-c invocation
// that exposes a known command-exec wrapper (nohup, nice, exec, command) in
// a form we can't safely collapse to a single binary — for example
// `sh -c "exec -a foo shutdown"` or `sh -c "nohup --preserve-status rm /"`.
// The caller (policy engine) should treat a true return as grounds to fail
// closed: the operator's allow-shell rule would otherwise cover a bypass
// attempt that DerivePolicyTarget declined to rewrite.
//
// Returns false for invocations that DerivePolicyTarget would succeed on,
// so a typical caller checks this only after DerivePolicyTarget reports
// ok=false.
func IsShellCBypassAttempt(command string, args []string) bool {
	if command == "" {
		return false
	}
	if !isKnownShell(basenameLower(command)) {
		return false
	}
	_, _, status := parseSimpleShellC(args)
	return status == statusBypass
}

// IsOpaqueShellC reports whether command+args is a shell-c invocation whose
// script is a multi-command program our parser can't safely reduce to a
// single binary. Opaque scripts contain shell features like metacharacters
// (`;`, `&`, `|`), redirects, subshells, globs, quoting, or parameter
// substitution — any of which can cause the shell to execute a different
// binary than the first token suggests.
//
// The caller (policy engine) should fail closed on true ONLY when the
// policy contains at least one restrictive command rule (deny, redirect,
// soft_delete, approve, audit). Policies that only allow are, by the
// operator's own expression, not relying on command-level restrictions —
// denying opaque scripts there would break legitimate shell use without
// closing any bypass. See Engine.hasRestrictiveCommandRule for the gate.
//
// Returns false for invocations DerivePolicyTarget can rewrite and for
// bypass forms (IsShellCBypassAttempt is the correct API for those).
func IsOpaqueShellC(command string, args []string) bool {
	if command == "" {
		return false
	}
	if !isKnownShell(basenameLower(command)) {
		return false
	}
	_, _, status := parseSimpleShellC(args)
	return status == statusOpaque
}

// basenameLower returns the last path segment of s, lowercased, treating
// both '/' and '\' as separators. Using stdlib filepath.Base would pick up
// host-OS separator rules at build time, which would cause the same input
// to parse differently on a Linux vs. Windows build of this binary. The
// policy engine normalizes command basenames the same way, so mirroring
// that behavior here closes the mismatch that would otherwise let a
// Windows-separator path slip past shell detection while still matching
// shell-targeted allow rules.
//
// A trailing ".real" suffix is stripped so shell detection also covers
// the agentsh shell shim's install layout. `agentsh shim install-shell`
// renames the original shell to `<name>.real` and places the shim at
// the original path (`/bin/sh` → shim, `/bin/sh.real` → real shell).
// When the shim forwards to `agentsh exec`, the server sees the real
// shell's `.real` path as the outer command. Without this normalization,
// `sh.real`/`bash.real` would miss isKnownShell, shell-c derivation
// would be skipped, and the policy would fall through to the outer
// allow-rule that must exist for the shim's real-shell invocations to
// run — silently admitting inner commands the policy would otherwise
// deny.
func basenameLower(s string) string {
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, ".real")
	return s
}

// isKnownShell reports whether base names a POSIX-compatible shell whose
// `-c` semantics are well-defined enough to justify looking past it.
// `busybox` and multi-call binaries are intentionally excluded: inferring
// which applet will run would require replicating busybox's argv dispatch,
// and a false-positive there could bypass policy.
//
// zsh is included even though its -c handling has some idiosyncrasies
// (globbing, word-splitting) because operators commonly set zsh as $SHELL;
// excluding it creates a bypass where `allow bin=zsh` admits denied inner
// commands. Our script byte allowlist already excludes glob metachars, so
// the practical derive path stays safe.
func isKnownShell(base string) bool {
	switch base {
	case "sh", "bash", "dash", "ash", "mksh", "ksh", "zsh":
		return true
	}
	return false
}

// parseStatus reports the outcome of shell-c derivation, distinguishing
// four cases the caller needs to act on differently:
//
//   - statusOK: the returned (cmd, args) is a safe policy substitute.
//   - statusFallback: shape isn't something we can rewrite (unknown shell
//     option, builtin first token, empty script, unknown assign-prefix
//     shape, etc.) AND we don't see a bypass risk. The caller should
//     evaluate the original shell invocation — this is the
//     default-safe fallback.
//   - statusBypass: we recognized a known command-exec wrapper in a form
//     we can't safely collapse (e.g. `exec -a foo bin`, `nohup --help bin`,
//     `nice --adjustment=N bin`). Falling back to the outer shell rule
//     would allow a deny bypass, because the operator named the shell
//     rule expecting only simple shell use. The caller should fail closed.
//   - statusOpaque: the script is a multi-command shell program we can't
//     parse — unquoted metachars like `;`, `&`, `|`, globs, redirects,
//     subshells, expansion-bearing double-quotes (`"$VAR"`, `"\`cmd\`"`,
//     `"\\foo"`), unterminated quotes, etc. The shell will execute
//     arbitrary binaries, so an operator with a restrictive command rule
//     (deny, redirect, audit, approve, soft_delete) anywhere in their
//     policy cannot rely on the outer `allow sh` rule to cover the
//     script. The caller should promote to deny iff any restrictive
//     command rule exists; otherwise fall back to the outer rule
//     (operator chose broad shell use, no bypass risk).
type parseStatus int

const (
	statusFallback parseStatus = iota
	statusOK
	statusBypass
	statusOpaque
)

// parseSimpleShellC detects the safe subset of `-c "<script>"` invocations
// that can be rewritten to a direct argv for policy purposes.
//
// Returns (cmd, args, statusOK) only when:
//   - shellArgs begins with zero or more SAFE short-option clusters
//     followed by the cluster containing 'c'. Safe clusters contain only
//     {c, e, u, f, x}: e (errexit) and u (nounset) are no-ops for a
//     single external command, f (noglob) is redundant with our script
//     byte-allowlist, and x (xtrace) only prints. So `sh -c "…"`,
//     `sh -ec "…"`, `sh -euxc "…"`, AND split forms like `sh -e -c "…"`
//     or `bash -e -u -c "…"` are all accepted. Long options (`--login`,
//     `--rcfile=…`), operand options (`-o name`, `+o name`), and unknown
//     short options are REJECTED — they either source profile scripts,
//     change the inherited environment, or we can't prove they don't.
//   - The argv entry immediately after the -c cluster is the script. Any
//     arguments AFTER the script are POSIX-positional parameters: the
//     first becomes `$0` inside the script and subsequent ones become
//     `$1`, `$2`, … (sh(1) "COMMAND_STRING" form). Because our script
//     byte-allowlist forbids `$`, the script's executed argv cannot
//     reference them, so it is safe to ignore the extras — the actual
//     command that will run is still `tokens[0] tokens[1:]` from the
//     script string.
//   - script is tokenized by tokenizeSimpleScript into an argv of
//     narrow-allowlisted atoms. Unquoted bytes must be from
//     [A-Za-z0-9_./-]; `'...'` spans accumulate literally; `"..."`
//     spans accumulate iff they contain no `$`, `` ` ``, or `\`.
//     Anything else (metachars, globs, expansions, unterminated
//     quotes) is opaque.
//   - after stripping transparent wrappers, the first token is NOT a shell
//     builtin or reserved word
//
// Known transparent wrappers (exec/command/nohup/nice) in flag forms we
// can't safely parse return statusBypass — see stripWrappers. Anything
// else returns statusFallback.
func parseSimpleShellC(shellArgs []string) (string, []string, parseStatus) {
	cFlagIdx, ok := findShellCFlag(shellArgs)
	if !ok {
		// findShellCFlag rejects the whole args sequence on the first
		// unsafe option, which conflates "no -c anywhere" with "-c is
		// present but preceded or combined with options we can't parse"
		// (e.g., `bash -lc "shutdown"`, `bash -o errexit -c "shutdown"`,
		// `bash --rcfile=X -c "shutdown"`). Returning statusFallback in
		// the latter case lets the outer shell rule admit a deny bypass:
		// operator writes `allow bash` + `deny shutdown`, user runs
		// `bash -lc "shutdown"`, the inner deny never fires. Distinguish
		// the two by scanning for a -c flag anywhere in any short cluster
		// and failing closed when it's present.
		if hasShellCWithUnsafeOptions(shellArgs) {
			return "", nil, statusBypass
		}
		return "", nil, statusFallback
	}
	if cFlagIdx+1 >= len(shellArgs) {
		return "", nil, statusFallback
	}
	script := strings.TrimSpace(shellArgs[cFlagIdx+1])
	if script == "" {
		return "", nil, statusFallback
	}
	// POSIX allows env-assignment prefixes: `PATH=/tmp cmd` runs `cmd` with
	// PATH overridden for that exec only. The `=` byte is never allowed
	// unquoted by tokenizeSimpleScript, which without this parse-through
	// would push assign-prefixed scripts to statusOpaque and silently
	// admit a deny bypass (operator writes `allow sh` + `deny shutdown`,
	// user runs `sh -c "PATH=/tmp shutdown"`, inner deny never fires).
	// Strip leading NAME=VALUE tokens and continue deriving with the
	// remainder, so the inner binary's rule fires normally. A VALUE
	// containing bytes outside the narrow allowlist (`:` in $PATH, `*`
	// in globs, `$` in substitutions, …) signals a bypass: the user is
	// smuggling shell-disallowed content through a pattern our
	// pure-string check can't safely reason about.
	script, dirty := stripLeadingAssignments(script)
	if dirty {
		return "", nil, statusBypass
	}
	script = strings.TrimSpace(script)
	if script == "" {
		// The entire script was env assignments — the shell sets vars and
		// exits with no exec. No command to derive; hand back to outer
		// shell rule.
		return "", nil, statusFallback
	}
	tokens, opaque := tokenizeSimpleScript(script)
	if opaque {
		// The tokenizer rejected some byte outside a quoted span: an
		// unquoted metachar (`;`, `|`, `&`, `>`, `<`, `(`, `)`, `*`, `?`,
		// `[`, etc.), an unterminated quote, or an expansion-triggering
		// byte inside a double-quoted span (`$`, `` ` ``, `\`). We can't
		// predict the argv the shell will execute.
		//
		// Distinguish two failure modes so the caller can pick the right
		// response:
		//   - If the first whitespace-delimited word is a known wrapper
		//     (nohup, nice, exec, …), the operator's `allow sh` rule was
		//     not written anticipating wrapper flag shapes — flag
		//     `--preserve-status=1` fails the tokenizer on `=`, but the
		//     shell would still exec the inner binary with the wrapper's
		//     side effects. Tag statusBypass so the engine fails closed
		//     regardless of policy strictness.
		//   - Otherwise the script is a multi-command program we can't
		//     parse; tag statusOpaque so CheckCommand promotes to deny
		//     only when a restrictive rule exists. An allow-only policy
		//     (operator already chose broad shell use) won't be broken
		//     by ordinary pipelines or quoted expansions.
		if headWord := firstWord(script); isTransparentWrapper(headWord) {
			return "", nil, statusBypass
		}
		return "", nil, statusOpaque
	}
	if len(tokens) == 0 {
		return "", nil, statusFallback
	}
	tokens, bypass := stripWrappers(tokens)
	if bypass {
		return "", nil, statusBypass
	}
	if len(tokens) == 0 {
		return "", nil, statusFallback
	}
	if isShellBuiltin(tokens[0]) {
		return "", nil, statusFallback
	}
	return tokens[0], tokens[1:], statusOK
}

// firstWord returns the first whitespace-delimited token in s, or "" if
// none. It is cheaper than strings.Fields for the common case where we
// only need the head word.
func firstWord(s string) string {
	s = strings.TrimLeft(s, " \t")
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

// stripLeadingAssignments consumes leading whitespace-separated POSIX
// env-assignment tokens (NAME=VALUE) from script and returns the
// unconsumed remainder. The caller uses this to parse-through prefixes
// like `PATH=/tmp nohup shutdown`: after stripping `PATH=/tmp`, the
// remainder is `nohup shutdown`, which derives to `shutdown` via the
// usual wrapper strip. Without parse-through, the `=` byte would fail
// tokenizeSimpleScript and the inner deny rule would be masked by the
// outer shell's allow.
//
// A token is treated as an assignment iff:
//   - It contains an `=`.
//   - The bytes before `=` form a portable shell variable name:
//     leading letter or underscore, then letters/digits/underscores.
//     Names starting with a digit (`0FOO=bar`) are not assignments —
//     the shell would try to exec them — so they end stripping.
//
// The VALUE (bytes after `=`, up to the next whitespace) must be within
// the narrow byte allowlist [A-Za-z0-9_./-]. Any other byte (`:`, `*`,
// `$`, `=`, …) signals a bypass: the user is embedding content the
// shell would process specially that our downstream allowlist check
// can't safely reason about. dirty=true instructs the caller to fail
// closed.
//
// Returns (remainder, false) when zero or more clean assignments were
// consumed. The remainder may still have leading whitespace; callers
// that care should TrimSpace.
// Returns ("", true) when a leading assignment has a dirty VALUE.
func stripLeadingAssignments(script string) (string, bool) {
	remainder := script
	for {
		i := 0
		for i < len(remainder) && (remainder[i] == ' ' || remainder[i] == '\t') {
			i++
		}
		if i >= len(remainder) {
			break
		}
		start := i
		for i < len(remainder) && remainder[i] != ' ' && remainder[i] != '\t' {
			i++
		}
		tok := remainder[start:i]
		eq := strings.IndexByte(tok, '=')
		if eq < 1 {
			return remainder, false
		}
		if !isValidAssignName(tok[:eq]) {
			return remainder, false
		}
		if !valueBytesAllowed(tok[eq+1:]) {
			return "", true
		}
		remainder = remainder[i:]
	}
	return remainder, false
}

// isValidAssignName reports whether name has the shape of a portable
// POSIX shell variable name: leading letter or underscore, then
// letters/digits/underscores. Names that don't match this shape are
// not treated as assignments because the shell itself would not —
// it'd try to execute them as commands — so there's no bypass to
// defend against in that shape.
func isValidAssignName(name string) bool {
	if len(name) == 0 {
		return false
	}
	c := name[0]
	if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_') {
		return false
	}
	for i := 1; i < len(name); i++ {
		c = name[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// valueBytesAllowed reports whether every byte of value is in the
// narrow allowlist [A-Za-z0-9_./-]. This is isUnquotedAllowedByte
// applied over a whole string — VALUEs produced by whitespace-based
// token splitting cannot themselves contain whitespace, so there's no
// separator byte to admit. Characters outside the set (`:`, `*`, `$`,
// `=`, …) are either shell metachars, glob metachars, or embedded
// separators that the tokenizer would have rejected anyway; returning
// false here surfaces the bypass attempt at the point where we can
// still distinguish it from a benign mismatch.
func valueBytesAllowed(value string) bool {
	for i := 0; i < len(value); i++ {
		b := value[i]
		switch {
		case b >= 'A' && b <= 'Z':
		case b >= 'a' && b <= 'z':
		case b >= '0' && b <= '9':
		case b == '_' || b == '.' || b == '/' || b == '-':
		default:
			return false
		}
	}
	return true
}

// tokenizeSimpleScript splits script into argv-style tokens, honoring the
// narrow subset of shell quoting semantics we can reason about safely:
//
//   - Unquoted bytes must be from the narrow allowlist [A-Za-z0-9_./-] plus
//     space/tab as delimiters. Any other unquoted byte (`;`, `|`, `&`, `>`,
//     `<`, `(`, `)`, `*`, `?`, `[`, `=`, `!`, `#`, `~`, newline, non-ASCII,
//     …) triggers opaque — these are shell metachars, globs, expansions, or
//     compound-command markers whose effect on the executed argv we can't
//     predict without running a shell.
//
//   - `'...'`: literal single-quoted spans are always safe. Shell does no
//     interpretation inside — every byte is taken verbatim — so we
//     accumulate them into the current token as-is. An unterminated single
//     quote is opaque (the real shell would block awaiting more input or
//     throw a parse error; either way we shouldn't pretend to know what
//     runs).
//
//   - `"..."`: double-quoted spans are safe ONLY when they contain no
//     `$`, `` ` ``, or `\` — those bytes invoke parameter expansion,
//     command substitution, or C-style escapes whose expansions could
//     resolve to anything. Anything else (spaces, metachars, `=`, `:`,
//     `!`, etc.) is literal inside `"..."` and accumulates into the
//     current token. An unterminated double quote is opaque.
//
//   - Concatenation of unquoted and quoted spans into one token is
//     supported implicitly because state transitions (outside→quoted,
//     quoted→unquoted, etc.) happen without emitting. `foo'bar'` yields
//     one token `foobar`; `a"b c"d` yields `ab cd`. This matches POSIX
//     word-splitting behavior for the cases our byte allowlist admits.
//
// Returns (tokens, false) on clean parse; (nil, true) — opaque — on any
// byte or state we can't safely map to an argv. Trailing whitespace after
// a complete token is fine; a dangling unterminated quote is not.
//
// This is intentionally less permissive than a full shell parser: we err
// on the side of returning opaque so a restrictive policy rule fails
// closed rather than silently admitting a script we misunderstand.
func tokenizeSimpleScript(script string) ([]string, bool) {
	const (
		stateOutside = iota
		stateUnquoted
		stateSingleQuote
		stateDoubleQuote
	)
	var tokens []string
	var cur []byte
	state := stateOutside
	emit := func() {
		tokens = append(tokens, string(cur))
		cur = cur[:0]
	}
	for i := 0; i < len(script); i++ {
		b := script[i]
		switch state {
		case stateOutside:
			switch {
			case b == ' ' || b == '\t':
				// still outside a token
			case b == '\'':
				state = stateSingleQuote
			case b == '"':
				state = stateDoubleQuote
			case isUnquotedAllowedByte(b):
				cur = append(cur, b)
				state = stateUnquoted
			default:
				return nil, true
			}
		case stateUnquoted:
			switch {
			case b == ' ' || b == '\t':
				emit()
				state = stateOutside
			case b == '\'':
				state = stateSingleQuote
			case b == '"':
				state = stateDoubleQuote
			case isUnquotedAllowedByte(b):
				cur = append(cur, b)
			default:
				return nil, true
			}
		case stateSingleQuote:
			if b == '\'' {
				// Close the quote but stay inside the token so
				// `'foo'bar` concatenates to `foobar`.
				state = stateUnquoted
				continue
			}
			// Every other byte — including whitespace, metachars,
			// newlines, non-ASCII — is literal in single quotes.
			cur = append(cur, b)
		case stateDoubleQuote:
			switch b {
			case '"':
				state = stateUnquoted
			case '$', '`', '\\':
				// Parameter expansion, command substitution, C-style
				// escapes: the executed argv depends on shell state we
				// don't have.
				return nil, true
			default:
				cur = append(cur, b)
			}
		}
	}
	switch state {
	case stateOutside:
		// nothing to emit
	case stateUnquoted:
		emit()
	default:
		// dangling open quote — shell would keep reading or parse-error
		return nil, true
	}
	return tokens, false
}

// isUnquotedAllowedByte reports whether b is in the narrow byte set we
// consider safe outside quotes: [A-Za-z0-9_./-]. Anything else is a
// metachar, glob, expansion trigger, or separator that our pure-string
// tokenizer can't safely reduce to an argv. Whitespace is handled by the
// tokenizer state machine, not here.
func isUnquotedAllowedByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '_' || b == '.' || b == '/' || b == '-':
		return true
	}
	return false
}

// stripWrappers removes transparent-wrapper prefixes from tokens. Known
// wrappers are consumed one at a time until the head token is either a
// non-wrapper or unstrippable.
//
// Returns (rest, false) when either all wrappers were stripped cleanly
// or the head isn't a wrapper at all. Returns (nil, true) — bypass — when
// a wrapper is followed by a flag form we can't safely parse:
//
//   - exec -a NAME CMD … : `-a` sets a custom argv0. We don't parse it
//     (one could, but we'd need to validate NAME and the subsequent CMD
//     shape), so any `-` after `exec` fails closed.
//   - command -v / -V / -p : these print info or change the PATH; none
//     are transparent forwarding.
//   - nohup -FLAG … : POSIX nohup has no options; GNU nohup only has
//     --help / --version, neither of which runs a command. Any `-` is
//     either a deliberate bypass or a no-op.
//   - nice -n INCREMENT CMD … : the ONE nice flag form we recognize.
//     Consumed as three tokens (`nice`, `-n`, INCREMENT) when INCREMENT
//     parses as an optionally-signed integer. Other nice flags
//     (--adjustment=N, +N, --help, etc.) fall into bypass.
//
// Design note: we fail closed rather than fall back to the outer shell
// rule because the caller (policy engine) applies the outer rule when
// DerivePolicyTarget returns ok=false. If the head token is a known
// wrapper, the operator's `allow sh` rule was not written anticipating
// a `exec -a CMD shutdown` bypass — that's NOT simple shell use. The
// conservative answer is deny.
func stripWrappers(tokens []string) ([]string, bool) {
	for len(tokens) >= 2 && isTransparentWrapper(tokens[0]) {
		wrapper := tokens[0]
		next := tokens[1]
		if !strings.HasPrefix(next, "-") {
			tokens = tokens[1:]
			continue
		}
		// nice -n INCREMENT CMD … : the one flag form we parse.
		if wrapper == "nice" && next == "-n" && len(tokens) >= 3 && isNumericIncrement(tokens[2]) {
			tokens = tokens[3:]
			continue
		}
		return nil, true
	}
	return tokens, false
}

// isNumericIncrement reports whether s parses as an optionally-signed
// decimal integer. Used to validate the `nice -n <increment>` operand.
func isNumericIncrement(s string) bool {
	if len(s) == 0 {
		return false
	}
	i := 0
	if s[0] == '+' || s[0] == '-' {
		i = 1
		if i >= len(s) {
			return false
		}
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// findShellCFlag locates the short-option cluster that introduces `-c`
// inside shellArgs, walking past any leading safe-option clusters. It
// returns (idx, true) with idx = position of the cluster containing 'c';
// the script lives at shellArgs[idx+1]. On any unexpected option shape
// (long option, operand option like `-o errexit`, unknown short char)
// it returns (0, false).
//
// Safe leading option chars are {e, u, f, x} — see parseSimpleShellC for
// why each is harmless for our single-external-command scope. The 'c'
// option may appear anywhere in a cluster; it terminates scanning as
// soon as it is seen because -c's required argument is the script.
func findShellCFlag(shellArgs []string) (int, bool) {
	for i, arg := range shellArgs {
		if len(arg) < 2 || arg[0] != '-' {
			return 0, false
		}
		if arg[1] == '-' {
			// Rejects long options (`--login`, `--rcfile=…`, `--norc`)
			// AND the bare `--` end-of-options marker — we don't need
			// it since our option set is well-defined, and allowing
			// it would complicate reasoning about positional params.
			return 0, false
		}
		cluster := arg[1:]
		hasC := false
		for j := 0; j < len(cluster); j++ {
			switch cluster[j] {
			case 'c':
				hasC = true
			case 'e', 'u', 'f', 'x':
				// safe; no impact on a single-command script
			default:
				return 0, false
			}
		}
		if hasC {
			return i, true
		}
	}
	return 0, false
}

// hasShellCWithUnsafeOptions reports whether shellArgs contains a `-c`
// short option anywhere in any cluster, even when paired with options
// outside our safe subset. Called after findShellCFlag fails, it lets
// the caller distinguish "no -c at all" (fall back to the outer shell
// rule) from "-c present but option shape unparsable" (fail closed,
// because the outer allow-rule was not written with bypass-via-option
// shapes in mind).
//
// The scan stops at `--` since everything after it is positional. Long
// options (those starting with `--`) are skipped — they never contain
// a short `-c`. Non-option arguments are skipped too; they may appear
// after an `-o NAME` pairing or simply be operand junk, and none of
// them introduce a short-c flag.
func hasShellCWithUnsafeOptions(shellArgs []string) bool {
	for _, arg := range shellArgs {
		if arg == "--" {
			return false
		}
		if len(arg) < 2 || arg[0] != '-' {
			continue
		}
		if arg[1] == '-' {
			continue
		}
		for j := 1; j < len(arg); j++ {
			if arg[j] == 'c' {
				return true
			}
		}
	}
	return false
}

// isTransparentWrapper reports whether tok is a wrapper whose
// policy-relevant binary is the NEXT token. The wrapper itself is not what
// the caller ultimately wants to run — it merely forwards execution:
//
//   - exec: shell builtin that replaces the shell with the command.
//   - command: shell builtin that bypasses function lookup.
//   - nohup: spawns the next command with SIGHUP ignored.
//   - nice: spawns the next command with an adjusted niceness.
//   - time: shell reserved word / binary that runs the next command and
//     prints timing stats. Without this, `sh -c "time shutdown"` falls
//     through to the outer shell allow because `time` classifies as a
//     reserved word → statusFallback.
//   - env: exec wrapper that optionally modifies the environment before
//     running the next command. Without this, `sh -c "env shutdown"`
//     derives to `env` (a bare name with no rule), which default-denies
//     at the derived level but doesn't override the outer shell allow.
//
// Stripping these for policy derivation does NOT alter runtime semantics:
// policy derivation only picks which rule to evaluate. The command that
// actually executes is still the outer `sh -c "<script>"`, so the shell
// will run `nohup shutdown` with SIGHUP ignored exactly as written when
// the decision is allow/audit/approve. For deny the shell never runs, and
// for redirect the command is replaced entirely, so the lost wrapper is
// intentional. Treating these as transparent closes the bypass where
// `sh -c "nohup shutdown"` evaded a `deny bin=shutdown` rule by surfacing
// `nohup` (a bare name with no rule) as the policy target and falling
// through to the outer shell allow.
//
// Wrappers followed by any flag token (e.g. `exec -a`, `command -v`,
// `nice -n 19`, `env -i`, `time -p`) are rejected by the caller — flag
// parsing is wrapper-specific and out of scope; failing to derive at all
// is the safe default.
func isTransparentWrapper(tok string) bool {
	switch tok {
	case "exec", "command", "nohup", "nice", "time", "env":
		return true
	}
	return false
}

// isShellBuiltin reports whether tok is a POSIX or bash shell builtin,
// reserved word, or syntactic keyword that cannot be safely replaced by a
// same-named external binary for policy purposes. Reasons:
//   - No external equivalent (cd, eval, hash, builtin, let, shopt, …).
//   - Dual builtins with divergent semantics (echo, printf, pwd, test, …).
//   - Reserved words (if, while, …) aren't valid first tokens anyway, but
//     blocking them costs nothing.
func isShellBuiltin(tok string) bool {
	switch tok {
	// POSIX special builtins
	case ":", ".", "break", "continue", "eval", "exec", "exit",
		"export", "readonly", "return", "set", "shift", "trap", "unset":
		return true
	// POSIX regular builtins and dual builtins (echo/printf/pwd/test/[
	// blocked to avoid semantic divergence)
	case "alias", "bg", "cd", "command", "fc", "fg", "getopts", "jobs",
		"kill", "newgrp", "read", "umask", "unalias", "wait",
		"echo", "printf", "pwd", "test", "[", "true", "false":
		return true
	// Bash-specific builtins
	case "bind", "builtin", "caller", "compgen", "compopt", "complete",
		"coproc", "declare", "dirs", "disown", "enable", "hash", "help",
		"history", "let", "local", "logout", "mapfile", "popd", "pushd",
		"readarray", "shopt", "source", "suspend", "times", "type",
		"typeset", "ulimit":
		return true
	// Reserved words / syntactic keywords
	case "if", "then", "else", "elif", "fi", "case", "esac", "while",
		"do", "done", "for", "in", "function", "select", "time", "until",
		"{", "}", "!", "[[", "]]":
		return true
	}
	return false
}
