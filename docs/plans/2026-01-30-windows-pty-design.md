# Windows PTY (ConPTY) Implementation Design

**Date:** 2026-01-30
**Status:** Draft
**Author:** Claude + Eran

## Overview

Implement Windows PTY support using ConPTY (Windows Pseudo Console) via the `github.com/UserExistsError/conpty` library. This enables interactive terminal sessions on Windows, matching the functionality available on Linux/macOS.

## Library Selection

Using `github.com/UserExistsError/conpty` because it provides:
- Full ConPTY lifecycle management
- `io.ReadWriter` interface for input/output
- `Resize(width, height)` method
- `Pid()` method
- Options for dimensions, working directory, environment
- `IsConPtyAvailable()` for capability detection

## API Mapping

| Session Method | Unix Implementation | Windows Implementation |
|----------------|---------------------|------------------------|
| `Start()` | `pty.Open()` + `exec.Command` | `conpty.Start(cmdLine, opts...)` |
| `Output()` | Read from master FD → channel | Read from ConPTY → channel |
| `Write()` | Write to master FD | `conpty.Write()` |
| `Resize()` | `TIOCSWINSZ` ioctl | `conpty.Resize()` |
| `Signal()` | `syscall.Kill(-pgid, sig)` | See signal handling below |
| `Wait()` | `cmd.Wait()` | `conpty.Wait(ctx)` |
| `PID()` | `cmd.Process.Pid` | `conpty.Pid()` |

## Signal Handling

Windows lacks POSIX signals. Mapping strategy:

| Signal | Windows Equivalent |
|--------|-------------------|
| `SIGINT` | `GenerateConsoleCtrlEvent(CTRL_C_EVENT)` or write `\x03` to PTY |
| `SIGTERM` | `TerminateProcess()` with exit code 1 |
| `SIGKILL` | `TerminateProcess()` with exit code 1 |
| `SIGHUP` | `TerminateProcess()` with exit code 1 |
| `SIGQUIT` | Write `\x1c` to PTY (Ctrl+\) |
| `SIGWINCH` | N/A (use `Resize()` method instead) |

**Note:** For `SIGINT`, writing `\x03` (Ctrl+C) to the PTY input is the most reliable approach as it lets the shell/application handle it naturally.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Session                              │
│  - cpty *conpty.ConPty                                      │
│  - outCh chan []byte                                         │
│  - outDone chan struct{}                                     │
│  - pid int                                                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    conpty.ConPty                             │
│  - Read()/Write() for I/O                                   │
│  - Resize() for terminal size                               │
│  - Wait() for process exit                                  │
│  - Close() for cleanup                                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Windows ConPTY APIs                        │
│  - CreatePseudoConsole()                                    │
│  - ResizePseudoConsole()                                    │
│  - ClosePseudoConsole()                                     │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Details

### Session Struct

```go
type Session struct {
    cpty    *conpty.ConPty
    outCh   chan []byte
    outDone chan struct{}
    pid     int
    closed  bool
    mu      sync.Mutex
}
```

### Start Implementation

```go
func (e *Engine) Start(ctx context.Context, req StartRequest) (*Session, error) {
    if !conpty.IsConPtyAvailable() {
        return nil, ErrConPtyUnavailable
    }

    // Build command line (Windows requires single string)
    cmdLine := buildCommandLine(req.Command, req.Args)

    // Build options
    opts := []conpty.ConPtyOption{}
    if req.InitialSize.Rows > 0 && req.InitialSize.Cols > 0 {
        opts = append(opts, conpty.ConPtyDimensions(
            int(req.InitialSize.Cols),
            int(req.InitialSize.Rows),
        ))
    }
    if req.Dir != "" {
        opts = append(opts, conpty.ConPtyWorkDir(req.Dir))
    }
    if len(req.Env) > 0 {
        opts = append(opts, conpty.ConPtyEnv(req.Env))
    }

    cpty, err := conpty.Start(cmdLine, opts...)
    if err != nil {
        return nil, err
    }

    sess := &Session{
        cpty:    cpty,
        outCh:   make(chan []byte, 16),
        outDone: make(chan struct{}),
        pid:     cpty.Pid(),
    }

    // Start output reader goroutine
    go sess.readOutput()

    return sess, nil
}
```

### Output Reading

```go
func (s *Session) readOutput() {
    defer close(s.outDone)
    defer close(s.outCh)

    buf := make([]byte, 32*1024)
    for {
        n, err := s.cpty.Read(buf)
        if n > 0 {
            b := make([]byte, n)
            copy(b, buf[:n])
            s.outCh <- b
        }
        if err != nil {
            return
        }
    }
}
```

### Signal Handling

```go
func (s *Session) Signal(sig syscall.Signal) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    if s.closed || s.cpty == nil {
        return errors.New("session closed")
    }

    switch sig {
    case syscall.SIGINT:
        // Send Ctrl+C character to PTY
        _, err := s.cpty.Write([]byte{0x03})
        return err
    case syscall.SIGQUIT:
        // Send Ctrl+\ character to PTY
        _, err := s.cpty.Write([]byte{0x1c})
        return err
    case syscall.SIGTERM, syscall.SIGHUP:
        // Terminate the process
        return terminateProcess(s.pid)
    default:
        // Unsupported signal - terminate as fallback
        return terminateProcess(s.pid)
    }
}

func terminateProcess(pid int) error {
    proc, err := os.FindProcess(pid)
    if err != nil {
        return err
    }
    return proc.Kill()
}
```

### Wait Implementation

```go
func (s *Session) Wait() (exitCode int, err error) {
    if s.cpty == nil {
        return 127, errors.New("process not started")
    }

    code, err := s.cpty.Wait(context.Background())

    // Wait for output to drain
    <-s.outDone

    if err != nil {
        return 127, err
    }
    return int(code), nil
}
```

## Command Line Building

Windows requires a single command line string, not separate command/args:

```go
func buildCommandLine(command string, args []string) string {
    if len(args) == 0 {
        return command
    }

    parts := make([]string, 0, len(args)+1)
    parts = append(parts, quoteArg(command))
    for _, arg := range args {
        parts = append(parts, quoteArg(arg))
    }
    return strings.Join(parts, " ")
}

func quoteArg(arg string) string {
    if !strings.ContainsAny(arg, " \t\"") {
        return arg
    }
    // Windows command line escaping rules
    return `"` + strings.ReplaceAll(arg, `"`, `""`) + `"`
}
```

## Error Handling

```go
var (
    ErrConPtyUnavailable = errors.New("ConPTY not available (requires Windows 10 1809+)")
)
```

## Testing Strategy

1. **Unit tests** - Mock conpty for basic flow testing
2. **Integration tests** - Skip on non-Windows or if ConPTY unavailable
3. **Manual testing** - Interactive shell sessions via `agentsh exec --pty cmd.exe`

## Requirements

- Windows 10 version 1809 (October 2018 Update) or later
- `github.com/UserExistsError/conpty` library

## Files to Modify

| File | Change |
|------|--------|
| `internal/pty/engine_windows.go` | Replace stub with ConPTY implementation |
| `go.mod` | Add `github.com/UserExistsError/conpty` dependency |

## Limitations

1. **No process groups** - Windows doesn't have Unix-style process groups, so SIGINT goes to the PTY as Ctrl+C rather than to a process group
2. **Signal limitations** - Only SIGINT, SIGQUIT, SIGTERM, SIGHUP are meaningfully handled
3. **Windows 10 1809+** - Older Windows versions not supported
