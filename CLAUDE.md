# Claude Code Guidelines

Read and follow [AGENTS.md](./AGENTS.md) for cross-platform development rules.

## Project Structure

- `cmd/` - CLI entry points
- `internal/` - Private packages
- `pkg/` - Public packages
- `internal/platform/` - OS-specific implementations (darwin, windows, linux)

## Build & Test

```bash
go build ./...                    # Build all
go test ./...                     # Test all
GOOS=windows go build ./...       # Verify Windows cross-compile
```

## Before Committing

1. Verify cross-compilation: `GOOS=windows go build ./...`
2. Run tests: `go test ./...`
3. Check for hardcoded paths or OS-specific assumptions
