# eBPF connect hook assets

- `connect.bpf.c`: CO-RE BPF program (go:build ignore) built with clang/llc.
- `connect_bpfel.o`: compiled artifact embedded in Go via `program.go`.
- `Makefile`: helper to rebuild the object locally.

Rebuild (local, Linux with clang and BTF available):
```
cd internal/netmonitor/ebpf
make
```
Then re-run `go test ./...` to ensure the embedded object is updated.
