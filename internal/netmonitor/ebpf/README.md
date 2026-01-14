# eBPF connect hook assets

- `connect.bpf.c`: CO-RE BPF program (go:build ignore) built with clang/llc.
- `connect_bpfel.o`: compiled artifact embedded in Go via `program.go`.
- `connect_bpfel_arm64.o`: ARM64 version of the compiled artifact.
- `vmlinux.h`: BTF type definitions (regenerate from running kernel if needed).
- `Makefile`: helper to rebuild the object locally.

## Rebuild

Rebuild locally (Linux with clang and BTF available):
```bash
cd internal/netmonitor/ebpf
make clean && make
```
Then re-run `go test ./...` to ensure the embedded object is updated.

## Regenerate vmlinux.h

If you encounter BTF-related verifier errors on a new kernel:
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
make clean && make
```

## Kernel Compatibility

The eBPF programs use CO-RE (Compile Once - Run Everywhere) and are designed to work with Linux kernels 5.x and 6.x.

### CO-RE and Portability

The compiled `.o` files contain BTF (BPF Type Format) information that allows them to adapt to different kernel versions at load time. The context fields used (`user_ip4`, `user_ip6`, `user_port`) are stable across kernel versions.

The `vmlinux.h` file is gitignored because each build machine should generate it from its own kernel's BTF. However, the committed `.o` files should work across kernel versions thanks to CO-RE.

If you encounter load errors on a specific kernel version, rebuild locally:
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
make clean && make
```

### Kernel 6.x Notes

Kernel 6.x has stricter BPF verifier rules for cgroup socket programs:

1. **Context pointer restrictions**: Cannot pass `ctx` to helper functions after accessing its fields. All context values must be read into local variables first.

2. **Address family**: The `ctx->family` field may not be accessible in all program types. Use the program type to determine the family (e.g., `connect4`/`sendmsg4` = AF_INET, `connect6`/`sendmsg6` = AF_INET6).

3. **Return values**: cgroup/connect and cgroup/sendmsg programs must return 0 (block) or 1 (allow), not negative errno values.

4. **Socket pointer access**: Direct access to `struct sock` via `ctx->sk` is prohibited. Use context fields directly.

### Backward Compatibility

The code patterns used are intentionally conservative to maximize compatibility:

- Extracting context values to local variables works on all kernel versions
- Inferring address family from program type (connect4 = IPv4) is universally correct
- Return values 0/1 are the documented standard for cgroup socket programs

These patterns satisfy both older kernels (which were more lenient) and newer kernels (which are stricter).

### Supported Program Types

- `cgroup/connect4`: TCP connect for IPv4
- `cgroup/connect6`: TCP connect for IPv6
- `cgroup/sendmsg4`: UDP sendmsg for IPv4
- `cgroup/sendmsg6`: UDP sendmsg for IPv6

