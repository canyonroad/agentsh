BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf

all: connect_bpfel.o connect_bpfel_arm64.o

connect_bpfel.o: connect.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_x86 -c $< -o $@

connect_bpfel_arm64.o: connect.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_arm64 -c $< -o $@

clean:
	rm -f connect_bpfel.o connect_bpfel_arm64.o

.PHONY: all clean
