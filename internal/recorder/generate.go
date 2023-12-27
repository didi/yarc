package recorder

// $BPF_CLANG $BPF_IDENT $BPF_CFLAGS are set by Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel $BPF_IDENT ../../bpf/bpf.c
