ARCH = $(shell uname -m | sed 's/x86_64/x86/')
KERNEL_VERSION = $(shell uname -r)

DEFINES = -D__TARGET_ARCH_$(ARCH)
#DEFINES += -DDEBUG=1
#DEFINES += -DTRACE_BPF_LOG=1

INCLUDES = -I../../bpf/include \
#           -I/usr/src/kernels/$(KERNEL_VERSION)/include \
#           -I/usr/src/kernels/$(KERNEL_VERSION)/arch/$(ARCH)/include\

# 影响 bpf2go 工具生成的文件名、函数名前缀
BPF_IDENT ?= TrafficMirror
export BPF_IDENT

BPF_CLANG ?= clang
BPF_CFLAGS ?= $(DEFINES) $(INCLUDES) -Wall
export BPF_CLANG BPF_CFLAGS

BPF_PREFIX := $(shell echo $(BPF_IDENT) | tr A-Z a-z)
BPF_SOURCES := $(wildcard ../../bpf/*.h)
BPF_SOURCES += $(wildcard ../../bpf/*.c)
BPFEL_OBJECTS := $(BPF_PREFIX)_bpfel.go $(BPF_PREFIX)_bpfel.o

all: bpfel

bpfel: $(BPFEL_OBJECTS)

$(BPF_PREFIX)_bpfel.go: $(BPF_PREFIX)_bpfel.o

$(BPF_PREFIX)_bpfel.o: generate.go $(BPF_SOURCES)
	@echo "> bpf2go..."
	go generate -x
	@echo "> bpf2go done"
	@echo ""

clean:
	-$(RM) $(BPFEL_OBJECTS)

.PHONY: all bpfel clean
