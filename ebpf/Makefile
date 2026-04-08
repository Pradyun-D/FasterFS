CLANG   := clang
CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_x86

PROGS := fasterfs_monitor.bpf.o fasterfs_sockopts.bpf.o

all: $(PROGS)

%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) \
		-I. \
		-c $< -o $@
	@echo "[+] Compiled $@"

clean:
	rm -f $(PROGS)

.PHONY: all clean
