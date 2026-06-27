# AXIOM userspace build
AS      = as
LD      = ld
ASFLAGS = --64
LDFLAGS = -T hello.ld

all: hello.elf

hello.o: hello.s
	$(AS) $(ASFLAGS) -o $@ $

hello.elf: hello.o hello.ld
	$(LD) $(LDFLAGS) -o $@ $
	@echo "Built $@ ($$(wc -c < $@) bytes)"
	@readelf -h $@ | grep "Entry point"

clean:
	rm -f hello.o hello.elf

.PHONY: all clean
