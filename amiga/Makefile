# AmiSSL-Tunnel — shim build (amissl.library + amisslmaster.library)
#
# No custom bsdsocket.library: the shim rides the resident Roadshow/AmiTCP stack.
# Build under WSL:
#   export PATH=/opt/amiga/bin:/usr/bin:/bin && make
CC     = m68k-amigaos-gcc
CFLAGS = -m68000 -O2 -nostartfiles -nostdlib -fomit-frame-pointer

AMISSL_OBJS = amissl_start.o amissl.o
MASTER_OBJS = amisslmaster_start.o amisslmaster.o

all: amissl.library amisslmaster.library

amissl.library: $(AMISSL_OBJS)
	$(CC) -m68000 -nostartfiles -nostdlib -o $@ $(AMISSL_OBJS)
amissl_start.o: amissl_start.S
	$(CC) -m68000 -c -o $@ $<
amissl.o: amissl.c
	$(CC) $(CFLAGS) -c -o $@ $<

amisslmaster.library: $(MASTER_OBJS)
	$(CC) -m68000 -nostartfiles -nostdlib -o $@ $(MASTER_OBJS)
amisslmaster_start.o: amisslmaster_start.S
	$(CC) -m68000 -c -o $@ $<
amisslmaster.o: amisslmaster.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(AMISSL_OBJS) $(MASTER_OBJS) amissl.library amisslmaster.library
