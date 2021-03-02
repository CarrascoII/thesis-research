ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -g3 -D_FILE_OFFSET_BITS=64 -I../../../mbedtls/include
PAPI_CFLAGS ?=
CONFIG ?= 

OBJS_CORE =	arc4_alt.o des_alt.o aes_alt.o aria_alt.o camellia_alt.o \
			md5_alt.o sha1_alt.o sha256_alt.o sha512_alt.o

.SILENT:

.PHONY: all print clean

all: print libmbedcore.a

print:
	echo "make mbedcore:"

.c.o:
	echo "  CC    $<"
	$(CC) $(ALL_CFLAGS) $(PAPI_CFLAGS) $(CONFIG) -c $<

libmbedcore.a: $(OBJS_CORE)
	echo "  AR    $@"
	$(AR) src $@ $(OBJS_CORE)

clean:
	echo -n "Cleaning mbedcore........ "
	rm -f *.o libmbedcore.a
	echo "ok"