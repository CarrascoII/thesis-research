ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -g3 -D_FILE_OFFSET_BITS=64 -I../../mbedtls/include

CONFIG ?= 

.SILENT:

.PHONY: all cipher print aes aes_module sha256 clean

all: print aes aes_module sha256

cipher: print aes aes_module

print:
	echo "make my_mbedtls:"

aes:
	echo "  gcc   aes"
	gcc $(ALL_CFLAGS) -maes -msse4 $(CONFIG) -c aes/aes_alt.c -o aes/aes_alt.o
	# gcc $(ALL_CFLAGS) -O0 -msse2 -msse -march=native -maes $(CONFIG) -c aes/aes_alt.c -o aes/aes_alt.o

aes_module:
	echo "  gcc   aes_module"
	gcc $(ALL_CFLAGS) $(CONFIG) -c aes_module/aes_alt.c -o aes_module/aes_alt.o

sha256:
	echo "  gcc   sha256"
	gcc $(ALL_CFLAGS) $(CONFIG) -c sha256/sha256_alt.c -o sha256/sha256_alt.o

clean:
	echo -n "Cleaning my_mbedtls...... "
	rm -f */*.o
	echo "ok"