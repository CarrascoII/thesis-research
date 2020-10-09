MBEDTLS_DIR = ../mbedtls
MY_SHA256 = sha256/sha256_alt
MY_AES = aes/aes_alt
# PAPI_DIR = ../papi/src/install

MBEDTLS_LIB_MAKE = $(MAKE) -C $(MBEDTLS_DIR)/library
MBEDTLS_PROGS_MAKE = $(MAKE) -C $(MBEDTLS_DIR)/programs

ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -D_FILE_OFFSET_BITS=64
LOCAL_CFLAGS = $(MY_SHA256).o $(MY_AES).o -I$(MBEDTLS_DIR)/include -L$(MBEDTLS_DIR)/library -lmbedx509 -lmbedtls -lmbedcrypto
MBEDTLS_CFLAGS = -I$(CURDIR) -DMBEDTLS_CONFIG_FILE='<config_alt.h>'
# -I${PAPI_DIR}/include -L${PAPI_DIR}/lib -lpapi

.PHONY: all lib mbedtls server_obj server client_obj client cipher_obj cipher clean_progs clean

all: mbedtls server_obj client_obj cipher_obj

local: server_obj client_obj cipher_obj

lib: 
	$(CC) $(ALL_CFLAGS) $(MBEDTLS_CFLAGS) -I$(MBEDTLS_DIR)/include -c $(MY_SHA256).c -o $(MY_SHA256).o 
	$(CC) $(ALL_CFLAGS) $(MBEDTLS_CFLAGS) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(MBEDTLS_CFLAGS)"

mbedtls: lib
	$(MBEDTLS_PROGS_MAKE) CFLAGS="$(MBEDTLS_CFLAGS) $(CURDIR)/$(MY_SHA256).o $(CURDIR)/$(MY_AES).o"

server_obj: lib
	rm -f server.out
	$(CC) $(ALL_CFLAGS) server.c $(LOCAL_CFLAGS) -o server.out

server: server_obj
	./server.out

client_obj: lib
	rm -f client.out
	$(CC) $(ALL_CFLAGS) client.c $(LOCAL_CFLAGS) -o client.out

client: client_obj
	./client.out

cipher_obj: lib
	rm -f cipher.out
	$(CC) $(ALL_CFLAGS) cipher.c $(LOCAL_CFLAGS) -o cipher.out

cipher: cipher_obj
#	source init_papi.sh
	./cipher.out

clean_progs:
	rm -f server.out
	rm -f client.out
	rm -f cipher.out
	
clean: clean_progs
	$(MBEDTLS_PROGS_MAKE) clean
	$(MBEDTLS_LIB_MAKE) clean
	rm -f $(MY_SHA256).o
	rm -f $(MY_AES).o