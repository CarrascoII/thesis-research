MBEDTLS_DIR = ../mbedtls
MY_SHA256 = sha256/sha256_alt
MY_AES = aes/aes_alt
# PAPI_DIR = ../papi/src/install

MBEDTLS_LIB_MAKE = $(MAKE) -C $(MBEDTLS_DIR)/library
MBEDTLS_PROGS_MAKE = $(MAKE) -C $(MBEDTLS_DIR)/programs

ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -D_FILE_OFFSET_BITS=64
LOCAL_CFLAGS = $(MY_AES).o -I$(MBEDTLS_DIR)/include -L$(MBEDTLS_DIR)/library -lmbedx509 -lmbedtls -lmbedcrypto

TLS_CFLAGS = -I$(CURDIR) -DMBEDTLS_CONFIG_FILE='<config_alt.h>'
CIPHER_CFLAGS = -I$(CURDIR) -DMBEDTLS_CONFIG_FILE='<config_cipher.h>'
# -I${PAPI_DIR}/include -L${PAPI_DIR}/lib -lpapi

.PHONY: all lib_tls lib_cipher mbedtls server_obj server client_obj client cipher_obj cipher clean_progs clean

all: mbedtls server_obj client_obj cipher_obj

local: server_obj client_obj cipher_obj

lib_tls: 
	$(CC) $(ALL_CFLAGS) $(TLS_CFLAGS) -I$(MBEDTLS_DIR)/include -c $(MY_SHA256).c -o $(MY_SHA256).o 
	$(CC) $(ALL_CFLAGS) $(TLS_CFLAGS) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_CFLAGS)"

lib_cipher: 
	$(CC) $(ALL_CFLAGS) $(CIPHER_CFLAGS) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(CIPHER_CFLAGS)"

mbedtls: lib_tls
	$(MBEDTLS_PROGS_MAKE) CFLAGS="$(TLS_CFLAGS) $(CURDIR)/$(MY_SHA256).o $(CURDIR)/$(MY_AES).o"

server_obj: lib_tls
	rm -f server.out
	$(CC) $(ALL_CFLAGS) $(TLS_CFLAGS) server.c $(MY_SHA256).o $(LOCAL_CFLAGS) -o server.out

server: server_obj
	./server.out

client_obj: lib_tls
	rm -f client.out
	$(CC) $(ALL_CFLAGS) $(TLS_CFLAGS) client.c $(MY_SHA256).o $(LOCAL_CFLAGS) -o client.out

client: client_obj
	./client.out

cipher_obj: lib_cipher
	rm -f cipher.out
	$(CC) $(ALL_CFLAGS) $(CIPHER_CFLAGS) cipher.c $(LOCAL_CFLAGS) -o cipher.out

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