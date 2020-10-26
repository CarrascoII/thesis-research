MBEDTLS_DIR = ../mbedtls
MY_SHA256 = sha256/sha256_alt
MY_AES = aes/aes_alt
PAPI_DIR = ../papi/src/install

MBEDTLS_LIB_MAKE = $(MAKE) -C $(MBEDTLS_DIR)/library
MBEDTLS_PROGS_MAKE = $(MAKE) -C $(MBEDTLS_DIR)/programs

ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -g3 -D_FILE_OFFSET_BITS=64
LOCAL_CFLAGS = $(MY_AES).o -I$(MBEDTLS_DIR)/include -L$(MBEDTLS_DIR)/library -lmbedx509 -lmbedtls -lmbedcrypto
PAPI_CFLAGS = -I${PAPI_DIR}/include -L${PAPI_DIR}/lib -lpapi

TLS_CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/config_tls.h>'
CIPHER_CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/config_cipher.h>'

.PHONY: all local lib_tls lib_cipher progs server_obj server client_obj client tls cipher_obj cipher cipher_papi_obj cipher_papi clean_progs clean

# all: mbedtls server_obj client_obj cipher_obj

# local: server_obj client_obj cipher_obj

lib_tls:
	gcc $(ALL_CFLAGS) $(TLS_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_SHA256).c -o $(MY_SHA256).o 
	gcc $(ALL_CFLAGS) $(TLS_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	export DEBUG=1
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_CONFIG)"

lib_cipher:
	gcc $(ALL_CFLAGS) $(CIPHER_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	export DEBUG=1
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(CIPHER_CONFIG)"

progs: lib_tls
	$(MBEDTLS_PROGS_MAKE) CFLAGS="$(TLS_CONFIG) ../../personal/$(MY_SHA256).o ../../personal/$(MY_AES).o"

server_obj: lib_tls
	rm -f server.out
	gcc $(ALL_CFLAGS) $(TLS_CONFIG) tls_server.c $(MY_SHA256).o $(LOCAL_CFLAGS) -o server.out

server: server_obj
	./server.out

client_obj: lib_tls
	rm -f client.out
	gcc $(ALL_CFLAGS) $(TLS_CONFIG) tls_client.c $(MY_SHA256).o $(LOCAL_CFLAGS) -o client.out

client: client_obj
	./client.out

tls: server_obj client_obj

tls_papi:
	gcc $(ALL_CFLAGS) $(TLS_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_SHA256).c -o $(MY_SHA256).o 
	gcc $(ALL_CFLAGS) $(TLS_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_CONFIG) $(PAPI_CFLAGS)"
	gcc $(ALL_CFLAGS) $(TLS_CONFIG) tls_server.c $(MY_SHA256).o $(LOCAL_CFLAGS) -o server.out
	gcc $(ALL_CFLAGS) $(TLS_CONFIG) tls_client.c $(MY_SHA256).o $(LOCAL_CFLAGS) -o client.out

cipher_obj: lib_cipher
	rm -f cipher.out
	gcc $(ALL_CFLAGS) $(CIPHER_CONFIG) cipher.c -lm $(LOCAL_CFLAGS) -o cipher.out

cipher: cipher_obj
	./cipher.out

cipher_papi_obj: lib_cipher
	rm -f cipher.out
	gcc $(ALL_CFLAGS) $(CIPHER_CONFIG) cipher.c -lm $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o cipher.out

cipher_papi: cipher_papi_obj
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