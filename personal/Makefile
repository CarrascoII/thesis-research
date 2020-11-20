MBEDTLS_DIR = ../mbedtls
PERSONAL_DIR = ../personal
MY_SHA256 = sha256/sha256_alt
MY_AES = aes/aes_alt
PAPI_DIR = ../papi/src/install

MBEDTLS_LIB_MAKE = $(MAKE) -C $(MBEDTLS_DIR)/library
MBEDTLS_PROGS_MAKE = $(MAKE) -C $(MBEDTLS_DIR)/programs

ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -g3 -D_FILE_OFFSET_BITS=64
LOCAL_CFLAGS = $(MY_AES).o -I$(MBEDTLS_DIR)/include -L$(MBEDTLS_DIR)/library -lmbedx509 -lmbedtls -lmbedcrypto
PAPI_CFLAGS = -I${PAPI_DIR}/include -L${PAPI_DIR}/lib -lpapi

TLS_CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/config_tls_psk.h>'
CIPHER_CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/config_cipher.h>'

.PHONY: lib_mbedtls lib_tls lib_cipher lib_papi progs server_obj server client_obj client tls cipher_obj cipher server_papi_obj server_papi client_papi_obj client_papi tls_papi cipher_papi_obj cipher_papi clean_local clean

# all: mbedtls server_obj client_obj cipher_obj

# local: server_obj client_obj cipher_obj

### MAKE MBEDTLS LIBRARY ###
lib_mbedtls:
	gcc $(ALL_CFLAGS) -I$(MBEDTLS_DIR)/include -c $(MY_SHA256).c -o $(MY_SHA256).o 
	gcc $(ALL_CFLAGS) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	export DEBUG=1
	$(MBEDTLS_LIB_MAKE)

lib_tls:
	gcc $(ALL_CFLAGS) $(TLS_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_SHA256).c -o $(MY_SHA256).o 
	gcc $(ALL_CFLAGS) $(TLS_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	export DEBUG=1
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_CONFIG)"

lib_cipher:
	gcc $(ALL_CFLAGS) $(CIPHER_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	export DEBUG=1
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(CIPHER_CONFIG)"

lib_papi:
	gcc $(ALL_CFLAGS) $(TLS_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_SHA256).c -o $(MY_SHA256).o 
	gcc $(ALL_CFLAGS) $(TLS_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_CONFIG) -I../$(PAPI_DIR)/include -L../$(PAPI_DIR)/lib -lpapi"

### MAKE MBEDTLS PROGRAMS ###
progs: lib_mbedtls
	$(MBEDTLS_PROGS_MAKE) CFLAGS="../$(PERSONAL_DIR)/$(MY_SHA256).o ../$(PERSONAL_DIR)/$(MY_AES).o"

### MAKE PERSONAL ###
server_obj: lib_tls
	rm -f tls_server.out
	gcc $(ALL_CFLAGS) tls_server.c $(MY_SHA256).o $(LOCAL_CFLAGS) -o tls_server.out

server: server_obj
	./tls_server.out

client_obj: lib_tls
	rm -f tls_client.out
	gcc $(ALL_CFLAGS) tls_client.c $(MY_SHA256).o $(LOCAL_CFLAGS) -o tls_client.out

client: client_obj
	./tls_client.out

tls: clean server_obj client_obj
	./check_footprint.sh
	
cipher_obj: lib_cipher
	rm -f cipher.out
	gcc $(ALL_CFLAGS) cipher.c -lm $(LOCAL_CFLAGS) -o cipher.out

cipher: cipher_obj
	./cipher.out

### MAKE PERSONAL PAPI ###
server_papi_obj: lib_papi
	rm -f tls_server.out
	gcc $(ALL_CFLAGS) tls_server.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o tls_server.out

server_papi: server_papi_obj
#	source ./init_papi.sh
	./tls_server.out

client_papi_obj: lib_papi
	rm -f tls_client.out
	gcc $(ALL_CFLAGS) tls_client.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o tls_client.out

client_papi: client_papi_obj
#	source ./init_papi.sh
	./tls_client.out

tls_papi: clean server_papi_obj client_papi_obj
	./check_footprint.sh

cipher_papi_obj: lib_cipher
	rm -f cipher.out
	gcc $(ALL_CFLAGS) cipher.c -lm $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o cipher.out

cipher_papi: cipher_papi_obj
#	source ./init_papi.sh
	./cipher.out

### CLEAN ###
clean_local:
	rm -f tls_server.out
	rm -f tls_client.out
	rm -f cipher.out
	
clean: clean_local
	$(MBEDTLS_PROGS_MAKE) clean
	$(MBEDTLS_LIB_MAKE) clean
	rm -f $(MY_SHA256).o
	rm -f $(MY_AES).o