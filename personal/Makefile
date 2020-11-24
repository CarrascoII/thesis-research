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

TLS_PSK_CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/tls_psk/config_psk.h>'
TLS_RSA_CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/tls_rsa/config_rsa.h>'
CIPHER_CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/test_cipher/config_cipher.h>'

.PHONY: lib_mbedtls lib_psk lib_psk_papi lib_rsa lib_rsa_papi lib_cipher \
		progs \
		psk_server run_psk_server psk_client run_psk_client tls_psk \
		psk_server_papi run_psk_server_papi psk_client_papi run_psk_client_papi tls_psk_papi \
		rsa_server run_rsa_server rsa_client run_rsa_client tls_rsa \
		rsa_server_papi run_rsa_server_papi rsa_client_papi run_rsa_client_papi tls_rsa_papi \
		cipher run_cipher \
		cipher_papi run_cipher_papi \
		clean_local clean

### MAKE MBEDTLS LIBRARY ###
lib_mbedtls:
	gcc $(ALL_CFLAGS) -I$(MBEDTLS_DIR)/include -c $(MY_SHA256).c -o $(MY_SHA256).o 
	gcc $(ALL_CFLAGS) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	$(MBEDTLS_LIB_MAKE)

lib_psk:
	gcc $(ALL_CFLAGS) $(TLS_PSK_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_SHA256).c -o $(MY_SHA256).o 
	gcc $(ALL_CFLAGS) $(TLS_PSK_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_PSK_CONFIG)"

lib_psk_papi:
	gcc $(ALL_CFLAGS) $(TLS_PSK_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_SHA256).c -o $(MY_SHA256).o 
	gcc $(ALL_CFLAGS) $(TLS_PSK_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_PSK_CONFIG) -I../$(PAPI_DIR)/include -L../$(PAPI_DIR)/lib -lpapi"

lib_rsa:
	gcc $(ALL_CFLAGS) $(TLS_RSA_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_SHA256).c -o $(MY_SHA256).o 
	gcc $(ALL_CFLAGS) $(TLS_RSA_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_RSA_CONFIG)"

lib_rsa_papi:
	gcc $(ALL_CFLAGS) $(TLS_RSA_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_SHA256).c -o $(MY_SHA256).o 
	gcc $(ALL_CFLAGS) $(TLS_RSA_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_RSA_CONFIG) -I../$(PAPI_DIR)/include -L../$(PAPI_DIR)/lib -lpapi"

lib_cipher:
	gcc $(ALL_CFLAGS) $(CIPHER_CONFIG) -I$(MBEDTLS_DIR)/include -c $(MY_AES).c -o $(MY_AES).o
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(CIPHER_CONFIG)"

### MAKE MBEDTLS PROGRAMS ###
progs: lib_mbedtls
	$(MBEDTLS_PROGS_MAKE) CFLAGS="../$(PERSONAL_DIR)/$(MY_SHA256).o ../$(PERSONAL_DIR)/$(MY_AES).o"

### MAKE TLS PSK ###
psk_server: lib_psk
	rm -f tls_psk/psk_server.out
	gcc $(ALL_CFLAGS) tls_psk/psk_server.c $(MY_SHA256).o $(LOCAL_CFLAGS) -o tls_psk/psk_server.out

run_psk_server: psk_server
	./tls_psk/psk_server.out

psk_client: lib_psk
	rm -f tls_psk/psk_client.out
	gcc $(ALL_CFLAGS) tls_psk/psk_client.c $(MY_SHA256).o $(LOCAL_CFLAGS) -o tls_psk/psk_client.out

run_psk_client: psk_client
	./tls_psk/psk_client.out

tls_psk: clean psk_server psk_client

### MAKE TLS PSK PAPI ###
psk_server_papi: lib_psk_papi
	rm -f tls_psk/psk_server.out
	gcc $(ALL_CFLAGS) tls_psk/psk_server.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o tls_psk/psk_server.out

run_psk_server_papi: psk_server_papi
	./tls_psk/psk_server.out

psk_client_papi: lib_psk_papi
	rm -f tls_psk/psk_client.out
	gcc $(ALL_CFLAGS) tls_psk/psk_client.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o tls_psk/psk_client.out

run_psk_client_papi: psk_client_papi
	./tls_psk/psk_client.out

tls_psk_papi: clean psk_server_papi psk_client_papi

### MAKE TLS RSA ###
rsa_server: lib_rsa
	rm -f tls_rsa/rsa_server.out
	gcc $(ALL_CFLAGS) tls_rsa/rsa_server.c $(MY_SHA256).o $(LOCAL_CFLAGS) -o tls_rsa/rsa_server.out

run_rsa_server: rsa_server
	./tls_rsa/rsa_server.out

rsa_client: lib_rsa
	rm -f tls_rsa/rsa_client.out
	gcc $(ALL_CFLAGS) tls_rsa/rsa_client.c $(MY_SHA256).o $(LOCAL_CFLAGS) -o tls_rsa/rsa_client.out

run_rsa_client: rsa_client
	./tls_rsa/rsa_client.out

tls_rsa: clean rsa_server rsa_client

### MAKE TLS RSA PAPI ###
rsa_server_papi: lib_rsa_papi
	rm -f tls_rsa/rsa_server.out
	gcc $(ALL_CFLAGS) tls_rsa/rsa_server.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o tls_rsa/rsa_server.out

run_rsa_server_papi: rsa_server_papi
	./tls_rsa/rsa_server.out

rsa_client_papi: lib_rsa_papi
	rm -f tls_rsa/rsa_client.out
	gcc $(ALL_CFLAGS) tls_rsa/rsa_client.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o tls_rsa/rsa_client.out

run_rsa_client_papi: rsa_client_papi
	./tls_rsa/rsa_client.out

tls_rsa_papi: clean rsa_server_papi rsa_client_papi

### MAKE TEST CIPHER ###
cipher: lib_cipher
	rm -f test_cipher/cipher.out
	gcc $(ALL_CFLAGS) test_cipher/cipher.c -lm $(LOCAL_CFLAGS) -o test_cipher/cipher.out

run_cipher: cipher
	./test_cipher/cipher.out

### MAKE TEST CIPHER PAPI ###
cipher_papi: lib_cipher
	rm -f test_cipher/cipher.out
	gcc $(ALL_CFLAGS) test_cipher/cipher.c -lm $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o test_cipher/cipher.out

run_cipher_papi: cipher_papi
	./test_cipher/cipher.out

### CLEAN ###
clean_local:
	rm -f tls_psk/psk_server.out
	rm -f tls_psk/psk_client.out
	rm -f tls_rsa/rsa_server.out
	rm -f tls_rsa/rsa_client.out
	rm -f test_cipher/cipher.out
	
clean: clean_local
	$(MBEDTLS_PROGS_MAKE) clean
	$(MBEDTLS_LIB_MAKE) clean
	rm -f $(MY_SHA256).o
	rm -f $(MY_AES).o