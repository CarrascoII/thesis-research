MY_AES = my_aes/aes_alt
MY_AES_MODULE = my_aes_module/aes_alt
MY_SHA256 = my_sha256/sha256_alt

MBEDTLS_INC_DIR = ../mbedtls/include
MBEDTLS_LIB_DIR = ../mbedtls/library
MBEDTLS_PROG_DIR = ../mbedtls/programs
PERSONAL_DIR = ../../l-tls
MEASUREMENT_LIB_DIR = measurement/library

MBEDTLS_LIB_MAKE = $(MAKE) -C $(MBEDTLS_LIB_DIR)
MBEDTLS_PROGS_MAKE = $(MAKE) -C $(MBEDTLS_PROG_DIR)
MEASUREMENT_LIB_MAKE = $(MAKE) -C $(MEASUREMENT_LIB_DIR)
TLS_ALL_MAKE = $(MAKE) -C tls_all
TLS_PSK_MAKE = $(MAKE) -C tls_psk
TLS_RSA_MAKE = $(MAKE) -C tls_rsa
CIPHER_MAKE = $(MAKE) -C cipher

ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -g3 -D_FILE_OFFSET_BITS=64

.SILENT:

.PHONY: lib_measurement alt_all alt_psk alt_rsa alt_cipher \
		lib_mbedtls lib_all lib_all_papi lib_psk lib_psk_papi lib_rsa lib_rsa_papi lib_cipher progs \
		all_server run_all_server all_client run_all_client all \
		all_server_papi run_all_server_papi all_client_papi run_all_client_papi all_papi \		
		psk_server run_psk_server psk_client run_psk_client psk \
		psk_server_papi run_psk_server_papi psk_client_papi run_psk_client_papi psk_papi \
		rsa_server run_rsa_server rsa_client run_rsa_client rsa \
		rsa_server_papi run_rsa_server_papi rsa_client_papi run_rsa_client_papi rsa_papi \
		cipher run_cipher \
		clean_local clean

### MAKE MEASUREMENT LIBRARY ###
lib_measurement:
	$(MEASUREMENT_LIB_MAKE)
	
### MAKE MBEDTLS ALT ###
alt_all:
	$(TLS_ALL_MAKE) alt_lib

alt_psk:
	$(TLS_PSK_MAKE) alt_lib

alt_rsa:
	$(TLS_RSA_MAKE) alt_lib

alt_cipher:
	$(CIPHER_MAKE) alt_lib

### MAKE MBEDTLS LIBRARY ###
lib_mbedtls:
	gcc $(ALL_CFLAGS) -I$(MBEDTLS_INC_DIR) -c $(MY_AES).c -o $(MY_AES).o
	gcc $(ALL_CFLAGS) -I$(MBEDTLS_INC_DIR) -c $(MY_AES_MODULE).c -o $(MY_AES_MODULE).o
	gcc $(ALL_CFLAGS) -I$(MBEDTLS_INC_DIR) -c $(MY_SHA256).c -o $(MY_SHA256).o 
	$(MBEDTLS_LIB_MAKE)

lib_all:
	$(TLS_ALL_MAKE) lib

lib_all_papi:
	$(TLS_ALL_MAKE) lib_papi

lib_psk:
	$(TLS_PSK_MAKE) lib

lib_psk_papi:
	$(TLS_PSK_MAKE) lib_papi

lib_rsa:
	$(TLS_RSA_MAKE) lib

lib_rsa_papi:
	$(TLS_RSA_MAKE) lib_papi

lib_cipher:
	$(CIPHER_MAKE) lib

### MAKE MBEDTLS PROGRAMS ###
progs: lib_mbedtls
	$(MBEDTLS_PROGS_MAKE) CFLAGS="-I../../l-tls/my_aes_module $(PERSONAL_DIR)/$(MY_AES).o $(PERSONAL_DIR)/$(MY_AES_MODULE).o $(PERSONAL_DIR)/$(MY_SHA256).o"

### MAKE TLS ALL ###
all_server:
	$(TLS_ALL_MAKE) server

run_all_server: all_server
	./tls_all/server.out

all_client:
	$(TLS_ALL_MAKE) client

run_all_client: all_client
	./tls_all/client.out

all:
	$(TLS_ALL_MAKE) local

### MAKE TLS ALL PAPI ###
all_server_papi:
	$(TLS_ALL_MAKE) server_papi

run_all_server_papi: all_server_papi
	./tls_all/server.out

all_client_papi:
	$(TLS_ALL_MAKE) client_papi

run_all_client_papi: all_client_papi
	./tls_all/client.out

all_papi:
	$(TLS_ALL_MAKE) local_papi

### MAKE TLS PSK ###
psk_server:
	$(TLS_PSK_MAKE) server

run_psk_server: psk_server
	./tls_psk/server.out

psk_client:
	$(TLS_PSK_MAKE) client

run_psk_client: psk_client
	./tls_psk/client.out

psk:
	$(TLS_PSK_MAKE) local

### MAKE TLS PSK PAPI ###
psk_server_papi:
	$(TLS_PSK_MAKE) server_papi

run_psk_server_papi: psk_server_papi
	./tls_psk/server.out

psk_client_papi:
	$(TLS_PSK_MAKE) client_papi

run_psk_client_papi: psk_client_papi
	./tls_psk/client.out

psk_papi:
	$(TLS_PSK_MAKE) local_papi

### MAKE TLS RSA ###
rsa_server:
	$(TLS_RSA_MAKE) server

run_rsa_server: rsa_server
	./tls_rsa/server.out

rsa_client:
	$(TLS_RSA_MAKE) client

run_rsa_client: rsa_client
	./tls_rsa/client.out

rsa:
	$(TLS_RSA_MAKE) local

### MAKE TLS RSA PAPI ###
rsa_server_papi:
	$(TLS_RSA_MAKE) server_papi

run_rsa_server_papi: rsa_server_papi
	./tls_rsa/server.out

rsa_client_papi:
	$(TLS_RSA_MAKE) client_papi

run_rsa_client_papi: rsa_client_papi
	./tls_rsa/client.out

rsa_papi:
	$(TLS_RSA_MAKE) local_papi

### MAKE TEST CIPHER ###
cipher:
	$(CIPHER_MAKE) local

run_cipher:
	$(CIPHER_MAKE) run

### CLEAN ###
clean_local:
	$(TLS_ALL_MAKE) clean_local
	$(TLS_PSK_MAKE) clean_local
	$(TLS_RSA_MAKE) clean_local
	$(CIPHER_MAKE) clean_local
	
clean: clean_local
	$(MBEDTLS_PROGS_MAKE) clean
	$(MBEDTLS_LIB_MAKE) clean
	rm -f $(MY_AES).o
	rm -f $(MY_AES_MODULE).o
	rm -f $(MY_SHA256).o
	$(MEASUREMENT_LIB_MAKE) clean