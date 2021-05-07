MY_MBEDTLS_DIR = my_mbedtls
MEASUREMENT_LIB_DIR = measurement/library
MBEDCORE_LIB_DIR = mbedcore/library
MY_AES_MODULE_DIR = ../../l-tls/my_mbedtls/aes_module
MBEDTLS_LIB_DIR = ../mbedtls/library
MBEDTLS_PROG_DIR = ../mbedtls/programs
PERSONAL_DIR = ../../l-tls
PAPI_INC_DIR = ../../papi/src/install/include
PAPI_LIB_DIR = ../../papi/src/install/lib

MY_AES = $(MY_MBEDTLS_DIR)/aes/aes_alt
MY_AES_MODULE = $(MY_MBEDTLS_DIR)/aes_module/aes_alt
MY_SHA256 = $(MY_MBEDTLS_DIR)/sha256/sha256_alt

MEASUREMENT_LIB_MAKE = $(MAKE) -C $(MEASUREMENT_LIB_DIR)
MBEDCORE_LIB_MAKE = $(MAKE) -C $(MBEDCORE_LIB_DIR)
MY_MBEDTLS_MAKE = $(MAKE) -C $(MY_MBEDTLS_DIR)
MBEDTLS_LIB_MAKE = $(MAKE) -C $(MBEDTLS_LIB_DIR)
MBEDTLS_PROGS_MAKE = $(MAKE) -C $(MBEDTLS_PROG_DIR)
CIPHER_MAKE = $(MAKE) -C cipher
TLS_ALGS_MAKE = $(MAKE) -C tls_algs
TLS_SESSION_MAKE = $(MAKE) -C tls_session
TLS_CORE_MAKE = $(MAKE) -C tls_core
TLS_PSK_MAKE = $(MAKE) -C tls_psk
TLS_RSA_MAKE = $(MAKE) -C tls_rsa
TLS_EC_MAKE = $(MAKE) -C tls_ec

PAPI_CFLAGS = -I$(PAPI_INC_DIR) -L$(PAPI_LIB_DIR) -lpapi

.SILENT:

.PHONY: lib_measurement lib_measurement_papi alt_algs alt_session alt_core alt_psk alt_rsa alt_ec alt_cipher \
		lib_mbedtls lib_algs lib_algs_papi lib_session lib_session_papi lib_core lib_core_papi \
		lib_psk lib_psk_papi lib_rsa lib_rsa_papi lib_ec lib_ec_papi lib_cipher progs \
		algs_server run_algs_server algs_client run_algs_client algs \
		algs_server_papi run_algs_server_papi algs_client_papi run_algs_client_papi algs_papi \
		session_server run_session_server session_client run_session_client session \
		session_server_papi run_session_server_papi session_client_papi run_session_client_papi session_papi \
		core_server run_core_server core_client run_core_client core \
		core_server_papi run_core_server_papi core_client_papi run_core_client_papi core_papi \
		psk_server run_psk_server psk_client run_psk_client psk \
		psk_server_papi run_psk_server_papi psk_client_papi run_psk_client_papi psk_papi \
		rsa_server run_rsa_server rsa_client run_rsa_client rsa \
		rsa_server_papi run_rsa_server_papi rsa_client_papi run_rsa_client_papi rsa_papi \
		ec_server run_ec_server ec_client run_ec_client ec \
		ec_server_papi run_ec_server_papi ec_client_papi run_ec_client_papi ec_papi \
		cipher run_cipher \
		clean_local clean

### MAKE MEASUREMENT LIBRARY ###
lib_measurement:
	$(MEASUREMENT_LIB_MAKE)

lib_measurement_papi:
	$(MEASUREMENT_LIB_MAKE) PAPI_CFLAGS="$(PAPI_CFLAGS)"
	
### MAKE MBEDTLS ALT ###
alt_algs:
	$(TLS_ALGS_MAKE) alt_lib

alt_session:
	$(TLS_SESSION_MAKE) alt_lib

alt_core:
	$(TLS_CORE_MAKE) alt_lib

alt_psk:
	$(TLS_PSK_MAKE) alt_lib

alt_rsa:
	$(TLS_RSA_MAKE) alt_lib

alt_ec:
	$(TLS_EC_MAKE) alt_lib

alt_cipher:
	$(CIPHER_MAKE) alt_lib

### MAKE MBEDTLS LIBRARY ###
lib_mbedtls:
	$(MY_MBEDTLS_MAKE)
	echo "make mbedtls:"
	$(MBEDTLS_LIB_MAKE)

lib_algs:
	$(TLS_ALGS_MAKE) lib

lib_algs_papi:
	$(TLS_ALGS_MAKE) lib_papi

lib_session:
	$(TLS_SESSION_MAKE) lib

lib_session_papi:
	$(TLS_SESSION_MAKE) lib_papi

lib_core:
	$(TLS_CORE_MAKE) lib

lib_core_papi:
	$(TLS_CORE_MAKE) lib_papi

lib_psk:
	$(TLS_PSK_MAKE) lib

lib_psk_papi:
	$(TLS_PSK_MAKE) lib_papi

lib_rsa:
	$(TLS_RSA_MAKE) lib

lib_rsa_papi:
	$(TLS_RSA_MAKE) lib_papi

lib_ec:
	$(TLS_EC_MAKE) lib

lib_ec_papi:
	$(TLS_EC_MAKE) lib_papi

lib_cipher:
	$(CIPHER_MAKE) lib

### MAKE MBEDTLS PROGRAMS ###
progs: clean lib_mbedtls
	$(MBEDTLS_PROGS_MAKE) CFLAGS="-I$(MY_AES_MODULE_DIR) $(PERSONAL_DIR)/$(MY_AES).o $(PERSONAL_DIR)/$(MY_AES_MODULE).o $(PERSONAL_DIR)/$(MY_SHA256).o"

### MAKE TLS ALGS ###
algs_server:
	$(TLS_ALGS_MAKE) server

run_algs_server: algs_server
	./tls_algs/server.out

algs_client:
	$(TLS_ALGS_MAKE) client

run_algs_client: algs_client
	./tls_algs/client.out

algs:
ifndef PAPI_DIR
	$(TLS_ALGS_MAKE) local
else
	$(TLS_ALGS_MAKE) local_papi
endif

### MAKE TLS ALGS PAPI ###
algs_server_papi:
	$(TLS_ALGS_MAKE) server_papi

run_algs_server_papi: algs_server_papi
	./tls_algs/server.out

algs_client_papi:
	$(TLS_ALGS_MAKE) client_papi

run_algs_client_papi: algs_client_papi
	./tls_algs/client.out

algs_papi:
	$(TLS_ALGS_MAKE) local_papi

### MAKE TLS SESSION ###
session_server:
	$(TLS_SESSION_MAKE) server

run_session_server: session_server
	./tls_session/server.out

session_client:
	$(TLS_SESSION_MAKE) client

run_session_client: session_client
	./tls_session/client.out

session:
	$(TLS_SESSION_MAKE) local

### MAKE TLS SESSION PAPI ###
session_server_papi:
	$(TLS_SESSION_MAKE) server_papi

run_session_server_papi: session_server_papi
	./tls_session/server.out

session_client_papi:
	$(TLS_SESSION_MAKE) client_papi

run_session_client_papi: session_client_papi
	./tls_session/client.out

session_papi:
	$(TLS_SESSION_MAKE) local_papi

### MAKE TLS CORE ###
core_server:
	$(TLS_CORE_MAKE) server

run_core_server: core_server
	./tls_core/server.out

core_client:
	$(TLS_CORE_MAKE) client

run_core_client: core_client
	./tls_core/client.out

core:
	$(TLS_CORE_MAKE) local

### MAKE TLS CORE PAPI ###
core_server_papi:
	$(TLS_CORE_MAKE) server_papi

run_core_server_papi: core_server_papi
	./tls_core/server.out

core_client_papi:
	$(TLS_CORE_MAKE) client_papi

run_core_client_papi: core_client_papi
	./tls_core/client.out

core_papi:
	$(TLS_CORE_MAKE) local_papi

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

### MAKE TLS EC ###
ec_server:
	$(TLS_EC_MAKE) server

run_ec_server: ec_server
	./tls_ec/server.out

ec_client:
	$(TLS_EC_MAKE) client

run_ec_client: ec_client
	./tls_ec/client.out

ec:
	$(TLS_EC_MAKE) local

### MAKE TLS EC PAPI ###
ec_server_papi:
	$(TLS_EC_MAKE) server_papi

run_ec_server_papi: ec_server_papi
	./tls_ec/server.out

ec_client_papi:
	$(TLS_EC_MAKE) client_papi

run_ec_client_papi: ec_client_papi
	./tls_ec/client.out

ec_papi:
	$(TLS_EC_MAKE) local_papi

### MAKE TEST CIPHER ###
cipher:
	$(CIPHER_MAKE) local

run_cipher:
	$(CIPHER_MAKE) run

### CLEAN ###
clean_local:
	$(CIPHER_MAKE) clean_local
	$(TLS_ALGS_MAKE) clean_local
	$(TLS_SESSION_MAKE) clean_local
	$(TLS_CORE_MAKE) clean_local
	$(TLS_PSK_MAKE) clean_local
	$(TLS_RSA_MAKE) clean_local
	$(TLS_EC_MAKE) clean_local
	
clean: clean_local
	$(MEASUREMENT_LIB_MAKE) clean
	$(MBEDCORE_LIB_MAKE) clean
	$(MY_MBEDTLS_MAKE) clean
	echo -n "Cleaning mbedtls......... "
	$(MBEDTLS_LIB_MAKE) clean
	$(MBEDTLS_PROGS_MAKE) clean
	echo "ok"