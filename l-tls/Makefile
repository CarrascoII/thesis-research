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

PAPI_CFLAGS = -I$(PAPI_INC_DIR) -L$(PAPI_LIB_DIR) -lpapi

.SILENT:

.PHONY: lib_measurement lib_measurement_papi alt_algs alt_session alt_core alt_cipher \
		lib_mbedtls lib_algs lib_algs_papi lib_session lib_session_papi lib_core lib_core_papi \
		lib_cipher progs \
		algs_server run_algs_server algs_client run_algs_client algs \
		algs_server_papi run_algs_server_papi algs_client_papi run_algs_client_papi algs_papi \
		session_server run_session_server session_client run_session_client session \
		session_server_papi run_session_server_papi session_client_papi run_session_client_papi session_papi \
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

algs_core:
ifndef PAPI_DIR
	$(TLS_ALGS_MAKE) core
else
	$(TLS_ALGS_MAKE) core_papi
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
	
clean: clean_local
	$(MEASUREMENT_LIB_MAKE) clean
	$(MBEDCORE_LIB_MAKE) clean
	$(MY_MBEDTLS_MAKE) clean
	echo -n "Cleaning mbedtls......... "
	$(MBEDTLS_LIB_MAKE) clean
	$(MBEDTLS_PROGS_MAKE) clean
	echo "ok"