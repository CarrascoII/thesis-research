MY_MBEDTLS_DIR = my_mbedtls
MEASUREMENT_LIB_DIR = measurement/library
MBEDCORE_LIB_DIR = mbedcore/library
MBEDTLS_LIB_DIR = ../mbedtls/library
MBEDTLS_PROG_DIR = ../mbedtls/programs
MY_AES_MODULE_DIR = ../../l-tls/my_mbedtls/aes_module
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

.PHONY: lib_measurement alt_algs alt_session alt_core alt_cipher \
		lib_mbedtls lib_algs lib_session lib_core lib_cipher progs \
		tls_algs_server tls_algs_client tls_algs tls_algs_core \
		session_server session_client session \
		cipher clean_local clean

### MAKE MEASUREMENT LIBRARY ###
lib_measurement:
ifndef PAPI_DIR
	$(MEASUREMENT_LIB_MAKE)
else
	$(MEASUREMENT_LIB_MAKE) PAPI_CFLAGS="$(PAPI_CFLAGS)"
endif
	
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
ifndef PAPI_DIR
	$(TLS_ALGS_MAKE) lib
else
	$(TLS_ALGS_MAKE) lib_papi
endif

lib_session:
ifndef PAPI_DIR
	$(TLS_SESSION_MAKE) lib
else
	$(TLS_SESSION_MAKE) lib_papi
endif

lib_core:
ifndef PAPI_DIR
	$(TLS_CORE_MAKE) lib
else
	$(TLS_CORE_MAKE) lib_papi
endif

lib_cipher:
	$(CIPHER_MAKE) lib

### MAKE MBEDTLS PROGRAMS ###
progs: clean lib_mbedtls
	$(MBEDTLS_PROGS_MAKE) CFLAGS="-I$(MY_AES_MODULE_DIR) $(PERSONAL_DIR)/$(MY_AES).o \
									$(PERSONAL_DIR)/$(MY_AES_MODULE).o $(PERSONAL_DIR)/$(MY_SHA256).o"

### MAKE TLS ALGS ###
tls_algs_server:
ifndef PAPI_DIR
	$(TLS_ALGS_MAKE) server
else
	$(TLS_ALGS_MAKE) server_papi
endif

tls_algs_client:
ifndef PAPI_DIR
	$(TLS_ALGS_MAKE) client
else
	$(TLS_ALGS_MAKE) client_papi
endif

tls_algs:
ifndef PAPI_DIR
	$(TLS_ALGS_MAKE) local
else
	$(TLS_ALGS_MAKE) local_papi
endif

tls_algs_core:
ifndef PAPI_DIR
	$(TLS_ALGS_MAKE) core
else
	$(TLS_ALGS_MAKE) core_papi
endif

### MAKE TLS SESSION ###
session_server:
ifndef PAPI_DIR
	$(TLS_SESSION_MAKE) server
else
	$(TLS_SESSION_MAKE) server_papi
endif

session_client:
ifndef PAPI_DIR
	$(TLS_SESSION_MAKE) client
else
	$(TLS_SESSION_MAKE) client_papi
endif

session:
ifndef PAPI_DIR
	$(TLS_SESSION_MAKE) local
else
	$(TLS_SESSION_MAKE) local_papi
endif

### MAKE TEST CIPHER ###
cipher:
	$(CIPHER_MAKE) local

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