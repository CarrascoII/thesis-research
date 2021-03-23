MY_MBEDTLS_DIR = ../my_mbedtls
MEASUREMENT_INC_DIR = ../../l-tls/measurement/include
MEASUREMENT_LIB_DIR = ../../l-tls/measurement/library
MY_AES_MODULE_DIR = ../../l-tls/my_mbedtls/aes_module
MBEDTLS_INC_DIR = ../../mbedtls/include
MBEDTLS_LIB_DIR = ../../mbedtls/library
MBEDTLS_PROG_DIR = ../../mbedtls/programs
PAPI_INC_DIR = ../../papi/src/install/include
PAPI_LIB_DIR = ../../papi/src/install/lib

MY_AES = $(MY_MBEDTLS_DIR)/aes/aes_alt
MY_AES_MODULE = $(MY_MBEDTLS_DIR)/aes_module/aes_alt
MY_SHA256 = $(MY_MBEDTLS_DIR)/sha256/sha256_alt

MEASUREMENT_LIB_MAKE = $(MAKE) -C $(MEASUREMENT_LIB_DIR)
MY_MBEDTLS_MAKE = $(MAKE) -C $(MY_MBEDTLS_DIR)
MBEDTLS_LIB_MAKE = $(MAKE) -C $(MBEDTLS_LIB_DIR)
MBEDTLS_PROGS_MAKE = $(MAKE) -C $(MBEDTLS_PROG_DIR)

ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -g3 -D_FILE_OFFSET_BITS=64
MEASUREMENT_CFLAGS = -I$(MEASUREMENT_INC_DIR) -L$(MEASUREMENT_LIB_DIR) -lmeasurement
PROGS_MEASUREMENT_CFLAGS = -I../$(MEASUREMENT_INC_DIR) -L../$(MEASUREMENT_LIB_DIR) -lmeasurement
MBEDTLS_CFLAGS = -I$(MBEDTLS_INC_DIR) -L$(MBEDTLS_LIB_DIR) -lmbedx509 -lmbedtls -lmbedcrypto
MEASUREMENT_PAPI_CFLAGS = -I../$(PAPI_INC_DIR) -L../$(PAPI_LIB_DIR) -lpapi
PAPI_CFLAGS = -I$(PAPI_INC_DIR) -L$(PAPI_LIB_DIR) -lpapi
LOCAL_CFLAGS = $(MY_AES).o $(MY_AES_MODULE).o $(MY_SHA256).o -I$(MY_AES_MODULE_DIR) $(MBEDTLS_CFLAGS) $(MEASUREMENT_CFLAGS)

CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/config_algs.h>'

.SILENT:

.PHONY: all measurement measurement_papi \
		alt_lib lib lib_papi \
		server client local \
		server_papi client_papi local_papi \
		clean_local clean

all: local

### MAKE MEASUREMENT LIBRARY ###
measurement:
	$(MEASUREMENT_LIB_MAKE)

measurement_papi:
	$(MEASUREMENT_LIB_MAKE) PAPI_CFLAGS="$(MEASUREMENT_PAPI_CFLAGS)"

### MAKE MBEDTLS LIBRARY ###
alt_lib:
	$(MY_MBEDTLS_MAKE) CONFIG="$(CONFIG) -I$(MEASUREMENT_INC_DIR)"

lib: measurement alt_lib
	echo "make mbedtls:"
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(CONFIG) -I$(MY_AES_MODULE_DIR) $(MEASUREMENT_CFLAGS)"

lib_papi: measurement_papi alt_lib
	echo "make mbedtls:"
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(CONFIG) -I$(MY_AES_MODULE_DIR) $(MEASUREMENT_CFLAGS) $(PAPI_CFLAGS)"

### MAKE LOCAL ###
server: lib
	echo -n "Making server............ "
	rm -f server.out
	gcc $(ALL_CFLAGS) server.c $(LOCAL_CFLAGS) -o server.out
	echo "ok"

client: lib
	echo -n "Making client............ "
	rm -f client.out
	gcc $(ALL_CFLAGS) client.c $(LOCAL_CFLAGS) -o client.out
	echo "ok"

progs: lib
	$(MBEDTLS_PROGS_MAKE) CFLAGS="$(CONFIG) -I$(MEASUREMENT_INC_DIR)" pkey/gen_key
	$(MBEDTLS_PROGS_MAKE) CFLAGS="$(CONFIG) -I$(MEASUREMENT_INC_DIR)" x509/cert_write

local: clean server client progs

### MAKE LOCAL PAPI ###
server_papi: lib_papi
	echo -n "Making server............ "
	rm -f server.out
	gcc $(ALL_CFLAGS) server.c $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o server.out
	echo "ok"

client_papi: lib_papi
	echo -n "Making client............ "
	rm -f client.out
	gcc $(ALL_CFLAGS) client.c $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o client.out
	echo "ok"

local_papi: clean server_papi client_papi

### MAKE CLEAN ###
clean_local:
	echo -n "Cleaning tls_algs........ "
	rm -f *.out
	echo "ok"

clean: clean_local
	$(MEASUREMENT_LIB_MAKE) clean
	$(MY_MBEDTLS_MAKE) clean
	echo -n "Cleaning mbedtls......... "
	$(MBEDTLS_LIB_MAKE) clean
	echo "ok"