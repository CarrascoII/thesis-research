MEASUREMENT_INC_DIR = ../../l-tls/measurement/include
MEASUREMENT_LIB_DIR = ../../l-tls/measurement/library
MBEDCORE_INC_DIR = ../../l-tls/mbedcore/include
MBEDCORE_LIB_DIR = ../../l-tls/mbedcore/library
MBEDTLS_INC_DIR = ../../mbedtls/include
MBEDTLS_LIB_DIR = ../../mbedtls/library
PAPI_INC_DIR = ../../papi/src/install/include
PAPI_LIB_DIR = ../../papi/src/install/lib

MEASUREMENT_LIB_MAKE = $(MAKE) -C $(MEASUREMENT_LIB_DIR)
MBEDCORE_LIB_MAKE = $(MAKE) -C $(MBEDCORE_LIB_DIR)
MBEDTLS_LIB_MAKE = $(MAKE) -C $(MBEDTLS_LIB_DIR)

ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -g3 -D_FILE_OFFSET_BITS=64
MEASUREMENT_CFLAGS = -I$(MEASUREMENT_INC_DIR) -L$(MEASUREMENT_LIB_DIR) -lmeasurement
MBEDCORE_CFLAGS = -I$(MBEDCORE_INC_DIR) -L$(MBEDCORE_LIB_DIR) -lmbedcore
MBEDTLS_CFLAGS = -I$(MBEDTLS_INC_DIR) -L$(MBEDTLS_LIB_DIR) -lmbedx509 -lmbedtls -lmbedcrypto
MEASUREMENT_PAPI_CFLAGS = -I../$(PAPI_INC_DIR) -L../$(PAPI_LIB_DIR) -lpapi
PAPI_CFLAGS = -I$(PAPI_INC_DIR) -L$(PAPI_LIB_DIR) -lpapi
LOCAL_CFLAGS = $(MBEDTLS_CFLAGS) $(MBEDCORE_CFLAGS) $(MEASUREMENT_CFLAGS)

CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/config_core.h>'

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
	$(MBEDCORE_LIB_MAKE) CONFIG="$(CONFIG) -I../$(MEASUREMENT_INC_DIR) -I../$(MBEDCORE_INC_DIR)"

lib: measurement alt_lib
	echo "make mbedtls:"
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(CONFIG) $(MEASUREMENT_CFLAGS) $(MBEDCORE_CFLAGS)"

lib_papi: measurement_papi alt_lib
	echo "make mbedtls:"
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(CONFIG) $(MEASUREMENT_CFLAGS) $(PAPI_CFLAGS)"

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

local: clean server client

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
	echo -n "Cleaning tls_core........ "
	rm -f *.out
	echo "ok"

clean: clean_local
	$(MEASUREMENT_LIB_MAKE) clean
	$(MBEDCORE_LIB_MAKE) clean
	$(MBEDTLS_LIB_MAKE) clean