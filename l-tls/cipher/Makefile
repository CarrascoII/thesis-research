MY_MBEDTLS_DIR = ../my_mbedtls
MY_AES_MODULE_DIR = ../../l-tls/my_mbedtls/aes_module
MBEDTLS_INC_DIR = ../../mbedtls/include
MBEDTLS_LIB_DIR = ../../mbedtls/library
PAPI_INC_DIR = ../../papi/src/install/include
PAPI_LIB_DIR = ../../papi/src/install/lib

MY_AES = $(MY_MBEDTLS_DIR)/aes/aes_alt
MY_AES_MODULE = $(MY_MBEDTLS_DIR)/aes_module/aes_alt

MY_MBEDTLS_MAKE = $(MAKE) -C $(MY_MBEDTLS_DIR)
MBEDTLS_LIB_MAKE = $(MAKE) -C $(MBEDTLS_LIB_DIR)

ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -g3 -D_FILE_OFFSET_BITS=64
MBEDTLS_CFLAGS = -I$(MBEDTLS_INC_DIR) -L$(MBEDTLS_LIB_DIR) -lmbedx509 -lmbedtls -lmbedcrypto
PAPI_CFLAGS = -I$(PAPI_INC_DIR) -L$(PAPI_LIB_DIR) -lpapi
LOCAL_CFLAGS = $(MY_AES).o $(MY_AES_MODULE).o -I$(MY_AES_MODULE_DIR) $(MBEDTLS_CFLAGS) $(PAPI_CFLAGS)

CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/config_aes.h>'

.SILENT:

.PHONY: all alt_lib lib local run clean_local clean

all: local

### MAKE ALT MBEDTLS LIB ###
alt_lib:
	$(MY_MBEDTLS_MAKE) cipher CONFIG="$(CONFIG)"

lib: alt_lib
	echo "make mbedtls:"
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(CONFIG) -I$(MY_AES_MODULE_DIR) $(PAPI_CFLAGS)"

### MAKE LOCAL ###
local: clean lib
	gcc $(ALL_CFLAGS) test_aes.c $(LOCAL_CFLAGS) -o test_aes.out

run: local
	./test_aes.out

### MAKE CLEAN ###
clean_local:
	echo -n "Cleaning cipher.......... "
	rm -f *.out
	echo "ok"

clean: clean_local
	$(MY_MBEDTLS_MAKE) clean
	echo -n "Cleaning mbedtls......... "
	$(MBEDTLS_LIB_MAKE) clean
	echo "ok"