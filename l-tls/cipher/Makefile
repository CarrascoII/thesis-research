MY_AES = ../my_aes/aes_alt
MY_AES_MODULE = ../my_aes_module/aes_alt

MY_AES_MODULE_DIR = ../../l-tls/my_aes_module
MBEDTLS_INC_DIR = ../../mbedtls/include
MBEDTLS_LIB_DIR = ../../mbedtls/library
PAPI_INC_DIR = ../../papi/src/install/include
PAPI_LIB_DIR = ../../papi/src/install/lib

MBEDTLS_LIB_MAKE = $(MAKE) -C $(MBEDTLS_LIB_DIR)

ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -g3 -D_FILE_OFFSET_BITS=64
MBEDTLS_CFLAGS = -I$(MBEDTLS_INC_DIR) -L$(MBEDTLS_LIB_DIR) -lmbedx509 -lmbedtls -lmbedcrypto
PAPI_CFLAGS = -I$(PAPI_INC_DIR) -L$(PAPI_LIB_DIR) -lpapi
LOCAL_CFLAGS = $(MY_AES).o $(MY_AES_MODULE).o -I$(MY_AES_MODULE_DIR) $(MBEDTLS_CFLAGS) $(PAPI_CFLAGS)

CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/config_aes.h>'

.PHONY: alt_lib lib \
		local run \
		clean_local clean

### MAKE ALT MBEDTLS LIB ###
alt_lib:
	gcc $(ALL_CFLAGS) $(CONFIG) -I$(MBEDTLS_INC_DIR) -c $(MY_AES).c -o $(MY_AES).o
	gcc $(ALL_CFLAGS) $(CONFIG) -I$(MBEDTLS_INC_DIR) -c $(MY_AES_MODULE).c -o $(MY_AES_MODULE).o

lib: alt_lib
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(CONFIG) -I$(MY_AES_MODULE_DIR) $(PAPI_CFLAGS)"

### MAKE TLS ###
local: lib
	rm -f test_aes.out
	gcc $(ALL_CFLAGS) test_aes.c $(LOCAL_CFLAGS) -o test_aes.out

run: clean local
	./test_aes.out

### MAKE CLEAN ###
clean_local:
	rm -f test_aes.out

clean: clean_local
	rm -f $(MY_AES).o
	rm -f $(MY_AES_MODULE).o
	$(MBEDTLS_LIB_MAKE) clean