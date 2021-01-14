MY_AES = ../my_aes/aes_alt
MY_AES_MODULE = ../my_aes_module/aes_alt
MY_SHA256 = ../my_sha256/sha256_alt

MY_AES_MODULE_DIR = ../../l-tls/my_aes_module
MBEDTLS_INC_DIR = ../../mbedtls/include
MBEDTLS_LIB_DIR = ../../mbedtls/library
MEASUREMENT_INC_DIR = ../../l-tls/measurement/include
MEASUREMENT_LIB_DIR = ../../l-tls/measurement/library
PAPI_INC_DIR = ../../papi/src/install/include
PAPI_LIB_DIR = ../../papi/src/install/lib

LIB_INCLUDES = -I$(MBEDTLS_INC_DIR) -I$(MEASUREMENT_INC_DIR)

MBEDTLS_LIB_MAKE = $(MAKE) -C $(MBEDTLS_LIB_DIR)

ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -g3 -D_FILE_OFFSET_BITS=64
MBEDTLS_CFLAGS = -I$(MBEDTLS_INC_DIR) -L$(MBEDTLS_LIB_DIR) -lmbedx509 -lmbedtls -lmbedcrypto
MEASUREMENT_CFLAGS = -I$(MEASUREMENT_INC_DIR) -L$(MEASUREMENT_LIB_DIR) -lmeasurement
PAPI_CFLAGS = -I$(PAPI_INC_DIR) -L$(PAPI_LIB_DIR) -lpapi
LOCAL_CFLAGS = $(MY_AES).o $(MY_AES_MODULE).o $(MY_SHA256).o -I$(MY_AES_MODULE_DIR) $(MBEDTLS_CFLAGS) $(MEASUREMENT_CFLAGS)

CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/config_psk.h>'

.PHONY: measurement measurement_papi \
		alt_lib lib lib_papi \
		server client local \
		server_papi client_papi local_papi \
		clean_local clean

### MAKE MEASUREMENT LIBRARY ###
measurement:
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) -c $(MEASUREMENT_LIB_DIR)/measure.c -o $(MEASUREMENT_LIB_DIR)/measure.o
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) -c $(MEASUREMENT_LIB_DIR)/measure_wrap.c -o $(MEASUREMENT_LIB_DIR)/measure_wrap.o
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) -c $(MEASUREMENT_LIB_DIR)/papilib.c -o $(MEASUREMENT_LIB_DIR)/papilib.o
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) -c $(MEASUREMENT_LIB_DIR)/timelib.c -o $(MEASUREMENT_LIB_DIR)/timelib.o
	ar rcs $(MEASUREMENT_LIB_DIR)/libmeasurement.a $(MEASUREMENT_LIB_DIR)/measure.o \
				$(MEASUREMENT_LIB_DIR)/measure_wrap.o $(MEASUREMENT_LIB_DIR)/papilib.o $(MEASUREMENT_LIB_DIR)/timelib.o

measurement_papi:
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) -c $(MEASUREMENT_LIB_DIR)/measure.c -o $(MEASUREMENT_LIB_DIR)/measure.o
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) $(PAPI_CFLAGS) -c $(MEASUREMENT_LIB_DIR)/measure_wrap.c -o $(MEASUREMENT_LIB_DIR)/measure_wrap.o
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) $(PAPI_CFLAGS) -c $(MEASUREMENT_LIB_DIR)/papilib.c -o $(MEASUREMENT_LIB_DIR)/papilib.o
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) -c $(MEASUREMENT_LIB_DIR)/timelib.c -o $(MEASUREMENT_LIB_DIR)/timelib.o
	ar rcs $(MEASUREMENT_LIB_DIR)/libmeasurement.a $(MEASUREMENT_LIB_DIR)/measure.o \
				$(MEASUREMENT_LIB_DIR)/measure_wrap.o $(MEASUREMENT_LIB_DIR)/papilib.o $(MEASUREMENT_LIB_DIR)/timelib.o

### MAKE ALT MBEDTLS LIB ###
alt_lib:
	gcc $(ALL_CFLAGS) $(CONFIG) $(LIB_INCLUDES) -c $(MY_AES).c -o $(MY_AES).o
	gcc $(ALL_CFLAGS) $(CONFIG) $(LIB_INCLUDES) -c $(MY_AES_MODULE).c -o $(MY_AES_MODULE).o
	gcc $(ALL_CFLAGS) $(CONFIG) $(LIB_INCLUDES) -c $(MY_SHA256).c -o $(MY_SHA256).o

lib: measurement alt_lib
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(CONFIG) -I$(MY_AES_MODULE_DIR) $(MEASUREMENT_CFLAGS)"

lib_papi: measurement_papi alt_lib
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(CONFIG) -I$(MY_AES_MODULE_DIR) $(MEASUREMENT_CFLAGS) $(PAPI_CFLAGS)"

### MAKE TLS ###
server: lib
	rm -f server.out
	gcc $(ALL_CFLAGS) server.c $(LOCAL_CFLAGS) -o server.out

client: lib
	rm -f client.out
	gcc $(ALL_CFLAGS) client.c $(LOCAL_CFLAGS) -o client.out

local: clean server client

### MAKE TLS PAPI ###
server_papi: lib_papi
	rm -f server.out
	gcc $(ALL_CFLAGS) server.c $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o server.out

client_papi: lib_papi
	rm -f client.out
	gcc $(ALL_CFLAGS) client.c $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o client.out

local_papi: clean server_papi client_papi

### MAKE CLEAN ###
clean_local:
	rm -f server.out
	rm -f client.out

clean: clean_local
	rm -f $(MY_AES).o
	rm -f $(MY_AES_MODULE).o
	rm -f $(MY_SHA256).o
	$(MBEDTLS_LIB_MAKE) clean
	rm -f $(MEASUREMENT_LIB_DIR)/libmeasurement.a
	rm -f $(MEASUREMENT_LIB_DIR)/measure_wrap.o
	rm -f $(MEASUREMENT_LIB_DIR)/measure.o
	rm -f $(MEASUREMENT_LIB_DIR)/papilib.o
	rm -f $(MEASUREMENT_LIB_DIR)/timelib.o