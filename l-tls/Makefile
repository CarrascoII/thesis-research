MBEDTLS_INC_DIR = ../mbedtls/include
MBEDTLS_LIB_DIR = ../mbedtls/library
MBEDTLS_PROG_DIR = ../mbedtls/programs
PERSONAL_DIR = ../../l-tls
MY_AES = my_aes/aes_alt
MY_AES_MODULE = my_aes_module/aes_alt
MY_SHA256 = my_sha256/sha256_alt
PAPI_INC_DIR = ../papi/src/install/include
PAPI_LIB_DIR = ../papi/src/install/lib
MEASUREMENT_INC_DIR = measurement/include
MEASUREMENT_LIB_DIR = measurement/library

MBEDTLS_LIB_MAKE = $(MAKE) -C $(MBEDTLS_LIB_DIR)
MBEDTLS_PROGS_MAKE = $(MAKE) -C $(MBEDTLS_PROG_DIR)

INCLUDES = -I$(MBEDTLS_INC_DIR) -I$(MEASUREMENT_INC_DIR) -Imy_aes_module

ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -g3 -D_FILE_OFFSET_BITS=64
LOCAL_CFLAGS = $(MY_AES).o $(MY_AES_MODULE).o $(INCLUDES) -L$(MBEDTLS_LIB_DIR) -lmbedx509 -lmbedtls -lmbedcrypto
PAPI_CFLAGS = -I$(PAPI_INC_DIR) -L$(PAPI_LIB_DIR) -lpapi
MEASUREMENT_CFLAGS = -I$(MEASUREMENT_INC_DIR) -L$(MEASUREMENT_LIB_DIR) -lmeasurement

TLS_ALL_CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/tls_all/config_all.h>'
TLS_PSK_CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/tls_psk/config_psk.h>'
TLS_RSA_CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/tls_rsa/config_rsa.h>'
CIPHER_CONFIG = -DMBEDTLS_CONFIG_FILE='<$(CURDIR)/cipher/config_aes.h>'

.PHONY: lib_measurement lib_measurement_papi alt_all alt_psk alt_rsa \
		lib_mbedtls lib_all lib_all_papi lib_psk lib_psk_papi lib_rsa lib_rsa_papi lib_cipher progs \
		all_server run_all_server all_client run_all_client all \
		all_server_papi run_all_server_papi all_client_papi run_all_client_papi all_papi \		
		psk_server run_psk_server psk_client run_psk_client psk \
		psk_server_papi run_psk_server_papi psk_client_papi run_psk_client_papi psk_papi \
		rsa_server run_rsa_server rsa_client run_rsa_client rsa \
		rsa_server_papi run_rsa_server_papi rsa_client_papi run_rsa_client_papi rsa_papi \
		cipher run_cipher cipher_papi run_cipher_papi \
		clean_local clean

### MAKE MEASUREMENT LIBRARY ###
lib_measurement:
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) -c $(MEASUREMENT_LIB_DIR)/measure.c -o $(MEASUREMENT_LIB_DIR)/measure.o
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) -c $(MEASUREMENT_LIB_DIR)/measure_wrap.c -o $(MEASUREMENT_LIB_DIR)/measure_wrap.o
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) -c $(MEASUREMENT_LIB_DIR)/papilib.c -o $(MEASUREMENT_LIB_DIR)/papilib.o
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) -c $(MEASUREMENT_LIB_DIR)/timelib.c -o $(MEASUREMENT_LIB_DIR)/timelib.o
	ar rcs $(MEASUREMENT_LIB_DIR)/libmeasurement.a $(MEASUREMENT_LIB_DIR)/measure.o $(MEASUREMENT_LIB_DIR)/measure_wrap.o $(MEASUREMENT_LIB_DIR)/papilib.o $(MEASUREMENT_LIB_DIR)/timelib.o

lib_measurement_papi:
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) -c $(MEASUREMENT_LIB_DIR)/measure.c -o $(MEASUREMENT_LIB_DIR)/measure.o
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) $(PAPI_CFLAGS) -c $(MEASUREMENT_LIB_DIR)/measure_wrap.c -o $(MEASUREMENT_LIB_DIR)/measure_wrap.o
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) $(PAPI_CFLAGS) -c $(MEASUREMENT_LIB_DIR)/papilib.c -o $(MEASUREMENT_LIB_DIR)/papilib.o
	gcc $(ALL_CFLAGS) -I$(MEASUREMENT_INC_DIR) -c $(MEASUREMENT_LIB_DIR)/timelib.c -o $(MEASUREMENT_LIB_DIR)/timelib.o
	ar rcs $(MEASUREMENT_LIB_DIR)/libmeasurement.a $(MEASUREMENT_LIB_DIR)/measure.o $(MEASUREMENT_LIB_DIR)/measure_wrap.o $(MEASUREMENT_LIB_DIR)/papilib.o $(MEASUREMENT_LIB_DIR)/timelib.o
	
### MAKE MBEDTLS ALT ###
alt_all:
	gcc $(ALL_CFLAGS) $(TLS_ALL_CONFIG) $(INCLUDES) -c $(MY_AES).c -o $(MY_AES).o
	gcc $(ALL_CFLAGS) $(TLS_ALL_CONFIG) $(INCLUDES) -c $(MY_AES_MODULE).c -o $(MY_AES_MODULE).o
	gcc $(ALL_CFLAGS) $(TLS_ALL_CONFIG) $(INCLUDES) -c $(MY_SHA256).c -o $(MY_SHA256).o

alt_psk:
	gcc $(ALL_CFLAGS) $(TLS_PSK_CONFIG) $(INCLUDES) -c $(MY_AES).c -o $(MY_AES).o
	gcc $(ALL_CFLAGS) $(TLS_PSK_CONFIG) $(INCLUDES) -c $(MY_AES_MODULE).c -o $(MY_AES_MODULE).o
	gcc $(ALL_CFLAGS) $(TLS_PSK_CONFIG) $(INCLUDES) -c $(MY_SHA256).c -o $(MY_SHA256).o

alt_rsa:
	gcc $(ALL_CFLAGS) $(TLS_RSA_CONFIG) $(INCLUDES) -c $(MY_AES).c -o $(MY_AES).o
	gcc $(ALL_CFLAGS) $(TLS_RSA_CONFIG) $(INCLUDES) -c $(MY_AES_MODULE).c -o $(MY_AES_MODULE).o
	gcc $(ALL_CFLAGS) $(TLS_RSA_CONFIG) $(INCLUDES) -c $(MY_SHA256).c -o $(MY_SHA256).o 

### MAKE MBEDTLS LIBRARY ###
lib_mbedtls:
	gcc $(ALL_CFLAGS) -I$(MBEDTLS_INC_DIR) -c $(MY_AES).c -o $(MY_AES).o
	gcc $(ALL_CFLAGS) -I$(MBEDTLS_INC_DIR) -c $(MY_AES_MODULE).c -o $(MY_AES_MODULE).o
	gcc $(ALL_CFLAGS) -I$(MBEDTLS_INC_DIR) -c $(MY_SHA256).c -o $(MY_SHA256).o 
	$(MBEDTLS_LIB_MAKE)

lib_all: lib_measurement alt_all
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_ALL_CONFIG) -I../../l-tls/$(MEASUREMENT_INC_DIR) -L../../l-tls/$(MEASUREMENT_LIB_DIR) -lmeasurement"

lib_all_papi: lib_measurement_papi alt_all
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_ALL_CONFIG) -I../../l-tls/$(MEASUREMENT_INC_DIR) -I../$(PAPI_INC_DIR) -L../$(PAPI_LIB_DIR) -lpapi"

lib_psk: lib_measurement alt_psk
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_PSK_CONFIG) -I../../l-tls/my_aes_module -I../../l-tls/$(MEASUREMENT_INC_DIR) -L../../l-tls/$(MEASUREMENT_LIB_DIR) -lmeasurement"

lib_psk_papi: lib_measurement_papi alt_psk
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_PSK_CONFIG) -I../../l-tls/$(MEASUREMENT_INC_DIR) -I../$(PAPI_INC_DIR) -L../$(PAPI_LIB_DIR) -lpapi"

lib_rsa: lib_measurement alt_rsa
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_RSA_CONFIG) -I../../l-tls/$(MEASUREMENT_INC_DIR)"

lib_rsa_papi: lib_measurement_papi alt_rsa
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(TLS_RSA_CONFIG) -I../../l-tls/$(MEASUREMENT_INC_DIR) -I../$(PAPI_INC_DIR) -L../$(PAPI_LIB_DIR) -lpapi"

lib_cipher:
	gcc $(ALL_CFLAGS) $(CIPHER_CONFIG) -I$(MBEDTLS_INC_DIR) -c $(MY_AES).c -o $(MY_AES).o
	gcc $(ALL_CFLAGS) $(CIPHER_CONFIG) -I$(MBEDTLS_INC_DIR) -c $(MY_AES_MODULE).c -o $(MY_AES_MODULE).o
	$(MBEDTLS_LIB_MAKE) CFLAGS="$(CIPHER_CONFIG)"

### MAKE MBEDTLS PROGRAMS ###
progs: lib_mbedtls
	$(MBEDTLS_PROGS_MAKE) CFLAGS="$(PERSONAL_DIR)/$(MY_AES).o $(PERSONAL_DIR)/$(MY_AES_MODULE).o $(PERSONAL_DIR)/$(MY_SHA256).o"

### MAKE TLS ALL ###
all_server: lib_all
	rm -f tls_all/server.out
	gcc $(ALL_CFLAGS) tls_all/server.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(MEASUREMENT_CFLAGS) -o tls_all/server.out

run_all_server: all_server
	./tls_all/server.out

all_client: lib_all
	rm -f tls_all/client.out
	gcc $(ALL_CFLAGS) tls_all/client.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(MEASUREMENT_CFLAGS) -o tls_all/client.out

run_all_client: all_client
	./tls_all/client.out

all: clean all_server all_client

### MAKE TLS ALL PAPI ###
all_server_papi: lib_all_papi
	rm -f tls_all/server.out
	gcc $(ALL_CFLAGS) tls_all/server.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(MEASUREMENT_CFLAGS) $(PAPI_CFLAGS) -o tls_all/server.out

run_all_server_papi: all_server_papi
	./tls_all/server.out

all_client_papi: lib_all_papi
	rm -f tls_all/client.out
	gcc $(ALL_CFLAGS) tls_all/client.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(MEASUREMENT_CFLAGS) $(PAPI_CFLAGS) -o tls_all/client.out

run_all_client_papi: all_client_papi
	./tls_all/client.out

all_papi: clean all_server_papi all_client_papi

### MAKE TLS PSK ###
psk_server: lib_psk
	rm -f tls_psk/server.out
	gcc $(ALL_CFLAGS) tls_psk/server.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(MEASUREMENT_CFLAGS) -o tls_psk/server.out

run_psk_server: psk_server
	./tls_psk/server.out

psk_client: lib_psk
	rm -f tls_psk/client.out
	gcc $(ALL_CFLAGS) tls_psk/client.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(MEASUREMENT_CFLAGS) -o tls_psk/client.out

run_psk_client: psk_client
	./tls_psk/client.out

psk: clean psk_server psk_client

### MAKE TLS PSK PAPI ###
psk_server_papi: lib_psk_papi
	rm -f tls_psk/server.out
	gcc $(ALL_CFLAGS) tls_psk/server.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(MEASUREMENT_CFLAGS) $(PAPI_CFLAGS) -o tls_psk/server.out

run_psk_server_papi: psk_server_papi
	./tls_psk/server.out

psk_client_papi: lib_psk_papi
	rm -f tls_psk/client.out
	gcc $(ALL_CFLAGS) tls_psk/client.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(MEASUREMENT_CFLAGS) $(PAPI_CFLAGS) -o tls_psk/client.out

run_psk_client_papi: psk_client_papi
	./tls_psk/client.out

psk_papi: clean psk_server_papi psk_client_papi

### MAKE TLS RSA ###
rsa_server: lib_rsa
	rm -f tls_rsa/server.out
	gcc $(ALL_CFLAGS) tls_rsa/server.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(MEASUREMENT_CFLAGS) -o tls_rsa/server.out

run_rsa_server: rsa_server
	./tls_rsa/server.out

rsa_client: lib_rsa
	rm -f tls_rsa/client.out
	gcc $(ALL_CFLAGS) tls_rsa/client.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(MEASUREMENT_CFLAGS) -o tls_rsa/client.out

run_rsa_client: rsa_client
	./tls_rsa/client.out

rsa: clean rsa_server rsa_client

### MAKE TLS RSA PAPI ###
rsa_server_papi: lib_rsa_papi
	rm -f tls_rsa/server.out
	gcc $(ALL_CFLAGS) tls_rsa/server.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(MEASUREMENT_CFLAGS) $(PAPI_CFLAGS) -o tls_rsa/server.out

run_rsa_server_papi: rsa_server_papi
	./tls_rsa/server.out

rsa_client_papi: lib_rsa_papi
	rm -f tls_rsa/client.out
	gcc $(ALL_CFLAGS) tls_rsa/client.c $(MY_SHA256).o $(LOCAL_CFLAGS) $(MEASUREMENT_CFLAGS) $(PAPI_CFLAGS) -o tls_rsa/client.out

run_rsa_client_papi: rsa_client_papi
	./tls_rsa/client.out

rsa_papi: clean rsa_server_papi rsa_client_papi

### MAKE TEST CIPHER ###
cipher: lib_cipher
	rm -f cipher/test_aes.out
	gcc $(ALL_CFLAGS) cipher/test_aes.c -lm $(LOCAL_CFLAGS) -o cipher/test_aes.out

run_cipher: cipher
	./cipher/test_aes.out

### MAKE TEST CIPHER PAPI ###
cipher_papi: lib_cipher
	rm -f cipher/test_aes.out
	gcc $(ALL_CFLAGS) cipher/test_aes.c -lm $(LOCAL_CFLAGS) $(PAPI_CFLAGS) -o cipher/test_aes.out

run_cipher_papi: cipher_papi
	./cipher/test_aes.out

### CLEAN ###
clean_local:
	rm -f tls_all/server.out
	rm -f tls_all/client.out
	rm -f tls_psk/server.out
	rm -f tls_psk/client.out
	rm -f tls_rsa/server.out
	rm -f tls_rsa/client.out
	rm -f cipher/test_aes.out
	
clean: clean_local
	$(MBEDTLS_PROGS_MAKE) clean
	$(MBEDTLS_LIB_MAKE) clean
	rm -f $(MY_AES).o
	rm -f $(MY_AES_MODULE).o
	rm -f $(MY_SHA256).o
	rm -f $(MEASUREMENT_LIB_DIR)/libmeasurement.a
	rm -f $(MEASUREMENT_LIB_DIR)/measure_wrap.o
	rm -f $(MEASUREMENT_LIB_DIR)/measure.o
	rm -f $(MEASUREMENT_LIB_DIR)/papilib.o
	rm -f $(MEASUREMENT_LIB_DIR)/timelib.o