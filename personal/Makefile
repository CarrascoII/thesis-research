MBEDTLS_DIR = ../mbedtls
PAPI_DIR = ../papi/src/install
LIBS = -L$(MBEDTLS_DIR)/library -lmbedx509 -lmbedtls -lmbedcrypto -L${PAPI_DIR}/lib -lpapi
LIBS_MAKE = $(MAKE) -C $(MBEDTLS_DIR)/library
PROGS_MAKE = $(MAKE) -C $(MBEDTLS_DIR)/programs

MY_SHA256 = sha256/sha256_alt
MY_AES = aes/aes_alt

LOCAL_CFLAGS = -Wall -W -Wdeclaration-after-statement -I$(MBEDTLS_DIR)/include -I${PAPI_DIR}/include -D_FILE_OFFSET_BITS=64
CFLAGS = -I$(CURDIR) -DMBEDTLS_CONFIG_FILE='<config_alt.h>'

.PHONY: all lib mbedtls server_obj server client_obj client cipher_obj cipher all clean_progs clean

all: lib server_obj client_obj cipher_obj

lib: 
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -c $(MY_SHA256).c -o $(MY_SHA256).o 
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -c $(MY_AES).c -o $(MY_AES).o
	CFLAGS="$(CFLAGS)" $(LIBS_MAKE)

mbedtls: lib
	CFLAGS="$(CFLAGS) $(CURDIR)/$(MY_SHA256).o $(CURDIR)/$(MY_AES).o" $(PROGS_MAKE)

server_obj: lib
	$(CC) $(LOCAL_CFLAGS) server.c $(MY_SHA256).o $(MY_AES).o $(LIBS) -o server.out

server: lib server_obj
	./server.out

client_obj: lib
	$(CC) $(LOCAL_CFLAGS) client.c $(MY_SHA256).o $(MY_AES).o $(LIBS) -o client.out

client: lib client_obj
	./client.out

cipher_obj: lib
	$(CC) $(LOCAL_CFLAGS) cipher.c $(MY_SHA256).o $(MY_AES).o $(LIBS) -o cipher.out

cipher: lib cipher_obj
	./cipher.out

all: lib server_obj client_obj cipher_obj

clean_progs:
	rm -f server.out
	rm -f client.out
	rm -f cipher.out
	
clean: clean_progs
	$(PROGS_MAKE) clean
	$(LIBS_MAKE) clean
	rm -f $(MY_SHA256).o
	rm -f $(MY_AES).o