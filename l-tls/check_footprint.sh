#!/bin/sh
TLS_DIR=../mbedtls/library
MSR_DIR=measurement/library
CORE_DIR=mbedcore/library

CRYPTO=libmbedcrypto.a
TLS=libmbedtls.a
X509=libmbedx509.a
MSR=libmeasurement.a
CORE=libmbedcore.a
SERVER=tls_algs/server.out
CLIENT=tls_algs/client.out

CRYPTO_SIZE=$(stat -c%s "${TLS_DIR}/${CRYPTO}")
TLS_SIZE=$(stat -c%s "${TLS_DIR}/${TLS}")
X509_SIZE=$(stat -c%s "${TLS_DIR}/${X509}")
MSR_SIZE=$(stat -c%s "${MSR_DIR}/${MSR}")
SERVER_SIZE=$(stat -c%s "${SERVER}")
CLIENT_SIZE=$(stat -c%s "${CLIENT}")

LIB_TOTAL=$((CRYPTO_SIZE+TLS_SIZE+X509_SIZE+MSR_SIZE))
END_TOTAL=$((SERVER_SIZE+CLIENT_SIZE))

echo "Size of ${CRYPTO}  = $((${CRYPTO_SIZE}/1024)).$(((${CRYPTO_SIZE}%1024)*1000/1024)) KiB."
echo "Size of ${TLS}     = $((${TLS_SIZE}/1024)).$(((${TLS_SIZE}%1024)*1000/1024)) KiB."
echo "Size of ${X509}    = $((${X509_SIZE}/1024)).$(((${X509_SIZE}%1024)*1000/1024)) KiB."
echo "Size of ${MSR} = $((${MSR_SIZE}/1024)).$(((${MSR_SIZE}%1024)*1000/1024)) KiB."
echo "Libs total               = $(((${LIB_TOTAL})/1024)).$((((${LIB_TOTAL})%1024)*1000/1024)) KiB."
echo ""
echo "Size of ${SERVER}  = $((${SERVER_SIZE}/1024)).$(((${SERVER_SIZE}%1024)*1000/1024)) KiB."
echo "Size of ${CLIENT}  = $((${CLIENT_SIZE}/1024)).$(((${CLIENT_SIZE}%1024)*1000/1024)) KiB."
echo "Progs total                  = $(((${END_TOTAL})/1024)).$((((${END_TOTAL})%1024)*1000/1024)) KiB."
echo ""
echo "Total = $(((${END_TOTAL} + ${LIB_TOTAL})/1024)).$((((${END_TOTAL} + ${LIB_TOTAL})%1024)*1000/1024)) KiB."

CORE_SIZE=$(stat -c%s "${CORE_DIR}/${CORE}")
echo "Size of ${CORE}    = $((${CORE_SIZE}/1024)).$(((${CORE_SIZE}%1024)*1000/1024)) KiB."