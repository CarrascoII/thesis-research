#!/bin/sh

TLS_DIR=../mbedtls/library
CRYPTO=libmbedcrypto.a
TLS=libmbedtls.a
X509=libmbedx509.a

MSR_DIR=measurement/library
MEASUREMENT=libmeasurement.a

CORE_DIR=mbedcore/library
CORE=libmbedcore.a

# SERVER=tls_psk/server.out
# CLIENT=tls_psk/client.out

CRYPTO_SIZE=$(stat -c%s "${TLS_DIR}/${CRYPTO}")
TLS_SIZE=$(stat -c%s "${TLS_DIR}/${TLS}")
X509_SIZE=$(stat -c%s "${TLS_DIR}/${X509}")

MEASUREMENT_SIZE=$(stat -c%s "${MSR_DIR}/${MEASUREMENT}")

CORE_SIZE=$(stat -c%s "${CORE_DIR}/${CORE}")

# SERVER_SIZE=$(stat -c%s "${SERVER}")
# CLIENT_SIZE=$(stat -c%s "${CLIENT}")

echo "Size of ${CRYPTO}  = $((${CRYPTO_SIZE}/1024)).$(((${CRYPTO_SIZE}%1024)*1000/1024)) KiB."
echo "Size of ${TLS}     = $((${TLS_SIZE}/1024)).$(((${TLS_SIZE}%1024)*1000/1024)) KiB."
echo "Size of ${X509}    = $((${X509_SIZE}/1024)).$(((${X509_SIZE}%1024)*1000/1024)) KiB."

echo "Size of ${MEASUREMENT} = $((${MEASUREMENT_SIZE}/1024)).$(((${MEASUREMENT_SIZE}%1024)*1000/1024)) KiB."

echo "Size of ${CORE}    = $((${CORE_SIZE}/1024)).$(((${CORE_SIZE}%1024)*1000/1024)) KiB."

# echo "Size of ${SERVER}  = $((${SERVER_SIZE}/1024)).$(((${SERVER_SIZE}%1024)*1000/1024)) KiB."
# echo "Size of ${CLIENT}  = $((${CLIENT_SIZE}/1024)).$(((${CLIENT_SIZE}%1024)*1000/1024)) KiB."

# echo "Total = $(((${CRYPTO_SIZE} + ${TLS_SIZE} + ${X509_SIZE} + ${MEASUREMENT_SIZE} + ${SERVER_SIZE} + ${CLIENT_SIZE})/1024)).$((((${CRYPTO_SIZE} + ${TLS_SIZE} + ${X509_SIZE} + ${MEASUREMENT_SIZE} + ${SERVER_SIZE} + ${CLIENT_SIZE})%1024)*1000/1024)) KiB."
echo "Total                    = $(((${CRYPTO_SIZE} + ${TLS_SIZE} + ${X509_SIZE} + ${MEASUREMENT_SIZE} + ${CORE_SIZE})/1024)).$((((${CRYPTO_SIZE} + ${TLS_SIZE} + ${X509_SIZE} + ${MEASUREMENT_SIZE} + ${CORE_SIZE})%1024)*1000/1024)) KiB."