#!/bin/sh
EXTENTION=../mbedtls/library/
CRYPTO=libmbedcrypto.a
TLS=libmbedtls.a
X509=libmbedx509.a

MEASUREMENT=measurement/library/libmeasurement.a
SERVER=tls_psk/server.out
CLIENT=tls_psk/client.out

CRYPTO_SIZE=$(stat -c%s "${EXTENTION}/${CRYPTO}")
TLS_SIZE=$(stat -c%s "${EXTENTION}/${TLS}")
X509_SIZE=$(stat -c%s "${EXTENTION}/${X509}")


MEASUREMENT_SIZE=$(stat -c%s "${MEASUREMENT}")
SERVER_SIZE=$(stat -c%s "${SERVER}")
CLIENT_SIZE=$(stat -c%s "${CLIENT}")

echo "Size of ${CRYPTO} = $((${CRYPTO_SIZE}/1024)).$(((${CRYPTO_SIZE}%1024)*1000/1024)) KiB."
echo "Size of ${TLS}    = $((${TLS_SIZE}/1024)).$(((${TLS_SIZE}%1024)*1000/1024)) KiB."
echo "Size of ${X509}   = $((${X509_SIZE}/1024)).$(((${X509_SIZE}%1024)*1000/1024)) KiB."


echo "Size of ${MEASUREMENT}  = $((${MEASUREMENT_SIZE}/1024)).$(((${MEASUREMENT_SIZE}%1024)*1000/1024)) KiB."
echo "Size of ${SERVER}  = $((${SERVER_SIZE}/1024)).$(((${SERVER_SIZE}%1024)*1000/1024)) KiB."
echo "Size of ${CLIENT}  = $((${CLIENT_SIZE}/1024)).$(((${CLIENT_SIZE}%1024)*1000/1024)) KiB."

echo "Total = $(((${CRYPTO_SIZE} + ${TLS_SIZE} + ${X509_SIZE} + ${MEASUREMENT_SIZE} + ${SERVER_SIZE} + ${CLIENT_SIZE})/1024)).$((((${CRYPTO_SIZE} + ${TLS_SIZE} + ${X509_SIZE} + ${MEASUREMENT_SIZE} + ${SERVER_SIZE} + ${CLIENT_SIZE})%1024)*1000/1024)) KiB."