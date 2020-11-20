#!/bin/sh
EXTENTION=../mbedtls/library/
CRYPTO=libmbedcrypto.a
TLS=libmbedtls.a
X509=libmbedx509.a

CRYPTO_SIZE=$(stat -c%s "${EXTENTION}/${CRYPTO}")
TLS_SIZE=$(stat -c%s "${EXTENTION}/${TLS}")
X509_SIZE=$(stat -c%s "${EXTENTION}/${X509}")

echo "Size of ${CRYPTO} = $((${CRYPTO_SIZE}/1024)).$(((${CRYPTO_SIZE}%1024)*1000/1024)) KiB."
echo "Size of ${TLS} = $((${TLS_SIZE}/1024)).$(((${TLS_SIZE}%1024)*1000/1024)) KiB."
echo "Size of ${X509} = $((${X509_SIZE}/1024)).$(((${X509_SIZE}%1024)*1000/1024)) KiB."