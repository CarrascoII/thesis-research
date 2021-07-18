#!/bin/bash

#### VARIABLES ####
GEN_KEY=../mbedtls/programs/pkey/gen_key
WRITE_CERT=../mbedtls/programs/x509/cert_write
OUTPUT_PATH=material
DEADLINE=20221231235959
EC_CURVE_192=(192 secp192r1)
EC_CURVE_224=(224 secp224r1)
EC_CURVE_256=(256 secp256r1)
EC_CURVE_384=(384 secp384r1)
EC_CURVE_521=(521 secp521r1)
RSA_KEY_SIZES=(1024 2048 3072 7680 15360)
EC_CURVES=(EC_CURVE_192 EC_CURVE_224 EC_CURVE_256 EC_CURVE_384 EC_CURVE_521)
SRV=(srv localhost)
CLI=(cli mycli)
ENDPOINTS=(SRV CLI)

#### SCRIPT ####
# find ${OUTPUT_PATH}/ -mindepth 0 -type f -name '*' -delete

declare -n len curve end

for size in "${RSA_KEY_SIZES[@]}"; do
    # Generate DH params
    openssl dhparam -check -C -noout -out ${OUTPUT_PATH}/dh_prime_${size}.h ${size}
    
    # Generate peers RSA priv key and cert
    for end in "${ENDPOINTS[@]}"; do
        openssl req -new -newkey rsa:${size} -x509 -sha256 -subj "/CN=${end[1]}/O=myorganization/C=PT" \
        -days 365 -nodes -out ${OUTPUT_PATH}/${end[0]}_rsa_${size}.crt -keyout ${OUTPUT_PATH}/${end[0]}_rsa_${size}.key
    done
done

make gen_certs

for curve in "${EC_CURVES[@]}"; do
    # Generate peers EC priv key and cert
    for end in "${ENDPOINTS[@]}"; do
        ${GEN_KEY} type=ec ec_curve=${curve[1]} filename=${OUTPUT_PATH}/${end[0]}_ec_${curve[0]}.key
        ${WRITE_CERT} selfsign=1 issuer_key=${OUTPUT_PATH}/${end[0]}_ec_${curve[0]}.key issuer_name=CN=${end[1]},O=myorganization,C=PT \
                    not_after=${DEADLINE} max_pathlen=0 output_file=${OUTPUT_PATH}/${end[0]}_ec_${curve[0]}.crt
    done
done