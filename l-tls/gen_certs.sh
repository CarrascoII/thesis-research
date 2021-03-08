#!/bin/bash

#### VARIABLES ####
GEN_KEY=../mbedtls/programs/pkey/gen_key
WRITE_CERT=../mbedtls/programs/x509/cert_write
OUTPUT_PATH=examples
DEADLINE=20221231235959
EC_CURVE_192=(192 secp192r1)
EC_CURVE_224=(224 secp224r1)
EC_CURVE_384=(384 secp384r1)
EC_CURVE_521=(521 secp521r1)
RSA_KEY_SIZES=(1024 2048 4096 8192)
EC_CURVES=(EC_CURVE_192 EC_CURVE_224 EC_CURVE_384 EC_CURVE_521)
ENDPOINTS=(srv cli)

#### SCRIPT ####
find ${OUTPUT_PATH}/ -mindepth 0 -type f -name '*' -delete

for size in "${RSA_KEY_SIZES[@]}"; do
    ${GEN_KEY} type=rsa rsa_keysize=${size} filename=${OUTPUT_PATH}/ca_rsa_${size}.key
    ${WRITE_CERT} selfsign=1 issuer_key=${OUTPUT_PATH}/ca_rsa_${size}.key issuer_name=CN=myca,O=myorganization,C=NL \
                not_after=${DEADLINE} is_ca=1 max_pathlen=0 output_file=${OUTPUT_PATH}/ca_rsa_${size}.crt

    for end in "${ENDPOINTS[@]}"; do
        ${GEN_KEY} type=rsa rsa_keysize=${size} filename=${OUTPUT_PATH}/${end}_rsa_${size}.key
        ${WRITE_CERT} issuer_crt=${OUTPUT_PATH}/ca_rsa_${size}.crt issuer_key=${OUTPUT_PATH}/ca_rsa_${size}.key \
                    subject_key=${OUTPUT_PATH}/${end}_rsa_${size}.key issuer_name=CN=my${end},O=myorganization,C=NL \
                    not_after=${DEADLINE} output_file=${OUTPUT_PATH}/${end}_rsa_${size}.crt
    done
done

declare -n curve

for curve in "${EC_CURVES[@]}"; do
    ${GEN_KEY} type=ec ec_curve=${curve[1]} filename=${OUTPUT_PATH}/ca_ec_${curve[0]}.key
    ${WRITE_CERT} selfsign=1 issuer_key=${OUTPUT_PATH}/ca_ec_${curve[0]}.key issuer_name=CN=myca,O=myorganization,C=NL \
                not_after=${DEADLINE} is_ca=1 max_pathlen=0 output_file=${OUTPUT_PATH}/ca_ec_${curve[0]}.crt

    for end in "${ENDPOINTS[@]}"; do
        ${GEN_KEY} type=ec ec_curve=${curve[1]} filename=${OUTPUT_PATH}/${end}_ec_${curve[0]}.key
        ${WRITE_CERT} issuer_crt=${OUTPUT_PATH}/ca_ec_${curve[0]}.crt issuer_key=${OUTPUT_PATH}/ca_ec_${curve[0]}.key \
                    subject_key=${OUTPUT_PATH}/${end}_ec_${curve[0]}.key issuer_name=CN=my${end},O=myorganization,C=NL \
                    not_after=${DEADLINE} output_file=${OUTPUT_PATH}/${end}_ec_${curve[0]}.crt
    done
done