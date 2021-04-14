#!/bin/bash

#### VARIABLES ####
GEN_KEY=../mbedtls/programs/pkey/gen_key
WRITE_CERT=../mbedtls/programs/x509/cert_write
OUTPUT_PATH=examples
DEADLINE=20221231235959
EC_CURVE_192=(192 secp192r1)
EC_CURVE_224=(224 secp224r1)
EC_CURVE_256=(256 secp256r1)
EC_CURVE_384=(384 secp384r1)
EC_CURVE_521=(521 secp521r1)
KEY_SIZES_0=(1024 192)
KEY_SIZES_1=(2048 224)
KEY_SIZES_2=(3072 256)
KEY_SIZES_3=(7680 384)
KEY_SIZES_4=(15360 521)
RSA_KEY_SIZES=(1024 2048 3072 7680 15360)
EC_CURVES=(EC_CURVE_192 EC_CURVE_224 EC_CURVE_256 EC_CURVE_384 EC_CURVE_521)
KEY_SIZES=(KEY_SIZES_0 KEY_SIZES_1 KEY_SIZES_2 KEY_SIZES_3 KEY_SIZES_4)
SRV=(srv localhost)
CLI=(cli mycli)
ENDPOINTS=(SRV CLI)

#### SCRIPT ####
find ${OUTPUT_PATH}/ -mindepth 0 -type f -name '*' -delete

declare -n len curve end

for size in "${RSA_KEY_SIZES[@]}"; do
    # Generate DH params
    openssl dhparam -check -C -noout -out ${OUTPUT_PATH}/dh_prime_${size}.h ${size}
    
    # Generate CA RSA priv key and cert (RSA signed)
    openssl req -new -newkey rsa:${size} -x509 -sha256 -subj "/CN=myca/O=myorganization/C=PT" \
    -days 365 -nodes -out ${OUTPUT_PATH}/ca_rsa_${size}.crt -keyout ${OUTPUT_PATH}/ca_rsa_${size}.key

    for end in "${ENDPOINTS[@]}"; do
        # Generate peers RSA priv key, cert request and cert (RSA signed)
        openssl genrsa -out ${OUTPUT_PATH}/${end[0]}_rsa_${size}.key ${size}
        openssl req -new -key ${OUTPUT_PATH}/${end[0]}_rsa_${size}.key -subj "/CN=${end[1]}/O=myorganization/C=PT" \
        -out ${OUTPUT_PATH}/${end[0]}_reqout_${size}.txt
        openssl x509 -req -in ${OUTPUT_PATH}/${end[0]}_reqout_${size}.txt -days 3650 -sha256 -CAcreateserial \
        -CA ${OUTPUT_PATH}/ca_rsa_${size}.crt -CAkey ${OUTPUT_PATH}/ca_rsa_${size}.key -out ${OUTPUT_PATH}/${end[0]}_rsa_${size}.crt
    done
done

for curve in "${EC_CURVES[@]}"; do
    # Generate CA EC priv key and cert (ECDSA signed)
    ${GEN_KEY} type=ec ec_curve=${curve[1]} filename=${OUTPUT_PATH}/ca_ec_${curve[0]}.key
    ${WRITE_CERT} selfsign=1 issuer_key=${OUTPUT_PATH}/ca_ec_${curve[0]}.key issuer_name=CN=myca,O=myorganization,C=PT \
                not_after=${DEADLINE} is_ca=1 max_pathlen=0 output_file=${OUTPUT_PATH}/ca_ec_${curve[0]}.crt

    for end in "${ENDPOINTS[@]}"; do
        # Generate peers EC priv key and cert (ECDSA signed)
        ${GEN_KEY} type=ec ec_curve=${curve[1]} filename=${OUTPUT_PATH}/${end[0]}_ec_${curve[0]}.key
        ${WRITE_CERT} issuer_crt=${OUTPUT_PATH}/ca_ec_${curve[0]}.crt issuer_key=${OUTPUT_PATH}/ca_ec_${curve[0]}.key \
                    subject_key=${OUTPUT_PATH}/${end[0]}_ec_${curve[0]}.key subject_name=CN=${end[1]},O=myorganization,C=PT \
                    not_after=${DEADLINE} output_file=${OUTPUT_PATH}/${end[0]}_ec_${curve[0]}.crt
    done
done

for len in "${KEY_SIZES[@]}"; do
    # Generate srv EC cert (RSA signed)
    ${WRITE_CERT} issuer_crt=${OUTPUT_PATH}/ca_rsa_${len[0]}.crt issuer_key=${OUTPUT_PATH}/ca_rsa_${len[0]}.key \
        subject_key=${OUTPUT_PATH}/srv_ec_${len[1]}.key subject_name=CN=localhost,O=myorganization,C=PT \
        not_after=${DEADLINE} output_file=${OUTPUT_PATH}/srv_ecdh_${len[1]}.crt
done