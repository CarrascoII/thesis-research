#!/bin/sh

# Measure memory usage of a minimal client using a small configuration
# Currently hardwired to ccm-psk and suite-b, may be expanded later
#
# Use different build options for measuring executable size and memory usage,
# since for memory we want debug information.

set -eu

CONFIG_H='tls_algs/config_algs.h'

CLIENT='tls_algs/client'

CFLAGS_EXEC='-fno-asynchronous-unwind-tables -Wl,--gc-section -ffunction-sections -fdata-sections'
CFLAGS_MEM=-g3

if [ -r $CONFIG_H ]; then :; else
    echo "$CONFIG_H not found" >&2
    exit 1
fi

if grep -i cmake Makefile >/dev/null; then
    echo "Not compatible with CMake" >&2
    exit 1
fi

if [ $( uname ) != Linux ]; then
    echo "Only work on Linux" >&2
    exit 1
fi

if git status | grep -F $CONFIG_H >/dev/null 2>&1; then
    echo "config.h not clean" >&2
    exit 1
fi

# make measurements with one configuration
# usage: do_config <name> <unset-list> <server-args>
do_config()
{
    NAME=$1
    SERVER_ARGS=$2

    echo ""
    echo "$NAME:"

    grep -F SSL_MAX_CONTENT_LEN $CONFIG_H || echo 'SSL_MAX_CONTENT_LEN=16384'

    make -C ../mbedtls clean

    printf "    Executable size... "
    make OFLAGS=-Os lib_algs >/dev/null 2>&1
    make OFLAGS=-Os algs_client >/dev/null
    stat -c '%s' $CLIENT.out

    make -C ../mbedtls clean
    rm tls_algs/client.out

    printf "    Peak ram usage... "
    CFLAGS=$CFLAGS_MEM make OFLAGS=-Os lib_algs >/dev/null 2>&1
    CFLAGS=$CFLAGS_MEM make OFLAGS=-Os algs_client >/dev/null

    ./tls_algs/server.out $SERVER_ARGS >/dev/null &
    SRV_PID=$!
    sleep 1;

    if valgrind --tool=massif --stacks=yes $CLIENT.out >/dev/null 2>&1
    then
        FAILED=0
    else
        echo "client failed" >&2
        FAILED=1
    fi

    kill $SRV_PID
    wait $SRV_PID

    ../mbedtls/scripts/massif_max.pl massif.out.*
    mv massif.out.* massif-$NAME.$$
}

# preparation

CONFIG_BAK=${CONFIG_H}.bak
cp $CONFIG_H $CONFIG_BAK

rm -f massif.out.*

printf "building server... "

make clean
make lib_algs >/dev/null 2>&1
make algs_server >/dev/null

echo "done"

# actual measurements

do_config   "tls_algs/config_algs.h" \
            "ciphersuite=TLS-PSK-WITH-AES-256-CBC-SHA -n_tests=1 sec_lvl=1 max_sec_lvl=1"

do_config   "tls_algs/config_algs.h" \
            "ciphersuite=TLS-DHE-RSA-WITH-AES-256-CBC-SHA -n_tests=1 sec_lvl=1 max_sec_lvl=1"

# cleanup

mv $CONFIG_BAK $CONFIG_H
make clean

exit $FAILED
