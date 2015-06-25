#!/bin/sh

git submodule init
git submodule update dpdk

: ${RTE_SDK:=$(pwd)/dpdk}
: ${RTE_TARGET:=build}
export RTE_SDK
export RTE_TARGET

set -e
cd dpdk
make -j1 CONFIG_RTE_LIBRTE_ETHDEV_DEBUG=y T=$(uname -m)-native-linuxapp-gcc config
make SRCARCH=x86 CONFIG_RTE_BUILD_COMBINE_LIBS=y EXTRA_CFLAGS="-fPIC -g" \
  || (echo "dpdk build failed" && exit 1)

