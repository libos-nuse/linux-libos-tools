#!/bin/sh

export PID_SLEEP=`/bin/ls -ltr /tmp/rump-server-nuse.* | tail -1 | awk '{print $9}' | sed -e "s/.*rump-server-nuse\.//g" | sed "s/=//"`
export RUMP_URL=unix:///tmp/rump-server-nuse.${PID_SLEEP}
export RUMP_SERVER=${RUMP_URL}

export LD_LIBRARY_PATH=../../../../obj/dest.stage/usr/lib/
export LD_PRELOAD=librumphijack.so
export RUMPHIJACK=socket=all
#RUMP_SERVER=unix:///tmp/rump-server-nuse.39554


$*
