#!/bin/sh

export LD_LIBRARY_PATH=../../../../obj/dest.stage/usr/lib/
export LD_PRELOAD=librumphijack.so
export RUMPHIJACK=socket=all
#RUMP_SERVER=unix:///tmp/rump-server-nuse.39554

$*
