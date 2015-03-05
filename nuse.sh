#!/bin/sh
if [ -e /usr/lib64 ]; then
	sudo ln -f -s `pwd`/liblinux-nuse.so /usr/lib64/liblinux-nuse.so
fi
sudo ln -f -s `pwd`/liblinux-nuse.so /usr/lib/liblinux-nuse.so
sudo chown root liblinux-nuse.so
sudo chmod 4755 liblinux-nuse.so

LD_LIBRARY_PATH=. LD_PRELOAD=liblinux.so:liblinux-nuse.so $*
