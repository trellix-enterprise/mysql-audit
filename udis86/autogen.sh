#!/bin/bash
#
if [ ! -e build/m4 ]; then mkdir -p build/m4; fi
autoreconf --force -v --install || ( echo "autogen: autoreconf -i failed." && false )
CFLAGS=-fPIC ./configure --with-python=/usr/bin/python2 --enable-utf --disable-cpp --disable-shared --enable-static
