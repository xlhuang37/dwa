#!/bin/bash

make clean
make CC="gcc -Wno-error=attributes" LD=gcc BUILD_MODE=release


#make run-tests
#sudo make install


