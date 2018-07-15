#!/bin/sh

mkdir -p build
cd build
cmake ..
make -j ${NUMBER_OF_PROCESSORS}
