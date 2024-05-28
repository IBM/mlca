#!/bin/sh
mkdir -p build_cov
cd build_cov
cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=coverage ..
make
ctest -j16
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage

