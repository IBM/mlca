#!/bin/sh
export CUR_DIR=`pwd`
if [ ! -d $CUR_DIR/liboqs-0100 ]; then
    git clone --depth 1 --branch 0.10.0 https://github.com/open-quantum-safe/liboqs.git $CUR_DIR/liboqs-0100
    cd $CUR_DIR/liboqs-0100 && mkdir -p build && cd build && cmake -DCMAKE_INSTALL_PREFIX=$CUR_DIR/lib0100 -DOQS_BUILD_ONLY_LIB=OFF -DOQS_USE_OPENSSL=OFF -DCMAKE_C_COMPILER=gcc -DOQS_MINIMAL_BUILD="SIG_dilithium_2;SIG_dilithium_3;SIG_dilithium_5;KEM_kyber_512;KEM_kyber_768;KEM_kyber_1024" .. && make -j8 && make install
elif [ ! -d $CUR_DIR/lib0100/lib ]; then
    cd $CUR_DIR/liboqs-0100/build && make install
fi

if [ ! -d $CUR_DIR/liboqs-040 ]; then
    git clone --depth 1 --branch 0.4.0 https://github.com/open-quantum-safe/liboqs.git $CUR_DIR/liboqs-040
    cd $CUR_DIR/liboqs-040 && git apply ../no_warn_errors.patch && mkdir -p build && cd build && cmake -DCMAKE_INSTALL_PREFIX=$CUR_DIR/lib040 -DOQS_USE_OPENSSL=OFF -DOQS_ENABLE_SIG_DILITHIUM=ON -DOQS_ENABLE_KEM_KYBER=ON -DOQS_ENABLE_KEM_SIDH=OFF -DOQS_ENABLE_KEM_SIKE=OFF -DOQS_ENABLE_SIG_QTESLA=OFF .. && make -j8 && make install
elif [ ! -d $CUR_DIR/lib040/lib ]; then
    cd $CUR_DIR/liboqs-040/build && make install
fi

