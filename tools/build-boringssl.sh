#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: build-boringssl.sh <source-dir> <build-dir> <cmake-build-type> <fips>" >&2
    exit 64
fi

source_dir=$1
build_dir=$2
cmake_build_type=$3
fips=$4

case "$cmake_build_type" in
    Debug | Release | RelWithDebInfo | MinSizeRel) ;;
    *)
        echo "invalid CMake build type: $cmake_build_type" >&2
        exit 64
        ;;
esac

case "$fips" in
    true | false) ;;
    *)
        echo "invalid FIPS flag: $fips" >&2
        exit 64
        ;;
esac

if [ ! -f "$source_dir/CMakeLists.txt" ]; then
    echo "BoringSSL source missing CMakeLists.txt: $source_dir" >&2
    exit 66
fi

if [ "$fips" = true ] && [ "$(uname -s)" != Linux ]; then
    echo "BoringSSL source FIPS builds require a Linux host" >&2
    exit 64
fi

if [ "$fips" = true ]; then
    cmake \
        -S "$source_dir" \
        -B "$build_dir" \
        -DCMAKE_BUILD_TYPE="$cmake_build_type" \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_ASM_COMPILER=clang \
        -DCMAKE_C_FLAGS=-Wno-unused-command-line-argument \
        -DFIPS=1
else
    cmake \
        -S "$source_dir" \
        -B "$build_dir" \
        -DCMAKE_BUILD_TYPE="$cmake_build_type"
fi

cmake \
    --build "$build_dir" \
    --target ssl crypto \
    --config "$cmake_build_type"

if [ ! -f "$build_dir/ssl/libssl.a" ]; then
    echo "BoringSSL build did not produce ssl/libssl.a" >&2
    exit 70
fi

if [ ! -f "$build_dir/crypto/libcrypto.a" ]; then
    echo "BoringSSL build did not produce crypto/libcrypto.a" >&2
    exit 70
fi
