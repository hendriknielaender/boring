#!/bin/sh
set -eu

if [ "$#" -ne 8 ]; then
    echo "usage: build-boringssl.sh <source-dir> <build-dir> <cmake-build-type> <fips> <zig> <zig-target> <target-os> <target-arch>" >&2
    exit 64
fi

source_dir=$1
build_dir=$2
cmake_build_type=$3
fips=$4
zig=$5
zig_target=$6
target_os=$7
target_arch=$8

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
elif [ "$target_os" = linux ] && { [ "$(uname -s)" != Linux ] || [ "$target_arch" != "$(uname -m)" ]; }; then
    mkdir -p "$build_dir/zig-toolchain"

    cat >"$build_dir/zig-toolchain/cc" <<EOF
#!/bin/sh
exec "$zig" cc -target "$zig_target" "\$@"
EOF

    cat >"$build_dir/zig-toolchain/cxx" <<EOF
#!/bin/sh
exec "$zig" c++ -target "$zig_target" "\$@"
EOF

    cat >"$build_dir/zig-toolchain/ar" <<EOF
#!/bin/sh
exec "$zig" ar "\$@"
EOF

    cat >"$build_dir/zig-toolchain/ranlib" <<EOF
#!/bin/sh
exec "$zig" ranlib "\$@"
EOF

    chmod +x \
        "$build_dir/zig-toolchain/cc" \
        "$build_dir/zig-toolchain/cxx" \
        "$build_dir/zig-toolchain/ar" \
        "$build_dir/zig-toolchain/ranlib"

    cmake \
        -S "$source_dir" \
        -B "$build_dir" \
        -DCMAKE_BUILD_TYPE="$cmake_build_type" \
        -DCMAKE_C_COMPILER="$build_dir/zig-toolchain/cc" \
        -DCMAKE_CXX_COMPILER="$build_dir/zig-toolchain/cxx" \
        -DCMAKE_ASM_COMPILER="$build_dir/zig-toolchain/cc" \
        -DCMAKE_AR="$build_dir/zig-toolchain/ar" \
        -DCMAKE_RANLIB="$build_dir/zig-toolchain/ranlib" \
        -DCMAKE_SYSTEM_NAME=Linux \
        -DCMAKE_SYSTEM_PROCESSOR=x86_64 \
        -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY
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
