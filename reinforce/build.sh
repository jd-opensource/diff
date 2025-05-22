#!/bin/bash
# rm -rf target

if [[ ! -e target ]]; then
    mkdir -p target
fi

cd target

OS_NAME=$(uname)

DEPENDENCIES=$(ldd ${LLVM_HOME}/bin/clang)
if echo "$DEPENDENCIES" | grep -q "libstdc++"; then
    echo "clang using libstdc++"
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_CXX_COMPILER=${LLVM_HOME}/bin/clang++  \
        -DCMAKE_C_COMPILER=${LLVM_HOME}/bin/clang \
        -DCMAKE_CXX_FLAGS="-Wno-everything -stdlib=libstdc++"  \
        ..
else
    echo "clang using libc++"
    cmake -G "Ninja" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_CXX_COMPILER=${LLVM_HOME}/bin/clang++  \
        -DCMAKE_C_COMPILER=${LLVM_HOME}/bin/clang \
        -DCMAKE_CXX_FLAGS="-Wno-everything -stdlib=libc++"  \
        ..   
fi

ninja

cd ..

${LLVM_HOME}/bin/clang -o ../tests/newobj -fplugin=./target/Hikari/libHikari.so -fpass-plugin=./target/Hikari/libHikari.so -Os ../tests/input.c
