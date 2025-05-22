#!/bin/bash

if [[ ! -e target ]]; then
    mkdir target
fi


cd target

cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_COMPILER=$LLVM_HOME/bin/clang++  \
      -DCMAKE_C_COMPILER=$LLVM_HOME/bin/clang ..
ninja

cd ..

$LLVM_HOME/bin/clang -S -emit-llvm ../tests/input.c -o ../tests/input.ll


#$LLVM_HOME/bin/opt -enable-new-pm=0 -mem2reg -S tests/input.ll -o tests/2.ll
#$LLVM_HOME/bin/clang -fno-discard-value-names -g -flegacy-pass-manager  -lm -lffi -Xclang -load -Xclang target/parsers/libtypeanalysis.so -mllvm -genepath="." tests/input.c -o tests/1

rm input.json5

$LLVM_HOME/bin/opt -enable-new-pm=0 -load target/parsers/libtypeanalysis.so -parser -genepath="." ../tests/input.ll 

md5sum input.json5
