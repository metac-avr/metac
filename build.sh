#!/bin/bash
set -e

# Build metapro first
pushd metapro
# Build tree-sitter
pushd tree-sitter
pushd c
make -j20 install
popd
pushd cpp
make -j20 install
popd
pushd tree-sitter
make -j20 install
popd
popd

# Build metapro
mkdir -p build
pushd build
cmake ..
make -j20
make -j20 install 
popd
popd

exit 0