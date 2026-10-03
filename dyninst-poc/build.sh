#!/usr/bin/env bash
# Builds mutator_launch (the Dyninst-based function replacer used by
# ArvoValidator.dyninst_patch()/dyninst_test()) against an already-built and
# installed Dyninst (see setup_dyninst() in benchmarks/arvo/scripts/checkout.py,
# which builds Dyninst from the `dyninst` submodule and `make install`s it to
# DYNINST_PREFIX before this script runs).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

DYNINST_PREFIX="${DYNINST_PREFIX:-/usr/local}"

echo "[build] mutator_launch (Dyninst-based function replacer, launch-suspended mode)"
g++ -std=c++17 -g -O0 \
    -I"${DYNINST_PREFIX}/include" \
    -L"${DYNINST_PREFIX}/lib" \
    -Wl,-rpath,"${DYNINST_PREFIX}/lib" \
    -o mutator_launch mutator_launch.cpp \
    -ldyninstAPI -lsymtabAPI -lpcontrol -lparseAPI -linstructionAPI -lcommon \
    -lpthread

echo "[build] done."
