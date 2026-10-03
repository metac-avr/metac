#!/bin/sh
set -e
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <source-directory>"
    exit 1
fi

cd $1
make clean
make
