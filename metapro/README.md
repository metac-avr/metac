# MetaProgram
Meta-program generator for C/C++ program for Automated Program Repair.

## Environments & Dependencies
MetaPro needs LLVM and Clang 16.
When you run cmake to build LLVM/Clang, use these options:
```
-DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra" -DLLVM_BUILD_LLVM_DYLIB=ON
```
After you build or install LLVM/Clang, `libclang-cpp.so` and `libLLVM.so` should be in your library path (e.g. `/usr/local/lib` or `/usr/lib`).

MetaPro also needs `nlohmann-json`, `json-c` and `spdlog`.
On Debian-based systems, install them by:
```sh
sudo apt install nlohmann-json3-dev libspdlog-dev libjson-c-dev libjson-c4 libcurl4 libcurl4-openssl-dev bear libboost-dev libboost-system-dev libboost-filesystem-dev
```

MetaPro needs cmake 3.22+.

Modified tree-sitter and tree-sitter-c from [tree-sitter](https://github.com/tree-sitter/tree-sitter).

## Installation
To build MetaPro, run following commands:
```sh
mkdir build
cd build
cmake ..
cmake --build . --parallel `nproc`
```

MetaPro in composed of multiple executables and libraries:

* `bin/metapro` is the main program of MetaPro.
* `lib/libmetapro-fl-plugin.so` and `lib/libmetapro-fl-runtime.so`
  are plugins for Fault Localization.
* `bin/metapro-pcc` and `bin/metapro-pcxx` are C and C++ compiler wrappers
  adding instrumentation for fault localization.
* `include/fl/runtime/_fl_runtime.h` is the header
  for fault localization instrumentations.
* `lib/libmetapro-runtime-c.so` and `lib/libmetapro-runtime-cxx.so`
  are runtime libraries for C and C++, respectively.
* `bin/metapro-tcc` and `bin/metapro-tcxx` are C and C++ compiler wrappers
  linking the target program to those runtime.

They must be installed to find each other:
```sh
sudo cmake --install .
```

By default, MetaPro is to be installed in `/usr/local`,
though any other preferred `$prefix` it could be specified:
```sh
cmake --install . --prefix $prefix
```

If `$prefix` is not a standard location like `/usr` or `/usr/local`,
the following environment variables must be set:
```sh
export PATH="$prefix/bin:$PATH"
export CPATH="$prefix/include:$CPATH"
export LIBRARY_PATH="$prefix/lib:$LIBRARY_PATH"
export LD_LIBRARY_PATH="$prefix/lib:$LIBRARY_PATH"
```

## Quick Start
### Run MetaPro
We prepared simple examples for MetaPro. You can find them in `examples` directory.

To run with example, run following commands:
```sh
cd examples/<example>
metapro <path-to-metapro>/examples/<example> <example>\
  ./build.sh ./test.py <failing test ID> <# of passing tests>
```

For example, to run with `if-condition`:
```sh
cd examples/if-condition
metapro <path-to-metapro>/examples/if-condition if-condition\
  ./build.sh ./test.py 2 3
```

### Outputs
Outputs are stored in `examples/<example>/output` directory.
In this directory:
* `__backup-<file>.c/.cpp`: Backup of `<file>.c/.cpp` before MetaPro runs.
* `<ID>-<file>.c/.cpp-<pattern>.c/.cpp`: Individual patched source files.
* `temp.c/.cpp`: Temp source file for parsing AST.
* `<file>.c/.cpp`: Metaprogrammed source file.
  
All slashes (`/`) for directory is replaced to `#`.

For example, after you run `if-condition`:
```
output/
├── __backup-test.c
├── 0-test.c-INSERT_ASSIGN.c
├── 1-test.c-REPLACE_CONDITION.c
├── 2-test.c-INSERT_ASSIGN.c
├── 3-test.c-INSERT_ASSIGN.c
├── 4-test.c-INSERT_ASSIGN.c
├── 5-test.c-INSERT_ASSIGN.c
├── 6-test.c-REPLACE_CONDITION.c
├── temp.c
└── test.c
```
