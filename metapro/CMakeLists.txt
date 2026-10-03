cmake_minimum_required(VERSION 3.22)

project(MetaPro VERSION 0.1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_C_COMPILER_ID STREQUAL "clang" AND NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(STATUS "C compiler should be clang, set to clang")
    set(CMAKE_C_COMPILER "clang")
endif()
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "clang" AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(STATUS "C++ compiler should be clang++, set to clang++")
    set(CMAKE_CXX_COMPILER "clang++")
endif()

message(STATUS "Using C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Using C++ compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "Clang version: ${CMAKE_C_COMPILER_VERSION}")

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()

find_package(nlohmann_json REQUIRED)
find_package(spdlog REQUIRED)
find_library(CLANG NAMES clang-cpp REQUIRED)
find_library(LLVM NAMES LLVM REQUIRED)
find_library(PARSER_TREE_SITTER NAMES tree-sitter-cpp REQUIRED)
find_library(PARSER_TREE_SITTER_C NAMES tree-sitter-c REQUIRED)
find_library(TREE_SITTER NAMES tree-sitter REQUIRED)
find_library(CURL NAMES curl REQUIRED)
find_library(JSON_C NAMES cjson REQUIRED)
find_package(Boost REQUIRED COMPONENTS system filesystem)

# DynInst libs
# message(STATUS "Looking for DynInst library...")
# find_package(Dyninst REQUIRED)

add_compile_options(-g3 -Wno-varargs -frtti)

string(REPLACE "." ";" CLANG_VERSION "${CMAKE_C_COMPILER_VERSION}")
list(GET CLANG_VERSION 0 CLANG_VERSION_MAJOR)
add_compile_definitions(CLANG_MAJOR=${CLANG_VERSION_MAJOR})

find_program(LLVM_CONFIG llvm-config)
if(NOT LLVM_CONFIG)
    find_program(LLVM_CONFIG "llvm-config-${CLANG_VERSION_MAJOR}")
    if(NOT LLVM_CONFIG)
        message(FATAL_ERROR "llvm-config not found! Check PATH is set properly to find llvm-config.")
    endif()
endif()
message(STATUS "Found llvm-config: ${LLVM_CONFIG}")
execute_process(COMMAND ${LLVM_CONFIG} --cflags OUTPUT_VARIABLE LLVM_CFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --cxxflags OUTPUT_VARIABLE LLVM_CXXFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --ldflags OUTPUT_VARIABLE LLVM_LDFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
message(STATUS "LLVM CFLAGS: ${LLVM_CFLAGS}")
message(STATUS "LLVM CXXFLAGS: ${LLVM_CXXFLAGS}")
message(STATUS "LLVM LDFLAGS: ${LLVM_LDFLAGS}")
separate_arguments(LLVM_CFLAGS)
separate_arguments(LLVM_CXXFLAGS)
separate_arguments(LLVM_LDFLAGS)
list(FILTER LLVM_CXXFLAGS EXCLUDE REGEX "^-std=")
list(FILTER LLVM_CXXFLAGS EXCLUDE REGEX "^-fno-exceptions$")

add_link_options(-g3)

message(STATUS "Found Clang: ${CLANG}, Version: ${CLANG_VERSION_MAJOR}")
message(STATUS "Found LLVM: ${LLVM}")
message(STATUS "Found tree-sitter: ${TREE_SITTER}, ${PARSER_TREE_SITTER_C} and ${PARSER_TREE_SITTER}")
message(STATUS "Found curl: ${CURL}")
message(STATUS "Found cJSON: ${JSON_C}")

# message(STATUS "Found DynInst: ${Dyninst_FOUND}")

# Runtime libraries
add_library(metapro-runtime-c SHARED src/_runtime_c.c)
# add_library(metapro-runtime-cxx SHARED src/_runtime_cxx.cpp)
# add_library(metapro-runtime-cxx-debug SHARED src/_runtime_cxx.cpp)
add_library(metapro-func-finder SHARED src/plugin/function_finder.cpp)
add_library(metapro-ast-plugin SHARED src/plugin/ast_fl_plugin.cpp)
add_library(metapro-keep-static SHARED src/plugin/keep_static_plugin.cpp)
target_link_libraries(metapro-runtime-c PRIVATE ${TREE_SITTER} ${PARSER_TREE_SITTER_C} ${CURL} ${JSON_C} ${CMAKE_DL_LIBS}) # dlsym resolves a callee of a patch expression
# target_link_libraries(metapro-runtime-cxx PRIVATE ${TREE_SITTER} ${PARSER_TREE_SITTER} ${CURL} nlohmann_json::nlohmann_json)
# target_link_libraries(metapro-runtime-cxx-debug PRIVATE ${TREE_SITTER} ${PARSER_TREE_SITTER} ${CURL} nlohmann_json::nlohmann_json)
target_link_libraries(metapro-func-finder PRIVATE ${CLANG} ${LLVM})
target_link_libraries(metapro-ast-plugin PRIVATE ${CLANG} ${LLVM} Boost::filesystem)
target_link_libraries(metapro-keep-static PRIVATE ${CLANG} ${LLVM})

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Add sanitizers for Debug build
    message(STATUS "Enabling Debug build")
    target_compile_options(metapro-runtime-c PUBLIC -O0 -ggdb -fno-limit-debug-info)
    target_link_options(metapro-runtime-c PUBLIC -O0 -ggdb -fno-limit-debug-info)
    # target_compile_options(metapro-runtime-cxx PUBLIC -O0 -ggdb -fno-limit-debug-info)
    # target_link_options(metapro-runtime-cxx PUBLIC -O0 -ggdb -fno-limit-debug-info)
    # target_compile_options(metapro-runtime-cxx-debug PUBLIC -O0 -ggdb -fno-limit-debug-info)
    # target_link_options(metapro-runtime-cxx-debug PUBLIC -O0 -ggdb -fno-limit-debug-info)
endif()

target_compile_options(metapro-runtime-c PRIVATE -fno-rtti -Wno-pointer-to-int-cast ${LLVM_CFLAGS})
# target_compile_options(metapro-runtime-cxx PRIVATE -fno-rtti -fpermissive ${LLVM_CXXFLAGS})
# target_compile_options(metapro-runtime-cxx-debug PRIVATE -fno-rtti -fpermissive -D_GLIBCXX_DEBUG -g ${LLVM_CXXFLAGS})
target_compile_options(metapro-func-finder PRIVATE -fno-rtti -fpermissive ${LLVM_CXXFLAGS})
target_compile_options(metapro-ast-plugin PRIVATE -fno-rtti -fpermissive ${LLVM_CXXFLAGS})
target_compile_options(metapro-keep-static PRIVATE -fno-rtti -fpermissive ${LLVM_CXXFLAGS})
target_link_options(metapro-runtime-c PRIVATE ${LLVM_LDFLAGS})
# target_link_options(metapro-runtime-cxx PRIVATE ${LLVM_LDFLAGS})
# target_link_options(metapro-runtime-cxx-debug PRIVATE ${LLVM_LDFLAGS} -g)
target_link_options(metapro-func-finder PRIVATE ${LLVM_LDFLAGS})
target_link_options(metapro-ast-plugin PRIVATE ${LLVM_LDFLAGS})
target_link_options(metapro-keep-static PRIVATE ${LLVM_LDFLAGS})

# metapro executable
add_executable(metapro)
target_compile_features(metapro PUBLIC cxx_std_17)
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Add sanitizers for Debug build
    target_compile_options(metapro PUBLIC -O0 -ggdb -fno-limit-debug-info)
    target_link_options(metapro PUBLIC -O0 -ggdb -fno-limit-debug-info)
endif()
include_directories(include)
target_link_libraries(metapro PRIVATE ${CLANG} ${LLVM} nlohmann_json::nlohmann_json spdlog::spdlog Boost::system ${CURL} Boost::filesystem)
target_compile_options(metapro PRIVATE -fno-rtti ${LLVM_CXXFLAGS})
target_link_options(metapro PRIVATE ${LLVM_LDFLAGS})

add_subdirectory(src)

# E9Patch runtime
add_executable(metapro-e9patch src/binary/patch_e9patch.c)
if (NOT EXISTS "/usr/share/e9compile/include/stdlib.c")
    message(FATAL_ERROR "E9Patch stdlib.c not found! Please ensure E9Patch is installed and stdlib.c is located at /usr/share/e9compile/include/stdlib.c")
endif()
target_compile_options(metapro-e9patch PRIVATE
    -fno-stack-protector -fno-builtin -fno-exceptions 
    -fpie -O2 -Wno-unused-function -U_FORTIFY_SOURCE 
    -mno-mmx -mno-sse -mno-avx -mno-avx2 -mno-avx512f -msoft-float 
    -fno-builtin-memcpy -fno-tree-vectorize -fomit-frame-pointer 
    -I /usr/share/e9compile/include/
)
target_link_libraries(metapro-e9patch PRIVATE -pie -nostdlib 
    -Wl,-z -Wl,max-page-size=4096 
    -Wl,-z -Wl,norelro 
    -Wl,-z -Wl,stack-size=0 
    -Wl,--export-dynamic 
    -Wl,--entry=0x0 
    -Wl,--strip-all
)

# Install
# install(TARGETS metapro-runtime-cxx)
# install(TARGETS metapro-runtime-cxx-debug)
install(TARGETS metapro-runtime-c)
install(TARGETS metapro-func-finder)
install(TARGETS metapro-ast-plugin)
install(TARGETS metapro-keep-static)
install(TARGETS metapro-e9patch)

install(TARGETS metapro)
# install(TARGETS binary_patcher)

install(PROGRAMS wrapper/metapro-tcc wrapper/metapro-tcxx DESTINATION bin)
# patcher.py imports binary_prep and dwarf_index as sibling modules, so all
# three must land in the same directory.
install(PROGRAMS
    src/binary/dwarf_index.py
    src/binary/patcher-e9patch.py
    DESTINATION bin)

install(DIRECTORY include DESTINATION include/metapro)