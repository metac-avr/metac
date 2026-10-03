#pragma once

#include <vector>
#include <string>
#include <cstdlib>
#include <cstdarg>
#include <cstdint>
#include <vector>
#include <iostream>
#include <fstream>
#include <cassert>
#include <cstring>
#include <nlohmann/json.hpp>
#include <setjmp.h>

#include "tree_sitter/api.h"
#include "utils/uthash/uthash.h"

/* Jumps for continue, break and goto stmt */
extern "C" jmp_buf __metapro_continue_jmp_bufs[10000]; // To handle continue
extern "C" jmp_buf __metapro_break_jmp_bufs[10000]; // To handle break

extern "C" char* __metapro_goto_jmp_names[10000];
extern "C" jmp_buf __metapro_goto_jmps[10000];
extern "C" uint32_t __metapro_goto_jmp_count;

void __metapro_add_goto(std::string jmp_label);
uint32_t __metapro_find_goto_jmp(std::string jmp_label);

struct __metapro_return_label_info {
    char func_name[200];
    jmp_buf jmpbuf;
    UT_hash_handle hh;
};

extern "C" __metapro_return_label_info* __metapro_return_labels;

void __metapro_add_return(std::string func_name);
__metapro_return_label_info* __metapro_find_return_label(std::string func_name);

struct __metapro_var_info {
    char name[30];
    const void* ref; // pointer to the variable. This is because we don't want to update the value manually.
    uint32_t size;
    enum Type {
        MetaproVarTypeInt,
        MetaproVarTypeUInt,
        MetaproVarTypeDouble,
        MetaproVarTypePointer,
        // An array is a pointer to the interpreter, but `ref` is the array itself rather than a
        // variable holding its address, so that subscripting it off `ref` reaches the elements
        MetaproVarTypeArray,
        MetaproVarTypeStruct,
        MetaproVarTypeStructPointer, // To handle arrow

        // Function pointers
        MetaproVarTypeFunctionVoid,
        MetaproVarTypeFunctionInt,
        MetaproVarTypeFunctionUInt,
        MetaproVarTypeFunctionPointer,
        
        MetaproVarTypeUnknown // for other types
    } type;
    char struct_type_name[50]; // only for struct type; name of the struct type
    UT_hash_handle hh;
};

struct __metapro_function_var_info {
    char func_id[100];
    __metapro_var_info* var_info_table; // hashtable of __metapro_var_info
    UT_hash_handle hh;
};

extern __metapro_function_var_info* __metapro_var_info_tables;

#define __metapro_func_var_clean(func_name) \
    do { \
        __metapro_function_var_info* func_var_info = nullptr; \
        HASH_FIND_STR(__metapro_var_info_tables, #func_name, func_var_info); \
        if (func_var_info != nullptr) { \
            __metapro_var_info* current_var, *tmp; \
            HASH_ITER(hh, func_var_info->var_info_table, current_var, tmp) { \
                HASH_DEL(func_var_info->var_info_table, current_var); \
                delete current_var; \
            } \
            HASH_DEL(__metapro_var_info_tables, func_var_info); \
            delete func_var_info; \
        } \
    } while(0)

#define __metapro_get_var_value(func_name, var_name, out_ptr) \
    do { \
        __metapro_function_var_info* func_var_info = nullptr; \
        HASH_FIND_STR(__metapro_var_info_tables, func_name, func_var_info); \
        if (func_var_info == nullptr) { \
            break; \
        } \
        __metapro_var_info* var_info_table = func_var_info->var_info_table; \
        __metapro_var_info* var_info = nullptr; \
        std::string var_name_buf = var_name; \
        HASH_FIND_STR(var_info_table, var_name_buf.c_str(), var_info); \
        if (var_info == nullptr) { \
            var_name_buf = var_name + "-1"; \
            HASH_FIND_STR(var_info_table, var_name_buf.c_str(), var_info); \
            if (var_info == nullptr) { \
                var_name_buf = var_name + "-2"; \
                HASH_FIND_STR(var_info_table, var_name_buf.c_str(), var_info); /* Try 5 times to handle same variable in different scope */ \
                if (var_info == nullptr) { \
                    var_name_buf = var_name + "-3"; \
                    HASH_FIND_STR(var_info_table, var_name_buf.c_str(), var_info); \
                    if (var_info == nullptr) { \
                        var_name_buf = var_name + "-4"; \
                        HASH_FIND_STR(var_info_table, var_name_buf.c_str(), var_info); \
                    } \
                } \
            } \
        } \
        if (var_info != nullptr) { \
            out_ptr = var_info; \
        } \
        else { \
            out_ptr = nullptr; \
        } \
    } while(0)

#define __metapro_get_func_var_info(func_name, out_func_var_info) \
    HASH_FIND_STR(__metapro_var_info_tables, func_name, out_func_var_info)

void __metapro_table_insert_var_cxx(std::string func_name, std::string var_name, const void* ref_ptr, uint32_t var_size, __metapro_var_info::Type var_type,
    std::string struct_type);

/* Register a variable while it is being initialized, and evaluate to init_value. See __metapro_init_var_c */
#define __metapro_init_var_cxx(func_name, var_name, ref_ptr, var_size, var_type, struct_type, init_value) \
    (__metapro_table_insert_var_cxx(func_name, var_name, ref_ptr, var_size, var_type, struct_type), (init_value))
void __metapro_func_var_init_cxx(std::string func_name);
void __metapro_remove_var_info_cxx(std::string funcName, std::string varName);
void __metapro_table_remove_var_cxx(std::string func_name, std::string var_name);

/* Function pointers */
#define MAX_FUNCTIONS 200
extern "C" void (*void_functions[MAX_FUNCTIONS])();
extern "C" int64_t (*int64_functions[MAX_FUNCTIONS])();
extern "C" uint64_t (*uint64_functions[MAX_FUNCTIONS])();
extern "C" void* (*ptr_functions[MAX_FUNCTIONS])();
extern "C" char* void_func_names[MAX_FUNCTIONS];
extern "C" char* int64_func_names[MAX_FUNCTIONS];
extern "C" char* uint64_func_names[MAX_FUNCTIONS];
extern "C" char* ptr_func_names[MAX_FUNCTIONS];
extern "C" uint32_t void_func_count, int64_func_count, uint64_func_count, ptr_func_count;

void __metapro_register_void_function_cxx(std::string func_name, uint32_t func_number, std::vector<std::string> func_names, std::vector<void (*)()> func_ptr);
void __metapro_register_int_function_cxx(std::string func_name, uint32_t func_number, std::vector<std::string> func_names, std::vector<int64_t (*)()> func_ptr);
void __metapro_register_uint_function_cxx(std::string func_name, uint32_t func_number, std::vector<std::string> func_names, std::vector<uint64_t (*)()> func_ptr);
void __metapro_register_ptr_function_cxx(std::string func_name, uint32_t func_number, std::vector<std::string> func_names, std::vector<void* (*)()> func_ptr);

bool __metapro_new_cond_cxx(uint64_t id, std::string funcName);
bool __metapro_new_not_null_check_cxx(uint64_t id, std::string funcName);
int64_t __metapro_get_int_var_cxx(uint64_t id, std::string funcName);
uint64_t __metapro_get_uint_var_cxx(uint64_t id, std::string funcName);
void* __metapro_get_ptr_var_cxx(uint64_t id, std::string funcName);
bool __metapro_replace_cond_cxx(uint64_t id, std::string orig_cond_str, bool orig_cond, std::string funcName);
void __metapro_exec_expr_cxx(uint64_t id, std::string funcName, uint32_t jumpId);

long long __metapro_replace_int_var_cxx(unsigned long id, long long original,
                                    unsigned int int_var_count, std::vector<unsigned long long> int_var_sizes, std::vector<std::string> int_var_names, std::vector<long long> int_vars,
                                    unsigned int uint_var_count, std::vector<unsigned long long> uint_var_sizes, std::vector<std::string> uint_var_names, std::vector<unsigned long long> uint_vars);

unsigned long long __metapro_replace_uint_var_cxx(unsigned long id, unsigned long long original,
                                    unsigned int int_var_count, std::vector<unsigned long long> int_var_sizes, std::vector<std::string> int_var_names, std::vector<long long> int_vars,
                                    unsigned int uint_var_count, std::vector<unsigned long long> uint_var_sizes, std::vector<std::string> uint_var_names, std::vector<unsigned long long> uint_vars);

typedef long long (*__metapro_int_func_type_cxx)();
typedef unsigned long long (*__metapro_uint_func_type_cxx)();
typedef void (*__metapro_void_func_type_cxx)();

__metapro_int_func_type_cxx __metapro_replace_int_func_cxx(unsigned long id, __metapro_int_func_type_cxx orig_func,
                unsigned int func_number, std::vector<std::string> new_func_names, std::vector<__metapro_int_func_type_cxx> new_funcs);
__metapro_uint_func_type_cxx __metapro_replace_uint_func_cxx(unsigned long id, __metapro_uint_func_type_cxx orig_func,
                unsigned int func_number, std::vector<std::string> new_func_names, std::vector<__metapro_uint_func_type_cxx> new_funcs);
__metapro_void_func_type_cxx __metapro_replace_void_func_cxx(unsigned long id, __metapro_void_func_type_cxx orig_func,
                unsigned int func_number, std::vector<std::string> new_func_names, std::vector<__metapro_void_func_type_cxx> new_funcs);

const std::string __metapro_replace_string_literal_cxx(unsigned long id, const std::string orig_str);

int __metapro_env_to_int_cxx(const char* env);

void __metapro_mark_block_cxx(void);