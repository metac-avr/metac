#include <cstdarg>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <iostream>
#include <fstream>
#include <cassert>
#include <cstring>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/shm.h>
#include <iomanip>
#include <cinttypes>
#include <cstdio>
#include <sstream>

#include "tree_sitter/api.h"
#include "_runtime_cxx.h"

#define MAX_SIZE 10000

extern "C" TSLanguage *tree_sitter_cpp(void);

/* Output debugging to file (to debug in fuzzer) */
#define WRITE_DEBUG_TO_FILE(fmt, ...) do { \
    char* file_name = getenv("METAPRO_DEBUG_OUTPUT_FILE"); \
    if (file_name == NULL) { \
        break; \
    } \
    FILE* debug_file = fopen(file_name, "a"); \
    if (debug_file != NULL) { \
        fprintf(debug_file, fmt, ##__VA_ARGS__); \
        fclose(debug_file); \
    } \
} while (0)

/* Print to debug file and stderr error msg and abort */
#define PRINTF_ERROR(fmt, ...) do { \
    WRITE_DEBUG_TO_FILE("ERROR: " fmt, ##__VA_ARGS__); \
    fprintf(stderr, "ERROR: " fmt, ##__VA_ARGS__); \
    abort(); \
} while (0)

/* Jumps for continue, break and goto stmt */
void __metapro_add_goto(std::string jmp_label) {
    for (uint32_t i = 0; i < __metapro_goto_jmp_count; i++) {
        if (strcmp(__metapro_goto_jmp_names[i], jmp_label.c_str()) == 0) {
            return;
        }
    }
    __metapro_goto_jmp_names[__metapro_goto_jmp_count] = (char*)malloc(sizeof(char) * (strlen(jmp_label.c_str()) + 2));
    strcpy(__metapro_goto_jmp_names[__metapro_goto_jmp_count], jmp_label.c_str());
    __metapro_goto_jmp_count++;
}

uint32_t __metapro_find_goto_jmp(std::string jmp_label) {
    for (uint32_t i = 0; i < __metapro_goto_jmp_count; i++) {
        if (strcmp(__metapro_goto_jmp_names[i], jmp_label.c_str()) == 0) {
            return i;
        }
    }
    PRINTF_ERROR("Goto label not found: %s\n", jmp_label.c_str());
}

__metapro_return_label_info* __metapro_return_labels = NULL;
void __metapro_add_return(std::string func_name) {
    __metapro_return_label_info* label_info = new __metapro_return_label_info;
    strcpy(label_info->func_name, func_name.c_str());
    HASH_ADD_STR(__metapro_return_labels, func_name, label_info);
    WRITE_DEBUG_TO_FILE("Add new return jmp buf: %s, %p\n", func_name.c_str(), &label_info->jmpbuf);
}

__metapro_return_label_info* __metapro_find_return_label(std::string func_name) {
    __metapro_return_label_info* label_info;
    HASH_FIND_STR(__metapro_return_labels, func_name.c_str(), label_info);
    if (label_info == NULL) {
        PRINTF_ERROR("Return label not found for function: %s\n", func_name.c_str());
    }
    return label_info;
}

using json=nlohmann::json;

int startswith(const std::string str, const std::string prefix) {
    return str.compare(0,prefix.size(),prefix)==0;
}

/**
 * Split a string by a delimiter character.
 * 
 * @param str string to split
 * @param delimiter delimiter
 * @return vector of splitted strings
 */
static std::vector<std::string> str_split(std::string str, char delimiter) {
    std::vector<std::string> result;
    size_t count = 0;
    size_t pos = 0;
    while ((pos = str.find(delimiter)) != std::string::npos) {
        result.push_back(str.substr(0, pos));
        str.erase(0, pos + 1);
        count++;
    }
    result.push_back(str);
    return result;
}

static std::string extract_label(const std::string str, const std::string function_name) {
    std::string prefix = "__metapro_" + function_name + "_";
    size_t pos = str.find(prefix);
    if (pos == std::string::npos) {
        return "";
    }
    return str.substr(pos + prefix.size());
}

static int32_t* __shm_addr = nullptr;
static size_t __shm_size = 0;
static size_t __shm_offset = sizeof(size_t);

static void __store_state(unsigned int int_var_count, std::vector<unsigned long long> int_var_sizes, std::vector<std::string> int_var_names, std::vector<long long> int_vars,
                                    unsigned int uint_var_count, std::vector<unsigned long long> uint_var_sizes, std::vector<std::string> uint_var_names, std::vector<unsigned long long> uint_vars,
                                    unsigned int double_var_count, std::vector<unsigned long long> double_var_sizes, std::vector<std::string> double_var_names, std::vector<long double> double_vars,
                                    unsigned int ptr_var_count, std::vector<std::string> ptr_var_names, std::vector<void*> ptr_vars) {
    char *pac_reached_env = getenv("PAC_REACHED_ENV");
    if (pac_reached_env) {
        size_t id = atoi(pac_reached_env);
        __shm_addr = (int32_t*)shmat(id, nullptr, 0);

        __shm_size++;
        memcpy(__shm_addr, &__shm_size, sizeof(size_t)/sizeof(int32_t));
        memcpy(__shm_addr + __shm_offset, &int_var_count, sizeof(unsigned int)/sizeof(int32_t));
        __shm_offset += sizeof(unsigned int)/sizeof(int32_t);
        for (size_t i=0;i<int_var_count;i++) {
            memcpy(__shm_addr + __shm_offset, &int_vars[i], sizeof(long long)/sizeof(int32_t));
            __shm_offset += sizeof(long long)/sizeof(int32_t);
        }
        memcpy(__shm_addr + __shm_offset, &uint_var_count, sizeof(unsigned int)/sizeof(int32_t));
        __shm_offset += sizeof(unsigned int)/sizeof(int32_t);
        for (size_t i=0;i<uint_var_count;i++) {
            memcpy(__shm_addr + __shm_offset, &uint_vars[i], sizeof(unsigned long long)/sizeof(int32_t));
            __shm_offset += sizeof(unsigned long long)/sizeof(int32_t);
        }
        memcpy(__shm_addr + __shm_offset, &double_var_count, sizeof(unsigned int)/sizeof(int32_t));
        __shm_offset += sizeof(unsigned int)/sizeof(int32_t);
        for (size_t i=0;i<double_var_count;i++) {
            memcpy(__shm_addr + __shm_offset, &double_vars[i], sizeof(long double)/sizeof(int32_t));
            __shm_offset += sizeof(long double)/sizeof(int32_t);
        }
        memcpy(__shm_addr + __shm_offset, &ptr_var_count, sizeof(unsigned int)/sizeof(int32_t));
        __shm_offset += sizeof(unsigned int)/sizeof(int32_t);
        for (size_t i=0;i<ptr_var_count;i++) {
            unsigned int is_not_null = (ptr_vars[i] != nullptr);
            memcpy(__shm_addr + __shm_offset, &is_not_null, sizeof(unsigned int)/sizeof(int32_t));
            __shm_offset += sizeof(unsigned int)/sizeof(int32_t);
        }
    }
}

/* Record and field stuffs */

struct FieldInfo {
    char name[30];
    uint32_t offset;
    uint32_t size;
    uint32_t index;
    char type[20];
    char *struct_type;
    uint32_t array_element_size;
    UT_hash_handle hh;
};

struct RecordInfo {
    char name[300];
    uint32_t field_count;
    FieldInfo* field_info_table;
    UT_hash_handle hh;
};

RecordInfo* record_info_table = nullptr;

struct VarSizeInfo {
    char var_name[100];
    uint32_t size;
    UT_hash_handle hh;
};

VarSizeInfo* var_size_info_table = nullptr;

static void parse_record_info_cxx() {
    char* patch_info_file_name = getenv("METAPRO_STRUCT_INFO_FILE");
    if (patch_info_file_name == nullptr) {
        return;
    }

    std::ifstream file(patch_info_file_name);
    if (!file.good()) {
        return;
    }
    // Read entire file content
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string file_content = buffer.str();
    file.close();

    json info = json::parse(file_content);
    json record_info = info["struct"];
    for (json::iterator it = record_info.begin(); it != record_info.end(); ++it) {
        // Create and add RecordInfo
        json record_obj = it.value();
        RecordInfo* record = new RecordInfo();
        strcpy(record->name, it.key().c_str());
        record->field_count = 0;
        record->field_info_table = nullptr;
        HASH_ADD_STR(record_info_table, name, record);

        // Iterate field info
        for (json::iterator field_it = record_obj.begin(); field_it != record_obj.end(); ++field_it) {
            json field_info = field_it.value();
            FieldInfo* field = new FieldInfo();
            strcpy(field->name, field_it.key().c_str());
            field->offset = field_info["offset"].get<uint32_t>();
            field->size = field_info["size"].get<uint32_t>();
            field->index = field_info["index"].get<uint32_t>();
            strcpy(field->type, field_info["type"].get<std::string>().c_str());
            if (std::string(field->type) == "struct" || std::string(field->type) == "struct_ptr") {
                if (field_info.find("struct_type") == field_info.end()) {
                    field->struct_type = new char[1];
                    field->struct_type[0] = '\0';
                }
                else {
                    field->struct_type = new char[field_info["struct_type"].get<std::string>().size() + 1];
                    strcpy(field->struct_type, field_info["struct_type"].get<std::string>().c_str());
                }
            }
            if (field_info.find("element_size") != field_info.end()) {
                field->array_element_size = field_info["element_size"].get<uint32_t>();
            } else {
                field->array_element_size = 0;
            }
            HASH_ADD_STR(record->field_info_table, name, field);
        }
    }

    json var_size_info = info["type"];
    for (json::iterator func_it = var_size_info.begin(); func_it != var_size_info.end(); ++func_it) {
        for (json::iterator var_it = func_it.value().begin(); var_it != func_it.value().end(); ++var_it) {
            VarSizeInfo* var_size_info = new VarSizeInfo();
            std::string full_var_name = func_it.key() + "::" + var_it.key();
            strcpy(var_size_info->var_name, full_var_name.c_str());
            var_size_info->size = var_it.value()["size"].get<uint32_t>();
            HASH_ADD_STR(var_size_info_table, var_name, var_size_info);
        }
    }
}

void print_var_table() {
    RecordInfo* record_info, *record_tmp;
    FieldInfo *cur_record, *tmp;
    HASH_ITER(hh, record_info_table, record_info, record_tmp) {
        std::cout << "Record: " << record_info->name << ", #: " << HASH_COUNT(record_info->field_info_table) <<
                    ", addr: " << record_info->field_info_table << std::endl;
        HASH_ITER(hh, record_info->field_info_table, cur_record, tmp) {
            std::cout << "  Name: " << cur_record->name << ", Type: " << cur_record->type << ", Size: " << cur_record->size <<
                        ", Offset: " << cur_record->offset << ", Index: " << cur_record->index << std::endl;
        }
    }
}

void __metapro_table_remove_var_cxx(std::string func_name, std::string var_name) {
    __metapro_function_var_info* func_var_info = nullptr;
    HASH_FIND_STR(__metapro_var_info_tables, func_name.c_str(), func_var_info);
    if (func_var_info == nullptr) {
        return;
    }
    __metapro_var_info* var_top_info = func_var_info->var_info_table;
    __metapro_var_info* var_info = nullptr;
    std::string var_name_buf = var_name + "-4";
    HASH_FIND_STR(var_top_info, var_name.c_str(), var_info);
    if (var_info != nullptr) {
        HASH_DEL(var_top_info, var_info);
        delete var_info;
    }
    else {
        var_name_buf = var_name + "-3";
        HASH_FIND_STR(var_top_info, var_name_buf.c_str(), var_info);
        if (var_info != nullptr) {
            HASH_DEL(var_top_info, var_info);
            delete var_info;
        }
        else {
            var_name_buf = var_name + "-2";
            HASH_FIND_STR(var_top_info, var_name_buf.c_str(), var_info);
            if (var_info != nullptr) {
                HASH_DEL(var_top_info, var_info);
                delete var_info;
            }
            else {
                var_name_buf = var_name + "-1";
                HASH_FIND_STR(var_top_info, var_name_buf.c_str(), var_info);
                if (var_info != nullptr) {
                    HASH_DEL(var_top_info, var_info);
                    delete var_info;
                }
                else {
                    HASH_FIND_STR(var_top_info, var_name.c_str(), var_info);
                    if (var_info != nullptr) {
                        HASH_DEL(var_top_info, var_info);
                        delete var_info;
                    }
                }
            }
        }
    }
}

void __metapro_print_var_table_cxx(std::string funcName) {
    __metapro_function_var_info* func_var_info=nullptr;
    __metapro_var_info *cur_func, *tmp;
    __metapro_get_func_var_info(funcName.c_str(), func_var_info);
    if (func_var_info==nullptr) {
        std::cout << "No variable table for function " << funcName << "!" << std::endl;
        return;
    }
    std::cout << "Variable table for function " << funcName << ", #: " << HASH_COUNT(func_var_info->var_info_table) <<
                ", addr: " << func_var_info->var_info_table << std::endl;
    HASH_ITER(hh, func_var_info->var_info_table, cur_func, tmp) {
        if (cur_func==nullptr) 
            std::cout << "  Null variable info!" << std::endl;
        else
            std::cout << "  Name: " << cur_func->name << ", Type: " << cur_func->type << ", Size: " << cur_func->size <<
                        ", Ref: " << cur_func->ref << std::endl;
    }
}

/* Utility functions */

int has_field_access(const std::string expr) {
    return expr.find('.') || expr.find("->");
}

std::vector<std::string> get_field_accesses(std::string expr) {
    // Replace "->" to "."
    size_t pos = 0;
    while ((pos = expr.find("->", pos)) != std::string::npos) {
        expr.replace(pos, 2, ".");
        pos += 1; // Move past the replaced character
    }

    // Split into each field accesses
    pos = 0;
    std::vector<std::string> field_accesses;
    while ((pos = expr.find('.')) != std::string::npos) {
        std::string token = expr.substr(0, pos);
        field_accesses.push_back(token);
        expr.erase(0, pos + 1);
    }
    return field_accesses;
}

FieldInfo* get_final_field_info(std::vector<std::string> field_accesses) {
    // Find the type of the final field
    RecordInfo* record_info=nullptr;
    FieldInfo* field_info=nullptr;
    size_t i = 0;
    for (std::string field_name : field_accesses) {
        if (i==0) {
            // First field: find the record info
            HASH_FIND_STR(record_info_table, field_accesses[i].c_str(), record_info);
            if (record_info == nullptr) {
                return nullptr; // Not found
            }
        }
        else {
            // Subsequent fields: find the field info
            HASH_FIND_STR(record_info->field_info_table, field_accesses[i].c_str(), field_info);
            if (field_info == nullptr) {
                return nullptr; // Not found
            }
            // If not the last field, update record_info for next field access
            if (i < field_accesses.size() - 1) {
                HASH_FIND_STR(record_info_table, field_info->struct_type, record_info);
                if (record_info == nullptr) {
                    return nullptr; // Not found
                }
            }
        }
        i++;
    }

    return field_info;
}

void* get_final_field_reference(std::vector<std::string> field_accesses, const void* base_ref) {
    uint8_t* current_ref = (uint8_t*)base_ref; // Convert to 1 byte to access field with offset
    RecordInfo* record_info = nullptr;
    FieldInfo* field_info = nullptr;

    size_t i = 0;
    for (std::string field_name : field_accesses) {
        if (i == 0) {
            // First field: find the record info
            HASH_FIND_STR(record_info_table, field_accesses[i].c_str(), record_info);
            if (record_info == nullptr) {
                return nullptr; // Not found
            }
        }
        else {
            // Subsequent fields: find the field info
            HASH_FIND_STR(record_info->field_info_table, field_accesses[i].c_str(), field_info);
            if (field_info == nullptr) {
                return nullptr; // Not found
            }
            // Update current_ref to point to the field
            current_ref = (uint8_t*)(current_ref + field_info->offset);

            // If not the last field, update record_info for next field access
            if (i < field_accesses.size() - 1) {
                // Dereference if pointer, but we don't deref if last field
                if (std::string(field_info->type) == "struct_ptr") {
                    current_ref = *(uint8_t**)current_ref;
                }
                HASH_FIND_STR(record_info_table, field_info->struct_type, record_info);
                if (record_info == nullptr) {
                    return nullptr; // Not found
                }
            }
        }
        i++;
    }

    return (void*)current_ref;
}

uint32_t get_var_size_from_type(std::string type_name) {
    VarSizeInfo* var_size_info = nullptr;
    HASH_FIND_STR(var_size_info_table, type_name.c_str(), var_size_info);
    if (var_size_info != nullptr) {
        return var_size_info->size;
    }
    return 0; // Not found
}

void __metapro_table_insert_var_cxx(std::string func_name, std::string var_name, const void* ref_ptr, uint32_t var_size, __metapro_var_info::Type var_type,
                std::string struct_type) {
    if (ref_ptr == nullptr) return;
    __metapro_function_var_info* func_var_info = nullptr;
    HASH_FIND_STR(__metapro_var_info_tables, func_name.c_str(), func_var_info);
    if (func_var_info == nullptr) {
        return;
    }
    __metapro_var_info* var_info = nullptr;
    HASH_FIND_STR(func_var_info->var_info_table, var_name.c_str(), var_info);
    if (0 && var_info != nullptr) { // Temorary disable duplicate var name handling to avoid UTHash issue
        std::string new_var_name = var_name + "-1";
        HASH_FIND_STR(func_var_info->var_info_table, new_var_name.c_str(), var_info); /* Try 5 times to handle same variable in different scope */
        if (var_info != nullptr) {
            new_var_name = var_name + "-2";
            HASH_FIND_STR(func_var_info->var_info_table, new_var_name.c_str(), var_info);
            if (var_info != nullptr) {
                new_var_name = var_name + "-3";
                HASH_FIND_STR(func_var_info->var_info_table, new_var_name.c_str(), var_info);
                if (var_info != nullptr) {
                    new_var_name = var_name + "-4";
                    HASH_FIND_STR(func_var_info->var_info_table, new_var_name.c_str(), var_info);
                    if (var_info != nullptr) {
                        return; /* Cannot insert more */
                    } else {
                        /* 4 */
                        var_info = new __metapro_var_info();
                        sprintf(var_info->name, "%s", (var_name + "-4").c_str());
                    }
                } else {
                    /* 3 */
                    var_info = new __metapro_var_info();
                    sprintf(var_info->name, "%s", (var_name + "-3").c_str());
                }
            } else {
                /* 2 */
                var_info = new __metapro_var_info();
                sprintf(var_info->name, "%s", (var_name + "-2").c_str());
            }
        } else {
            /* 1 */
            var_info = new __metapro_var_info();
            sprintf(var_info->name, "%s", (var_name + "-1").c_str());
        }
    }
    else {
        var_info = new __metapro_var_info();
        sprintf(var_info->name, "%s", var_name.c_str());
    }
    var_info->ref=(const void*)ref_ptr;
    var_info->size=var_size;
    var_info->type=var_type;
    if (var_type == __metapro_var_info::MetaproVarTypeStruct || var_type == __metapro_var_info::MetaproVarTypeStructPointer) {
        sprintf(var_info->struct_type_name, "%s", struct_type.c_str());
    } else {
        var_info->struct_type_name[0] = '\0';
    }
    HASH_ADD_STR(func_var_info->var_info_table, name, var_info);

    // Debug print
    return;
    std::cout << "# of variables in function " << func_name << ": " << HASH_COUNT(func_var_info->var_info_table) <<
                ", addr: " << var_info << std::endl;
    __metapro_var_info *cur_func, *tmp;
    HASH_ITER(hh, func_var_info->var_info_table, cur_func, tmp) {
        if (cur_func==nullptr) 
            std::cout << "  Null variable info!" << std::endl;
        else
            std::cout << "  Name: " << cur_func->name << ", Type: " << cur_func->type << ", Size: " << cur_func->size <<
                        ", Ref: " << cur_func->ref << std::endl;
    }
}

void __metapro_func_var_init_cxx(std::string func_name) {
    __metapro_function_var_info* func_var_info = nullptr;
    HASH_FIND_STR(__metapro_var_info_tables, func_name.c_str(), func_var_info);
    if (func_var_info != nullptr) {
        __metapro_func_var_clean(func_name.c_str());
    }
    func_var_info = new __metapro_function_var_info();
    sprintf(func_var_info->func_id, "%s", func_name.c_str());
    func_var_info->var_info_table = nullptr;
    HASH_ADD_STR(__metapro_var_info_tables, func_id, func_var_info);
}

void __metapro_remove_var_info_cxx(std::string funcName, std::string varName) {
    __metapro_table_remove_var_cxx(funcName, varName);
}

/* Function Pointers*/

void __metapro_register_void_function_cxx(std::string func_name, uint32_t func_number, std::vector<std::string> func_names, std::vector<void (*)()> func_ptr) {
    for (size_t i = 0; i < func_number; i++) {
        if (void_func_count >= MAX_FUNCTIONS) break; // Max limit
        int insert = 1;
        for (size_t j = 0; j < void_func_count; j++) {
            if (strcmp(void_func_names[j], func_names[i].c_str()) == 0) {
                // Already registered
                insert = 0;
                break;
            }
        }
        __metapro_table_insert_var_cxx(func_name, func_names[i], (const void*)func_ptr[i], sizeof(void (*)()), __metapro_var_info::MetaproVarTypeFunctionVoid, "");
        if (insert == 0) continue;
        WRITE_DEBUG_TO_FILE("Registering void function: %s\n", func_names[i].c_str());
        void_functions[void_func_count] = func_ptr[i];
        void_func_names[void_func_count] = (char*)malloc(sizeof(char)*(func_names[i].size() + 1));
        strcpy(void_func_names[void_func_count],func_names[i].c_str());
        void_func_count++;
    }
}

void __metapro_register_int_function_cxx(std::string func_name, uint32_t func_number, std::vector<std::string> func_names, std::vector<int64_t (*)()> func_ptr) {
    for (size_t i = 0; i < func_number; i++) {
        if (int64_func_count >= MAX_FUNCTIONS) break; // Max limit
        int insert = 1;
        for (size_t j = 0; j < int64_func_count; j++) {
            if (strcmp(int64_func_names[j], func_names[i].c_str()) == 0) {
                // Already registered
                insert = 0;
                break;
            }
        }
        __metapro_table_insert_var_cxx(func_name, func_names[i], (const void*)func_ptr[i], sizeof(int64_t (*)()), __metapro_var_info::MetaproVarTypeFunctionInt, "");
        if (insert == 0) continue;
        WRITE_DEBUG_TO_FILE("Registering int function: %s\n", func_names[i].c_str());
        int64_functions[int64_func_count] = func_ptr[i];
        int64_func_names[int64_func_count] = (char*)malloc(sizeof(char)*(func_names[i].size() + 1));
        strcpy(int64_func_names[int64_func_count], func_names[i].c_str());
        int64_func_count++;
    }
}

void __metapro_register_uint_function_cxx(std::string func_name, uint32_t func_number, std::vector<std::string> func_names, std::vector<uint64_t (*)()> func_ptr) {
    for (size_t i = 0; i < func_number; i++) {
        if (uint64_func_count >= MAX_FUNCTIONS) break; // Max limit
        int insert = 1;
        for (size_t j = 0; j < uint64_func_count; j++) {
            if (strcmp(uint64_func_names[j], func_names[i].c_str()) == 0) {
                // Already registered
                insert = 0;
                break;
            }
        }
        __metapro_table_insert_var_cxx(func_name, func_names[i], (const void*)func_ptr[i], sizeof(uint64_t (*)()), __metapro_var_info::MetaproVarTypeFunctionUInt, "");
        if (insert == 0) continue;
        WRITE_DEBUG_TO_FILE("Registering uint function: %s\n", func_names[i].c_str());
        uint64_functions[uint64_func_count] = func_ptr[i];
        uint64_func_names[uint64_func_count] = (char*)malloc(sizeof(char)*(func_names[i].size() + 1));
        strcpy(uint64_func_names[uint64_func_count], func_names[i].c_str());
        uint64_func_count++;
    }
}

void __metapro_register_ptr_function_cxx(std::string func_name, uint32_t func_number, std::vector<std::string> func_names, std::vector<void* (*)()> func_ptr) {
    for (size_t i = 0; i < func_number; i++) {
        if (ptr_func_count >= MAX_FUNCTIONS) break; // Max limit
        int insert = 1;
        for (size_t j = 0; j < ptr_func_count; j++) {
            if (strcmp(ptr_func_names[j], func_names[i].c_str()) == 0) {
                // Already registered
                insert = 0;
                break;
            }
        }
        __metapro_table_insert_var_cxx(func_name, func_names[i], (const void*)func_ptr[i], sizeof(void* (*)()), __metapro_var_info::MetaproVarTypeFunctionPointer, "");
        if (insert == 0) continue;
        WRITE_DEBUG_TO_FILE("Registering pointer function: %s\n", func_names[i].c_str());
        ptr_functions[ptr_func_count] = func_ptr[i];
        ptr_func_names[ptr_func_count] = (char*)malloc(sizeof(char)*(func_names[i].size() + 1));
        strcpy(ptr_func_names[ptr_func_count], func_names[i].c_str());
        ptr_func_count++;
    }
}

/* Applying patches with shared memory */

struct PatchInfo {
  uint32_t id;
  char tmpl[30];
  char file[100];
  uint32_t line;
  char exprs[5][256];
  uint32_t expr_count;
}; // Patch information

PatchInfo* shm_patch_infos = nullptr;
uint32_t* shm_patch_count = nullptr;
int32_t shm_patch_infos_id = -1;
int32_t shm_patch_count_id = -1;

void init_shmems() {
    char* shm_patch_infos_id_str = getenv("FUZZ_PATCH_INFO_SHM_ID");
    char* shm_patch_count_id_str = getenv("FUZZ_PATCH_COUNT_SHM_ID");
    if (shm_patch_infos_id_str == nullptr || shm_patch_count_id_str == nullptr ||
        std::atoi(shm_patch_infos_id_str) == -1 || std::atoi(shm_patch_count_id_str) == -1) {
        return;
    }
    WRITE_DEBUG_TO_FILE("SHM IDs: infos=%s, count=%s\n", shm_patch_infos_id_str, shm_patch_count_id_str);

    shm_patch_infos_id = std::atoi(shm_patch_infos_id_str);
    shm_patch_count_id = std::atoi(shm_patch_count_id_str);
    shm_patch_infos = (PatchInfo*)shmat(shm_patch_infos_id, nullptr, 0);
    shm_patch_count = (uint32_t*)shmat(shm_patch_count_id, nullptr, 0);
}

// Constructor to initialize
__attribute__((constructor)) void init_runtime_lib() {
    // parse_record_info_cxx();
    // This is for debugging only
    // print_var_table();
    init_shmems();
}

/* helper functions */

bool __metapro_new_cond_cxx(uint64_t id, std::string funcName) {
    PatchInfo patch_info;
    if (shm_patch_infos_id != -1) {
        bool is_patch = false;
        for (uint32_t i = 0; i < *shm_patch_count; i++) {
            if (shm_patch_infos[i].id == id) {
                patch_info = shm_patch_infos[i];
                is_patch = true;
                break;
            }
        }
        if (!is_patch) {
            return false;
        }
    }
    else {
        char* patch_id=getenv("METAPRO_PATCH_ID");
        bool is_patch = false;
        if (patch_id==nullptr) {
            return false;
        }
        else {
            std::vector<std::string> ids = str_split(patch_id, ',');
            for (std::string id_str : ids) {
                if (std::stoul(id_str) == id) {
                    is_patch = true;
                    break;
                }
            }
            if (!is_patch) {
                return false;
            }
        }
    }
    WRITE_DEBUG_TO_FILE("New condition, ID: %" PRIu64 "\n", id);
    if (shm_patch_count != nullptr)
        WRITE_DEBUG_TO_FILE("# of patches in SHM: %" PRIu32 "\n", *shm_patch_count);

    // Apply patch
    if (!getenv("METAPRO_PATCH_MODE") || std::string(getenv("METAPRO_PATCH_MODE")) == "patch") {
        // Apply new condition
        std::string condition;
        if (shm_patch_infos_id != -1) {
            condition = std::string(patch_info.exprs[0]);
        }
        else {
            std::string condition_env_var("METAPRO_PATCH_COND_");
            condition_env_var += std::to_string(id);
            condition=std::string(getenv(condition_env_var.c_str()));
        }

        if (condition == "1") {
            WRITE_DEBUG_TO_FILE("New condition, expr: true\n");
            return true; // Always true
        }
        
        condition = "(" + condition + ")";

        // Find function variable info
        __metapro_function_var_info* func_var_info=nullptr;
        __metapro_get_func_var_info(funcName.c_str(), func_var_info);

        // Parse AST with tree-sitter
        TSParser *parser = ts_parser_new();
        ts_parser_set_language(parser, tree_sitter_cpp());
        TSTree *tree = ts_parser_parse_string(
            parser,
            nullptr,
            condition.c_str(),
            condition.length()
        );
        TSNode root_node = ts_tree_root_node(tree); // translation_unit
        root_node=ts_node_named_child(root_node,0); // expression_statement
        if (std::string(ts_node_type(root_node)) == "expression_statement") { // ERROR
            root_node=ts_node_named_child(root_node,0); // expression_statement
        }

        std::vector<TSNodeObject> node_obj_array;
        char* variables_temp[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, condition.c_str(), &var_count, variables_temp);
        // Copy arrays into vectors
        std::vector<std::string> variables;
        for (size_t i=0;i<var_count;i++) {
            variables.push_back(std::string(variables_temp[i]));
        }
        uint32_t ptr_elem_size = 0;

        for (std::string var_name : variables) {
            TSNodeObject node_obj;
            strcpy(node_obj.name, var_name.c_str());
            __metapro_var_info* cur_var;
            // Need for field expr
            std::vector<std::string> field_accesses;
            if (has_field_access(var_name)) {
                field_accesses = get_field_accesses(var_name);
                __metapro_get_var_value(funcName.c_str(), field_accesses[0], cur_var); // Get base struct variable
                field_accesses[0] = std::string(cur_var->struct_type_name);
            }
            else {
                __metapro_get_var_value(funcName.c_str(), var_name, cur_var);
                std::string ptr_type_name = funcName + "::" + var_name;
                VarSizeInfo* var_size_info = nullptr;
                HASH_FIND_STR(var_size_info_table, ptr_type_name.c_str(), var_size_info);
                if (var_size_info != nullptr) {
                    ptr_elem_size = var_size_info->size;
                }
            }
            if (cur_var != nullptr) {
                switch (cur_var->type) {
                    case __metapro_var_info::MetaproVarTypeInt:
                        node_obj.type=TSNodeObjectTypeInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.int64=*(int64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeUInt:
                        node_obj.type=TSNodeObjectTypeUInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.uint64=*(uint64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeDouble:
                        node_obj.type=TSNodeObjectTypeDouble;
                        node_obj.size=cur_var->size;
                        node_obj.value.double64=*(long double*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypePointer:
                    case __metapro_var_info::MetaproVarTypeArray:
                        node_obj.type=TSNodeObjectTypePointer;
                        node_obj.size=sizeof(void*);
                        // An array is registered as itself, so `ref` already is the elements; a pointer
                        // variable holds their address, which has to be read out of it
                        node_obj.value.pointer=(cur_var->type == __metapro_var_info::MetaproVarTypeArray)
                                ? (void*)(cur_var->ref) : *(void**)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        node_obj.array_element_size=ptr_elem_size;
                        break;
                    case __metapro_var_info::MetaproVarTypeStruct:
                    case __metapro_var_info::MetaproVarTypeStructPointer: {
                        if (field_accesses.size() == 0) {
                            // Just struct variable, not field access
                            node_obj.type=TSNodeObjectTypePointer;
                            node_obj.size=sizeof(void*);
                            node_obj.value.pointer=*(void**)(cur_var->ref);
                            node_obj.reference=(void*)(cur_var->ref);
                            node_obj.array_element_size=ptr_elem_size;
                        }
                        else {
                            // Get final field info
                            FieldInfo* final_field_info=get_final_field_info(field_accesses);
                            if (final_field_info == nullptr) {
                                PRINTF_ERROR("Failed to get final field type of struct variable: %s\n", var_name.c_str());
                            }
                            void* final_ref = get_final_field_reference(field_accesses, cur_var->ref);
                            if (std::string(final_field_info->type) == "int") {
                                node_obj.type=TSNodeObjectTypeInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.int64=*(int64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "uint") {
                                node_obj.type=TSNodeObjectTypeUInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.uint64=*(uint64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "double") {
                                node_obj.type=TSNodeObjectTypeDouble;
                                node_obj.size=final_field_info->size;
                                node_obj.value.double64=*(long double*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "ptr" || std::string(final_field_info->type) == "struct_ptr") {
                                node_obj.type=TSNodeObjectTypePointer;
                                node_obj.size=sizeof(void*);
                                node_obj.value.pointer=*(void**)final_ref;
                                node_obj.reference=final_ref;
                                node_obj.array_element_size=final_field_info->array_element_size;
                                break;
                            }
                        }
                    }
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionVoid:
                        node_obj.type = TSNodeObjectTypeFunctionVoid;
                        node_obj.size = sizeof(void (*)());
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionInt:
                        node_obj.type = TSNodeObjectTypeFunctionInt;
                        node_obj.size = sizeof(int64_t (*)(void));
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionUInt:
                        node_obj.type = TSNodeObjectTypeFunctionUInt;
                        node_obj.size = sizeof(uint64_t (*)(void));
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionPointer:
                        node_obj.type = TSNodeObjectTypeFunctionPointer;
                        node_obj.size = sizeof(void* (*)(void));
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    default: {
                        PRINTF_ERROR("Unsupported variable type in new condition: %d\n", cur_var->type);
                    }
                }
                node_obj_array.push_back(node_obj);
            }
        }
        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_array.size(),node_obj_array.data(),NULL);

        WRITE_DEBUG_TO_FILE("New condition, result: %" PRId64 "\n", result.value.int64);
        return result.value.int64 != 0 ? true : false;
    }

    return false;
}

bool __metapro_new_not_null_check_cxx(uint64_t id, std::string funcName) {
    PatchInfo patch_info;
    if (shm_patch_infos_id != -1) {
        bool is_patch = false;
        for (uint32_t i = 0; i < *shm_patch_count; i++) {
            if (shm_patch_infos[i].id == id) {
                patch_info = shm_patch_infos[i];
                is_patch = true;
                break;
            }
        }
        if (!is_patch) {
            return false;
        }
    }
    else {
        char* patch_id=getenv("METAPRO_PATCH_ID");
        bool is_patch = false;
        if (patch_id==nullptr) {
            return false;
        }
        else {
            std::vector<std::string> ids = str_split(patch_id, ',');
            uint32_t i = 0;
            for (std::string id_str : ids) {
                if (std::stoul(id_str) == id) {
                    is_patch = true;
                    break;
                }
                i++;
            }
            if (!is_patch) {
                return false;
            }
        }
    }
    WRITE_DEBUG_TO_FILE("New not null checker, ID: %" PRIu64 "\n", id);

    // patch
    if (!getenv("METAPRO_PATCH_MODE") || std::string(getenv("METAPRO_PATCH_MODE")) == "patch") {
        // Apply new condition
        std::string condition;
        if (shm_patch_infos_id != -1) {
            condition = std::string(patch_info.exprs[0]);
        }
        else {
            std::string condition_env_var("METAPRO_PATCH_NOT_NULL_CHECKER_EXPR_");
            condition_env_var += std::to_string(id);
            condition=std::string(getenv(condition_env_var.c_str()));
        }

        if (condition == "0") {
            WRITE_DEBUG_TO_FILE("Not null checker, expr: false\n");
            return false; // Always true
        }
        
        condition = "(" + condition + ")";

        // Find function variable info
        __metapro_function_var_info* func_var_info=nullptr;
        __metapro_get_func_var_info(funcName.c_str(), func_var_info);

        // Parse AST with tree-sitter
        TSParser *parser = ts_parser_new();
        ts_parser_set_language(parser, tree_sitter_cpp());
        TSTree *tree = ts_parser_parse_string(
            parser,
            nullptr,
            condition.c_str(),
            condition.length()
        );
        TSNode root_node = ts_tree_root_node(tree); // translation_unit
        root_node=ts_node_named_child(root_node,0); // expression_statement
        if (std::string(ts_node_type(root_node)) == "expression_statement") { // ERROR
            root_node=ts_node_named_child(root_node,0); // expression_statement
        }

        std::vector<TSNodeObject> node_obj_array;
        char* variables_temp[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, condition.c_str(), &var_count, variables_temp);
        // Copy arrays into vectors
        std::vector<std::string> variables;
        for (size_t i=0;i<var_count;i++) {
            variables.push_back(std::string(variables_temp[i]));
        }

        uint32_t ptr_elem_size = 0;
        for (std::string var_name : variables) {
            TSNodeObject node_obj;
            strcpy(node_obj.name, var_name.c_str());
            __metapro_var_info* cur_var;
            // Need for field expr
            std::vector<std::string> field_accesses;
            if (has_field_access(var_name)) {
                field_accesses = get_field_accesses(var_name);
                __metapro_get_var_value(funcName.c_str(), field_accesses[0], cur_var); // Get base struct variable
                field_accesses[0] = std::string(cur_var->struct_type_name);
            }
            else {
                __metapro_get_var_value(funcName.c_str(), var_name, cur_var);
                std::string ptr_type_name = funcName + "::" + var_name;
                VarSizeInfo* var_size_info = nullptr;
                HASH_FIND_STR(var_size_info_table, ptr_type_name.c_str(), var_size_info);
                if (var_size_info != nullptr) {
                    ptr_elem_size = var_size_info->size;
                }
            }
            if (cur_var != nullptr) {
                switch (cur_var->type) {
                    case __metapro_var_info::MetaproVarTypeInt:
                        node_obj.type=TSNodeObjectTypeInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.int64=*(int64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeUInt:
                        node_obj.type=TSNodeObjectTypeUInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.uint64=*(uint64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeDouble:
                        node_obj.type=TSNodeObjectTypeDouble;
                        node_obj.size=cur_var->size;
                        node_obj.value.double64=*(long double*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypePointer:
                    case __metapro_var_info::MetaproVarTypeArray:
                        node_obj.type=TSNodeObjectTypePointer;
                        node_obj.size=sizeof(void*);
                        // An array is registered as itself, so `ref` already is the elements; a pointer
                        // variable holds their address, which has to be read out of it
                        node_obj.value.pointer=(cur_var->type == __metapro_var_info::MetaproVarTypeArray)
                                ? (void*)(cur_var->ref) : *(void**)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        node_obj.array_element_size=ptr_elem_size;
                        break;
                    case __metapro_var_info::MetaproVarTypeStruct:
                    case __metapro_var_info::MetaproVarTypeStructPointer: {
                        if (field_accesses.size() == 0) {
                            // Just struct variable, not field access
                            node_obj.type=TSNodeObjectTypePointer;
                            node_obj.size=sizeof(void*);
                            node_obj.value.pointer=*(void**)(cur_var->ref);
                            node_obj.reference=(void*)(cur_var->ref);
                            node_obj.array_element_size=ptr_elem_size;
                        }
                        else {
                            // Get final field info
                            FieldInfo* final_field_info=get_final_field_info(field_accesses);
                            if (final_field_info == nullptr) {
                                PRINTF_ERROR("Failed to get final field type of struct variable: %s\n", var_name.c_str());
                            }
                            void* final_ref = get_final_field_reference(field_accesses, cur_var->ref);
                            if (std::string(final_field_info->type) == "int") {
                                node_obj.type=TSNodeObjectTypeInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.int64=*(int64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "uint") {
                                node_obj.type=TSNodeObjectTypeUInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.uint64=*(uint64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "double") {
                                node_obj.type=TSNodeObjectTypeDouble;
                                node_obj.size=final_field_info->size;
                                node_obj.value.double64=*(long double*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "ptr" || std::string(final_field_info->type) == "struct_ptr") {
                                node_obj.type=TSNodeObjectTypePointer;
                                node_obj.size=sizeof(void*);
                                node_obj.value.pointer=*(void**)final_ref;
                                node_obj.reference=final_ref;
                                node_obj.array_element_size=final_field_info->array_element_size;
                                break;
                            }
                        }
                    }
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionVoid:
                        node_obj.type = TSNodeObjectTypeFunctionVoid;
                        node_obj.size = sizeof(void (*)());
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionInt:
                        node_obj.type = TSNodeObjectTypeFunctionInt;
                        node_obj.size = sizeof(int64_t (*)(void));
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionUInt:
                        node_obj.type = TSNodeObjectTypeFunctionUInt;
                        node_obj.size = sizeof(uint64_t (*)(void));
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionPointer:
                        node_obj.type = TSNodeObjectTypeFunctionPointer;
                        node_obj.size = sizeof(void* (*)(void));
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    default: {
                        PRINTF_ERROR("Unsupported variable type in not null condition: %d\n", cur_var->type);
                    }
                }
                node_obj_array.push_back(node_obj);
            }
        }
        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_array.size(),node_obj_array.data(),NULL);

        WRITE_DEBUG_TO_FILE("New not null checker, result: %" PRId64 "\n", result.value.int64);
        return result.value.int64 != 0 ? true : false;
    }

    return true;
}

/**
 * Take the value of the `return` an interpreted patch executed, if this is the function it jumped into.
 *
 * The C runtime does the same, see take_interpreted_return() in _runtime_c.c: longjmp() carries the patch
 * id and nothing else, so the value waits in ts_interpreter_return_value (api.h) and is taken here, once.
 */
static int take_interpreted_return(uint64_t id, TSNodeObject* out) {
    if (ts_interpreter_return_value_id == 0) {
        return 0;
    }
    int is_mine = (ts_interpreter_return_value_id == (uint32_t)id);
    if (is_mine) {
        *out = ts_interpreter_return_value;
    }
    ts_interpreter_return_value_id = 0;
    return is_mine;
}

int64_t __metapro_get_int_var_cxx(uint64_t id, std::string funcName) {
    if (!getenv("METAPRO_PATCH_MODE") || std::string(getenv("METAPRO_PATCH_MODE")) == "patch") {
        TSNodeObject returned;
        if (take_interpreted_return(id, &returned)) {
            switch (returned.type.category) {
                case TSNodeObjectTypeInt:
                    return returned.value.int64;
                case TSNodeObjectTypeUInt:
                    return (int64_t)returned.value.uint64;
                case TSNodeObjectTypeDouble:
                    return (int64_t)returned.value.double64;
                case TSNodeObjectTypePointer:
                    return (int64_t)(intptr_t)returned.value.pointer;
                default:
                    PRINTF_ERROR("Unsupported type of an interpreted return: %d\n", returned.type.category);
            }
        }
        std::string var;
        if (shm_patch_infos_id != -1) {
            for (uint32_t i = 0; i < *shm_patch_count; i++) {
                if (shm_patch_infos[i].id == id) {
                    var = std::string(shm_patch_infos[i].exprs[1]);
                    break;
                }
            }
        }
        else {
            std::string var_env_var("METAPRO_EXPR_");
            var_env_var += std::to_string(id);
            var=std::string(getenv(var_env_var.c_str()));
        }

        __metapro_function_var_info* func_var_info=nullptr;
        __metapro_get_func_var_info(funcName.c_str(), func_var_info);

        // Prune prefix 'return '
        if (var.find("return ") == 0) {
            var = var.substr(7);
        }

        TSParser *parser = ts_parser_new();
        ts_parser_set_language(parser, tree_sitter_cpp());
        TSTree *tree = ts_parser_parse_string(
            parser,
            nullptr,
            var.c_str(),
            var.length()
        );
        TSNode root_node = ts_tree_root_node(tree); // translation_unit
        root_node=ts_node_named_child(root_node,0); // expression_statement
        if (std::string(ts_node_type(root_node)) == "expression_statement") { // ERROR
            root_node=ts_node_named_child(root_node,0); // expression_statement
        }

        std::vector<TSNodeObject> node_obj_array;
        char* variables_temp[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, var.c_str(), &var_count, variables_temp);
        // Copy arrays into vectors
        std::vector<std::string> variables;
        for (size_t i=0;i<var_count;i++) {
            variables.push_back(std::string(variables_temp[i]));
        }

        uint32_t ptr_elem_size = 0;
        for (std::string var_name : variables) {
            TSNodeObject node_obj;
            strcpy(node_obj.name, var_name.c_str());
            __metapro_var_info* cur_var;
            // Need for field expr
            std::vector<std::string> field_accesses;
            if (has_field_access(var_name)) {
                field_accesses = get_field_accesses(var_name);
                __metapro_get_var_value(funcName.c_str(), field_accesses[0], cur_var); // Get base struct variable
                field_accesses[0] = std::string(cur_var->struct_type_name);
            }
            else {
                __metapro_get_var_value(funcName.c_str(), var_name, cur_var);
                std::string ptr_type_name = funcName + "::" + var_name;
                VarSizeInfo* var_size_info = nullptr;
                HASH_FIND_STR(var_size_info_table, ptr_type_name.c_str(), var_size_info);
                if (var_size_info != nullptr) {
                    ptr_elem_size = var_size_info->size;
                }
            }
            if (cur_var != nullptr) {
                switch (cur_var->type) {
                    case __metapro_var_info::MetaproVarTypeInt:
                        node_obj.type=TSNodeObjectTypeInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.int64=*(int64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeUInt:
                        node_obj.type=TSNodeObjectTypeUInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.uint64=*(uint64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeDouble:
                        node_obj.type=TSNodeObjectTypeDouble;
                        node_obj.size=cur_var->size;
                        node_obj.value.double64=*(long double*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypePointer:
                    case __metapro_var_info::MetaproVarTypeArray:
                        node_obj.type=TSNodeObjectTypePointer;
                        node_obj.size=sizeof(void*);
                        // An array is registered as itself, so `ref` already is the elements; a pointer
                        // variable holds their address, which has to be read out of it
                        node_obj.value.pointer=(cur_var->type == __metapro_var_info::MetaproVarTypeArray)
                                ? (void*)(cur_var->ref) : *(void**)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        node_obj.array_element_size=ptr_elem_size;
                        break;
                    case __metapro_var_info::MetaproVarTypeStruct:
                    case __metapro_var_info::MetaproVarTypeStructPointer: {
                        if (field_accesses.size() == 0) {
                            // Just struct variable, not field access
                            node_obj.type=TSNodeObjectTypePointer;
                            node_obj.size=sizeof(void*);
                            node_obj.value.pointer=*(void**)(cur_var->ref);
                            node_obj.reference=(void*)(cur_var->ref);
                            node_obj.array_element_size=ptr_elem_size;
                        }
                        else {
                            // Get final field info
                            FieldInfo* final_field_info=get_final_field_info(field_accesses);
                            if (final_field_info == nullptr) {
                                PRINTF_ERROR("Failed to get final field type of struct variable: %s\n", var_name.c_str());
                            }
                            void* final_ref = get_final_field_reference(field_accesses, cur_var->ref);
                            if (std::string(final_field_info->type) == "int") {
                                node_obj.type=TSNodeObjectTypeInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.int64=*(int64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "uint") {
                                node_obj.type=TSNodeObjectTypeUInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.uint64=*(uint64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "double") {
                                node_obj.type=TSNodeObjectTypeDouble;
                                node_obj.size=final_field_info->size;
                                node_obj.value.double64=*(long double*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "ptr" || std::string(final_field_info->type) == "struct_ptr") {
                                node_obj.type=TSNodeObjectTypePointer;
                                node_obj.size=sizeof(void*);
                                node_obj.value.pointer=*(void**)final_ref;
                                node_obj.reference=final_ref;
                                node_obj.array_element_size=final_field_info->array_element_size;
                                break;
                            }
                        }
                    }
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionVoid:
                        node_obj.type = TSNodeObjectTypeFunctionVoid;
                        node_obj.size = sizeof(void (*)());
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionInt:
                        node_obj.type = TSNodeObjectTypeFunctionInt;
                        node_obj.size = sizeof(int64_t (*)(void));
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionUInt:
                        node_obj.type = TSNodeObjectTypeFunctionUInt;
                        node_obj.size = sizeof(uint64_t (*)(void));
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionPointer:
                        node_obj.type = TSNodeObjectTypeFunctionPointer;
                        node_obj.size = sizeof(void* (*)(void));
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    default: {
                        PRINTF_ERROR("Unsupported variable type in get int var: %d\n", cur_var->type);
                    }
                }
                node_obj_array.push_back(node_obj);
            }
        }
        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_array.size(),node_obj_array.data(),NULL);

        switch (result.type) {
            case TSNodeObjectTypeInt:
                WRITE_DEBUG_TO_FILE("Int variable, result: %" PRId64 "\n", result.value.int64);
                return result.value.int64;
            case TSNodeObjectTypeUInt:
                WRITE_DEBUG_TO_FILE("Int variable, result: %" PRIu64 "\n", result.value.uint64);
                return result.value.uint64;
            default: {
                PRINTF_ERROR("Unsupported type in get int var: %d\n", result.type);
            }
        }
    }
    PRINTF_ERROR("METAPRO_PATCH_MODE is not set or not in patch mode!\n");
    return 0;
}

uint64_t __metapro_get_uint_var_cxx(uint64_t id, std::string funcName) {
    if (!getenv("METAPRO_PATCH_MODE") || std::string(getenv("METAPRO_PATCH_MODE")) == "patch") {
        TSNodeObject returned;
        if (take_interpreted_return(id, &returned)) {
            switch (returned.type.category) {
                case TSNodeObjectTypeUInt:
                    return returned.value.uint64;
                case TSNodeObjectTypeInt:
                    return (uint64_t)returned.value.int64;
                case TSNodeObjectTypeDouble:
                    return (uint64_t)returned.value.double64;
                case TSNodeObjectTypePointer:
                    return (uint64_t)(uintptr_t)returned.value.pointer;
                default:
                    PRINTF_ERROR("Unsupported type of an interpreted return: %d\n", returned.type.category);
            }
        }
        std::string var;
        if (shm_patch_infos_id != -1) {
            for (uint32_t i = 0; i < *shm_patch_count; i++) {
                if (shm_patch_infos[i].id == id) {
                    var = std::string(shm_patch_infos[i].exprs[1]);
                    break;
                }
            }
        }
        else {
            std::string var_env_var("METAPRO_EXPR_");
            var_env_var += std::to_string(id);
            var=std::string(getenv(var_env_var.c_str()));
        }

        // Prune prefix 'return '
        if (var.find("return ") == 0) {
            var = var.substr(7);
        }

        __metapro_function_var_info* func_var_info=nullptr;
        __metapro_get_func_var_info(funcName.c_str(), func_var_info);

        TSParser *parser = ts_parser_new();
        ts_parser_set_language(parser, tree_sitter_cpp());
        TSTree *tree = ts_parser_parse_string(
            parser,
            nullptr,
            var.c_str(),
            var.length()
        );
        TSNode root_node = ts_tree_root_node(tree); // translation_unit
        root_node=ts_node_named_child(root_node,0); // expression_statement
        if (std::string(ts_node_type(root_node)) == "expression_statement") { // ERROR
            root_node=ts_node_named_child(root_node,0); // expression_statement
        }

        std::vector<TSNodeObject> node_obj_array;
        char* variables_temp[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, var.c_str(), &var_count, variables_temp);
        // Copy arrays into vectors
        std::vector<std::string> variables;
        for (size_t i=0;i<var_count;i++) {
            variables.push_back(std::string(variables_temp[i]));
        }

        uint32_t ptr_elem_size = 0;
        for (std::string var_name : variables) {
            TSNodeObject node_obj;
            strcpy(node_obj.name, var_name.c_str());
            __metapro_var_info* cur_var;
            // Need for field expr
            std::vector<std::string> field_accesses;
            if (has_field_access(var_name)) {
                field_accesses = get_field_accesses(var_name);
                __metapro_get_var_value(funcName.c_str(), field_accesses[0], cur_var); // Get base struct variable
                field_accesses[0] = std::string(cur_var->struct_type_name);
            }
            else {
                __metapro_get_var_value(funcName.c_str(), var_name, cur_var);
                std::string ptr_type_name = funcName + "::" + var_name;
                VarSizeInfo* var_size_info = nullptr;
                HASH_FIND_STR(var_size_info_table, ptr_type_name.c_str(), var_size_info);
                if (var_size_info != nullptr) {
                    ptr_elem_size = var_size_info->size;
                }
            }
            if (cur_var != nullptr) {
                switch (cur_var->type) {
                    case __metapro_var_info::MetaproVarTypeInt:
                        node_obj.type=TSNodeObjectTypeInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.int64=*(int64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeUInt:
                        node_obj.type=TSNodeObjectTypeUInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.uint64=*(uint64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeDouble:
                        node_obj.type=TSNodeObjectTypeDouble;
                        node_obj.size=cur_var->size;
                        node_obj.value.double64=*(long double*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypePointer:
                    case __metapro_var_info::MetaproVarTypeArray:
                        node_obj.type=TSNodeObjectTypePointer;
                        node_obj.size=sizeof(void*);
                        // An array is registered as itself, so `ref` already is the elements; a pointer
                        // variable holds their address, which has to be read out of it
                        node_obj.value.pointer=(cur_var->type == __metapro_var_info::MetaproVarTypeArray)
                                ? (void*)(cur_var->ref) : *(void**)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        node_obj.array_element_size=ptr_elem_size;
                        break;
                    case __metapro_var_info::MetaproVarTypeStruct:
                    case __metapro_var_info::MetaproVarTypeStructPointer: {
                        if (field_accesses.size() == 0) {
                            // Just struct variable, not field access
                            node_obj.type=TSNodeObjectTypePointer;
                            node_obj.size=sizeof(void*);
                            node_obj.value.pointer=*(void**)(cur_var->ref);
                            node_obj.reference=(void*)(cur_var->ref);
                            node_obj.array_element_size=ptr_elem_size;
                        }
                        else {
                            // Get final field info
                            FieldInfo* final_field_info=get_final_field_info(field_accesses);
                            if (final_field_info == nullptr) {
                                PRINTF_ERROR("Failed to get final field type of struct variable: %s\n", var_name.c_str());
                            }
                            void* final_ref = get_final_field_reference(field_accesses, cur_var->ref);
                            if (std::string(final_field_info->type) == "int") {
                                node_obj.type=TSNodeObjectTypeInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.int64=*(int64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "uint") {
                                node_obj.type=TSNodeObjectTypeUInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.uint64=*(uint64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "double") {
                                node_obj.type=TSNodeObjectTypeDouble;
                                node_obj.size=final_field_info->size;
                                node_obj.value.double64=*(long double*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "ptr" || std::string(final_field_info->type) == "struct_ptr") {
                                node_obj.type=TSNodeObjectTypePointer;
                                node_obj.size=sizeof(void*);
                                node_obj.value.pointer=*(void**)final_ref;
                                node_obj.reference=final_ref;
                                node_obj.array_element_size=final_field_info->array_element_size;
                                break;
                            }
                        }
                    }
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionVoid:
                        node_obj.type = TSNodeObjectTypeFunctionVoid;
                        node_obj.size = sizeof(void (*)());
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionInt:
                        node_obj.type = TSNodeObjectTypeFunctionInt;
                        node_obj.size = sizeof(int64_t (*)(void));
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionUInt:
                        node_obj.type = TSNodeObjectTypeFunctionUInt;
                        node_obj.size = sizeof(uint64_t (*)(void));
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionPointer:
                        node_obj.type = TSNodeObjectTypeFunctionPointer;
                        node_obj.size = sizeof(void* (*)(void));
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    default: {
                        PRINTF_ERROR("Unsupported variable type in get int var: %d\n", cur_var->type);
                    }
                }
                node_obj_array.push_back(node_obj);
            }
        }
        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_array.size(),node_obj_array.data(),NULL);

        switch (result.type) {
            case TSNodeObjectTypeInt:
                WRITE_DEBUG_TO_FILE("Unsigned int variable, result: %" PRId64 "\n", result.value.int64);
                return result.value.int64;
            case TSNodeObjectTypeUInt:
                WRITE_DEBUG_TO_FILE("Unsigned Int variable, result: %" PRIu64 "\n", result.value.uint64);
                return result.value.uint64;
            default: {
                PRINTF_ERROR("Unsupported type in get int var: %d\n", result.type);
            }
        }
    }
    PRINTF_ERROR("METAPRO_PATCH_MODE is not set or not in patch mode!\n");
    return 0;
}

void* __metapro_get_ptr_var_cxx(uint64_t id, std::string funcName) {
    if (!getenv("METAPRO_PATCH_MODE") || std::string(getenv("METAPRO_PATCH_MODE")) == "patch") {
        TSNodeObject returned;
        if (take_interpreted_return(id, &returned)) {
            switch (returned.type.category) {
                case TSNodeObjectTypePointer:
                    return returned.value.pointer;
                /* `return NULL` and `return 0` of a function returning a pointer are integers here */
                case TSNodeObjectTypeInt:
                    return (void*)(intptr_t)returned.value.int64;
                case TSNodeObjectTypeUInt:
                    return (void*)(uintptr_t)returned.value.uint64;
                default:
                    PRINTF_ERROR("Unsupported type of an interpreted return: %d\n", returned.type.category);
            }
        }
        std::string var;
        if (shm_patch_infos_id != -1) {
            for (uint32_t i = 0; i < *shm_patch_count; i++) {
                if (shm_patch_infos[i].id == id) {
                    var = std::string(shm_patch_infos[i].exprs[1]);
                    break;
                }
            }
        }
        else {
            std::string var_env_var("METAPRO_EXPR_");
            var_env_var += std::to_string(id);
            var=std::string(getenv(var_env_var.c_str()));
        }
        if (var == "NULL" || var == "nullptr" || var == "0")
            return nullptr;

        __metapro_function_var_info* func_var_info=nullptr;
        __metapro_get_func_var_info(funcName.c_str(), func_var_info);

        // Prune prefix 'return '
        if (var.find("return ") == 0) {
            var = var.substr(7);
        }

        TSParser *parser = ts_parser_new();
        ts_parser_set_language(parser, tree_sitter_cpp());
        TSTree *tree = ts_parser_parse_string(
            parser,
            nullptr,
            var.c_str(),
            var.length()
        );
        TSNode root_node = ts_tree_root_node(tree); // translation_unit
        root_node=ts_node_named_child(root_node,0); // expression_statement
        if (std::string(ts_node_type(root_node)) == "expression_statement") { // ERROR
            root_node=ts_node_named_child(root_node,0); // expression_statement
        }

        std::vector<TSNodeObject> node_obj_array;
        char* variables_temp[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, var.c_str(), &var_count, variables_temp);
        // Copy arrays into vectors
        std::vector<std::string> variables;
        for (size_t i=0;i<var_count;i++) {
            variables.push_back(std::string(variables_temp[i]));
        }

        uint32_t ptr_elem_size = 0;
        for (std::string var_name : variables) {
            TSNodeObject node_obj;
            strcpy(node_obj.name, var_name.c_str());
            __metapro_var_info* cur_var;
            // Need for field expr
            std::vector<std::string> field_accesses;
            if (has_field_access(var_name)) {
                field_accesses = get_field_accesses(var_name);
                __metapro_get_var_value(funcName.c_str(), field_accesses[0], cur_var); // Get base struct variable
                field_accesses[0] = std::string(cur_var->struct_type_name);
            }
            else {
                __metapro_get_var_value(funcName.c_str(), var_name, cur_var);
                std::string ptr_type_name = funcName + "::" + var_name;
                VarSizeInfo* var_size_info = nullptr;
                HASH_FIND_STR(var_size_info_table, ptr_type_name.c_str(), var_size_info);
                if (var_size_info != nullptr) {
                    ptr_elem_size = var_size_info->size;
                }
            }
            if (cur_var != nullptr) {
                switch (cur_var->type) {
                    case __metapro_var_info::MetaproVarTypeInt:
                        node_obj.type=TSNodeObjectTypeInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.int64=*(int64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeUInt:
                        node_obj.type=TSNodeObjectTypeUInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.uint64=*(uint64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeDouble:
                        node_obj.type=TSNodeObjectTypeDouble;
                        node_obj.size=cur_var->size;
                        node_obj.value.double64=*(long double*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypePointer:
                    case __metapro_var_info::MetaproVarTypeArray:
                        node_obj.type=TSNodeObjectTypePointer;
                        node_obj.size=sizeof(void*);
                        // An array is registered as itself, so `ref` already is the elements; a pointer
                        // variable holds their address, which has to be read out of it
                        node_obj.value.pointer=(cur_var->type == __metapro_var_info::MetaproVarTypeArray)
                                ? (void*)(cur_var->ref) : *(void**)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        node_obj.array_element_size=ptr_elem_size;
                        break;
                    case __metapro_var_info::MetaproVarTypeStruct:
                    case __metapro_var_info::MetaproVarTypeStructPointer: {
                        if (field_accesses.size() == 0) {
                            // Just struct variable, not field access
                            node_obj.type=TSNodeObjectTypePointer;
                            node_obj.size=sizeof(void*);
                            node_obj.value.pointer=*(void**)(cur_var->ref);
                            node_obj.reference=(void*)(cur_var->ref);
                            node_obj.array_element_size=ptr_elem_size;
                        }
                        else {
                            // Get final field info
                            FieldInfo* final_field_info=get_final_field_info(field_accesses);
                            if (final_field_info == nullptr) {
                                PRINTF_ERROR("Failed to get final field type of struct variable: %s\n", var_name.c_str());
                            }
                            void* final_ref = get_final_field_reference(field_accesses, cur_var->ref);
                            if (std::string(final_field_info->type) == "int") {
                                node_obj.type=TSNodeObjectTypeInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.int64=*(int64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "uint") {
                                node_obj.type=TSNodeObjectTypeUInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.uint64=*(uint64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "double") {
                                node_obj.type=TSNodeObjectTypeDouble;
                                node_obj.size=final_field_info->size;
                                node_obj.value.double64=*(long double*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "ptr" || std::string(final_field_info->type) == "struct_ptr") {
                                node_obj.type=TSNodeObjectTypePointer;
                                node_obj.size=sizeof(void*);
                                node_obj.value.pointer=*(void**)final_ref;
                                node_obj.reference=final_ref;
                                node_obj.array_element_size=final_field_info->array_element_size;
                                break;
                            }
                        }
                    }
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionVoid:
                        node_obj.type = TSNodeObjectTypeFunctionVoid;
                        node_obj.size = sizeof(void (*)());
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionInt:
                        node_obj.type = TSNodeObjectTypeFunctionInt;
                        node_obj.size = sizeof(int64_t (*)(void));
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionUInt:
                        node_obj.type = TSNodeObjectTypeFunctionUInt;
                        node_obj.size = sizeof(uint64_t (*)(void));
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionPointer:
                        node_obj.type = TSNodeObjectTypeFunctionPointer;
                        node_obj.size = sizeof(void* (*)(void));
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    default: {
                        PRINTF_ERROR("Unsupported variable type in get int var: %d\n", cur_var->type);
                    }
                }
                node_obj_array.push_back(node_obj);
            }
        }
        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_array.size(),node_obj_array.data(),NULL);

        WRITE_DEBUG_TO_FILE("Pointer variable, result: %p\n", result.value.pointer);
        return result.value.pointer;
    }
    PRINTF_ERROR("METAPRO_PATCH_MODE is not set or not in patch mode!\n");
    return 0;
}

bool __metapro_replace_cond_cxx(uint64_t id, std::string orig_cond_str, bool orig_cond, std::string funcName) {
    PatchInfo patch_info;
    if (shm_patch_infos_id != -1) {
        bool is_patch = false;
        for (uint32_t i = 0; i < *shm_patch_count; i++) {
            if (shm_patch_infos[i].id == id) {
                patch_info = shm_patch_infos[i];
                is_patch = true;
                break;
            }
        }
        if (!is_patch) {
            return orig_cond;
        }
    }
    else {
        char* patch_id=getenv("METAPRO_PATCH_ID");
        bool is_patch = false;
        if (patch_id==nullptr) {
            return orig_cond;
        }
        else {
            std::vector<std::string> ids = str_split(patch_id, ',');
            for (std::string id_str : ids) {
                if (std::stoul(id_str) == id) {
                    is_patch = true;
                    break;
                }
            }
            if (!is_patch) {
                return orig_cond;
            }
        }
    }
    WRITE_DEBUG_TO_FILE("Replace cond, ID: %" PRIu64 "\n", id);

    // patch
    if (!getenv("METAPRO_PATCH_MODE") || std::string(getenv("METAPRO_PATCH_MODE")) == "patch") {
        std::string patch_expr;
        std::string second_expr;
        if (shm_patch_infos_id != -1) {
            patch_expr = std::string(patch_info.exprs[0]);
            if (patch_info.expr_count > 1) {
                second_expr = std::string(patch_info.exprs[1]);
            }
            else {
                second_expr = "";
            }
        }
        else {
            std::string condition_env_var = "METAPRO_PATCH_COND_";
            condition_env_var += std::to_string(id) + "_1";
            patch_expr=std::string(getenv(condition_env_var.c_str()));
            condition_env_var = "METAPRO_PATCH_COND_";
            condition_env_var += std::to_string(id) + "_2";
            second_expr=std::string(getenv(condition_env_var.c_str()));
        }

        if (patch_expr == "1" || patch_expr == "true") {
            WRITE_DEBUG_TO_FILE("Replace cond, original: %s, to 'true'\n", orig_cond_str.c_str());
            return true; // Always true
        }
        else if (patch_expr == "0" || patch_expr == "false") {
            WRITE_DEBUG_TO_FILE("Replace cond, original: %s, to 'false'\n", orig_cond_str.c_str());
            return false; // Always false
        }
        else if (patch_expr == "!") {
            WRITE_DEBUG_TO_FILE("Replace cond, original: %s, negated\n", orig_cond_str.c_str());
            return !orig_cond; // Negate original condition
        }

        std::string temp_expr;
        if (patch_expr == "&&" || patch_expr == "||") {
            temp_expr = "(" + second_expr + ")";
        }
        else {
            temp_expr = "(" + patch_expr + ")";
        }

        __metapro_function_var_info* func_var_info=nullptr;
        __metapro_get_func_var_info(funcName.c_str(), func_var_info);
        
        TSParser *parser = ts_parser_new();
        ts_parser_set_language(parser, tree_sitter_cpp());
        TSTree *tree = ts_parser_parse_string(
            parser,
            nullptr,
            temp_expr.c_str(),
            temp_expr.length()
        );
        TSNode root_node = ts_tree_root_node(tree); // translation_unit
        root_node=ts_node_named_child(root_node,0); // expression_statement
        if (strcmp(ts_node_type(root_node),"expression_statement")!=0) { // ERROR
            root_node=ts_node_named_child(root_node,0); // expression_statement
        }

        std::vector<TSNodeObject> node_obj_array;
        char* variables_temp[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, temp_expr.c_str(), &var_count, variables_temp);
        // Copy arrays into vectors
        std::vector<std::string> variables;
        for (size_t i=0;i<var_count;i++) {
            variables.push_back(std::string(variables_temp[i]));
        }

        uint32_t ptr_elem_size = 0;
        for (std::string var_name : variables) {
            TSNodeObject node_obj;
            strcpy(node_obj.name, var_name.c_str());
            __metapro_var_info* cur_var;
            // Need for field expr
            std::vector<std::string> field_accesses;
            if (has_field_access(var_name)) {
                field_accesses = get_field_accesses(var_name);
                __metapro_get_var_value(funcName.c_str(), field_accesses[0], cur_var); // Get base struct variable
                field_accesses[0] = std::string(cur_var->struct_type_name);
            }
            else {
                __metapro_get_var_value(funcName.c_str(), var_name, cur_var);
                std::string ptr_type_name = funcName + "::" + var_name;
                VarSizeInfo* var_size_info = nullptr;
                HASH_FIND_STR(var_size_info_table, ptr_type_name.c_str(), var_size_info);
                if (var_size_info != nullptr) {
                    ptr_elem_size = var_size_info->size;
                }
            }
            if (cur_var != nullptr) {
                switch (cur_var->type) {
                    case __metapro_var_info::MetaproVarTypeInt:
                        node_obj.type=TSNodeObjectTypeInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.int64=*(int64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeUInt:
                        node_obj.type=TSNodeObjectTypeUInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.uint64=*(uint64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeDouble:
                        node_obj.type=TSNodeObjectTypeDouble;
                        node_obj.size=cur_var->size;
                        node_obj.value.double64=*(long double*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypePointer:
                    case __metapro_var_info::MetaproVarTypeArray:
                        node_obj.type=TSNodeObjectTypePointer;
                        node_obj.size=sizeof(void*);
                        // An array is registered as itself, so `ref` already is the elements; a pointer
                        // variable holds their address, which has to be read out of it
                        node_obj.value.pointer=(cur_var->type == __metapro_var_info::MetaproVarTypeArray)
                                ? (void*)(cur_var->ref) : *(void**)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        node_obj.array_element_size=ptr_elem_size;
                        break;
                    case __metapro_var_info::MetaproVarTypeStruct:
                    case __metapro_var_info::MetaproVarTypeStructPointer: {
                        if (field_accesses.size() == 0) {
                            // Just struct variable, not field access
                            node_obj.type=TSNodeObjectTypePointer;
                            node_obj.size=sizeof(void*);
                            node_obj.value.pointer=*(void**)(cur_var->ref);
                            node_obj.reference=(void*)(cur_var->ref);
                            node_obj.array_element_size=ptr_elem_size;
                        }
                        else {
                            // Get final field info
                            FieldInfo* final_field_info=get_final_field_info(field_accesses);
                            if (final_field_info == nullptr) {
                                PRINTF_ERROR("Failed to get final field type of struct variable: %s\n", var_name.c_str());
                            }
                            void* final_ref = get_final_field_reference(field_accesses, cur_var->ref);
                            if (std::string(final_field_info->type) == "int") {
                                node_obj.type=TSNodeObjectTypeInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.int64=*(int64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "uint") {
                                node_obj.type=TSNodeObjectTypeUInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.uint64=*(uint64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "double") {
                                node_obj.type=TSNodeObjectTypeDouble;
                                node_obj.size=final_field_info->size;
                                node_obj.value.double64=*(long double*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "ptr" || std::string(final_field_info->type) == "struct_ptr") {
                                node_obj.type=TSNodeObjectTypePointer;
                                node_obj.size=sizeof(void*);
                                node_obj.value.pointer=*(void**)final_ref;
                                node_obj.reference=final_ref;
                                node_obj.array_element_size=final_field_info->array_element_size;
                                break;
                            }
                        }
                    }
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionVoid:
                        node_obj.type = TSNodeObjectTypeFunctionVoid;
                        node_obj.size = sizeof(void (*)());
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionInt:
                        node_obj.type = TSNodeObjectTypeFunctionInt;
                        node_obj.size = sizeof(int64_t (*)(void));
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionUInt:
                        node_obj.type = TSNodeObjectTypeFunctionUInt;
                        node_obj.size = sizeof(uint64_t (*)(void));
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionPointer:
                        node_obj.type = TSNodeObjectTypeFunctionPointer;
                        node_obj.size = sizeof(void* (*)(void));
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    default: {
                        PRINTF_ERROR("Unsupported variable type in not null condition: %d\n", cur_var->type);
                    }
                }
                node_obj_array.push_back(node_obj);
            }
        }

        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_array.size(),node_obj_array.data(),NULL);

        if (second_expr != "") {
            if (second_expr == "&&") {
                // new && orig
                WRITE_DEBUG_TO_FILE("Replace cond, insert && before orig, original result: %" PRIu32 ", to %" PRId32 "\n",
                            orig_cond, result.value.int64 && orig_cond);
                return result.value.int64 && orig_cond;
            }
            else if (second_expr == "||") {
                // new || orig
                WRITE_DEBUG_TO_FILE("Replace cond, insert || before orig, original result: %" PRIu32 ", to %" PRId32 "\n",
                            orig_cond, result.value.int64 || orig_cond);
                return result.value.int64 || orig_cond;
            }
            else if (patch_expr == "&&") {
                // orig && new
                WRITE_DEBUG_TO_FILE("Replace cond, insert && after orig, original result: %" PRIu32 ", to %" PRId32 "\n",
                            orig_cond, orig_cond && result.value.int64);
                return orig_cond && result.value.int64;
            }
            else if (patch_expr == "||") {
                // orig || new
                WRITE_DEBUG_TO_FILE("Replace cond, insert || after orig, original result: %" PRIu32 ", to %" PRId32 "\n",
                            orig_cond, orig_cond || result.value.int64);
                return orig_cond || result.value.int64;
            }
            else {
                PRINTF_ERROR("Invalid second expr for replace cond: %s\n", second_expr.c_str());
            }
        }
        else {
            WRITE_DEBUG_TO_FILE("Replace cond, replace orig to new, original result: %" PRIu32 ", to %" PRId64 "\n",
                        orig_cond, result.value.int64);
            return result.value.int64;
        }
    }
    PRINTF_ERROR("Invalid patch expr, check patch json file!\n");
    return 0;
}

void __metapro_exec_expr_cxx(uint64_t id, std::string funcName, uint32_t jumpId) {
    /* No return of an earlier run is waiting to be taken: a run starts with none of its own */
    ts_interpreter_return_value_id = 0;
    PatchInfo patch_info;
    if (shm_patch_infos_id != -1) {
        bool is_patch = false;
        for (uint32_t i = 0; i < *shm_patch_count; i++) {
            if (shm_patch_infos[i].id == id) {
                patch_info = shm_patch_infos[i];
                is_patch = true;
                break;
            }
        }
        if (!is_patch) {
            return;
        }
    }
    else {
        char* patch_id=getenv("METAPRO_PATCH_ID");
        bool is_patch = false;
        if (patch_id==nullptr) {
            return;
        }
        else {
            std::vector<std::string> ids = str_split(patch_id, ',');
            for (std::string id_str : ids) {
                if (std::stoul(id_str) == id) {
                    is_patch = true;
                    break;
                }
            }
            if (!is_patch) {
                return;
            }
        }
    }
    WRITE_DEBUG_TO_FILE("Exec expr, ID: %" PRIu64 "\n", id);

    // Apply patch
    if (!getenv("METAPRO_PATCH_MODE") || std::string(getenv("METAPRO_PATCH_MODE")) == "patch") {
        // Apply new condition
        std::string expr;
        if (shm_patch_infos_id != -1) {
            expr = std::string(patch_info.exprs[0]);
        }
        else {
            std::string condition_env_var("METAPRO_EXPR_");
            condition_env_var += std::to_string(id);
            expr=std::string(getenv(condition_env_var.c_str()));
        }

        // Find function variable info
        __metapro_function_var_info* func_var_info=nullptr;
        __metapro_get_func_var_info(funcName.c_str(), func_var_info);

        // Parse AST with tree-sitter
        TSParser *parser = ts_parser_new();
        ts_parser_set_language(parser, tree_sitter_cpp());
        TSTree *tree = ts_parser_parse_string(
            parser,
            nullptr,
            expr.c_str(),
            expr.length()
        );
        TSNode root_node = ts_tree_root_node(tree); // translation_unit
        root_node=ts_node_named_child(root_node,0); // expression_statement
        if (std::string(ts_node_type(root_node)) == "expression_statement") { // ERROR
            root_node=ts_node_named_child(root_node,0); // expression_statement
        }

        std::vector<TSNodeObject> node_obj_array;
        char* variables_temp[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, expr.c_str(), &var_count, variables_temp);
        // Copy arrays into vectors
        std::vector<std::string> variables;
        for (size_t i=0;i<var_count;i++) {
            variables.push_back(std::string(variables_temp[i]));
        }

        uint32_t ptr_elem_size = 0;
        for (std::string var_name : variables) {
            TSNodeObject node_obj;
            strcpy(node_obj.name, var_name.c_str());
            __metapro_var_info* cur_var;
            // Need for field expr
            std::vector<std::string> field_accesses;
            if (has_field_access(var_name)) {
                field_accesses = get_field_accesses(var_name);
                __metapro_get_var_value(funcName.c_str(), field_accesses[0], cur_var); // Get base struct variable
                field_accesses[0] = std::string(cur_var->struct_type_name);
            }
            else {
                __metapro_get_var_value(funcName.c_str(), var_name, cur_var);
                std::string ptr_type_name = funcName + "::" + var_name;
                VarSizeInfo* var_size_info = nullptr;
                HASH_FIND_STR(var_size_info_table, ptr_type_name.c_str(), var_size_info);
                if (var_size_info != nullptr) {
                    ptr_elem_size = var_size_info->size;
                }
            }
            if (cur_var != nullptr) {
                switch (cur_var->type) {
                    case __metapro_var_info::MetaproVarTypeInt:
                        node_obj.type=TSNodeObjectTypeInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.int64=*(int64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeUInt:
                        node_obj.type=TSNodeObjectTypeUInt;
                        node_obj.size=cur_var->size;
                        node_obj.value.uint64=*(uint64_t*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeDouble:
                        node_obj.type=TSNodeObjectTypeDouble;
                        node_obj.size=cur_var->size;
                        node_obj.value.double64=*(long double*)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypePointer:
                    case __metapro_var_info::MetaproVarTypeArray:
                        node_obj.type=TSNodeObjectTypePointer;
                        node_obj.size=sizeof(void*);
                        // An array is registered as itself, so `ref` already is the elements; a pointer
                        // variable holds their address, which has to be read out of it
                        node_obj.value.pointer=(cur_var->type == __metapro_var_info::MetaproVarTypeArray)
                                ? (void*)(cur_var->ref) : *(void**)(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        node_obj.array_element_size=ptr_elem_size;
                        break;
                    case __metapro_var_info::MetaproVarTypeStruct:
                    case __metapro_var_info::MetaproVarTypeStructPointer: {
                        if (field_accesses.size() == 0) {
                            // Just struct variable, not field access
                            node_obj.type=TSNodeObjectTypePointer;
                            node_obj.size=sizeof(void*);
                            node_obj.value.pointer=*(void**)(cur_var->ref);
                            node_obj.reference=(void*)(cur_var->ref);
                            node_obj.array_element_size=ptr_elem_size;
                        }
                        else {
                            // Get final field info
                            FieldInfo* final_field_info=get_final_field_info(field_accesses);
                            if (final_field_info == nullptr) {
                                PRINTF_ERROR("Failed to get final field type of struct variable: %s\n", var_name.c_str());
                            }
                            void* final_ref = get_final_field_reference(field_accesses, cur_var->ref);
                            if (std::string(final_field_info->type) == "int") {
                                node_obj.type=TSNodeObjectTypeInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.int64=*(int64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "uint") {
                                node_obj.type=TSNodeObjectTypeUInt;
                                node_obj.size=final_field_info->size;
                                node_obj.value.uint64=*(uint64_t*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "double") {
                                node_obj.type=TSNodeObjectTypeDouble;
                                node_obj.size=final_field_info->size;
                                node_obj.value.double64=*(long double*)final_ref;
                                node_obj.reference=final_ref;
                                break;
                            }
                            else if (std::string(final_field_info->type) == "ptr" || std::string(final_field_info->type) == "struct_ptr") {
                                node_obj.type=TSNodeObjectTypePointer;
                                node_obj.size=sizeof(void*);
                                node_obj.value.pointer=*(void**)final_ref;
                                node_obj.reference=final_ref;
                                node_obj.array_element_size=final_field_info->array_element_size;
                                break;
                            }
                        }
                    }
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionVoid:
                        node_obj.type = TSNodeObjectTypeFunctionVoid;
                        node_obj.size = sizeof(void (*)());
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionInt:
                        node_obj.type = TSNodeObjectTypeFunctionInt;
                        node_obj.size = sizeof(int64_t (*)(void));
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionUInt:
                        node_obj.type = TSNodeObjectTypeFunctionUInt;
                        node_obj.size = sizeof(uint64_t (*)(void));
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    case __metapro_var_info::MetaproVarTypeFunctionPointer:
                        node_obj.type = TSNodeObjectTypeFunctionPointer;
                        node_obj.size = sizeof(void* (*)(void));
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=(void*)(cur_var->ref);
                        break;
                    default: {
                        PRINTF_ERROR("Unsupported variable type in Exec expr: %d\n", cur_var->type);
                    }
                }
                node_obj_array.push_back(node_obj);
            }
        }
                // Add control flow stmts in array
        TSNodeObject continue_obj;
        continue_obj.type = TSNodeObjectTypeJmpBuf;
        continue_obj.size = sizeof(jmp_buf);
        continue_obj.value.jmpbuf = &__metapro_continue_jmp_bufs[jumpId];
        continue_obj.reference = &__metapro_continue_jmp_bufs[jumpId];
        continue_obj.name = new char[10];
        sprintf(continue_obj.name, "continue");
        node_obj_array.push_back(continue_obj);

        TSNodeObject break_obj;
        break_obj.type = TSNodeObjectTypeJmpBuf;
        break_obj.size = sizeof(jmp_buf);
        break_obj.value.jmpbuf = &__metapro_break_jmp_bufs[jumpId];
        break_obj.reference = &__metapro_break_jmp_bufs[jumpId];
        break_obj.name = new char[7];
        sprintf(break_obj.name, "break");
        node_obj_array.push_back(break_obj);

        for (size_t i=0;i<__metapro_goto_jmp_count;i++) {
            TSNodeObject goto_obj;
            goto_obj.type = TSNodeObjectTypeJmpBuf;
            goto_obj.size = sizeof(jmp_buf);
            std::string name(__metapro_goto_jmp_names[i]);
            goto_obj.name = new char[7 + name.size()];
            sprintf(goto_obj.name, "goto %s", extract_label(name, funcName).c_str());
            goto_obj.value.jmpbuf = &__metapro_goto_jmps[i];
            goto_obj.reference = &__metapro_goto_jmps[i];
            node_obj_array.push_back(goto_obj);
        }

        TSNodeObject return_obj;
        return_obj.type = TSNodeObjectTypeJmpBuf;
        return_obj.size = sizeof(jmp_buf);
        return_obj.value.jmpbuf = &__metapro_find_return_label(funcName)->jmpbuf;
        return_obj.reference = &__metapro_find_return_label(funcName)->jmpbuf;
        return_obj.name = new char[8];
        sprintf(return_obj.name, "return");
        return_obj.array_element_size = id; // Use array_element_size to store ID for return, to distinguish with other jmps
        node_obj_array.push_back(return_obj);

        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_array.size(),node_obj_array.data(),NULL);
    }
}

long long __metapro_replace_int_var_cxx(unsigned long id,long long original,
                                    unsigned int int_var_count, std::vector<unsigned long long> int_var_sizes, std::vector<std::string> int_var_names, std::vector<long long> int_vars,
                                    unsigned int uint_var_count, std::vector<unsigned long long> uint_var_sizes, std::vector<std::string> uint_var_names, std::vector<unsigned long long> uint_vars) {
    char* patch_id=getenv("METAPRO_PATCH_ID");
    if (!patch_id) return original;
    else if (atoi(patch_id)==id) {
        if (getenv("METAPRO_PATCH_MODE")==nullptr || std::string(getenv("METAPRO_PATCH_MODE"))=="patch") {
            std::string expr(getenv("METAPRO_PATCH_EXPR_1"));

            for (size_t i=0;i<int_var_count;i++) {
                if (int_var_names[i]==expr) {
                    return int_vars[i];
                }
            }
            for (size_t i=0;i<uint_var_count;i++) {
                if (uint_var_names[i]==expr) {
                    return uint_vars[i];
                }
            }

            return std::stoll(expr);
        }
        else if (std::string(getenv("METAPRO_PATCH_MODE"))=="value") {
            // Write vector of variable values to file
            char* patch_file=getenv("METAPRO_PATCH_FILE");
            json root;
            std::ifstream ifs(patch_file);
            if (!ifs.good()) {
                root=json::array();
            }
            else {
                ifs >> root;
                ifs.close();
            }

            json cur_root=json::array();
            // Original value
            json original_value=json::object();
            original_value["name"]=getenv("METAPRO_ORIGINAL");
            original_value["value"]=original;
            original_value["size"]=sizeof(long long);
            original_value["type"]="int";
            cur_root.push_back(original_value);
            for (size_t i=0;i<int_var_count;i++) {
                // int vars
                json var=json::object();
                var["name"]=int_var_names[i];
                var["value"]=int_vars[i];
                var["size"]=int_var_sizes[i];
                var["type"]="int";
                cur_root.push_back(var);
            }
            for (size_t i=0;i<uint_var_count;i++) {
                // int vars
                json var=json::object();
                var["name"]=uint_var_names[i];
                var["value"]=uint_vars[i];
                var["size"]=uint_var_sizes[i];
                var["type"]="uint";
                cur_root.push_back(var);
            }
            root.push_back(cur_root);

            std::ofstream ofs(patch_file);
            ofs << std::setw(2) << root << std::endl;
            ofs.close();
        }
    }
    return original;
}

unsigned long long __metapro_replace_uint_var_cxx(unsigned long id, unsigned long long original,
                                    unsigned int int_var_count, std::vector<unsigned long long> int_var_sizes, std::vector<std::string> int_var_names, std::vector<long long> int_vars,
                                    unsigned int uint_var_count, std::vector<unsigned long long> uint_var_sizes, std::vector<std::string> uint_var_names, std::vector<unsigned long long> uint_vars) {
    char* patch_id=getenv("METAPRO_PATCH_ID");
    if (!patch_id) return original;
    else if (atoi(patch_id)==id) {
        if (getenv("METAPRO_PATCH_MODE")==nullptr || std::string(getenv("METAPRO_PATCH_MODE"))=="patch") {
            std::string expr(getenv("METAPRO_PATCH_EXPR_1"));

            for (size_t i=0;i<int_var_count;i++) {
                if (int_var_names[i]==expr) {
                    return int_vars[i];
                }
            }
            for (size_t i=0;i<uint_var_count;i++) {
                if (uint_var_names[i]==expr) {
                    return uint_vars[i];
                }
            }

            return std::stoll(expr);
        }
    }
    return original;
}

__metapro_int_func_type_cxx __metapro_replace_int_func_cxx(unsigned long id, __metapro_int_func_type_cxx orig_func,
                unsigned int func_number, std::vector<std::string> new_func_names, std::vector<__metapro_int_func_type_cxx> new_funcs) {
    char* patch_id=getenv("METAPRO_PATCH_ID");
    if (!patch_id) return orig_func;
    if (atoi(patch_id)!=id) return orig_func;

    std::string func_name(getenv("METAPRO_PATCH_EXPR_1"));
    for (size_t i=0;i<func_number;i++) {
        if (func_name==new_func_names[i]) {
            return new_funcs[i];
        }
    }
    PRINTF_ERROR("Invalid function name!\n");
}

__metapro_uint_func_type_cxx __metapro_replace_uint_func_cxx(unsigned long id, __metapro_uint_func_type_cxx orig_func,
                unsigned int func_number, std::vector<std::string> new_func_names, std::vector<__metapro_uint_func_type_cxx> new_funcs) {
    char* patch_id=getenv("METAPRO_PATCH_ID");
    if (!patch_id) return orig_func;
    if (atoi(patch_id)!=id) return orig_func;
    
    std::string func_name(getenv("METAPRO_PATCH_EXPR_1"));
    for (size_t i=0;i<func_number;i++) {
        if (func_name==new_func_names[i]) {
            return new_funcs[i];
        }
    }
    PRINTF_ERROR("Invalid function name!\n");
}

__metapro_void_func_type_cxx __metapro_replace_void_func_cxx(unsigned long id, __metapro_void_func_type_cxx orig_func,
                unsigned int func_number, std::vector<std::string> new_func_names, std::vector<__metapro_void_func_type_cxx> new_funcs) {
    char* patch_id=getenv("METAPRO_PATCH_ID");
    if (!patch_id) return orig_func;
    if (atoi(patch_id)!=id) return orig_func;

    std::string func_name(getenv("METAPRO_PATCH_EXPR_1"));
    for (size_t i=0;i<func_number;i++) {
        if (func_name==new_func_names[i]) {
            return new_funcs[i];
        }
    }
    PRINTF_ERROR("Invalid function name!\n");
}

const std::string __metapro_replace_string_literal_cxx(unsigned long id, const std::string orig_str) {
    char* patch_id=getenv("METAPRO_PATCH_ID");
    if (!patch_id) return orig_str;
    if (atoi(patch_id)!=id) return orig_str;

    return getenv("METAPRO_PATCH_EXPR_1");
}

int __metapro_env_to_int_cxx(const char* env) {
    char* cur_env=getenv(env);
    if(cur_env==nullptr) return -1;
    return atoi(cur_env);

}

void __metapro_mark_block_cxx(void) {}