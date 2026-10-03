#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <cjson/cJSON.h>
#include <sys/shm.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>

#include "tree_sitter/api.h"
#include "_runtime_c.h"

#define MAX_SIZE 10000

static int __metapro_is_target_function(const char* func_name);

/*
    METAPRO_DISABLE_CACHE=1 turns off the caches of this runtime, for an ablation study of what they save:
    the AST of a patch expression, the variable info of a function, the address of a callee, the symbol
    table of the program, and the parsed METAPRO_TARGET_FUNCTIONS / METAPRO_PATCH_ID lists. Everything
    is then computed again on every use; the results stay the same. Unset or any other value keeps them on.

    The switch itself is read once, so that it does not add a getenv() of its own to every use it guards.
*/
static int __metapro_cache_disabled(void) {
    static int disabled = -1;
    if (disabled < 0) {
        const char* env = getenv("METAPRO_DISABLE_CACHE");
        disabled = (env != NULL && strcmp(env, "1") == 0) ? 1 : 0;
    }
    return disabled;
}

/* Debug output file, opened once at startup (see init_runtime_lib) */
static FILE* __metapro_debug_file = NULL;

/* Output debugging to file (to debug in fuzzer) */
#define WRITE_DEBUG_TO_FILE(fmt, ...) do { \
    if (__metapro_debug_file != NULL) { \
        fprintf(__metapro_debug_file, fmt, ##__VA_ARGS__); \
        fflush(__metapro_debug_file); \
    } \
} while (0)

/* Print to debug file and stderr error msg and abort */
#define PRINTF_ERROR(fmt, ...) do { \
    WRITE_DEBUG_TO_FILE("ERROR: " fmt, ##__VA_ARGS__); \
    fprintf(stderr, "ERROR: " fmt, ##__VA_ARGS__); \
    abort(); \
} while (0)

/* Global variable to observe execution time (nanoseconds) */



typedef enum Type {
    INT,
    UINT,
    DOUBLE,
    PTR,
    LITERAL
} Type;

/* Jumps for continue, break and goto stmt */
jmp_buf __metapro_continue_jmp_bufs[50000]; // To handle continue
jmp_buf __metapro_break_jmp_bufs[50000]; // To handle break

char* __metapro_goto_jmp_names[50000]; // Goto labels
jmp_buf __metapro_goto_jmps[50000]; // Goto jmp_bufs
uint32_t __metapro_goto_jmp_count = 0; // Number of goto jmps

void __metapro_add_goto(char* jmp_label) {
    for (uint32_t i = 0; i < __metapro_goto_jmp_count; i++) {
        if (strcmp(__metapro_goto_jmp_names[i], jmp_label) == 0) {
            return;
        }
    }
    __metapro_goto_jmp_names[__metapro_goto_jmp_count] = malloc(sizeof(char) * (strlen(jmp_label) + 2));
    strcpy(__metapro_goto_jmp_names[__metapro_goto_jmp_count], jmp_label);
    __metapro_goto_jmp_count++;
}

uint32_t __metapro_find_goto_jmp(char* jmp_label) {
    for (uint32_t i = 0; i < __metapro_goto_jmp_count; i++) {
        if (strcmp(__metapro_goto_jmp_names[i], jmp_label) == 0) {
            return i;
        }
    }
    PRINTF_ERROR("Goto label not found: %s\n", jmp_label);
}

__metapro_return_label_info* __metapro_return_labels = NULL;
void __metapro_add_return(char* func_name) {
    // if (!__metapro_is_target_function(func_name)) return;
    // Dedup: if a label for this function is already registered, reuse it.
    // Without this, every function entry leaks a record and bloats the table.
    __metapro_return_label_info* existing = NULL;
    HASH_FIND_STR(__metapro_return_labels, func_name, existing);
    if (existing != NULL) return;
    __metapro_return_label_info* label_info = malloc(sizeof(__metapro_return_label_info));
    strcpy(label_info->func_name, func_name);
    HASH_ADD_STR(__metapro_return_labels, func_name, label_info);
    // WRITE_DEBUG_TO_FILE("Add new return jmp buf: %s, %p\n", func_name, &label_info->jmpbuf);
}

__metapro_return_label_info* __metapro_find_return_label(char* func_name) {
    __metapro_return_label_info* label_info;
    HASH_FIND_STR(__metapro_return_labels, func_name, label_info);
    if (label_info == NULL) {
        WRITE_DEBUG_TO_FILE("Return label not found for function: %s, may be not a primitive return type?\n", func_name);
    }
    return label_info;
}

TSLanguage *tree_sitter_c();

/* Utils */

/**
 * Split a string by a delimiter character.
 * 
 * It returns array of strings.
 * The last element is NULL to indicate the end.
 * 
 * This function will alloc new memories for each splitted strings and array itself.
 * Don't forget to free them.
 * 
 * Max size of the array is 10.
 * If more than 10 tokens, the rest will be ignored.
 * 
 * @param str string to split
 * @param delimiter delimiter
 * @return NULL-terminated array of strings
 */
__attribute__((unused))
static char** str_split(const char* str, char delimiter) {
    char** result = malloc(sizeof(char*) * (10 + 1));
    size_t count = 0;
    const char* start = str;
    const char* ptr = str;
    while (*ptr) {
        if (*ptr == delimiter) {
            size_t len = ptr - start;
            result[count] = malloc(len + 1);
            strncpy(result[count], start, len);
            result[count][len] = '\0';
            count++;
            start = ptr + 1;
        }
        ptr++;
    }
    // Last token
    if (start != ptr) {
        size_t len = ptr - start;
        result[count] = malloc(len + 1);
        strncpy(result[count], start, len);
        result[count][len] = '\0';
        count++;
    }
    result[count] = NULL; // NULL-terminate the array
    return result;
}

static char *extract_label(const char *str, const char *function_name) {
    char prefix[256];
    snprintf(prefix, sizeof(prefix), "__metapro_%s_", function_name);

    char *p = strstr(str, prefix);
    if (!p) return NULL;

    return p + strlen(prefix);  // points directly to label_name
}

/* For fuzzing, we use shared memory due to the performance issue. */
static void* __shm_addr = NULL;
static size_t __shm_size = 0;
static size_t __shm_offset = sizeof(size_t);

static void __store_state(uint64_t int_var_count, uint32_t* int_var_sizes, char** int_var_names, int64_t* int_vars,
                                    uint64_t uint_var_count, uint32_t* uint_var_sizes, char** uint_var_names, uint64_t* uint_vars,
                                    uint64_t double_var_count, uint32_t* double_var_sizes, char** double_var_names, long double* double_vars,
                                    uint64_t ptr_var_count, char** ptr_var_names, void** ptr_vars) {
    char *pac_reached_env = getenv("PAC_REACHED_ENV");
    if (pac_reached_env) {
        size_t id = (uint32_t)strtoul(pac_reached_env, NULL, 10);
        __shm_addr = shmat(id, NULL, 0);

        __shm_size++;
        memcpy(__shm_addr, &__shm_size, sizeof(size_t));
        memcpy(__shm_addr + __shm_offset, &int_var_count, sizeof(uint32_t));
        __shm_offset += sizeof(uint64_t);
        for (size_t i=0;i<int_var_count;i++) {
            memcpy(__shm_addr + __shm_offset, &int_vars[i], sizeof(int64_t));
            __shm_offset += sizeof(int64_t);
        }
        memcpy(__shm_addr + __shm_offset, &uint_var_count, sizeof(uint32_t));
        __shm_offset += sizeof(uint32_t);
        for (size_t i=0;i<uint_var_count;i++) {
            memcpy(__shm_addr + __shm_offset, &uint_vars[i], sizeof(uint64_t));
            __shm_offset += sizeof(uint64_t);
        }
        memcpy(__shm_addr + __shm_offset, &double_var_count, sizeof(uint32_t));
        __shm_offset += sizeof(uint32_t);
        for (size_t i=0;i<double_var_count;i++) {
            memcpy(__shm_addr + __shm_offset, &double_vars[i], sizeof(long double));
            __shm_offset += sizeof(long double);
        }
        memcpy(__shm_addr + __shm_offset, &ptr_var_count, sizeof(uint32_t));
        __shm_offset += sizeof(uint32_t);
        for (size_t i=0;i<ptr_var_count;i++) {
            unsigned int is_not_null = (ptr_vars[i] != NULL);
            memcpy(__shm_addr + __shm_offset, &is_not_null, sizeof(uint32_t));
            __shm_offset += sizeof(uint32_t);
        }
    }
}

/* Record and field stuffs */

__metapro_function_var_info* __metapro_var_info_tables = NULL;

/*
    TSRecordInfo and TSFieldInfo are declared in tree_sitter/api.h, together with record_info_table, which
    is defined by the interpreter. parse_record_info() below fills it, so the interpreter resolves a field
    expression from the same table.
*/

typedef struct VarSizeInfo {
    char var_name[100];
    uint32_t size;
    UT_hash_handle hh;
} VarSizeInfo;

VarSizeInfo* var_size_info_table = NULL;

/**
 * Read the entire content of a file.
 *
 * @param file_name path of the file to read
 * @return NUL-terminated content, or NULL if the file cannot be read. Free it when done.
 */
static char* read_file_content(const char* file_name) {
    FILE* file = fopen(file_name, "rt");
    if (file == NULL) {
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (file_size < 0) {
        fclose(file);
        return NULL;
    }
    char* file_content = (char*)malloc(file_size + 1);
    size_t read_size = fread(file_content, 1, file_size, file);
    file_content[read_size] = '\0'; // Text mode may read less than file_size
    fclose(file);
    return file_content;
}

/**
 * Copy a string into a fixed size field of a hash table record.
 *
 * @param dest field to copy into
 * @param dest_size size of the field, including the NUL
 * @param src string to copy, may be NULL
 * @return 0 if src is NULL or does not fit, 1 otherwise
 */
static int copy_to_field(char* dest, size_t dest_size, const char* src) {
    if (src == NULL || strlen(src) >= dest_size) {
        return 0;
    }
    strcpy(dest, src);
    return 1;
}

/* Directory metapro wrote its json files into, or NULL if not set */
static char* metapro_output_dir() {
    return getenv("METAPRO_OUTPUT_DIR");
}

static void parse_record_info() {
    char* metapro_dir = metapro_output_dir();
    if (metapro_dir == NULL) {
        return;
    }
    char patch_info_file_name[1024];
    snprintf(patch_info_file_name, sizeof(patch_info_file_name), "%s/struct-info.json", metapro_dir);

    char* file_content = read_file_content(patch_info_file_name);
    if (file_content == NULL) {
        return;
    }

    // Parse record info
    cJSON* info = cJSON_Parse(file_content);
    cJSON* record_info = cJSON_GetObjectItem(info, "struct");
    cJSON* record_obj = NULL;
    cJSON_ArrayForEach(record_obj, record_info) {
        // Create and add TSRecordInfo
        TSRecordInfo* record = malloc(sizeof(TSRecordInfo));
        strcpy(record->name, record_obj->string);
        record->field_count = 0;
        record->field_info_table = NULL;
        HASH_ADD_STR(record_info_table, name, record);

        // Iterate field info
        cJSON* field_info = NULL;
        cJSON_ArrayForEach(field_info, record_obj) {
            TSFieldInfo* field = malloc(sizeof(TSFieldInfo));
            memset(field, 0, sizeof(TSFieldInfo)); // Leaves a missing name empty instead of garbage
            strcpy(field->name, field_info->string);
            field->offset = cJSON_GetObjectItem(field_info, "offset")->valueint;
            field->size = cJSON_GetObjectItem(field_info, "size")->valueint;
            field->index = cJSON_GetObjectItem(field_info, "index")->valueint;
            const char* type_str = cJSON_GetObjectItem(field_info, "type")->valuestring;
            strcpy(field->type, type_str);
            cJSON* category = cJSON_GetObjectItem(field_info, "category");
            field->category = ts_interpreter_get_category_type((category != NULL) ? category->valuestring : NULL);
            cJSON* type_name = cJSON_GetObjectItem(field_info, "type_name");
            if (type_name != NULL) {
                copy_to_field(field->type_name, sizeof(field->type_name), type_name->valuestring);
            }
            if (cJSON_HasObjectItem(field_info, "struct_type")) {
                cJSON* struct_type_item = cJSON_GetObjectItem(field_info, "struct_type");
                if (struct_type_item != NULL) {
                    field->struct_type = malloc(strlen(struct_type_item->valuestring) + 1);
                    strcpy(field->struct_type, struct_type_item->valuestring);
                } else {
                    field->struct_type = malloc(1);
                    field->struct_type[0] = '\0';
                }
            }
            else {
                field->struct_type = malloc(1);
                field->struct_type[0] = '\0';
            }
            if (cJSON_HasObjectItem(field_info, "element_size")) {
                field->array_element_size = cJSON_GetObjectItem(field_info, "element_size")->valueint;
            } else {
                field->array_element_size = 0;
            }
            if (cJSON_HasObjectItem(field_info, "element_type")) {
                strcpy(field->array_element_type, cJSON_GetObjectItem(field_info, "element_type")->valuestring);
            } else field->array_element_type[0] = '\0';
            HASH_ADD_STR(record->field_info_table, name, field);
        }
    }

    // Parse var size info
    cJSON* var_size_info = cJSON_GetObjectItem(info, "type");
    cJSON* var_size_func_obj = NULL;
    cJSON_ArrayForEach(var_size_func_obj, var_size_info) {
        cJSON* var_size_obj = NULL;
        cJSON_ArrayForEach(var_size_obj, var_size_func_obj) {
            VarSizeInfo* var_size = malloc(sizeof(VarSizeInfo));
            sprintf(var_size->var_name, "%s::%s", var_size_func_obj->string, var_size_obj->string);
            var_size->size = cJSON_GetObjectItem(var_size_obj, "size")->valueint;
            HASH_ADD_STR(var_size_info_table, var_name, var_size);
            // printf("Added var size info: %s, size: %" PRIu32 "\n", var_size->var_name, var_size->size);
        }
    }
    cJSON_Delete(info);
    free(file_content);
}

/* Type and variable info stuffs */

#define MAX_VAR_NAME_SIZE 100
#define MAX_FUNC_NAME_SIZE 100
#define MAX_VAR_TYPE_NAME_SIZE 32 // Longest is MetaproVarTypeStructPointer

/* Function name the global variables are stored under, matching VarInformation */
#define GLOBAL_VARIABLE_SCOPE "global"

/**
 * Split the "<type>:<size>" descriptor a variable is registered with into its two parts.
 *
 * The descriptor of a struct or a struct pointer names a record of record_info_table, so the name has to
 * be taken without the size for the interpreter to find it.
 *
 * @param descriptor descriptor of __metapro_var_info::struct_type_name, may be empty
 * @param name out, name of the type. Empty if the descriptor has none
 * @param name_size size of name, including the NUL
 * @param size out, size of the type in bytes. 0 if the descriptor has none
 */
static void split_type_descriptor(const char* descriptor, char* name, size_t name_size, uint32_t* size) {
    name[0] = '\0';
    *size = 0;
    if (descriptor == NULL) {
        return;
    }
    const char* colon_ptr = strchr(descriptor, ':');
    if (colon_ptr == NULL) {
        copy_to_field(name, name_size, descriptor); // No size in the descriptor, keep it all as the name
        return;
    }

    size_t name_length = (size_t)(colon_ptr - descriptor);
    if (name_length >= name_size) {
        name_length = name_size - 1;
    }
    memcpy(name, descriptor, name_length);
    name[name_length] = '\0';
    *size = (uint32_t)atoi(colon_ptr + 1);
}

/*
    A single type of the program, from type-info.json. Unlike TSFieldInfo and VarSizeInfo, this describes a
    type itself instead of a field or a variable, so a type is stored once no matter how often it is used.

    TSTypeInfo is declared in tree_sitter/api.h, because this table is passed to the interpreter.
*/
TSTypeInfo* type_info_table = NULL;

/*
    The declared type of a single variable, from <function>-vars.json. This is the type the variable was
    declared with, not its value, which lives in the __metapro_var_info table.

    size, var_type and descriptor are the arguments __metapro_table_insert_var_c() is called with for this
    variable, so a lookup here answers exactly what the variable table holds, without searching it.
*/
typedef struct VarInfo {
    char name[MAX_VAR_NAME_SIZE]; // Key
    char type[TS_MAX_TYPE_NAME_SIZE]; // Name of a type of type_info_table
    TSNodeObjectType category; // Category of that type, repeated to save a lookup
    uint32_t size; // var_size
    char var_type[MAX_VAR_TYPE_NAME_SIZE]; // var_type, a MetaproVarType* enumerator
    char descriptor[TS_MAX_TYPE_NAME_SIZE]; // struct_type, empty if the variable has none
    UT_hash_handle hh;
} VarInfo;

/* The variables of one function. Global variables are stored under the function name "global" */
typedef struct FunctionVarInfo {
    char func_name[MAX_FUNC_NAME_SIZE]; // Key
    VarInfo* var_info_table; // Hashtable of VarInfo
    UT_hash_handle hh;
} FunctionVarInfo;

FunctionVarInfo* function_var_info_table = NULL;

/**
 * Parse every type of the program from <METAPRO_OUTPUT_DIR>/type-info.json into type_info_table.
 *
 * The whole file is parsed at once, at startup, because a type is looked up by name without knowing
 * which function asks for it.
 */
static void parse_type_info() {
    char* output_dir = metapro_output_dir();
    if (output_dir == NULL) {
        return;
    }

    size_t file_name_size = strlen(output_dir) + sizeof("/type-info.json");
    char* file_name = malloc(file_name_size);
    snprintf(file_name, file_name_size, "%s/type-info.json", output_dir);
    char* file_content = read_file_content(file_name);
    if (file_content == NULL) {
        WRITE_DEBUG_TO_FILE("Cannot read type info file: %s\n", file_name);
        free(file_name);
        return;
    }
    free(file_name);

    cJSON* types = cJSON_Parse(file_content);
    if (types == NULL) {
        WRITE_DEBUG_TO_FILE("Cannot parse type info file\n");
        free(file_content);
        return;
    }

    cJSON* type_obj = NULL;
    cJSON_ArrayForEach(type_obj, types) {
        cJSON* name = cJSON_GetObjectItem(type_obj, "type"); // TypeInformation stores the name as "type"
        if (name == NULL || name->valuestring == NULL) {
            continue;
        }

        // Anonymous structs of different files share one name, so keep the first one only
        TSTypeInfo* existing = NULL;
        HASH_FIND_STR(type_info_table, name->valuestring, existing);
        if (existing != NULL) {
            continue;
        }

        TSTypeInfo* type_info = malloc(sizeof(TSTypeInfo));
        memset(type_info, 0, sizeof(TSTypeInfo));
        if (!copy_to_field(type_info->name, sizeof(type_info->name), name->valuestring)) {
            WRITE_DEBUG_TO_FILE("Too long type name, skipped: %s\n", name->valuestring);
            free(type_info);
            continue;
        }
        cJSON* size = cJSON_GetObjectItem(type_obj, "size");
        type_info->size = (size != NULL) ? (uint32_t)size->valueint : 0;
        cJSON* category = cJSON_GetObjectItem(type_obj, "category");
        type_info->category = ts_interpreter_get_category_type((category != NULL) ? category->valuestring : NULL);
        /*
            Name of what a pointer points at or an array holds, which names another entry of this file.
            A type info written before metapro recorded it has none, and then the element stays unknown
            rather than being an error: the file is only rewritten when metapro runs again.
        */
        cJSON* element_type = cJSON_GetObjectItem(type_obj, "element_type");
        if (element_type != NULL && element_type->valuestring != NULL) {
            char* element_name = (char*)malloc(strlen(element_type->valuestring) + 1);
            strcpy(element_name, element_type->valuestring);
            type_info->element_name = element_name; // Owned by this table, which lives on
        }
        HASH_ADD_STR(type_info_table, name, type_info);
    }

    cJSON_Delete(types);
    free(file_content);
}

/**
 * Parse the variables of a single function from <METAPRO_OUTPUT_DIR>/variables/<func_name>-vars.json.
 *
 * Only the functions that are asked for are parsed, and each one is parsed once. A function without a
 * file is stored with an empty table too, so that a missing file is not opened again on every lookup.
 *
 * With the caches disabled, the file is parsed on every call instead, into a record that is not stored:
 * free it with free_var_info() once done with it.
 *
 * @param func_name name of the function, or "global" for the global variables
 * @return record of func_name, or NULL if its name is too long to store
 */
static FunctionVarInfo* parse_var_info(char* func_name) {
    FunctionVarInfo* func_var_info = NULL;
    if (!__metapro_cache_disabled()) {
        HASH_FIND_STR(function_var_info_table, func_name, func_var_info);
        if (func_var_info != NULL) {
            return func_var_info; // Already parsed
        }
    }

    func_var_info = malloc(sizeof(FunctionVarInfo));
    memset(func_var_info, 0, sizeof(FunctionVarInfo));
    if (!copy_to_field(func_var_info->func_name, sizeof(func_var_info->func_name), func_name)) {
        WRITE_DEBUG_TO_FILE("Too long function name, skipped: %s\n", func_name);
        free(func_var_info);
        return NULL;
    }
    func_var_info->var_info_table = NULL;
    if (!__metapro_cache_disabled()) {
        HASH_ADD_STR(function_var_info_table, func_name, func_var_info);
    }

    char* output_dir = metapro_output_dir();
    if (output_dir == NULL) {
        return func_var_info;
    }

    // VarInformation::store() replaces the characters that cannot be used in a file name
    char sanitized_name[MAX_FUNC_NAME_SIZE];
    for (size_t i = 0; i <= strlen(func_name); i++) {
        sanitized_name[i] = (func_name[i] == '/' || func_name[i] == ':') ? '#' : func_name[i];
    }

    size_t file_name_size = strlen(output_dir) + strlen(sanitized_name) + sizeof("/variables/-vars.json");
    char* file_name = malloc(file_name_size);
    snprintf(file_name, file_name_size, "%s/variables/%s-vars.json", output_dir, sanitized_name);
    char* file_content = read_file_content(file_name);
    if (file_content == NULL) {
        WRITE_DEBUG_TO_FILE("Cannot read variable info file: %s\n", file_name);
        free(file_name);
        return func_var_info;
    }
    free(file_name);

    cJSON* variables = cJSON_Parse(file_content);
    if (variables == NULL) {
        WRITE_DEBUG_TO_FILE("Cannot parse variable info file of function: %s\n", func_name);
        free(file_content);
        return func_var_info;
    }

    cJSON* var_obj = NULL;
    cJSON_ArrayForEach(var_obj, variables) {
        cJSON* name = cJSON_GetObjectItem(var_obj, "name");
        if (name == NULL || name->valuestring == NULL) {
            continue;
        }

        VarInfo* existing = NULL;
        HASH_FIND_STR(func_var_info->var_info_table, name->valuestring, existing);
        if (existing != NULL) {
            continue; // Already added
        }

        VarInfo* var_info = malloc(sizeof(VarInfo));
        memset(var_info, 0, sizeof(VarInfo));
        if (!copy_to_field(var_info->name, sizeof(var_info->name), name->valuestring)) {
            WRITE_DEBUG_TO_FILE("Too long variable name, skipped: %s\n", name->valuestring);
            free(var_info);
            continue;
        }
        cJSON* type = cJSON_GetObjectItem(var_obj, "type");
        if (type != NULL) {
            copy_to_field(var_info->type, sizeof(var_info->type), type->valuestring);
        }
        cJSON* category = cJSON_GetObjectItem(var_obj, "category");
        var_info->category = ts_interpreter_get_category_type((category != NULL) ? category->valuestring : NULL);
        cJSON* size = cJSON_GetObjectItem(var_obj, "size");
        var_info->size = (size != NULL) ? (uint32_t)size->valueint : 0;
        cJSON* var_type = cJSON_GetObjectItem(var_obj, "var_type");
        if (var_type != NULL) {
            copy_to_field(var_info->var_type, sizeof(var_info->var_type), var_type->valuestring);
        }
        // Absent when the variable is registered with no descriptor, which leaves it empty
        cJSON* descriptor = cJSON_GetObjectItem(var_obj, "descriptor");
        if (descriptor != NULL) {
            copy_to_field(var_info->descriptor, sizeof(var_info->descriptor), descriptor->valuestring);
        }
        HASH_ADD_STR(func_var_info->var_info_table, name, var_info);
    }

    cJSON_Delete(variables);
    free(file_content);
    return func_var_info;
}

/**
 * Find a type of the program by name.
 *
 * @param type_name name of the type, as stored in the "type" of a VarInfo
 * @return type info, or NULL if the type is unknown
 */
TSTypeInfo* __metapro_find_type_info(char* type_name) {
    TSTypeInfo* type_info = NULL;
    HASH_FIND_STR(type_info_table, type_name, type_info);
    return type_info;
}

/* Free a record of parse_var_info() that is not stored in function_var_info_table */
static void free_var_info(FunctionVarInfo* func_var_info) {
    if (func_var_info == NULL) {
        return;
    }
    VarInfo *var_info, *tmp;
    HASH_ITER(hh, func_var_info->var_info_table, var_info, tmp) {
        HASH_DEL(func_var_info->var_info_table, var_info);
        free(var_info);
    }
    free(func_var_info);
}

/* Look var_name up in the variables of one function, copying what is found into out */
static int find_var_in(char* func_name, char* var_name, VarInfo* out) {
    FunctionVarInfo* func_var_info = parse_var_info(func_name);
    VarInfo* var_info = NULL;
    if (func_var_info != NULL) {
        HASH_FIND_STR(func_var_info->var_info_table, var_name, var_info);
        if (var_info != NULL) {
            *out = *var_info;
        }
    }
    if (__metapro_cache_disabled()) {
        free_var_info(func_var_info); // Not stored, so the copy in out is all that is left of it
    }
    return var_info != NULL;
}

/**
 * Find the declared type of a variable of a function. Parses the file of the function on the first lookup.
 *
 * The variable table registers the globals of a function under the name of that function, while they are
 * stored once under "global", so a variable that func_name does not declare is looked up there. A local
 * of func_name is found first, the same way it shadows a global in the program itself.
 *
 * The info is copied out rather than pointed at, because with the caches disabled the record it is read
 * from is freed before this returns.
 *
 * @param func_name name of the function the variable is visible in
 * @param var_name name of the variable
 * @param out variable info, only written when this returns 1
 * @return 1 if the function or the globals have such a variable, 0 otherwise
 */
int __metapro_find_var_info(char* func_name, char* var_name, VarInfo* out) {
    if (find_var_in(func_name, var_name, out)) {
        return 1;
    }
    if (strcmp(func_name, GLOBAL_VARIABLE_SCOPE) == 0) {
        return 0; // The globals were just searched
    }
    return find_var_in(GLOBAL_VARIABLE_SCOPE, var_name, out);
}

/**
 * Type of a variable, named the way it is declared in the source code.
 *
 * The variable table only knows the category of a variable, so an int32_t and a char are both "int" there.
 * The name comes from the variable info instead, which keeps the declared name, e.g. "int32_t", "my_size_t"
 * or "char *", so that the type is a name of the type info as well.
 *
 * @param func_name name of the function the variable is visible in
 * @param var_name name of the variable
 * @param fallback_name name to use when the variable has no info, which happens for a field name, for a
 *                      function, or when metapro wrote no variable info at all
 * @param size size of the variable in bytes
 * @param category category of the variable
 * @return type of the variable
 */
static TSTypeInfo get_var_type_info(char* func_name, char* var_name, const char* fallback_name,
                                    uint32_t size, TSNodeObjectType category) {
    VarInfo var_info;
    int found = __metapro_find_var_info(func_name, var_name, &var_info);
    const char* type_name = (found && var_info.type[0] != '\0') ? var_info.type : fallback_name;
    return ts_interpreter_get_type_info(type_name, size, category);
}

void print_var_table() {
    TSRecordInfo* record_info, *record_tmp;
    TSFieldInfo *cur_record, *tmp;
    HASH_ITER(hh, record_info_table, record_info, record_tmp) {
        WRITE_DEBUG_TO_FILE("Record: %s, #: %u, addr: %p\n",record_info->name, HASH_COUNT(record_info->field_info_table), record_info->field_info_table);
        HASH_ITER(hh, record_info->field_info_table, cur_record, tmp) {
            WRITE_DEBUG_TO_FILE("  Name: %s, Type: %s, Size: %" PRIu32 ", Offset: %" PRIu32 ", Index: %" PRIu32 "\n",cur_record->name, cur_record->type, cur_record->size, cur_record->offset, cur_record->index);
        }
    }
}

void __metapro_table_remove_var_c(char* func_name, char* var_name) {
    if (!__metapro_is_target_function(func_name)) {
        return;
    }
    __metapro_function_var_info* func_var_info = NULL;
    HASH_FIND_STR(__metapro_var_info_tables, func_name, func_var_info);
    if (func_var_info == NULL) {
        return;
    }
    __metapro_var_info* var_top_info = func_var_info->var_info_table;
    __metapro_var_info* var_info = NULL;
    char var_name_buf[40];
    sprintf(var_name_buf, "%s-4", var_name);
    HASH_FIND_STR(var_top_info, var_name_buf, var_info);
    if (var_info != NULL) {
        HASH_DEL(var_top_info, var_info);
        free(var_info);
    }
    else {
        sprintf(var_name_buf, "%s-3", var_name);
        HASH_FIND_STR(var_top_info, var_name_buf, var_info);
        if (var_info != NULL) {
            HASH_DEL(var_top_info, var_info);
            free(var_info);
        }
        else {
            sprintf(var_name_buf, "%s-2", var_name);
            HASH_FIND_STR(var_top_info, var_name_buf, var_info);
            if (var_info != NULL) {
                HASH_DEL(var_top_info, var_info);
                free(var_info);
            }
            else {
                sprintf(var_name_buf, "%s-1", var_name);
                HASH_FIND_STR(var_top_info, var_name_buf, var_info);
                if (var_info != NULL) {
                    HASH_DEL(var_top_info, var_info);
                    free(var_info);
                }
                else {
                    sprintf(var_name_buf, "%s", var_name);
                    HASH_FIND_STR(var_top_info, var_name_buf, var_info);
                    if (var_info != NULL) {
                        HASH_DEL(var_top_info, var_info);
                        free(var_info);
                    }
                }
            }
        }
    }
}

void __metapro_print_var_table_c(char* funcName) {
    if (!__metapro_is_target_function(funcName)) return;
    __metapro_function_var_info* func_var_info=NULL;
    __metapro_var_info *cur_func, *tmp;
    __metapro_get_func_var_info(funcName, func_var_info);
    if (func_var_info==NULL) {
        printf("No variable table for function %s!\n",funcName);
        return;
    }
    printf("Variable table for function %s, #: %u, addr: %p\n",funcName, HASH_COUNT(func_var_info->var_info_table), func_var_info->var_info_table);
    HASH_ITER(hh, func_var_info->var_info_table, cur_func, tmp) {
        if (cur_func==NULL) 
            printf("  Null variable info!");
        else
            printf("  Name: %s, Type: %d, Size: %" PRIu32 ", Ref: %p\n",cur_func->name,cur_func->type,cur_func->size,cur_func->ref);
    }
}

/* Utility functions */

uint32_t get_var_size_from_type(char* type_name) {
    VarSizeInfo* var_size_info = NULL;
    HASH_FIND_STR(var_size_info_table, type_name, var_size_info);
    if (var_size_info != NULL) {
        return var_size_info->size;
    }
    return 0; // Not found
}

void __metapro_table_insert_var_c(char* func_name, char* var_name, const void* ref_ptr, uint32_t var_size, int var_type, char* struct_type) {
    if (!__metapro_is_target_function(func_name) || ref_ptr == NULL) {
        return;
    }
    __metapro_function_var_info* func_var_info = NULL;
    HASH_FIND_STR(__metapro_var_info_tables, func_name, func_var_info);
    if (func_var_info == NULL) {
        return;
    }
    __metapro_var_info* var_info = NULL;
    HASH_FIND_STR(func_var_info->var_info_table, var_name, var_info);
    int is_new = (var_info == NULL);
    if (is_new) {
        // New variable: allocate and key it once. An existing entry is updated
        // in place below, avoiding the free/malloc/rehash churn on the hot path.
        var_info = (struct __metapro_var_info*)malloc(sizeof(struct __metapro_var_info));
        strcpy(var_info->name, var_name);
    }
    var_info->ref=(const void*)ref_ptr;
    var_info->size=var_size;
    var_info->type=var_type;
    if (struct_type != NULL) {
        strcpy(var_info->struct_type_name, struct_type);
    } else {
        var_info->struct_type_name[0] = '\0';
    }
    if (is_new) {
        HASH_ADD_STR(func_var_info->var_info_table, name, var_info);
    }

    // Debug print (resolve the env var once instead of getenv() on every call)
    static int print_var_insert = -1;
    if (print_var_insert < 0) {
        char* e = getenv("METAPRO_DEBUG_PRINT_VAR_INSERT");
        print_var_insert = (e && strcmp(e, "1") == 0) ? 1 : 0;
    }
    if (print_var_insert) {
        WRITE_DEBUG_TO_FILE("# of variables in function %s: %u, addr: %p\n", func_name, HASH_COUNT(func_var_info->var_info_table), var_info);
        __metapro_var_info *cur_func, *tmp;
        HASH_ITER(hh, func_var_info->var_info_table, cur_func, tmp) {
            if (cur_func==NULL) 
                WRITE_DEBUG_TO_FILE("  Null variable info!");
            else
                WRITE_DEBUG_TO_FILE("  Name: %s, Type: %d, Size: %" PRIu32 ", Ref: %p\n",cur_func->name,cur_func->type,cur_func->size,cur_func->ref);
        }
    }
}

/* Cache of METAPRO_TARGET_FUNCTIONS: comma-separated list of function names
 * that should be instrumented. Parsed lazily on first query. If the env var
 * is unset or empty, no filtering is applied (all functions allowed). */
static char** __metapro_target_functions = NULL;
static size_t __metapro_target_function_count = 0;
static int __metapro_target_functions_parsed = 0;
static int __metapro_target_functions_filtering = 0;

static void __metapro_parse_target_functions(void) {
    if (__metapro_target_functions_parsed) {
        if (!__metapro_cache_disabled()) return;
        // Parse the list again, dropping the one of the previous query
        for (size_t i = 0; i < __metapro_target_function_count; i++) {
            free(__metapro_target_functions[i]);
        }
        free(__metapro_target_functions);
        __metapro_target_functions = NULL;
        __metapro_target_function_count = 0;
        __metapro_target_functions_filtering = 0;
    }
    __metapro_target_functions_parsed = 1;

    const char* env = getenv("METAPRO_TARGET_FUNCTIONS");
    if (env == NULL || *env == '\0') return; // No target functions specified, skip every functions
    if (strcmp(env, "all") == 0) {
        __metapro_target_functions_filtering = 2; // All functions are allowed
        return;
    }
    __metapro_target_functions_filtering = 1;

    size_t cap = 1;
    for (const char* p = env; *p; p++) {
        if (*p == ',') cap++;
    }
    __metapro_target_functions = (char**)malloc(cap * sizeof(char*));
    if (__metapro_target_functions == NULL) return;

    char* dup = strdup(env);
    if (dup == NULL) return;
    char* save = NULL;
    char* tok = strtok_r(dup, ",", &save);
    while (tok != NULL && __metapro_target_function_count < cap) {
        __metapro_target_functions[__metapro_target_function_count++] = strdup(tok);
        tok = strtok_r(NULL, ",", &save);
    }
    free(dup);
}

static int __metapro_is_target_function(const char* func_name) {
    __metapro_parse_target_functions();
    if (!__metapro_target_functions_filtering) return 0; // Ignore every functions
    if (__metapro_target_functions_filtering == 2) return 1; // All functions are allowed
    for (size_t i = 0; i < __metapro_target_function_count; i++) {
        if (strcmp(__metapro_target_functions[i], func_name) == 0) return 1;
    }
    return 0;
}

/* Cache of METAPRO_PATCH_ID: comma-separated list of patch IDs that are
 * active. The list is identical for every hook call in a run, so parse it once
 * (on the first query) into a uint32_t array and just scan the cache after.
 * This avoids the getenv + str_split (malloc/strtoul per element) churn that
 * previously ran on every hook invocation. Returns 1 if `id` is active, 0
 * otherwise (including when the env var is unset/empty). */
static uint32_t* __metapro_patch_ids = NULL;
static size_t __metapro_patch_id_count = 0;
static int __metapro_patch_ids_parsed = 0;

static int __metapro_is_patch_id(uint32_t id) {
    if (__metapro_patch_ids_parsed && __metapro_cache_disabled()) {
        // Parse the list again, dropping the one of the previous query
        free(__metapro_patch_ids);
        __metapro_patch_ids = NULL;
        __metapro_patch_id_count = 0;
        __metapro_patch_ids_parsed = 0;
    }
    if (!__metapro_patch_ids_parsed) {
        __metapro_patch_ids_parsed = 1;
        const char* env = getenv("METAPRO_PATCH_ID");
        if (env != NULL && *env != '\0') {
            size_t cap = 1;
            for (const char* p = env; *p; p++) {
                if (*p == ',') cap++;
            }
            __metapro_patch_ids = (uint32_t*)malloc(cap * sizeof(uint32_t));
            char* dup = (__metapro_patch_ids != NULL) ? strdup(env) : NULL;
            if (dup != NULL) {
                char* save = NULL;
                char* tok = strtok_r(dup, ",", &save);
                while (tok != NULL && __metapro_patch_id_count < cap) {
                    __metapro_patch_ids[__metapro_patch_id_count++] = (uint32_t)strtoul(tok, NULL, 10);
                    tok = strtok_r(NULL, ",", &save);
                }
                free(dup);
            }
        }
    }
    for (size_t i = 0; i < __metapro_patch_id_count; i++) {
        if (__metapro_patch_ids[i] == id) return 1;
    }
    return 0;
}

void __metapro_func_var_init_c(char* func_name) {
    if (!__metapro_is_target_function(func_name)) {
        return;
    }

    __metapro_function_var_info* func_var_info = NULL;
    HASH_FIND_STR(__metapro_var_info_tables, func_name, func_var_info);
    if (func_var_info != NULL) {
        // TODO: Now we just re-use same func info for recursive function call
        //       Add recursive call later (we need to found function exit point in this case)
        return;
        __metapro_func_var_clean(func_name);
    }
    func_var_info = (struct __metapro_function_var_info*)malloc(sizeof(struct __metapro_function_var_info));
    sprintf(func_var_info->func_id, "%s", func_name);
    func_var_info->var_info_table = NULL;
    HASH_ADD_STR(__metapro_var_info_tables, func_id, func_var_info);
}

void __metapro_remove_var_info_c(char* funcName, char* varName) {
    if (!__metapro_is_target_function(funcName)) return;
    __metapro_table_remove_var_c(funcName, varName);
}

/* Function info stuffs */

/*
    A function a patch expression may call, from function-info.json. The meta-program does not take the
    address of any function, so a callee is resolved by name while the expression is evaluated: a function
    this build does not have simply stays unresolved, instead of breaking the link of the meta-program.

    address is resolved once and then reused, and a name that resolves to nothing is remembered as well, so
    that each name costs one lookup per process.
*/
typedef struct FunctionInfo {
    char name[MAX_FUNC_NAME_SIZE]; // Key
    int var_type; // MetaproVarTypeFunction*, from the category of the return type
    void* address; // NULL until it is resolved, and when this process has no such function
    int resolved;
    UT_hash_handle hh;
} FunctionInfo;

static FunctionInfo* function_info_table = NULL;

/**
 * Parse every function of <METAPRO_OUTPUT_DIR>/function-info.json into function_info_table.
 *
 * Called from the constructor, like the record and type info, so that a program which forks to run its
 * inputs parses the file once instead of once per child.
 */
static void parse_function_info() {
    char* output_dir = metapro_output_dir();
    if (output_dir == NULL) {
        return;
    }

    size_t file_name_size = strlen(output_dir) + sizeof("/function-info.json");
    char* file_name = malloc(file_name_size);
    snprintf(file_name, file_name_size, "%s/function-info.json", output_dir);
    char* file_content = read_file_content(file_name);
    if (file_content == NULL) {
        WRITE_DEBUG_TO_FILE("Cannot read function info file: %s\n", file_name);
        free(file_name);
        return;
    }
    free(file_name);

    cJSON* functions = cJSON_Parse(file_content);
    if (functions == NULL) {
        WRITE_DEBUG_TO_FILE("Cannot parse function info file\n");
        free(file_content);
        return;
    }

    cJSON* function_obj = NULL;
    cJSON_ArrayForEach(function_obj, functions) {
        cJSON* category = cJSON_GetObjectItem(function_obj, "category");
        if (function_obj->string == NULL || category == NULL || category->valuestring == NULL) {
            continue;
        }
        int var_type;
        if (strcmp(category->valuestring, "int") == 0) var_type = MetaproVarTypeFunctionInt;
        else if (strcmp(category->valuestring, "uint") == 0) var_type = MetaproVarTypeFunctionUInt;
        else if (strcmp(category->valuestring, "ptr") == 0) var_type = MetaproVarTypeFunctionPointer;
        else if (strcmp(category->valuestring, "void") == 0) var_type = MetaproVarTypeFunctionVoid;
        else continue; // The interpreter has no result to hand back

        FunctionInfo* existing = NULL;
        HASH_FIND_STR(function_info_table, function_obj->string, existing);
        if (existing != NULL) {
            continue;
        }
        FunctionInfo* function_info = malloc(sizeof(FunctionInfo));
        memset(function_info, 0, sizeof(FunctionInfo));
        if (!copy_to_field(function_info->name, sizeof(function_info->name), function_obj->string)) {
            WRITE_DEBUG_TO_FILE("Too long function name, skipped: %s\n", function_obj->string);
            free(function_info);
            continue;
        }
        function_info->var_type = var_type;
        HASH_ADD_STR(function_info_table, name, function_info);
    }

    cJSON_Delete(functions);
    free(file_content);
}

/*
    Symbols of the program itself, read from its own file. dlsym() only searches dynamic symbols, so it
    cannot see a static function: its symbol is local, and no linker flag exports it. The table is built at
    most once per process and only when a name misses dlsym, because reading it costs about 20 ms on a
    program with tens of thousands of symbols.
*/
typedef struct LocalSymbol {
    char name[MAX_FUNC_NAME_SIZE]; // Key
    void* address;
    UT_hash_handle hh;
} LocalSymbol;

static LocalSymbol* local_symbol_table = NULL;
static int local_symbols_read = 0;

/* Load bias of the program: 0 for a non-PIE binary, the address it is mapped at for a PIE one */
static int read_load_bias(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    *(uintptr_t*)data = (uintptr_t)info->dlpi_addr; // The first object is the program itself
    return 1;                                       // Stop after it
}

static void read_local_symbols() {
    local_symbols_read = 1;

    uintptr_t load_bias = 0;
    dl_iterate_phdr(read_load_bias, &load_bias);

    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) {
        return;
    }
    struct stat file_stat;
    if (fstat(fd, &file_stat) != 0 || (size_t)file_stat.st_size < sizeof(Elf64_Ehdr)) {
        close(fd);
        return;
    }
    char* file = mmap(NULL, file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (file == MAP_FAILED) {
        return;
    }

    Elf64_Ehdr* header = (Elf64_Ehdr*)file;
    Elf64_Shdr* sections = (Elf64_Shdr*)(file + header->e_shoff);
    for (int i = 0; i < header->e_shnum; i++) {
        // .dynsym is what dlsym already searched, .symtab is what a stripped program does not have
        if (sections[i].sh_type != SHT_SYMTAB) continue;
        Elf64_Sym* symbols = (Elf64_Sym*)(file + sections[i].sh_offset);
        const char* strings = file + sections[sections[i].sh_link].sh_offset;
        for (size_t s = 0; s < sections[i].sh_size / sizeof(Elf64_Sym); s++) {
            if (ELF64_ST_TYPE(symbols[s].st_info) != STT_FUNC || symbols[s].st_value == 0) continue;
            const char* name = strings + symbols[s].st_name;
            LocalSymbol* existing = NULL;
            HASH_FIND_STR(local_symbol_table, name, existing);
            if (existing != NULL) {
                continue; // Two files may each define a static function of one name; keep the first
            }
            LocalSymbol* symbol = malloc(sizeof(LocalSymbol));
            memset(symbol, 0, sizeof(LocalSymbol));
            if (!copy_to_field(symbol->name, sizeof(symbol->name), name)) {
                free(symbol);
                continue;
            }
            symbol->address = (void*)(load_bias + symbols[s].st_value);
            HASH_ADD_STR(local_symbol_table, name, symbol);
        }
    }
    munmap(file, file_stat.st_size);
    WRITE_DEBUG_TO_FILE("Read %u symbols of the program itself\n", HASH_COUNT(local_symbol_table));
}

/* Address of a function of the program that dlsym cannot see, i.e. a static one */
static void* find_local_symbol(const char* name) {
    if (local_symbols_read && __metapro_cache_disabled()) {
        // Read the symbol table again, dropping the one of the previous miss
        LocalSymbol *symbol, *tmp;
        HASH_ITER(hh, local_symbol_table, symbol, tmp) {
            HASH_DEL(local_symbol_table, symbol);
            free(symbol);
        }
        local_symbols_read = 0;
    }
    if (!local_symbols_read) {
        read_local_symbols();
    }
    LocalSymbol* symbol = NULL;
    HASH_FIND_STR(local_symbol_table, name, symbol);
    return (symbol != NULL) ? symbol->address : NULL;
}

/*
    A global variable of the program that holds a function, e.g. libxml2's `xmlReallocFunc xmlRealloc`.

    Such a name is a callee of a patch expression like any other, but it is not a function of the program:
    nothing declares it in function-info.json and no symbol of that name exists, so it has to be registered.
    The meta-program does that at the entry of every function it instruments, see
    __metapro_register_func_ptrs_c(), and what is kept is the address *of the variable* rather than the
    function it holds today -- a program is free to replace it later (xmlMemSetup() does exactly that), and
    a call has to go to whatever it holds when the expression runs.
*/
typedef struct FuncPtrInfo {
    char name[MAX_FUNC_NAME_SIZE]; // Key: the name the expression spells
    void* const* ref;              // Address of the variable, dereferenced at every call
    int var_type;                  // MetaproVarTypeFunction*, from the category of the return type
    UT_hash_handle hh;
} FuncPtrInfo;

static FuncPtrInfo* func_ptr_info_table = NULL;

/* Fill `node_obj` with a callee of category `var_type` living at `address`. Shared by the two ways a
   callee is resolved: a function of the program, and a variable of the program holding one. */
static void bind_function_object(TSNodeObject* node_obj, int var_type, void* address) {
    switch (var_type) {
        case MetaproVarTypeFunctionInt:
            node_obj->type.category = TSNodeObjectTypeFunctionInt;
            node_obj->type.size = sizeof(int64_t (*)());
            node_obj->value.int_func = (int64_t (*)())address;
            break;
        case MetaproVarTypeFunctionUInt:
            node_obj->type.category = TSNodeObjectTypeFunctionUInt;
            node_obj->type.size = sizeof(uint64_t (*)());
            node_obj->value.uint_func = (uint64_t (*)())address;
            break;
        case MetaproVarTypeFunctionPointer:
            node_obj->type.category = TSNodeObjectTypeFunctionPointer;
            node_obj->type.size = sizeof(void* (*)());
            node_obj->value.pointer_func = (void* (*)())address;
            break;
        default:
            node_obj->type.category = TSNodeObjectTypeFunctionVoid;
            node_obj->type.size = sizeof(void (*)());
            node_obj->value.void_func = (void (*)())address;
            break;
    }
    node_obj->reference = address;
}

/* One group of the registration below: `count` variables of one return type, by name and by address. */
static void register_func_ptr_group(uint64_t count, char** names, void** refs, int var_type) {
    if (names == NULL || refs == NULL) {
        return;
    }
    for (uint64_t i = 0; i < count; i++) {
        if (names[i] == NULL || refs[i] == NULL) {
            continue;
        }
        FuncPtrInfo* existing = NULL;
        HASH_FIND_STR(func_ptr_info_table, names[i], existing);
        if (existing != NULL) {
            continue; // Registered by an earlier entry to this or another function
        }
        FuncPtrInfo* func_ptr = malloc(sizeof(FuncPtrInfo));
        if (func_ptr == NULL) {
            return;
        }
        memset(func_ptr, 0, sizeof(FuncPtrInfo));
        if (!copy_to_field(func_ptr->name, sizeof(func_ptr->name), names[i])) {
            WRITE_DEBUG_TO_FILE("Too long function pointer name, skipped: %s\n", names[i]);
            free(func_ptr);
            continue;
        }
        func_ptr->ref = (void* const*)refs[i];
        func_ptr->var_type = var_type;
        HASH_ADD_STR(func_ptr_info_table, name, func_ptr);
    }
}

__attribute__((force_align_arg_pointer))
void __metapro_register_func_ptrs_c(char* func_name,
        uint64_t void_count, char** void_names, void** void_refs,
        uint64_t int_count, char** int_names, void** int_refs,
        uint64_t uint_count, char** uint_names, void** uint_refs,
        uint64_t ptr_count, char** ptr_names, void** ptr_refs) {
    /* This runs at the entry of every instrumented function, so a function no patch targets pays only
       the name check -- the same guard the variable table registration uses */
    if (!__metapro_is_target_function(func_name)) {
        return;
    }
    register_func_ptr_group(void_count, void_names, void_refs, MetaproVarTypeFunctionVoid);
    register_func_ptr_group(int_count, int_names, int_refs, MetaproVarTypeFunctionInt);
    register_func_ptr_group(uint_count, uint_names, uint_refs, MetaproVarTypeFunctionUInt);
    register_func_ptr_group(ptr_count, ptr_names, ptr_refs, MetaproVarTypeFunctionPointer);
}

/**
 * Build the object of a callee of a patch expression, resolving its address by name.
 *
 * A global variable of the program holding a function comes first: it is registered with its own address
 * (see __metapro_register_func_ptrs_c) and read here, so a call goes to whatever it holds at that moment.
 *
 * Otherwise the name is a function of the program. dlsym() searches the program and every library loaded
 * with it, so it finds a function of the program itself as long as the meta-program is linked with
 * -rdynamic, and a function of a library either way. A static function has a local symbol that dlsym cannot
 * see and is looked up in the symbol table of the program instead. A function that is only declared, or that
 * the compiler never emitted at all, resolves to nothing and is left to the caller to skip.
 *
 * @param name name of the function, as the expression spells it
 * @param node_obj object to fill, untouched unless this returns 1
 * @return 1 if this process has such a function, 0 otherwise
 */
int __metapro_bind_function_c(const char* name, TSNodeObject* node_obj) {
    FuncPtrInfo* func_ptr = NULL;
    HASH_FIND_STR(func_ptr_info_table, name, func_ptr);
    if (func_ptr != NULL) {
        void* address = (func_ptr->ref != NULL) ? *(func_ptr->ref) : NULL;
        if (address == NULL) {
            WRITE_DEBUG_TO_FILE("Function pointer holds nothing: %s\n", name);
            return 0; // The program has not set it, so there is nothing to call
        }
        bind_function_object(node_obj, func_ptr->var_type, address);
        return 1;
    }

    FunctionInfo* function_info = NULL;
    HASH_FIND_STR(function_info_table, name, function_info);
    if (function_info == NULL) {
        return 0; // Not a function of the program, e.g. a variable that is not in scope here
    }
    if (!function_info->resolved || __metapro_cache_disabled()) {
        function_info->address = dlsym(RTLD_DEFAULT, function_info->name);
        if (function_info->address == NULL) {
            function_info->address = find_local_symbol(function_info->name); // A static function
        }
        function_info->resolved = 1;
        if (function_info->address == NULL) {
            WRITE_DEBUG_TO_FILE("Cannot resolve function: %s\n", function_info->name);
        }
    }
    if (function_info->address == NULL) {
        return 0;
    }

    bind_function_object(node_obj, function_info->var_type, function_info->address);
    return 1;
}

/* Applying patches with shared memory */

typedef struct PatchInfo {
  uint32_t id;
  char template[30];
  char file[100];
  uint32_t line;
  char exprs[5][256];
  uint32_t expr_count;
} PatchInfo; // Patch information

PatchInfo* shm_patch_infos = NULL;
uint32_t* shm_patch_count = NULL;
int32_t shm_patch_infos_id = -1;
int32_t shm_patch_count_id = -1;

void init_shmems() {
    char* shm_patch_infos_id_str = getenv("FUZZ_PATCH_INFO_SHM_ID");
    char* shm_patch_count_id_str = getenv("FUZZ_PATCH_COUNT_SHM_ID");
    if (shm_patch_infos_id_str == NULL || shm_patch_count_id_str == NULL ||
        atoi(shm_patch_infos_id_str) == -1 || atoi(shm_patch_count_id_str) == -1) {
        return;
    }
    WRITE_DEBUG_TO_FILE("SHM IDs: infos=%s, count=%s\n", shm_patch_infos_id_str, shm_patch_count_id_str);

    shm_patch_infos_id = atoi(shm_patch_infos_id_str);
    shm_patch_count_id = atoi(shm_patch_count_id_str);
    shm_patch_infos = (PatchInfo*)shmat(shm_patch_infos_id, NULL, 0);
    shm_patch_count = (uint32_t*)shmat(shm_patch_count_id, NULL, 0);
}

// Constructor to initialize
__attribute__((constructor)) void init_runtime_lib() {
    // Open the debug output file once at startup; the WRITE_DEBUG_TO_FILE macro
    // then just prints (and flushes) to this handle.
    char* debug_file_name = getenv("METAPRO_DEBUG_OUTPUT_FILE");
    if (debug_file_name != NULL) {
        __metapro_debug_file = fopen(debug_file_name, "w");
    }
    parse_record_info();
    parse_type_info();
    parse_function_info();
    // The interpreter resolves a callee of a patch expression through this, see api.h
    ts_interpreter_resolve_function = __metapro_bind_function_c;
    if (TS_NODE_COUNT_STMT_EXPR) {
        ts_node_init_stmt_expr_counter();
    }
    // Variable info is parsed lazily, per function, by __metapro_find_var_info()
    // This is for debugging only
    char* print_var_table_env = getenv("METAPRO_DEBUG_PRINT_VAR_TABLE");
    if (print_var_table_env && strcmp(print_var_table_env, "1") == 0) {
        print_var_table();
    }
    init_shmems();
}

/* Template a patch belongs to. A patch id is only unique within one of them, e.g. a NOT_NULL_CHECKER and
   an INSERT_EXPR of the same id both exist, so the template is part of the key of the cache below */
typedef enum PatchTemplate {
    PatchTemplateNewCondition,
    PatchTemplateNotNullChecker,
    PatchTemplateGetIntVar,
    PatchTemplateGetUIntVar,
    PatchTemplateGetPtrVar,
    PatchTemplateReplaceCondition,
    PatchTemplateInsertExpr
} PatchTemplate;

/*
    AST of the expression of a patch, parsed once and kept for every later execution of that patch.

    The tree is never deleted, because a TSNode points into the tree it came from and the values the
    interpreter reads with ts_node_find_value() live there too.
*/
typedef struct ParsedExpr {
    uint64_t key; // Patch id and template
    char* expr; // Expression the tree was parsed from, to notice that the patch has changed
    TSTree* tree;
    TSNode root_node;
    UT_hash_handle hh;
} ParsedExpr;

static ParsedExpr* parsed_expr_table = NULL;

/* Parse expr into a new tree, setting root_node to the node of the expression to execute */
static TSTree* parse_expr_tree(const char* expr, TSNode* root_node) {
    TSParser* parser = ts_parser_new();
    ts_parser_set_language(parser, tree_sitter_c());
    TSTree* tree = ts_parser_parse_string(parser, NULL, expr, strlen(expr));
    ts_parser_delete(parser); // Only the tree is needed from here on

    TSNode node = ts_tree_root_node(tree); // translation_unit
    node = ts_node_named_child(node, 0); // expression_statement
    if (strcmp(ts_node_type(node), "ERROR") == 0) { // ERROR
        node = ts_node_named_child(node, 0); // expression_statement
    }
    *root_node = node;
    return tree;
}

/**
 * Parse the expression of a patch, or take the AST parsed for it before.
 *
 * Parsing is the expensive part of running a patch, and the same patch runs again on every execution of
 * the instrumented code, so the tree of an expression is kept and reused.
 *
 * @param id id of the patch
 * @param patch_template template of the patch, which the id alone does not tell apart
 * @param expr expression to parse. The AST is parsed again when it differs from the cached one, which
 *             happens when the fuzzer replaces the expression of a patch in shared memory
 * @param owned_tree set to the tree of the returned node when the caches are disabled, which the caller
 *                   deletes with ts_tree_delete() after executing it; NULL when the tree is cached
 * @return node of the expression to execute
 */
static TSNode __metapro_get_parsed_expr(uint32_t id, PatchTemplate patch_template, const char* expr,
                                        TSTree** owned_tree) {
    *owned_tree = NULL;
    if (__metapro_cache_disabled()) {
        /* Parsed on every execution and never stored: a callee of the expression may run another patch,
           even this same one, so the tree cannot be dropped by the next parse, only by its own caller */
        TSNode root_node;
        *owned_tree = parse_expr_tree(expr, &root_node);
        return root_node;
    }

    uint64_t key = ((uint64_t)patch_template << 32) | (uint64_t)id;
    ParsedExpr* parsed = NULL;
    HASH_FIND(hh, parsed_expr_table, &key, sizeof(uint64_t), parsed);
    if (parsed != NULL) {
        if (strcmp(parsed->expr, expr) == 0) {
            return parsed->root_node; // Already parsed
        }
        // The expression of this patch changed, so the tree of the old one is of no use anymore
        HASH_DEL(parsed_expr_table, parsed);
        ts_tree_delete(parsed->tree);
        free(parsed->expr);
        free(parsed);
    }

    TSNode root_node;
    TSTree* tree = parse_expr_tree(expr, &root_node);

    parsed = (ParsedExpr*)malloc(sizeof(ParsedExpr));
    memset(parsed, 0, sizeof(ParsedExpr));
    parsed->key = key;
    parsed->expr = (char*)malloc(strlen(expr) + 1);
    strcpy(parsed->expr, expr);
    parsed->tree = tree;
    parsed->root_node = root_node;
    HASH_ADD(hh, parsed_expr_table, key, sizeof(uint64_t), parsed);
    return root_node;
}

/* Helper functions for meta-program.
   They would be called by target program. */
__attribute__((force_align_arg_pointer))
uint32_t __metapro_new_cond_c(uint32_t id, char* funcName) {
    PatchInfo patch_info;
    if (shm_patch_infos_id != -1) {
        int is_patch = 0;
        for (uint32_t i = 0; i < *shm_patch_count; i++) {
            if (shm_patch_infos[i].id == id) {
                patch_info = shm_patch_infos[i];
                is_patch = 1;
                break;
            }
        }
        if (!is_patch) {
            return 0;
        }
    }
    else {
        if (!__metapro_is_patch_id(id)) {
            return 0;
        }
    }

    // Apply patch
    if (!getenv("METAPRO_PATCH_MODE") || strcmp(getenv("METAPRO_PATCH_MODE"),"patch")==0) {
        // Apply new condition
        char* condition;
        if (shm_patch_infos_id != -1) {
            condition = patch_info.exprs[0];
        }
        else {
            char condition_env_var[100];
            sprintf(condition_env_var, "METAPRO_PATCH_COND_%" PRIu32, id);
            condition=getenv(condition_env_var);
            if (condition == NULL) {
                return 0;
            }
        }
        WRITE_DEBUG_TO_FILE("New condition, ID: %" PRIu32 "\n", id);
        if (shm_patch_count != NULL)
            WRITE_DEBUG_TO_FILE("# of patches in SHM: %" PRIu32 "\n", *shm_patch_count);

        if (strcmp(condition,"1")==0) {
            WRITE_DEBUG_TO_FILE("New condition, expr: 1\n");
            return 1; // Always true
        }
        
        char* temp=condition;
        condition=(char*)malloc(strlen(condition)+4);
        sprintf(condition,"(%s)",temp);

        // Find function variable info
        __metapro_function_var_info* func_var_info=NULL;
        __metapro_get_func_var_info(funcName, func_var_info);

        // Take the AST of this patch, parsing it only the first time it runs
        TSTree* uncached_tree;
        TSNode root_node = __metapro_get_parsed_expr(id, PatchTemplateNewCondition, condition, &uncached_tree);

        static TSNodeObject node_obj_array[MAX_SIZE];
        uint64_t node_obj_count=0;
        char* variables[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, condition, &var_count, variables);
        free(condition);
        uint32_t ptr_elem_size = 0;
        for (uint32_t i=0;i<var_count;i++) {
            TSNodeObject node_obj = {0}; // TSTypeInfo holds a name, so zero it instead of leaving garbage
            node_obj.name=variables[i];
            node_obj.array_element_type.size = 0;
            __metapro_var_info* cur_var;
            __metapro_get_var_value(funcName, variables[i], cur_var);
            char ptr_type_name[100];
            sprintf(ptr_type_name, "%s::%s", funcName, variables[i]);
            VarSizeInfo* var_size_info = NULL;
            HASH_FIND_STR(var_size_info_table, ptr_type_name, var_size_info);
            if (var_size_info != NULL) {
                ptr_elem_size = var_size_info->size;
            }
            if (cur_var != NULL) {
                switch (cur_var->type) {
                    case MetaproVarTypeInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "int", cur_var->size, TSNodeObjectTypeInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.int64 = *(int8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.int64 = *(int16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.int64 = *(int32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.int64 = *(int64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported int size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeUInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "uint", cur_var->size, TSNodeObjectTypeUInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.uint64 = *(uint8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.uint64 = *(uint16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.uint64 = *(uint32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.uint64 = *(uint64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported uint size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeDouble:
                        node_obj.type = get_var_type_info(funcName, variables[i], "double", cur_var->size, TSNodeObjectTypeDouble);
                        switch (cur_var->size) {
                            case 4:
                                node_obj.value.double64 = *(float*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.double64 = *(double*)(cur_var->ref);
                                break;
                            case 16:
                                node_obj.value.double64 = *(long double*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported double size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypePointer:
                    case MetaproVarTypeArray: {
                        // struct_type_name is the "<type>:<size>" descriptor of the pointee, or of the
                        // element when the variable is an array
                        char pointee_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t pointee_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, pointee_name, sizeof(pointee_name), &pointee_size);
                        TSNodeObjectType pointee_category = ts_interpreter_get_category_type(pointee_name);
                        if (pointee_category == TSNodeObjectTypeUnknown) {
                            WRITE_DEBUG_TO_FILE("Unknown pointee type: %s of %s\n", pointee_name, cur_var->name);
                        }
                        node_obj.array_element_type = ts_interpreter_get_type_info(pointee_name, pointee_size,
                                pointee_category);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        /* An array is as wide as all of its elements together, which is what a
                           `sizeof` of it answers; a pointer variable is one address wide */
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                (cur_var->type == MetaproVarTypeArray) ? cur_var->size : (uint32_t)sizeof(void*),
                                TSNodeObjectTypePointer);
                        // An array is registered as itself, so `ref` already is the elements: it is both
                        // the value of the pointer and the reference the interpreter subscripts off. A
                        // pointer variable holds the address instead, so that has to be read out of it.
                        node_obj.value.pointer = (cur_var->type == MetaproVarTypeArray)
                                ? (void*)cur_var->ref : *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStruct: {
                        // struct_type_name is the "<type>:<size>" descriptor, and the interpreter looks the
                        // record up by name, so the size has to be split off it
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.type = ts_interpreter_get_type_info(record_name, record_size, TSNodeObjectTypeStruct);
                        node_obj.value.pointer = (void*)cur_var->ref; // A struct is represented by its address
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStructPointer: {
                        // The descriptor of a struct pointer names the struct it points to, not the pointer
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.array_element_type = ts_interpreter_get_type_info(record_name, record_size,
                                TSNodeObjectTypeStruct);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                sizeof(void*), TSNodeObjectTypePointer);
                        node_obj.value.pointer = *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeFunctionVoid:
                        node_obj.type = ts_interpreter_get_type_info("void", sizeof(void (*)()), TSNodeObjectTypeFunctionVoid);
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionInt:
                        node_obj.type = ts_interpreter_get_type_info("int", sizeof(int64_t (*)(void)), TSNodeObjectTypeFunctionInt);
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionUInt:
                        node_obj.type = ts_interpreter_get_type_info("uint", sizeof(uint64_t (*)(void)), TSNodeObjectTypeFunctionUInt);
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionPointer: {
                        node_obj.type = ts_interpreter_get_type_info("pointer", sizeof(void* (*)(void)), TSNodeObjectTypeFunctionPointer);
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        /* struct_type_name of a pointer returning function is the type it returns a
                           pointer to, a plain name rather than a "<type>:<size>" descriptor. Resolving it
                           gives the call its element type, so the result can be subscripted and, for a
                           record, have its fields reached */
                        TSTypeInfo returned_type;
                        TSTypeInfo returned_element_type;
                        if (ts_interpreter_resolve_type(cur_var->struct_type_name, type_info_table,
                                                        &returned_type, &returned_element_type)) {
                            node_obj.array_element_type = returned_type;
                        }
                        break;
                    }
                    default: {
                        PRINTF_ERROR("Unsupported variable type in new condition: %d\n", cur_var->type);
                    }
                }
                node_obj_array[node_obj_count]=node_obj;
                node_obj_count++;
            }
        }
        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_count,node_obj_array,type_info_table);
        if (uncached_tree != NULL) ts_tree_delete(uncached_tree); // Parsed for this run only
        for (size_t i=0;i<var_count;i++) {
            free(variables[i]);
        }

        WRITE_DEBUG_TO_FILE("New condition, result: %" PRId64 "\n", result.value.int64);
        if (TS_NODE_COUNT_STMT_EXPR) ts_node_print_stmt_expr_counter();
        return result.value.int64;
    }

    return 0;
}

__attribute__((force_align_arg_pointer))
uint32_t __metapro_new_not_null_check_c(uint32_t id, char* funcName) {
    PatchInfo patch_info;
    if (shm_patch_infos_id != -1) {
        int is_patch = 0;
        for (uint32_t i = 0; i < *shm_patch_count; i++) {
            if (shm_patch_infos[i].id == id) {
                is_patch = 1;
                patch_info = shm_patch_infos[i];
                break;
            }
        }
        if (!is_patch) {
            return 1;
        }
    }
    else {
        if (!__metapro_is_patch_id(id)) {
            return 1;
        }
    }

    // patch
    if (!getenv("METAPRO_PATCH_MODE") || strcmp(getenv("METAPRO_PATCH_MODE"),"patch")==0) {
        // Apply new condition
        char* condition;
        if (shm_patch_infos_id != -1) {
            condition = patch_info.exprs[0];
        }
        else {
            char condition_env_var[300];
            sprintf(condition_env_var, "METAPRO_PATCH_NOT_NULL_CHECKER_EXPR_%" PRIu32, id);
            condition=getenv(condition_env_var);
            if (condition == NULL) {
                return 1; // Different patch template, just return original value (always 1)
            }
        }
        WRITE_DEBUG_TO_FILE("New not null checker, ID: %" PRIu32 "\n", id);

        if (strcmp(condition,"0")==0) {
            WRITE_DEBUG_TO_FILE("New not null checker, result: 0\n");
            return 0; // Always false
        }
        
        char* temp=condition;
        condition=(char *)malloc(strlen(condition)+4);
        sprintf(condition,"(%s)",temp);

        __metapro_function_var_info* func_var_info=NULL;
        __metapro_get_func_var_info(funcName, func_var_info);

        // Take the AST of this patch, parsing it only the first time it runs
        TSTree* uncached_tree;
        TSNode root_node = __metapro_get_parsed_expr(id, PatchTemplateNotNullChecker, condition, &uncached_tree);

        static TSNodeObject node_obj_array[MAX_SIZE];
        uint64_t node_obj_count=0;
        char* variables[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, condition, &var_count, variables);
        free(condition);
        uint32_t ptr_elem_size = 0;
        for (uint32_t i=0;i<var_count;i++) {
            TSNodeObject node_obj = {0}; // TSTypeInfo holds a name, so zero it instead of leaving garbage
            node_obj.name=variables[i];
            node_obj.array_element_type.size = 0;
            __metapro_var_info* cur_var;
            __metapro_get_var_value(funcName, variables[i], cur_var);
            char ptr_type_name[100];
            sprintf(ptr_type_name, "%s::%s", funcName, variables[i]);
            VarSizeInfo* var_size_info = NULL;
            HASH_FIND_STR(var_size_info_table, ptr_type_name, var_size_info);
            if (var_size_info != NULL) {
                ptr_elem_size = var_size_info->size;
            }
            if (cur_var != NULL) {
                switch (cur_var->type) {
                    case MetaproVarTypeInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "int", cur_var->size, TSNodeObjectTypeInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.int64 = *(int8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.int64 = *(int16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.int64 = *(int32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.int64 = *(int64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported int size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeUInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "uint", cur_var->size, TSNodeObjectTypeUInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.uint64 = *(uint8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.uint64 = *(uint16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.uint64 = *(uint32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.uint64 = *(uint64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported uint size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeDouble:
                        node_obj.type = get_var_type_info(funcName, variables[i], "double", cur_var->size, TSNodeObjectTypeDouble);
                        switch (cur_var->size) {
                            case 4:
                                node_obj.value.double64 = *(float*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.double64 = *(double*)(cur_var->ref);
                                break;
                            case 16:
                                node_obj.value.double64 = *(long double*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported double size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypePointer:
                    case MetaproVarTypeArray: {
                        // struct_type_name is the "<type>:<size>" descriptor of the pointee, or of the
                        // element when the variable is an array
                        char pointee_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t pointee_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, pointee_name, sizeof(pointee_name), &pointee_size);
                        TSNodeObjectType pointee_category = ts_interpreter_get_category_type(pointee_name);
                        if (pointee_category == TSNodeObjectTypeUnknown) {
                            WRITE_DEBUG_TO_FILE("Unknown pointee type: %s of %s\n", pointee_name, cur_var->name);
                        }
                        node_obj.array_element_type = ts_interpreter_get_type_info(pointee_name, pointee_size,
                                pointee_category);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        /* An array is as wide as all of its elements together, which is what a
                           `sizeof` of it answers; a pointer variable is one address wide */
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                (cur_var->type == MetaproVarTypeArray) ? cur_var->size : (uint32_t)sizeof(void*),
                                TSNodeObjectTypePointer);
                        // An array is registered as itself, so `ref` already is the elements: it is both
                        // the value of the pointer and the reference the interpreter subscripts off. A
                        // pointer variable holds the address instead, so that has to be read out of it.
                        node_obj.value.pointer = (cur_var->type == MetaproVarTypeArray)
                                ? (void*)cur_var->ref : *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStruct: {
                        // struct_type_name is the "<type>:<size>" descriptor, and the interpreter looks the
                        // record up by name, so the size has to be split off it
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.type = ts_interpreter_get_type_info(record_name, record_size, TSNodeObjectTypeStruct);
                        node_obj.value.pointer = (void*)cur_var->ref; // A struct is represented by its address
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStructPointer: {
                        // The descriptor of a struct pointer names the struct it points to, not the pointer
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.array_element_type = ts_interpreter_get_type_info(record_name, record_size,
                                TSNodeObjectTypeStruct);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                sizeof(void*), TSNodeObjectTypePointer);
                        node_obj.value.pointer = *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeFunctionVoid:
                        node_obj.type = ts_interpreter_get_type_info("void", sizeof(void (*)()), TSNodeObjectTypeFunctionVoid);
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionInt:
                        node_obj.type = ts_interpreter_get_type_info("int", sizeof(int64_t (*)(void)), TSNodeObjectTypeFunctionInt);
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionUInt:
                        node_obj.type = ts_interpreter_get_type_info("uint", sizeof(uint64_t (*)(void)), TSNodeObjectTypeFunctionUInt);
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionPointer: {
                        node_obj.type = ts_interpreter_get_type_info("pointer", sizeof(void* (*)(void)), TSNodeObjectTypeFunctionPointer);
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        /* struct_type_name of a pointer returning function is the type it returns a
                           pointer to, a plain name rather than a "<type>:<size>" descriptor. Resolving it
                           gives the call its element type, so the result can be subscripted and, for a
                           record, have its fields reached */
                        TSTypeInfo returned_type;
                        TSTypeInfo returned_element_type;
                        if (ts_interpreter_resolve_type(cur_var->struct_type_name, type_info_table,
                                                        &returned_type, &returned_element_type)) {
                            node_obj.array_element_type = returned_type;
                        }
                        break;
                    }
                    default: {
                        PRINTF_ERROR("Unsupported variable type in new not null checker: %d\n", cur_var->type);
                    }
                }
                node_obj_array[node_obj_count]=node_obj;
                node_obj_count++;
            }
        }

        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_count,node_obj_array,type_info_table);
        if (uncached_tree != NULL) ts_tree_delete(uncached_tree); // Parsed for this run only
        for (size_t i=0;i<var_count;i++) {
            free(variables[i]);
        }

        WRITE_DEBUG_TO_FILE("New not null checker, result: %" PRId64 "\n", result.value.int64);
        if (TS_NODE_COUNT_STMT_EXPR) ts_node_print_stmt_expr_counter();
        return result.value.int64;
    }

    return 1;
}

/**
 * Take the value of the `return` an interpreted patch executed, if this is the function it jumped into.
 *
 * A `return` of a patch leaves the interpreter with longjmp(), which carries the patch id and nothing
 * else, so the value waits in ts_interpreter_return_value (see api.h) and is read here, in the function
 * the jump lands in. It is taken once: the id is cleared, so the same value is never read again. A value
 * left by another patch can only be one that nothing took -- a `return` of a patch in a function that
 * returns void -- so it is dropped as well.
 *
 * @param id id the function was jumped with, i.e. the patch that returned
 * @param out value of that return, only written when this returns 1
 * @return 1 when the value of this patch was waiting, 0 when the caller has to evaluate the expression
 */
static int take_interpreted_return(uint32_t id, TSNodeObject* out) {
    if (ts_interpreter_return_value_id == 0) {
        return 0;
    }
    int is_mine = (ts_interpreter_return_value_id == id);
    if (is_mine) {
        *out = ts_interpreter_return_value;
    }
    ts_interpreter_return_value_id = 0;
    return is_mine;
}

__attribute__((force_align_arg_pointer))
int64_t __metapro_get_int_var_c(uint32_t id, char* funcName) {
    if (!getenv("METAPRO_PATCH_MODE") || strcmp(getenv("METAPRO_PATCH_MODE"),"patch")==0) {
        TSNodeObject returned;
        if (take_interpreted_return(id, &returned)) {
            WRITE_DEBUG_TO_FILE("Interpreted return, ID: %" PRIu32 "\n", id);
            if (TS_NODE_COUNT_STMT_EXPR) ts_node_print_stmt_expr_counter();
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
        char* var;
        if (shm_patch_infos_id != -1) {
            for (uint32_t i = 0; i < *shm_patch_count; i++) {
                if (shm_patch_infos[i].id == id) {
                    var = shm_patch_infos[i].exprs[1];
                    break;
                }
            }
        }
        else {
            char var_env_var[300];
            sprintf(var_env_var, "METAPRO_EXPR_%" PRIu32, id);
            var=getenv(var_env_var);
        }
        if (var == NULL) {
            PRINTF_ERROR("No expression found for ID: %" PRIu32 "\n", id);
            return 0;
        }

        __metapro_function_var_info* func_var_info=NULL;
        __metapro_get_func_var_info(funcName, func_var_info);

        char* _var;
        // Find and prune prefix 'return '
        _var = strstr(var, "return ");
        if (_var == NULL) {
            // There's no space after "return", try "return("
            _var = strstr(var, "return(");
            if (_var != NULL) {
                _var += 7; // Move past "return("
            }
        } else if (strncmp(_var, "return ", 7) == 0) {
            _var += 7;
        }
        char* temp=_var;
        var=(char*)malloc(strlen(_var)+4);
        sprintf(var,"(%s)",temp);

        // Take the AST of this patch, parsing it only the first time it runs
        TSTree* uncached_tree;
        TSNode root_node = __metapro_get_parsed_expr(id, PatchTemplateGetIntVar, var, &uncached_tree);

        static TSNodeObject node_obj_array[MAX_SIZE];
        uint64_t node_obj_count=0;
        char* variables[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, var, &var_count, variables);
        uint32_t ptr_elem_size = 0;
        for (uint32_t i=0;i<var_count;i++) {
            TSNodeObject node_obj = {0}; // TSTypeInfo holds a name, so zero it instead of leaving garbage
            node_obj.name=variables[i];
            node_obj.array_element_type.size = 0;
            __metapro_var_info* cur_var;
            __metapro_get_var_value(funcName, variables[i], cur_var);
            char ptr_type_name[100];
            sprintf(ptr_type_name, "%s::%s", funcName, variables[i]);
            VarSizeInfo* var_size_info = NULL;
            HASH_FIND_STR(var_size_info_table, ptr_type_name, var_size_info);
            if (var_size_info != NULL) {
                ptr_elem_size = var_size_info->size;
            }
            if (cur_var != NULL) {
                switch (cur_var->type) {
                    case MetaproVarTypeInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "int", cur_var->size, TSNodeObjectTypeInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.int64 = *(int8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.int64 = *(int16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.int64 = *(int32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.int64 = *(int64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported int size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeUInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "uint", cur_var->size, TSNodeObjectTypeUInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.uint64 = *(uint8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.uint64 = *(uint16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.uint64 = *(uint32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.uint64 = *(uint64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported uint size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeDouble:
                        node_obj.type = get_var_type_info(funcName, variables[i], "double", cur_var->size, TSNodeObjectTypeDouble);
                        switch (cur_var->size) {
                            case 4:
                                node_obj.value.double64 = *(float*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.double64 = *(double*)(cur_var->ref);
                                break;
                            case 16:
                                node_obj.value.double64 = *(long double*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported double size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypePointer:
                    case MetaproVarTypeArray: {
                        // struct_type_name is the "<type>:<size>" descriptor of the pointee, or of the
                        // element when the variable is an array
                        char pointee_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t pointee_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, pointee_name, sizeof(pointee_name), &pointee_size);
                        TSNodeObjectType pointee_category = ts_interpreter_get_category_type(pointee_name);
                        if (pointee_category == TSNodeObjectTypeUnknown) {
                            WRITE_DEBUG_TO_FILE("Unknown pointee type: %s of %s\n", pointee_name, cur_var->name);
                        }
                        node_obj.array_element_type = ts_interpreter_get_type_info(pointee_name, pointee_size,
                                pointee_category);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        /* An array is as wide as all of its elements together, which is what a
                           `sizeof` of it answers; a pointer variable is one address wide */
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                (cur_var->type == MetaproVarTypeArray) ? cur_var->size : (uint32_t)sizeof(void*),
                                TSNodeObjectTypePointer);
                        // An array is registered as itself, so `ref` already is the elements: it is both
                        // the value of the pointer and the reference the interpreter subscripts off. A
                        // pointer variable holds the address instead, so that has to be read out of it.
                        node_obj.value.pointer = (cur_var->type == MetaproVarTypeArray)
                                ? (void*)cur_var->ref : *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStruct: {
                        // struct_type_name is the "<type>:<size>" descriptor, and the interpreter looks the
                        // record up by name, so the size has to be split off it
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.type = ts_interpreter_get_type_info(record_name, record_size, TSNodeObjectTypeStruct);
                        node_obj.value.pointer = (void*)cur_var->ref; // A struct is represented by its address
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStructPointer: {
                        // The descriptor of a struct pointer names the struct it points to, not the pointer
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.array_element_type = ts_interpreter_get_type_info(record_name, record_size,
                                TSNodeObjectTypeStruct);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                sizeof(void*), TSNodeObjectTypePointer);
                        node_obj.value.pointer = *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeFunctionVoid:
                        node_obj.type = ts_interpreter_get_type_info("void", sizeof(void (*)()), TSNodeObjectTypeFunctionVoid);
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionInt:
                        node_obj.type = ts_interpreter_get_type_info("int", sizeof(int64_t (*)(void)), TSNodeObjectTypeFunctionInt);
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionUInt:
                        node_obj.type = ts_interpreter_get_type_info("uint", sizeof(uint64_t (*)(void)), TSNodeObjectTypeFunctionUInt);
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionPointer: {
                        node_obj.type = ts_interpreter_get_type_info("pointer", sizeof(void* (*)(void)), TSNodeObjectTypeFunctionPointer);
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        /* struct_type_name of a pointer returning function is the type it returns a
                           pointer to, a plain name rather than a "<type>:<size>" descriptor. Resolving it
                           gives the call its element type, so the result can be subscripted and, for a
                           record, have its fields reached */
                        TSTypeInfo returned_type;
                        TSTypeInfo returned_element_type;
                        if (ts_interpreter_resolve_type(cur_var->struct_type_name, type_info_table,
                                                        &returned_type, &returned_element_type)) {
                            node_obj.array_element_type = returned_type;
                        }
                        break;
                    }
                    default: {
                        PRINTF_ERROR("Unsupported variable type in get int var: %d\n", cur_var->type);
                    }
                }
                node_obj_array[node_obj_count]=node_obj;
                node_obj_count++;
            }
        }

        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_count,node_obj_array,type_info_table);
        if (uncached_tree != NULL) ts_tree_delete(uncached_tree); // Parsed for this run only
        free(var);
        for (size_t i=0;i<var_count;i++) {
            free(variables[i]);
        }

        if (TS_NODE_COUNT_STMT_EXPR) ts_node_print_stmt_expr_counter();
        switch (result.type.category) {
            case TSNodeObjectTypeInt:
                WRITE_DEBUG_TO_FILE("Int variable, result: %" PRId64 "\n", result.value.int64);
                return result.value.int64;
            case TSNodeObjectTypeUInt:
                WRITE_DEBUG_TO_FILE("Int variable, result: %" PRIu64 "\n", result.value.uint64);
                return result.value.uint64;
            default: {
                PRINTF_ERROR("Unsupported type in get int var: %d\n", result.type.category);
            }
        }
    }
    PRINTF_ERROR("METAPRO_PATCH_MODE is not set or not in patch mode!\n");
}

__attribute__((force_align_arg_pointer))
uint64_t __metapro_get_uint_var_c(uint32_t id, char* funcName) {
    if (!getenv("METAPRO_PATCH_MODE") || strcmp(getenv("METAPRO_PATCH_MODE"),"patch")==0) {
        TSNodeObject returned;
        if (take_interpreted_return(id, &returned)) {
            WRITE_DEBUG_TO_FILE("Interpreted return, ID: %" PRIu32 "\n", id);
            if (TS_NODE_COUNT_STMT_EXPR) ts_node_print_stmt_expr_counter();
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
        char* var;
        if (shm_patch_infos_id != -1) {
            for (uint32_t i = 0; i < *shm_patch_count; i++) {
                if (shm_patch_infos[i].id == id) {
                    var = shm_patch_infos[i].exprs[1];
                    break;
                }
            }
        }
        else {
            char var_env_var[300];
            sprintf(var_env_var, "METAPRO_EXPR_%" PRIu32, id);
            var=getenv(var_env_var);
        }

        __metapro_function_var_info* func_var_info=NULL;
        __metapro_get_func_var_info(funcName, func_var_info);

        char* _var;
        // Find and prune prefix 'return '
        _var = strstr(var, "return ");
        if (_var == NULL) {
            // There's no space after "return", try "return("
            _var = strstr(var, "return(");
            if (_var != NULL) {
                _var += 7; // Move past "return("
            }
        } else if (strncmp(_var, "return ", 7) == 0) {
            _var += 7;
        }
        char* temp=_var;
        var=(char*)malloc(strlen(_var)+4);
        sprintf(var,"(%s)",temp);

        // Take the AST of this patch, parsing it only the first time it runs
        TSTree* uncached_tree;
        TSNode root_node = __metapro_get_parsed_expr(id, PatchTemplateGetUIntVar, var, &uncached_tree);

        static TSNodeObject node_obj_array[MAX_SIZE];
        uint64_t node_obj_count=0;
        char* variables[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, var, &var_count, variables);
        uint32_t ptr_elem_size = 0;
        for (uint32_t i=0;i<var_count;i++) {
            TSNodeObject node_obj = {0}; // TSTypeInfo holds a name, so zero it instead of leaving garbage
            node_obj.name=variables[i];
            node_obj.array_element_type.size = 0;
            __metapro_var_info* cur_var;
            __metapro_get_var_value(funcName, variables[i], cur_var);
            char ptr_type_name[100];
            sprintf(ptr_type_name, "%s::%s", funcName, variables[i]);
            VarSizeInfo* var_size_info = NULL;
            HASH_FIND_STR(var_size_info_table, ptr_type_name, var_size_info);
            if (var_size_info != NULL) {
                ptr_elem_size = var_size_info->size;
            }
            if (cur_var != NULL) {
                switch (cur_var->type) {
                    case MetaproVarTypeInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "int", cur_var->size, TSNodeObjectTypeInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.int64 = *(int8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.int64 = *(int16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.int64 = *(int32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.int64 = *(int64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported int size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeUInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "uint", cur_var->size, TSNodeObjectTypeUInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.uint64 = *(uint8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.uint64 = *(uint16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.uint64 = *(uint32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.uint64 = *(uint64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported uint size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeDouble:
                        node_obj.type = get_var_type_info(funcName, variables[i], "double", cur_var->size, TSNodeObjectTypeDouble);
                        switch (cur_var->size) {
                            case 4:
                                node_obj.value.double64 = *(float*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.double64 = *(double*)(cur_var->ref);
                                break;
                            case 16:
                                node_obj.value.double64 = *(long double*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported double size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypePointer:
                    case MetaproVarTypeArray: {
                        // struct_type_name is the "<type>:<size>" descriptor of the pointee, or of the
                        // element when the variable is an array
                        char pointee_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t pointee_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, pointee_name, sizeof(pointee_name), &pointee_size);
                        TSNodeObjectType pointee_category = ts_interpreter_get_category_type(pointee_name);
                        if (pointee_category == TSNodeObjectTypeUnknown) {
                            WRITE_DEBUG_TO_FILE("Unknown pointee type: %s of %s\n", pointee_name, cur_var->name);
                        }
                        node_obj.array_element_type = ts_interpreter_get_type_info(pointee_name, pointee_size,
                                pointee_category);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        /* An array is as wide as all of its elements together, which is what a
                           `sizeof` of it answers; a pointer variable is one address wide */
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                (cur_var->type == MetaproVarTypeArray) ? cur_var->size : (uint32_t)sizeof(void*),
                                TSNodeObjectTypePointer);
                        // An array is registered as itself, so `ref` already is the elements: it is both
                        // the value of the pointer and the reference the interpreter subscripts off. A
                        // pointer variable holds the address instead, so that has to be read out of it.
                        node_obj.value.pointer = (cur_var->type == MetaproVarTypeArray)
                                ? (void*)cur_var->ref : *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStruct: {
                        // struct_type_name is the "<type>:<size>" descriptor, and the interpreter looks the
                        // record up by name, so the size has to be split off it
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.type = ts_interpreter_get_type_info(record_name, record_size, TSNodeObjectTypeStruct);
                        node_obj.value.pointer = (void*)cur_var->ref; // A struct is represented by its address
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStructPointer: {
                        // The descriptor of a struct pointer names the struct it points to, not the pointer
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.array_element_type = ts_interpreter_get_type_info(record_name, record_size,
                                TSNodeObjectTypeStruct);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                sizeof(void*), TSNodeObjectTypePointer);
                        node_obj.value.pointer = *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeFunctionVoid:
                        node_obj.type = ts_interpreter_get_type_info("void", sizeof(void (*)()), TSNodeObjectTypeFunctionVoid);
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionInt:
                        node_obj.type = ts_interpreter_get_type_info("int", sizeof(int64_t (*)(void)), TSNodeObjectTypeFunctionInt);
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionUInt:
                        node_obj.type = ts_interpreter_get_type_info("uint", sizeof(uint64_t (*)(void)), TSNodeObjectTypeFunctionUInt);
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionPointer: {
                        node_obj.type = ts_interpreter_get_type_info("pointer", sizeof(void* (*)(void)), TSNodeObjectTypeFunctionPointer);
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        /* struct_type_name of a pointer returning function is the type it returns a
                           pointer to, a plain name rather than a "<type>:<size>" descriptor. Resolving it
                           gives the call its element type, so the result can be subscripted and, for a
                           record, have its fields reached */
                        TSTypeInfo returned_type;
                        TSTypeInfo returned_element_type;
                        if (ts_interpreter_resolve_type(cur_var->struct_type_name, type_info_table,
                                                        &returned_type, &returned_element_type)) {
                            node_obj.array_element_type = returned_type;
                        }
                        break;
                    }
                    default: {
                        PRINTF_ERROR("Unsupported variable type in get uint var: %d\n", cur_var->type);
                    }
                }
                node_obj_array[node_obj_count]=node_obj;
                node_obj_count++;
            }
        }
        
        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_count,node_obj_array,type_info_table);
        if (uncached_tree != NULL) ts_tree_delete(uncached_tree); // Parsed for this run only
        free(var);
        for (size_t i=0;i<var_count;i++) {
            free(variables[i]);
        }

        if (TS_NODE_COUNT_STMT_EXPR) ts_node_print_stmt_expr_counter();
        switch (result.type.category) {
            case TSNodeObjectTypeInt:
                WRITE_DEBUG_TO_FILE("Unsigned int variable, result: %" PRId64 "\n", result.value.int64);
                return result.value.int64;
            case TSNodeObjectTypeUInt:
                WRITE_DEBUG_TO_FILE("Unsigned int variable, result: %" PRIu64 "\n", result.value.uint64);
                return result.value.uint64;
            default: {
                PRINTF_ERROR("Unsupported type in get uint var: %d\n", result.type.category);
            }
        }
    }
    PRINTF_ERROR("METAPRO_PATCH_MODE is not set or not in patch mode!\n");
}

__attribute__((force_align_arg_pointer))
void* __metapro_get_ptr_var_c(uint32_t id, char* funcName) {
    if (!getenv("METAPRO_PATCH_MODE") || strcmp(getenv("METAPRO_PATCH_MODE"),"patch")==0) {
        TSNodeObject returned;
        if (take_interpreted_return(id, &returned)) {
            WRITE_DEBUG_TO_FILE("Interpreted return, ID: %" PRIu32 "\n", id);
            if (TS_NODE_COUNT_STMT_EXPR) ts_node_print_stmt_expr_counter();
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
        char* var;
        if (shm_patch_infos_id != -1) {
            for (uint32_t i = 0; i < *shm_patch_count; i++) {
                if (shm_patch_infos[i].id == id) {
                    var = shm_patch_infos[i].exprs[1];
                    break;
                }
            }
        }
        else {
            char var_env_var[300];
            sprintf(var_env_var, "METAPRO_EXPR_%" PRIu32, id);
            var=getenv(var_env_var);
        }
        if (strcmp(var,"NULL")==0 || strcmp(var,"nullptr")==0 || strcmp(var,"0")==0) {
            return NULL;
        }

        __metapro_function_var_info* func_var_info=NULL;
        __metapro_get_func_var_info(funcName, func_var_info);

        char* _var;
        // Find and prune prefix 'return '
        _var = strstr(var, "return ");
        if (_var == NULL) {
            // There's no space after "return", try "return("
            _var = strstr(var, "return(");
            if (_var != NULL) {
                _var += 7; // Move past "return("
            }
        } else if (strncmp(_var, "return ", 7) == 0) {
            _var += 7;
        }
        char* temp=_var;
        var=(char*)malloc(strlen(_var)+4);
        sprintf(var,"(%s)",temp);

        // Take the AST of this patch, parsing it only the first time it runs
        TSTree* uncached_tree;
        TSNode root_node = __metapro_get_parsed_expr(id, PatchTemplateGetPtrVar, var, &uncached_tree);

        static TSNodeObject node_obj_array[MAX_SIZE];
        uint64_t node_obj_count=0;
        char* variables[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, var, &var_count, variables);
        uint32_t ptr_elem_size = 0;
        for (uint32_t i=0;i<var_count;i++) {
            TSNodeObject node_obj = {0}; // TSTypeInfo holds a name, so zero it instead of leaving garbage
            node_obj.name=variables[i];
            node_obj.array_element_type.size = 0;
            __metapro_var_info* cur_var;
            __metapro_get_var_value(funcName, variables[i], cur_var);
            char ptr_type_name[100];
            sprintf(ptr_type_name, "%s::%s", funcName, variables[i]);
            VarSizeInfo* var_size_info = NULL;
            HASH_FIND_STR(var_size_info_table, ptr_type_name, var_size_info);
            if (var_size_info != NULL) {
                ptr_elem_size = var_size_info->size;
            }
            if (cur_var != NULL) {
                switch (cur_var->type) {
                    case MetaproVarTypeInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "int", cur_var->size, TSNodeObjectTypeInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.int64 = *(int8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.int64 = *(int16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.int64 = *(int32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.int64 = *(int64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported int size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeUInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "uint", cur_var->size, TSNodeObjectTypeUInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.uint64 = *(uint8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.uint64 = *(uint16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.uint64 = *(uint32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.uint64 = *(uint64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported uint size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeDouble:
                        node_obj.type = get_var_type_info(funcName, variables[i], "double", cur_var->size, TSNodeObjectTypeDouble);
                        switch (cur_var->size) {
                            case 4:
                                node_obj.value.double64 = *(float*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.double64 = *(double*)(cur_var->ref);
                                break;
                            case 16:
                                node_obj.value.double64 = *(long double*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported double size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypePointer:
                    case MetaproVarTypeArray: {
                        // struct_type_name is the "<type>:<size>" descriptor of the pointee, or of the
                        // element when the variable is an array
                        char pointee_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t pointee_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, pointee_name, sizeof(pointee_name), &pointee_size);
                        TSNodeObjectType pointee_category = ts_interpreter_get_category_type(pointee_name);
                        if (pointee_category == TSNodeObjectTypeUnknown) {
                            WRITE_DEBUG_TO_FILE("Unknown pointee type: %s of %s\n", pointee_name, cur_var->name);
                        }
                        node_obj.array_element_type = ts_interpreter_get_type_info(pointee_name, pointee_size,
                                pointee_category);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        /* An array is as wide as all of its elements together, which is what a
                           `sizeof` of it answers; a pointer variable is one address wide */
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                (cur_var->type == MetaproVarTypeArray) ? cur_var->size : (uint32_t)sizeof(void*),
                                TSNodeObjectTypePointer);
                        // An array is registered as itself, so `ref` already is the elements: it is both
                        // the value of the pointer and the reference the interpreter subscripts off. A
                        // pointer variable holds the address instead, so that has to be read out of it.
                        node_obj.value.pointer = (cur_var->type == MetaproVarTypeArray)
                                ? (void*)cur_var->ref : *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStruct: {
                        // struct_type_name is the "<type>:<size>" descriptor, and the interpreter looks the
                        // record up by name, so the size has to be split off it
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.type = ts_interpreter_get_type_info(record_name, record_size, TSNodeObjectTypeStruct);
                        node_obj.value.pointer = (void*)cur_var->ref; // A struct is represented by its address
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStructPointer: {
                        // The descriptor of a struct pointer names the struct it points to, not the pointer
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.array_element_type = ts_interpreter_get_type_info(record_name, record_size,
                                TSNodeObjectTypeStruct);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                sizeof(void*), TSNodeObjectTypePointer);
                        node_obj.value.pointer = *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeFunctionVoid:
                        node_obj.type = ts_interpreter_get_type_info("void", sizeof(void (*)()), TSNodeObjectTypeFunctionVoid);
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionInt:
                        node_obj.type = ts_interpreter_get_type_info("int", sizeof(int64_t (*)(void)), TSNodeObjectTypeFunctionInt);
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionUInt:
                        node_obj.type = ts_interpreter_get_type_info("uint", sizeof(uint64_t (*)(void)), TSNodeObjectTypeFunctionUInt);
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionPointer: {
                        node_obj.type = ts_interpreter_get_type_info("pointer", sizeof(void* (*)(void)), TSNodeObjectTypeFunctionPointer);
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        /* struct_type_name of a pointer returning function is the type it returns a
                           pointer to, a plain name rather than a "<type>:<size>" descriptor. Resolving it
                           gives the call its element type, so the result can be subscripted and, for a
                           record, have its fields reached */
                        TSTypeInfo returned_type;
                        TSTypeInfo returned_element_type;
                        if (ts_interpreter_resolve_type(cur_var->struct_type_name, type_info_table,
                                                        &returned_type, &returned_element_type)) {
                            node_obj.array_element_type = returned_type;
                        }
                        break;
                    }
                    default: {
                        PRINTF_ERROR("Unsupported variable type in get ptr var: %d\n", cur_var->type);
                    }
                }
                node_obj_array[node_obj_count]=node_obj;
                node_obj_count++;
            }
        }

        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_count,node_obj_array,type_info_table);
        if (uncached_tree != NULL) ts_tree_delete(uncached_tree); // Parsed for this run only
        free(var);
        for (size_t i=0;i<var_count;i++) {
            free(variables[i]);
        }

        WRITE_DEBUG_TO_FILE("Pointer variable, result: %p\n", result.value.pointer);
        if (TS_NODE_COUNT_STMT_EXPR) ts_node_print_stmt_expr_counter();
        return result.value.pointer;
    }
    PRINTF_ERROR("METAPRO_PATCH_MODE is not set or not in patch mode!\n");
}

/* What the first phase of a call answered, see __metapro_replace_cond_c in _runtime_c.h */
_Thread_local uint32_t __metapro_cond_res = 0;

__attribute__((force_align_arg_pointer))
uint32_t __metapro_cond_c(uint32_t id, char* orig_cond_str, char* funcName, int has_orig, uint32_t orig_cond) {
    PatchInfo patch_info;
    if (shm_patch_infos_id != -1) {
        int is_patch = 0;
        for (uint32_t i = 0; i < *shm_patch_count; i++) {
            if (shm_patch_infos[i].id == id) {
                is_patch = 1;
                patch_info = shm_patch_infos[i];;
                break;
            }
        }
        if (!is_patch) {
            return METAPRO_COND_ORIG; // Nothing patches this condition, so it is its own result
        }
    }
    else {
        if (!__metapro_is_patch_id(id)) {
            return METAPRO_COND_ORIG;
        }
    }

    // patch
    if (!getenv("METAPRO_PATCH_MODE") || strcmp(getenv("METAPRO_PATCH_MODE"),"patch")==0) {
        char* patch_expr;
        char* second_expr;
        if (shm_patch_infos_id != -1) {
            patch_expr = patch_info.exprs[0];
            if (patch_info.expr_count > 1) {
                second_expr = patch_info.exprs[1];
            }
            else {
                second_expr = NULL;
            }
        }
        else {
            char condition_env_var[100];
            sprintf(condition_env_var, "METAPRO_PATCH_COND_%" PRIu32, id);
            patch_expr=getenv(condition_env_var);
            if (patch_expr == NULL)
                return METAPRO_COND_ORIG; // This is not our template, skip patching
            sprintf(condition_env_var, "METAPRO_PATCH_COND_%" PRIu32 "_2", id);
            second_expr=getenv(condition_env_var);
        }
        WRITE_DEBUG_TO_FILE("Replace cond, ID: %" PRIu32 "\n", id);

        if (strcmp(patch_expr,"1")==0) {
            WRITE_DEBUG_TO_FILE("Replace cond, original: %s, to 'true'\n", orig_cond_str);
            return 1; // Always true
        }
        else if (strcmp(patch_expr,"0")==0) {
            WRITE_DEBUG_TO_FILE("Replace cond, original: %s, to 'false'\n", orig_cond_str);
            return 0; // Always false
        }
        else if (strcmp(patch_expr,"!")==0) {
            WRITE_DEBUG_TO_FILE("Replace cond, original: %s, negated\n", orig_cond_str);
            return METAPRO_COND_ORIG_NOT; // The macro negates the original
        }

        /*
            "<orig> && <new>" and "<orig> || <new>" put the original first, so ask for it before anything of
            the patch is interpreted, and then let its value short-circuit <new> away
        */
        if (strcmp(patch_expr, "&&") == 0 || strcmp(patch_expr, "||") == 0) {
            if (!has_orig) {
                return METAPRO_COND_ORIG_FIRST;
            }
            if (strcmp(patch_expr, "&&") == 0 && orig_cond == 0) {
                WRITE_DEBUG_TO_FILE("Skip replace due to && and original is false, original: %s\n", orig_cond_str);
                return 0; // If original condition is false, && will always be false
            }
            else if (strcmp(patch_expr, "||") == 0 && orig_cond != 0) {
                WRITE_DEBUG_TO_FILE("Skip replace due to || and original is true, original: %s\n", orig_cond_str);
                return 1; // If original condition is true, || will always be true
            }
        }

        char* temp_expr;
        if (strcmp(patch_expr, "&&") == 0 || strcmp(patch_expr, "||") == 0) {
            char* temp=second_expr;
            temp_expr=(char*)malloc(strlen(second_expr)+4);
            sprintf(temp_expr,"(%s);",temp);    
        }
        else {
            char* temp=patch_expr;
            temp_expr=(char*)malloc(strlen(patch_expr)+4);
            sprintf(temp_expr,"(%s);",temp);
        }

        __metapro_function_var_info* func_var_info=NULL;
        __metapro_get_func_var_info(funcName, func_var_info);
        
        // Take the AST of this patch, parsing it only the first time it runs
        TSTree* uncached_tree;
        TSNode root_node = __metapro_get_parsed_expr(id, PatchTemplateReplaceCondition, temp_expr, &uncached_tree);

        static TSNodeObject node_obj_array[MAX_SIZE];
        uint64_t node_obj_count=0;
        char* variables[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, temp_expr, &var_count, variables);
        free(temp_expr);
        uint32_t ptr_elem_size = 0;
        for (uint32_t i=0;i<var_count;i++) {
            TSNodeObject node_obj = {0}; // TSTypeInfo holds a name, so zero it instead of leaving garbage
            node_obj.name=variables[i];
            node_obj.array_element_type.size = 0;
            __metapro_var_info* cur_var;
            __metapro_get_var_value(funcName, variables[i], cur_var);
            char ptr_type_name[100];
            sprintf(ptr_type_name, "%s::%s", funcName, variables[i]);
            VarSizeInfo* var_size_info = NULL;
            HASH_FIND_STR(var_size_info_table, ptr_type_name, var_size_info);
            if (var_size_info != NULL) {
                ptr_elem_size = var_size_info->size;
            }
            if (cur_var != NULL) {
                switch (cur_var->type) {
                    case MetaproVarTypeInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "int", cur_var->size, TSNodeObjectTypeInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.int64 = *(int8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.int64 = *(int16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.int64 = *(int32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.int64 = *(int64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported int size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeUInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "uint", cur_var->size, TSNodeObjectTypeUInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.uint64 = *(uint8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.uint64 = *(uint16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.uint64 = *(uint32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.uint64 = *(uint64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported uint size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeDouble:
                        node_obj.type = get_var_type_info(funcName, variables[i], "double", cur_var->size, TSNodeObjectTypeDouble);
                        switch (cur_var->size) {
                            case 4:
                                node_obj.value.double64 = *(float*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.double64 = *(double*)(cur_var->ref);
                                break;
                            case 16:
                                node_obj.value.double64 = *(long double*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported double size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypePointer:
                    case MetaproVarTypeArray: {
                        // struct_type_name is the "<type>:<size>" descriptor of the pointee, or of the
                        // element when the variable is an array
                        char pointee_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t pointee_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, pointee_name, sizeof(pointee_name), &pointee_size);
                        TSNodeObjectType pointee_category = ts_interpreter_get_category_type(pointee_name);
                        if (pointee_category == TSNodeObjectTypeUnknown) {
                            WRITE_DEBUG_TO_FILE("Unknown pointee type: %s of %s\n", pointee_name, cur_var->name);
                        }
                        node_obj.array_element_type = ts_interpreter_get_type_info(pointee_name, pointee_size,
                                pointee_category);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        /* An array is as wide as all of its elements together, which is what a
                           `sizeof` of it answers; a pointer variable is one address wide */
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                (cur_var->type == MetaproVarTypeArray) ? cur_var->size : (uint32_t)sizeof(void*),
                                TSNodeObjectTypePointer);
                        // An array is registered as itself, so `ref` already is the elements: it is both
                        // the value of the pointer and the reference the interpreter subscripts off. A
                        // pointer variable holds the address instead, so that has to be read out of it.
                        node_obj.value.pointer = (cur_var->type == MetaproVarTypeArray)
                                ? (void*)cur_var->ref : *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStruct: {
                        // struct_type_name is the "<type>:<size>" descriptor, and the interpreter looks the
                        // record up by name, so the size has to be split off it
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.type = ts_interpreter_get_type_info(record_name, record_size, TSNodeObjectTypeStruct);
                        node_obj.value.pointer = (void*)cur_var->ref; // A struct is represented by its address
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStructPointer: {
                        // The descriptor of a struct pointer names the struct it points to, not the pointer
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.array_element_type = ts_interpreter_get_type_info(record_name, record_size,
                                TSNodeObjectTypeStruct);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                sizeof(void*), TSNodeObjectTypePointer);
                        node_obj.value.pointer = *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeFunctionVoid:
                        node_obj.type = ts_interpreter_get_type_info("void", sizeof(void (*)()), TSNodeObjectTypeFunctionVoid);
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionInt:
                        node_obj.type = ts_interpreter_get_type_info("int", sizeof(int64_t (*)(void)), TSNodeObjectTypeFunctionInt);
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionUInt:
                        node_obj.type = ts_interpreter_get_type_info("uint", sizeof(uint64_t (*)(void)), TSNodeObjectTypeFunctionUInt);
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionPointer: {
                        node_obj.type = ts_interpreter_get_type_info("pointer", sizeof(void* (*)(void)), TSNodeObjectTypeFunctionPointer);
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        /* struct_type_name of a pointer returning function is the type it returns a
                           pointer to, a plain name rather than a "<type>:<size>" descriptor. Resolving it
                           gives the call its element type, so the result can be subscripted and, for a
                           record, have its fields reached */
                        TSTypeInfo returned_type;
                        TSTypeInfo returned_element_type;
                        if (ts_interpreter_resolve_type(cur_var->struct_type_name, type_info_table,
                                                        &returned_type, &returned_element_type)) {
                            node_obj.array_element_type = returned_type;
                        }
                        break;
                    }
                    default: {
                        PRINTF_ERROR("Unsupported variable type in replace cond: %d\n", cur_var->type);
                    }
                }
                node_obj_array[node_obj_count]=node_obj;
                node_obj_count++;
            }
        }

        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_count,node_obj_array,type_info_table);
        if (uncached_tree != NULL) ts_tree_delete(uncached_tree); // Parsed for this run only
        for (size_t i=0;i<var_count;i++) {
            free(variables[i]);
        }

        /*
            A result is normalized to 0 or 1, so that it can never be read as one of the METAPRO_COND_*
            codes: `x - 3` is a perfectly good replacement condition and evaluates to 2 often enough
        */
        if (TS_NODE_COUNT_STMT_EXPR) ts_node_print_stmt_expr_counter();
        uint32_t new_cond = (result.value.int64 != 0);
        if (second_expr != NULL) {
            if (strcmp(second_expr,"&&")==0) {
                // new && orig: the original is the result when the new condition did not settle it
                WRITE_DEBUG_TO_FILE("Replace cond, insert && before orig, new result: %" PRIu32 "\n", new_cond);
                return new_cond ? METAPRO_COND_ORIG : 0;
            }
            else if (strcmp(second_expr,"||")==0) {
                // new || orig
                WRITE_DEBUG_TO_FILE("Replace cond, insert || before orig, new result: %" PRIu32 "\n", new_cond);
                return new_cond ? 1 : METAPRO_COND_ORIG;
            }
            else if (strcmp(patch_expr,"&&") == 0) {
                // orig && new, reached with the original true, so the new condition is the result
                WRITE_DEBUG_TO_FILE("Replace cond, insert && after orig, original result: %" PRIu32 ", to %" PRIu32 "\n",
                            orig_cond, new_cond);
                return new_cond;
            }
            else if (strcmp(patch_expr,"||") == 0) {
                // orig || new, reached with the original false
                WRITE_DEBUG_TO_FILE("Replace cond, insert || after orig, original result: %" PRIu32 ", to %" PRIu32 "\n",
                            orig_cond, new_cond);
                return new_cond;
            }
            else {
                PRINTF_ERROR("Invalid second expr for replace cond: %s\n", second_expr);
            }
        }
        else {
            WRITE_DEBUG_TO_FILE("Replace cond, replace orig to new, to %" PRIu32 "\n", new_cond);
            return new_cond;
        }
    }
    PRINTF_ERROR("Invalid patch expr, check patch json file!\n");
}

__attribute__((force_align_arg_pointer))
void __metapro_exec_expr_c(uint32_t id, char* funcName, uint32_t jumpId) {
    /* No return of an earlier run is waiting to be taken: a run starts with none of its own */
    ts_interpreter_return_value_id = 0;
    PatchInfo patch_info;
    if (shm_patch_infos_id != -1) {
        int is_patch = 0;
        for (uint32_t i = 0; i < *shm_patch_count; i++) {
            if (shm_patch_infos[i].id == id) {
                patch_info = shm_patch_infos[i];
                is_patch = 1;
                break;
            }
        }
        if (!is_patch) {
            return;
        }
    }
    else {
        if (!__metapro_is_patch_id(id)) {
            return;
        }
    }

    if (!getenv("METAPRO_PATCH_MODE") || strcmp(getenv("METAPRO_PATCH_MODE"),"patch") == 0) {
        // Apply new expr
        char* expr;
        if (shm_patch_infos_id != -1) {
            expr = patch_info.exprs[0];
        }
        else {
            char condition_env_var[100];
            sprintf(condition_env_var, "METAPRO_EXPR_%" PRIu32, id);
            expr=getenv(condition_env_var);
            if (expr == NULL) return; // Different patch template, do nothing
        }
        WRITE_DEBUG_TO_FILE("New expr, ID: %" PRIu32 "\n", id);

        // Find function variable info
        __metapro_function_var_info* func_var_info=NULL;
        __metapro_get_func_var_info(funcName, func_var_info);

        // Take the AST of this patch, parsing it only the first time it runs
        TSTree* uncached_tree;
        TSNode root_node = __metapro_get_parsed_expr(id, PatchTemplateInsertExpr, expr, &uncached_tree);

        static TSNodeObject node_obj_array[MAX_SIZE];
        uint64_t node_obj_count=0;
        char* variables[MAX_SIZE];
        uint32_t var_count=0;
        ts_node_find_variables(root_node, expr, &var_count, variables);
        // free(expr);
        uint32_t ptr_elem_size = 0;
        for (uint32_t i=0;i<var_count;i++) {
            TSNodeObject node_obj = {0}; // TSTypeInfo holds a name, so zero it instead of leaving garbage
            node_obj.name=variables[i];
            node_obj.array_element_type.size = 0;
            __metapro_var_info* cur_var;
            __metapro_get_var_value(funcName, variables[i], cur_var);
            char ptr_type_name[100];
            sprintf(ptr_type_name, "%s::%s", funcName, variables[i]);
            VarSizeInfo* var_size_info = NULL;
            HASH_FIND_STR(var_size_info_table, ptr_type_name, var_size_info);
            if (var_size_info != NULL) {
                ptr_elem_size = var_size_info->size;
            }
            if (cur_var != NULL) {
                switch (cur_var->type) {
                    case MetaproVarTypeInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "int", cur_var->size, TSNodeObjectTypeInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.int64 = *(int8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.int64 = *(int16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.int64 = *(int32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.int64 = *(int64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported int size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeUInt:
                        node_obj.type = get_var_type_info(funcName, variables[i], "uint", cur_var->size, TSNodeObjectTypeUInt);
                        switch (cur_var->size) {
                            case 1:
                                node_obj.value.uint64 = *(uint8_t*)(cur_var->ref);
                                break;
                            case 2:
                                node_obj.value.uint64 = *(uint16_t*)(cur_var->ref);
                                break;
                            case 4:
                                node_obj.value.uint64 = *(uint32_t*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.uint64 = *(uint64_t*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported uint size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeDouble:
                        node_obj.type = get_var_type_info(funcName, variables[i], "double", cur_var->size, TSNodeObjectTypeDouble);
                        switch (cur_var->size) {
                            case 4:
                                node_obj.value.double64 = *(float*)(cur_var->ref);
                                break;
                            case 8:
                                node_obj.value.double64 = *(double*)(cur_var->ref);
                                break;
                            case 16:
                                node_obj.value.double64 = *(long double*)(cur_var->ref);
                                break;
                            default:
                                PRINTF_ERROR("Unsupported double size for variable %s: %" PRIu32 "\n", variables[i], cur_var->size);
                                break;
                        }
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypePointer:
                    case MetaproVarTypeArray: {
                        // struct_type_name is the "<type>:<size>" descriptor of the pointee, or of the
                        // element when the variable is an array
                        char pointee_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t pointee_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, pointee_name, sizeof(pointee_name), &pointee_size);
                        TSNodeObjectType pointee_category = ts_interpreter_get_category_type(pointee_name);
                        if (pointee_category == TSNodeObjectTypeUnknown) {
                            WRITE_DEBUG_TO_FILE("Unknown pointee type: %s of %s\n", pointee_name, cur_var->name);
                        }
                        node_obj.array_element_type = ts_interpreter_get_type_info(pointee_name, pointee_size,
                                pointee_category);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        /* An array is as wide as all of its elements together, which is what a
                           `sizeof` of it answers; a pointer variable is one address wide */
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                (cur_var->type == MetaproVarTypeArray) ? cur_var->size : (uint32_t)sizeof(void*),
                                TSNodeObjectTypePointer);
                        // An array is registered as itself, so `ref` already is the elements: it is both
                        // the value of the pointer and the reference the interpreter subscripts off. A
                        // pointer variable holds the address instead, so that has to be read out of it.
                        node_obj.value.pointer = (cur_var->type == MetaproVarTypeArray)
                                ? (void*)cur_var->ref : *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStruct: {
                        // struct_type_name is the "<type>:<size>" descriptor, and the interpreter looks the
                        // record up by name, so the size has to be split off it
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.type = ts_interpreter_get_type_info(record_name, record_size, TSNodeObjectTypeStruct);
                        node_obj.value.pointer = (void*)cur_var->ref; // A struct is represented by its address
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeStructPointer: {
                        // The descriptor of a struct pointer names the struct it points to, not the pointer
                        char record_name[TS_MAX_TYPE_NAME_SIZE];
                        uint32_t record_size = 0;
                        split_type_descriptor(cur_var->struct_type_name, record_name, sizeof(record_name), &record_size);
                        node_obj.array_element_type = ts_interpreter_get_type_info(record_name, record_size,
                                TSNodeObjectTypeStruct);
                        // The declared name is preferred over "<pointee>*", which is built from a category
                        TSTypeInfo pointer_type = ts_interpreter_get_pointer_type_info(node_obj.array_element_type);
                        node_obj.type = get_var_type_info(funcName, variables[i], pointer_type.name,
                                sizeof(void*), TSNodeObjectTypePointer);
                        node_obj.value.pointer = *(void**)(cur_var->ref);
                        node_obj.reference = cur_var->ref;
                    }
                        break;
                    case MetaproVarTypeFunctionVoid:
                        node_obj.type = ts_interpreter_get_type_info("void", sizeof(void (*)()), TSNodeObjectTypeFunctionVoid);
                        node_obj.value.void_func = (void (*)())(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionInt:
                        node_obj.type = ts_interpreter_get_type_info("int", sizeof(int64_t (*)(void)), TSNodeObjectTypeFunctionInt);
                        node_obj.value.int_func = (int64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionUInt:
                        node_obj.type = ts_interpreter_get_type_info("uint", sizeof(uint64_t (*)(void)), TSNodeObjectTypeFunctionUInt);
                        node_obj.value.uint_func = (uint64_t (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        break;
                    case MetaproVarTypeFunctionPointer: {
                        node_obj.type = ts_interpreter_get_type_info("pointer", sizeof(void* (*)(void)), TSNodeObjectTypeFunctionPointer);
                        node_obj.value.pointer_func = (void* (*)(void))(cur_var->ref);
                        node_obj.reference=cur_var->ref;
                        /* struct_type_name of a pointer returning function is the type it returns a
                           pointer to, a plain name rather than a "<type>:<size>" descriptor. Resolving it
                           gives the call its element type, so the result can be subscripted and, for a
                           record, have its fields reached */
                        TSTypeInfo returned_type;
                        TSTypeInfo returned_element_type;
                        if (ts_interpreter_resolve_type(cur_var->struct_type_name, type_info_table,
                                                        &returned_type, &returned_element_type)) {
                            node_obj.array_element_type = returned_type;
                        }
                        break;
                    }
                    default: {
                        PRINTF_ERROR("Unsupported variable type in exec expr: %d\n", cur_var->type);
                    }
                }
                node_obj_array[node_obj_count]=node_obj;
                node_obj_count++;
            }
        }
        // Add control flow stmts in array
        TSNodeObject continue_obj = {0}; // TSTypeInfo holds a name, so zero it instead of leaving garbage
        continue_obj.type.category = TSNodeObjectTypeJmpBuf;
        continue_obj.type.size = sizeof(jmp_buf);
        continue_obj.value.jmpbuf = &__metapro_continue_jmp_bufs[jumpId];
        continue_obj.reference = &__metapro_continue_jmp_bufs[jumpId];
        continue_obj.name = "continue";
        node_obj_array[node_obj_count++] = continue_obj;

        TSNodeObject break_obj = {0}; // TSTypeInfo holds a name, so zero it instead of leaving garbage
        break_obj.type.category = TSNodeObjectTypeJmpBuf;
        break_obj.type.size = sizeof(jmp_buf);
        break_obj.value.jmpbuf = &__metapro_break_jmp_bufs[jumpId];
        break_obj.reference = &__metapro_break_jmp_bufs[jumpId];
        break_obj.name = "break";
        node_obj_array[node_obj_count++] = break_obj;

        for (size_t i=0;i<__metapro_goto_jmp_count;i++) {
            TSNodeObject goto_obj = {0}; // TSTypeInfo holds a name, so zero it instead of leaving garbage
            goto_obj.type.category = TSNodeObjectTypeJmpBuf;
            goto_obj.type.size = sizeof(jmp_buf);
            char* name = __metapro_goto_jmp_names[i];
            goto_obj.name = malloc(strlen(name) + 7);
            sprintf(goto_obj.name, "goto %s", extract_label(name, funcName));
            goto_obj.value.jmpbuf = &__metapro_goto_jmps[i];
            goto_obj.reference = &__metapro_goto_jmps[i];
            node_obj_array[node_obj_count++] = goto_obj;
        }

        __metapro_return_label_info* return_label = __metapro_find_return_label(funcName);
        if (return_label != NULL) {
            TSNodeObject return_obj = {0}; // TSTypeInfo holds a name, so zero it instead of leaving garbage
            return_obj.type.category = TSNodeObjectTypeJmpBuf;
            return_obj.type.size = sizeof(jmp_buf);
            return_obj.value.jmpbuf = &return_label->jmpbuf;
            return_obj.reference = &return_label->jmpbuf;
            return_obj.name = "return";
            return_obj.array_element_type.size = id; // Use the element size to store ID for return, to distinguish with other jmps
            node_obj_array[node_obj_count++] = return_obj;
        }

        TSNodeObject result=ts_interpreter_simulate(root_node,node_obj_count,node_obj_array,type_info_table);
        if (uncached_tree != NULL) ts_tree_delete(uncached_tree); // Parsed for this run only
        for (size_t i=0;i<var_count;i++) {
            free(variables[i]);
        }
        if (TS_NODE_COUNT_STMT_EXPR) ts_node_print_stmt_expr_counter();
    }
}

int64_t __metapro_replace_int_var_c(uint64_t id, int64_t original,
                                    uint64_t int_var_count, uint32_t* int_var_sizes, char** int_var_names, int64_t* int_vars,
                                    uint64_t uint_var_count, uint32_t* uint_var_sizes, char** uint_var_names, uint64_t* uint_vars) {
    char* patch_id=getenv("METAPRO_PATCH_ID");
    if (!patch_id) return original;
    else if ((uint32_t)strtoul(patch_id, NULL, 10)==id) {
        if (!getenv("METAPRO_PATCH_MODE") || strcmp(getenv("METAPRO_PATCH_MODE"),"patch")==0) {
            const char* expr=getenv("METAPRO_PATCH_EXPR_1");

            for (size_t i=0;i<int_var_count;i++) {
                if (strcmp(int_var_names[i],expr)==0) {
                    return int_vars[i];
                }
            }

            for (size_t i=0;i<uint_var_count;i++) {
                if (strcmp(uint_var_names[i],expr)==0) {
                    return uint_vars[i];
                }
            }

            return atoll(expr);
        }
    }
    return original;
}

uint64_t __metapro_replace_uint_var_c(uint64_t id, uint64_t original,
                                    uint64_t int_var_count, uint32_t* int_var_sizes, char** int_var_names, int64_t* int_vars,
                                    uint64_t uint_var_count, uint32_t* uint_var_sizes, char** uint_var_names, uint64_t* uint_vars) {
    char* patch_id=getenv("METAPRO_PATCH_ID");
    if (!patch_id) return original;
    else if ((uint32_t)strtoul(patch_id, NULL, 10)==id) {
        if (!getenv("METAPRO_PATCH_MODE") || strcmp(getenv("METAPRO_PATCH_MODE"),"patch")==0) {
            const char* expr=getenv("METAPRO_PATCH_EXPR_1");

            for (size_t i=0;i<int_var_count;i++) {
                if (strcmp(int_var_names[i],expr)==0) {
                    return int_vars[i];
                }
            }

            for (size_t i=0;i<uint_var_count;i++) {
                if (strcmp(uint_var_names[i],expr)==0) {
                    return uint_vars[i];
                }
            }

            return atoll(expr);
        }
    }
    return original;
}

__metapro_int_func_type_c __metapro_replace_int_func_c(uint64_t id, __metapro_int_func_type_c orig_func,
                uint64_t func_number, char** new_func_names, __metapro_int_func_type_c* new_funcs) {
    char* patch_id=getenv("METAPRO_PATCH_ID");
    if (!patch_id) return orig_func;
    if ((uint32_t)strtoul(patch_id, NULL, 10)!=id) return orig_func;

    char* func_name=getenv("METAPRO_PATCH_EXPR_1");
    for (size_t i=0;i<func_number;i++) {
        if (strcmp(func_name,new_func_names[i])==0) {
            return new_funcs[i];
        }
    }
    PRINTF_ERROR("Invalid function name!\n");
}

__metapro_uint_func_type_c __metapro_replace_uint_func_c(uint64_t id, __metapro_uint_func_type_c orig_func,
                uint64_t func_number, char** new_func_names, __metapro_uint_func_type_c* new_funcs) {
    char* patch_id=getenv("METAPRO_PATCH_ID");
    if (!patch_id) return orig_func;
    if ((uint32_t)strtoul(patch_id, NULL, 10)!=id) return orig_func;

    char* func_name=getenv("METAPRO_PATCH_EXPR_1");
    for (size_t i=0;i<func_number;i++) {
        if (strcmp(func_name,new_func_names[i])==0) {
            return new_funcs[i];
        }
    }
    PRINTF_ERROR("Invalid function name!\n");
}

__metapro_void_func_type_c __metapro_replace_void_func_c(uint64_t id, __metapro_void_func_type_c orig_func,
                uint64_t func_number, char** new_func_names, __metapro_void_func_type_c* new_funcs) {
    char* patch_id=getenv("METAPRO_PATCH_ID");
    if (!patch_id) return orig_func;
    if ((uint32_t)strtoul(patch_id, NULL, 10)!=id) return orig_func;

    char* func_name=getenv("METAPRO_PATCH_EXPR_1");
    for (size_t i=0;i<func_number;i++) {
        if (strcmp(func_name,new_func_names[i])==0) {
            return new_funcs[i];
        }
    }
    PRINTF_ERROR("Invalid function name!\n");
}

const char* __metapro_replace_string_literal_c(uint64_t id, const char* orig_str) {
    char* patch_id=getenv("METAPRO_PATCH_ID");
    if (!patch_id) return orig_str;
    if ((uint32_t)strtoul(patch_id, NULL, 10)!=id) return orig_str;

    return getenv("METAPRO_PATCH_EXPR_1");
}

int32_t __metapro_env_to_int_c(const char* env) {
    char* cur_env=getenv(env);
    if(cur_env==NULL) return -1;
    return atoi(cur_env);
}

void __metapro_mark_block_c(void) {}

void __metapro_noop(uint64_t id) {
    WRITE_DEBUG_TO_FILE("No-op called with ID: %" PRIu64 "\n", id);
}