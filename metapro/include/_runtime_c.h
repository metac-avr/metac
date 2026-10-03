#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "utils/uthash/uthash.h"
#include <setjmp.h>

/* Jumps for continue, break and goto stmt */
extern jmp_buf __metapro_continue_jmp_bufs[50000]; // To handle continue
extern jmp_buf __metapro_break_jmp_bufs[50000]; // To handle break

extern char* __metapro_goto_jmp_names[50000];
extern jmp_buf __metapro_goto_jmps[50000];
extern uint32_t __metapro_goto_jmp_count;

void __metapro_add_goto(char* jmp_label);
uint32_t __metapro_find_goto_jmp(char* jmp_label);

typedef struct __metapro_return_label_info {
    char func_name[200];
    jmp_buf jmpbuf;
    UT_hash_handle hh;
} __metapro_return_label_info;

extern __metapro_return_label_info* __metapro_return_labels;

void __metapro_add_return(char* func_name);
__metapro_return_label_info* __metapro_find_return_label(char* func_name);

typedef struct __metapro_var_info {
    char name[30];
    const void* ref; // pointer to the variable. This is because we don't want to update the value manually.
    uint32_t size;
    enum {
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
} __metapro_var_info;

typedef struct __metapro_function_var_info {
    char func_id[100];
    __metapro_var_info* var_info_table; // hashtable of __metapro_var_info
    UT_hash_handle hh;
} __metapro_function_var_info;

extern __metapro_function_var_info* __metapro_var_info_tables;

#define __metapro_func_var_clean(func_name) \
    do { \
        __metapro_function_var_info* func_var_info = NULL; \
        HASH_FIND_STR(__metapro_var_info_tables, #func_name, func_var_info); \
        if (func_var_info != NULL) { \
            __metapro_var_info* current_var, *tmp; \
            HASH_ITER(hh, func_var_info->var_info_table, current_var, tmp) { \
                HASH_DEL(func_var_info->var_info_table, current_var); \
                free(current_var); \
            } \
            HASH_DEL(__metapro_var_info_tables, func_var_info); \
            free(func_var_info); \
        } \
    } while(0)

#define __metapro_get_var_value(func_name, var_name, out_ptr) \
    do { \
        __metapro_function_var_info* func_var_info = NULL; \
        HASH_FIND_STR(__metapro_var_info_tables, func_name, func_var_info); \
        if (func_var_info == NULL) { \
            /* No variable table for this function (yet): out_ptr has to be set here, or it is left \
               at whatever __metapro_var_info* the caller's stack slot happened to hold -- garbage \
               that ends up dereferenced as a pointer at the call site. */ \
            out_ptr = NULL; \
            break; \
        } \
        __metapro_var_info* var_info_table = func_var_info->var_info_table; \
        __metapro_var_info* var_info = NULL; \
        char var_name_buf[40]; \
        sprintf(var_name_buf, "%s", var_name); \
        HASH_FIND_STR(var_info_table, var_name_buf, var_info); \
        if (var_info == NULL) { \
            sprintf(var_name_buf, "%s-1", var_name); \
            HASH_FIND_STR(var_info_table, var_name_buf, var_info); \
            if (var_info == NULL) { \
                sprintf(var_name_buf, "%s-2", var_name); \
                HASH_FIND_STR(var_info_table, var_name_buf, var_info); /* Try 5 times to handle same variable in different scope */ \
                if (var_info == NULL) { \
                    sprintf(var_name_buf, "%s-3", var_name); \
                    HASH_FIND_STR(var_info_table, var_name_buf, var_info); \
                    if (var_info == NULL) { \
                        sprintf(var_name_buf, "%s-4", var_name); \
                        HASH_FIND_STR(var_info_table, var_name_buf, var_info); \
                    } \
                } \
            } \
        } \
        if (var_info != NULL) { \
            out_ptr = var_info; \
        } \
        else { \
            out_ptr = NULL; \
        } \
    } while(0)

#define __metapro_get_func_var_info(func_name, out_func_var_info) \
    HASH_FIND_STR(__metapro_var_info_tables, func_name, out_func_var_info)

void __metapro_func_var_init_c(char* func_name);
void __metapro_remove_var_info_c(char* funcName, char* varName);
void __metapro_table_remove_var_c(char* func_name, char* var_name);
/**
 * Insert variable info to the hashtable
 * var_name: name of the variable (should be string literal)
 * ref_ptr: pointer to the variable
 * var_size: size of the variable
 * var_type: type of the variable (MetaproVarType*)
 * struct_type: name of the struct type if the variable is struct or struct pointer; NULL otherwise
 */
void __metapro_table_insert_var_c(char* func_name, char* var_name, const void* ref_ptr, uint32_t var_size, int var_type, char* struct_type);

/**
 * Register a variable while it is being initialized, and evaluate to init_value.
 *
 * This is for a declaration that cannot be followed by a statement, i.e. the init clause of a for
 * statement, where a registration inserted into the body would only run after the condition has already
 * been evaluated once:
 *
 *     for (int i = __metapro_init_var_c("f", "i", &i, sizeof(int), MetaproVarTypeInt, NULL, 0);
 *             __metapro_replace_cond_c(1, "i < 64", (unsigned int)(i < 64), "f"); i++)
 *
 * Taking &i here is well defined, because a variable is in scope in its own initializer, and the comma
 * operator registers it before init_value is evaluated. The arguments are those of
 * __metapro_table_insert_var_c(), so only a scalar variable fits: an array is registered through a temp
 * holding its address, which needs a declaration of its own.
 */
#define __metapro_init_var_c(func_name, var_name, ref_ptr, var_size, var_type, struct_type, init_value) \
    (__metapro_table_insert_var_c(func_name, var_name, ref_ptr, var_size, var_type, struct_type), (init_value))

/**
 * Register the global variables holding a function that are visible at the entry of func_name.
 *
 * A patch expression may call one of them -- libxml2 calls its allocator through `xmlReallocFunc
 * xmlRealloc`, a variable, not a function -- and such a name is in neither function-info.json nor the
 * symbol table, so the interpreter cannot resolve it on its own. The meta-program passes them here
 * instead, at the entry of every function it instruments, and the runtime keeps them in a table of its
 * own that __metapro_bind_function_c() consults first.
 *
 * The variables are grouped by what the function they hold returns, which is the only thing the
 * interpreter needs to know to call one: names[i] is the name the expression spells and refs[i] is
 * `(void*)&<variable>` -- the address of the variable, not the function in it, so a program that
 * replaces it later (xmlMemSetup()) is followed rather than remembered. A group with nothing in it
 * passes 0, NULL, NULL.
 *
 * @param func_name function being entered; nothing is registered unless a patch targets it
 * @param void_count/void_names/void_refs variables holding a function returning void
 * @param int_count/int_names/int_refs variables holding a function returning a signed integer
 * @param uint_count/uint_names/uint_refs variables holding a function returning an unsigned integer
 * @param ptr_count/ptr_names/ptr_refs variables holding a function returning a pointer
 */
void __metapro_register_func_ptrs_c(char* func_name,
        uint64_t void_count, char** void_names, void** void_refs,
        uint64_t int_count, char** int_names, void** int_refs,
        uint64_t uint_count, char** uint_names, void** uint_refs,
        uint64_t ptr_count, char** ptr_names, void** ptr_refs);

uint32_t __metapro_new_cond_c(uint32_t id, char* funcName);
uint32_t __metapro_new_not_null_check_c(uint32_t id, char* funcName);
int64_t __metapro_get_int_var_c(uint32_t id, char* funcName);
uint64_t __metapro_get_uint_var_c(uint32_t id, char* funcName);
void* __metapro_get_ptr_var_c(uint32_t id, char* funcName);
/*
    Condition of a patched statement.

    The original condition is not an argument of the call: it is a macro parameter, so it is compiled where
    the macro spells it out and runs only in the branches below that mention it. A patch that replaces the
    condition outright therefore never evaluates it, which is what lets a patch guard a fault that lies in
    the condition itself -- libxml2-42522290 (`if (CUR == 0)` -> `if ((ctxt->input->cur < ctxt->input->end)
    && ...)`) and mruby-42513620 (`y->p[1] > 1` -> `y->sz < 2 || y->p[1] > 1`) are both of that shape.

    __metapro_cond_c() runs in two phases. It is first asked to decide without the original, and answers
    either with the result, or with one of the codes below saying what it needs:

        METAPRO_COND_ORIG        the result is the original: the macro evaluates it and that is the value
        METAPRO_COND_ORIG_NOT    the result is its negation, for the "!" patch
        METAPRO_COND_ORIG_FIRST  the patch reads "<orig> && <new>" or "<orig> || <new>", so the original
                                 goes first: the macro evaluates it and calls again with has_orig set, and
                                 the second phase interprets <new> only if the original did not settle it

    So whichever side of the operator the original sits on, it is evaluated natively, at most once, and in
    the order the patch text says.

    __metapro_cond_res holds what the first phase answered, because a call of the second phase carries the
    value it needs and a plain expression has nowhere else to keep it. Every read of it happens before any
    of the program's own code runs: the original condition is evaluated only in a branch that has already
    stopped consulting it, so a patched condition reached from inside the original cannot disturb the
    evaluation around it.
*/
#define METAPRO_COND_ORIG       2u
#define METAPRO_COND_ORIG_NOT   3u
#define METAPRO_COND_ORIG_FIRST 4u

extern _Thread_local uint32_t __metapro_cond_res;

/*
    @param has_orig   0 to decide without the original, 1 when orig_cond carries its value
    @param orig_cond  value of the original condition, read only when has_orig is 1
*/
uint32_t __metapro_cond_c(uint32_t id, char* orig_cond_str, char* funcName, int has_orig, uint32_t orig_cond);

/* The original condition is (orig_cond), and stays unevaluated unless a branch below names it */
#define __metapro_replace_cond_c(id, orig_str, orig_cond, func) \
    (((__metapro_cond_res = __metapro_cond_c((id), (orig_str), (func), 0, 0)) \
             == METAPRO_COND_ORIG)                     ? (orig_cond) \
    : (__metapro_cond_res == METAPRO_COND_ORIG_NOT)    ? (unsigned int)(!(orig_cond)) \
    : (__metapro_cond_res == METAPRO_COND_ORIG_FIRST)  ? __metapro_cond_c((id), (orig_str), (func), 1, (orig_cond)) \
    : __metapro_cond_res)
void __metapro_exec_expr_c(uint32_t id, char* funcName, uint32_t jumpId);

// For debugging: do not insert in meta-program in actual use
void __metapro_print_var_table_c(char* funcName);
int64_t __metapro_replace_int_var_c(uint64_t id, int64_t original,
                                    uint64_t int_var_count, uint32_t* int_var_sizes, char** int_var_names, int64_t* int_vars,
                                    uint64_t uint_var_count, uint32_t* uint_var_sizes, char** uint_var_names, uint64_t* uint_vars);

uint64_t __metapro_replace_uint_var_c(uint64_t id, uint64_t original,
                                    uint64_t int_var_count, uint32_t* int_var_sizes, char** int_var_names, int64_t* int_vars,
                                    uint64_t uint_var_count, uint32_t* uint_var_sizes, char** uint_var_names, uint64_t* uint_vars);

typedef int64_t (*__metapro_int_func_type_c)();
typedef uint64_t (*__metapro_uint_func_type_c)();
typedef void (*__metapro_void_func_type_c)();

__metapro_int_func_type_c __metapro_replace_int_func_c(uint64_t id, __metapro_int_func_type_c orig_func,
                uint64_t func_number, char** new_func_names, __metapro_int_func_type_c* new_funcs);
__metapro_uint_func_type_c __metapro_replace_uint_func_c(uint64_t id, __metapro_uint_func_type_c orig_func,
                uint64_t func_number, char** new_func_names, __metapro_uint_func_type_c* new_funcs);
__metapro_void_func_type_c __metapro_replace_void_func_c(uint64_t id, __metapro_void_func_type_c orig_func,
                uint64_t func_number, char** new_func_names, __metapro_void_func_type_c* new_funcs);

const char* __metapro_replace_string_literal_c(uint64_t id, const char* orig_str);

int32_t __metapro_env_to_int_c(const char* env);

void __metapro_mark_block_c(void);

// Force the linker to emit PLT entries for runtime functions the binary
// patcher injects calls to, even when no source-level patch references them.
// The body is unreachable at runtime (volatile guard prevents the compiler
// from folding it away) but the `call ...@plt` instructions survive in the
// object file, producing JUMP_SLOT relocations that materialize as PLT
// entries in the final binary. `retain` keeps the function past --gc-sections
// (clang 13+/GCC 11+); on older toolchains we fall back to `used` alone.
#if defined(__has_attribute) && __has_attribute(retain)
__attribute__((used, retain))
#else
__attribute__((used))
#endif
static void __metapro_runtime_keepalive(void) {
    volatile int never = 0;
    if (never) {
        __metapro_new_cond_c(0, 0);
        __metapro_new_not_null_check_c(0, 0);
        __metapro_exec_expr_c(0, 0, 0);
        printf("");
    }
}

#ifdef __GLIBC__
#undef __GLIBC__
#endif