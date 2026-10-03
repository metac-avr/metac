/**
    Wrapper for metapro runtime library for e9patch.

    E9Patch requires special gcc wrapper, so we wrap the runtime library functions to thin wrapper
    to avoid compiling whole library with gcc wrapper.
 */
#define LIBDL
#include <stdint.h>
#include "/usr/share/e9compile/include/stdlib.c"

static void* runtime_lib = NULL;
static void* exec_expr_func = NULL;
static void* new_not_null_check_func = NULL;

void patch_insert_expr(uint64_t id, const char* funcName, uint32_t jumpId) {
    dlcall(exec_expr_func, id, (char*)funcName, jumpId);
}

// Return destination address if the check is 0, otherwise return 0
uint64_t patch_insert_if_wrapper(uint64_t id, const char* funcName, uint64_t destAddr) {
    if ((uint32_t)dlcall(new_not_null_check_func, id, (char*)funcName)) {
        return 0;
    } else {
        return destAddr;
    }
}


void entry(void) {}
void init(int argc, char **argv, char **envp, void* dynamic) {
    int result = dlinit(dynamic);
    if (result != 0) {
        // Handle error
        fprintf(stderr, "Error initializing dynamic loading!\n");
        return;
    }

    runtime_lib = dlopen("/usr/local/lib/libmetapro-runtime-c.so", RTLD_LAZY);
    if (!runtime_lib) {
        // Handle error
        fprintf(stderr, "Error loading runtime library!\n");
        return;
    }

    // Insert statement function
    exec_expr_func = dlsym(runtime_lib, "__metapro_exec_expr_c");
    if (!exec_expr_func) {
        // Handle error
        fprintf(stderr, "Error loading function __metapro_exec_expr_c!\n");
        return;
    }

    // If wrapper function
    new_not_null_check_func = dlsym(runtime_lib, "__metapro_new_not_null_check_c");
    if (!new_not_null_check_func) {
        // Handle error
        fprintf(stderr, "Error loading function __metapro_new_not_null_check_c!\n");
        return;
    }
}