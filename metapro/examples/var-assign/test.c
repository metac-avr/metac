#include "_runtime_c.h"
#include <stdio.h>
#include <stdlib.h>

void func(int a){
  
// INSERT
if (__metapro_new_cond_c(0, 1, (unsigned long long[]){sizeof (a)}, (char *[]){"a"}, (long long[]){a}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double[]){}, 0, (char *[]){}, (void *[]){}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){}))
    switch (__metapro_select_minor_id_c()) {
      case 2:
        {
            __metapro_insert_assign_c(0, 2, 1, (unsigned long long[]){sizeof (a)}, (char *[]){"a"}, (long long *[]){(long long *)&(a)}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long *[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double *[]){}, 0, (char *[]){}, (void **[]){}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){});
            break;
        }
      case 0:
        return;
      case 1:
        exit(1);
    }
int b=a;

  // if (b < 0) b = 0;
  
// INSERT
if (__metapro_new_cond_c(1, 2, (unsigned long long[]){sizeof (b), sizeof (a)}, (char *[]){"b", "a"}, (long long[]){b, a}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double[]){}, 0, (char *[]){}, (void *[]){}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){}))
    switch (__metapro_select_minor_id_c()) {
      case 2:
        {
            __metapro_insert_assign_c(1, 2, 2, (unsigned long long[]){sizeof (b), sizeof (a)}, (char *[]){"b", "a"}, (long long *[]){(long long *)&(b), (long long *)&(a)}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long *[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double *[]){}, 0, (char *[]){}, (void **[]){}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){});
            break;
        }
      case 0:
        return;
      case 1:
        exit(1);
    }

// REPLACE
if (__metapro_new_not_null_check_c(1, 0, 2, (unsigned long long[]){sizeof (b), sizeof (a)}, (char *[]){"b", "a"}, (long long[]){b, a}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double[]){}, 0, (char *[]){}, (void *[]){}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){}))
    printf("%d\n", b);
;

// INSERT
if (__metapro_new_cond_c(3, 2, (unsigned long long[]){sizeof (b), sizeof (a)}, (char *[]){"b", "a"}, (long long[]){b, a}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double[]){}, 0, (char *[]){}, (void *[]){}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){}))
    switch (__metapro_select_minor_id_c()) {
      case 0:
        {
            return;
            break;
        }
      case 1:
        exit(1);
    }
}

int main(int argc, char *argv[]) {
  
// INSERT
if (__metapro_new_cond_c(4, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long[]){argc}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double[]){}, 1, (char *[]){"argv"}, (void *[]){argv}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){}))
    switch (__metapro_select_minor_id_c()) {
      case 2:
        {
            __metapro_insert_assign_c(4, 2, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long *[]){(long long *)&(argc)}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long *[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double *[]){}, 1, (char *[]){"argv"}, (void **[]){(void **)&(argv)}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){});
            break;
        }
      case 0:
        return __metapro_get_int_var_c(4, 0, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long[]){argc}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0});
      case 1:
        exit(1);
    }
if (
// REPLACE
__metapro_replace_cond_c(10, argc != 2, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long[]){argc}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double[]){}, 1, (char *[]){"argv"}, (void *[]){argv}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){})) {
    printf("Usage: %s <a>\n", argv[0]);
    return 1;
  }
  
  
// INSERT
if (__metapro_new_cond_c(5, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long[]){argc}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double[]){}, 1, (char *[]){"argv"}, (void *[]){argv}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){}))
    switch (__metapro_select_minor_id_c()) {
      case 2:
        {
            __metapro_insert_assign_c(5, 2, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long *[]){(long long *)&(argc)}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long *[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double *[]){}, 1, (char *[]){"argv"}, (void **[]){(void **)&(argv)}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){});
            break;
        }
      case 0:
        return __metapro_get_int_var_c(5, 0, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long[]){argc}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0});
      case 1:
        exit(1);
    }

// REPLACE
if (__metapro_new_not_null_check_c(5, 0, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long[]){argc}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double[]){}, 1, (char *[]){"argv"}, (void *[]){argv}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){}))
    func(atoi(argv[1]));
;  
  
// INSERT
if (__metapro_new_cond_c(7, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long[]){argc}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double[]){}, 1, (char *[]){"argv"}, (void *[]){argv}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){}))
    switch (__metapro_select_minor_id_c()) {
      case 2:
        {
            __metapro_insert_assign_c(7, 2, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long *[]){(long long *)&(argc)}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long *[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double *[]){}, 1, (char *[]){"argv"}, (void **[]){(void **)&(argv)}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){});
            break;
        }
      case 0:
        return __metapro_get_int_var_c(7, 0, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long[]){argc}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0});
      case 1:
        exit(1);
    }

// REPLACE
if (__metapro_new_not_null_check_c(7, 0, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long[]){argc}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double[]){}, 1, (char *[]){"argv"}, (void *[]){argv}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){}))
    return 0;
;

// INSERT
if (__metapro_new_cond_c(9, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long[]){argc}, 0, (unsigned long long[]){}, (char *[]){}, (unsigned long long[]){}, 0, (unsigned long long[]){}, (char *[]){}, (long double[]){}, 1, (char *[]){"argv"}, (void *[]){argv}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0}, 11, (unsigned long long[]){sizeof (4278190080U), sizeof (16711680U), sizeof (65280U), sizeof (18374686479671623680ULL), sizeof (71776119061217280ULL), sizeof (280375465082880ULL), sizeof (1095216660480ULL), sizeof (4278190080ULL), sizeof (16711680ULL), sizeof (65280ULL), sizeof (255ULL)}, (unsigned long long[]){4278190080U, 16711680U, 65280U, 18374686479671623680ULL, 71776119061217280ULL, 280375465082880ULL, 1095216660480ULL, 4278190080ULL, 16711680ULL, 65280ULL, 255ULL}, 0, (unsigned long long[]){}, (long double[]){}))
    switch (__metapro_select_minor_id_c()) {
      case 0:
        {
            return __metapro_get_int_var_c(9, 0, 1, (unsigned long long[]){sizeof (argc)}, (char *[]){"argc"}, (long long[]){argc}, 16, (unsigned long long[]){sizeof (2), sizeof (4), sizeof (1), sizeof (15), sizeof (20), sizeof (8), sizeof (255), sizeof (24), sizeof (56), sizeof (40), sizeof (1024), sizeof (7), sizeof (48), sizeof (32), sizeof (3), sizeof (0)}, (long long[]){2, 4, 1, 15, 20, 8, 255, 24, 56, 40, 1024, 7, 48, 32, 3, 0});
            break;
        }
      case 1:
        exit(1);
    }
}
