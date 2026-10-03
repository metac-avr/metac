#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * String example for metapro.
 * 
 * This example is to check metapro can handle string literals, string variables or function calls.
 * 
 * If either of the input strings is "hello", it prints a message. Otherwise, it aborts.
 * Metapro should avoid abort with new condition.
 */
int main(int argc, char *argv[]) {
  if (argc!=3) {
    printf("Usage: %s <string_a> <string_b>\n", argv[0]);
    return 1;
  }
  
  const char* str_a = argv[1];
  const char* str_b = argv[2];
  if (strcmp(str_a, "hello") == 0 || strcmp(str_b, "hello") == 0) {
    printf("One of the strings are hello.\n");
  } else {
    abort();
  }
  return 0;
}
