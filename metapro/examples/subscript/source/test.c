#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Subscript example for metapro.
 * 
 * When <index> == 4, j == 5 and crash in b[j].
 * if (a[i] == 5) return 1; to avoid crash.
 */
int main(int argc, char *argv[]) {
  if (argc!=2) {
    printf("Usage: %s <index>\n", argv[0]);
    return 1;
  }
  
  int a[5] = {1, 2, 3, 4, 5};
  int b[5] = {10, 20, 30, 40, 50};

  int i = atoi(argv[1]);
  if (i < 0 || i >= 5) {
    return 1;
  }
  int j = a[i];

  int v = b[j];
  printf("%d\n", v);

  return 0;
}
