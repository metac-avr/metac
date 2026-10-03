#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Goto example for metapro.
 * 
 * Crash when <index> > 5.
 * goto error; to avoid crash.
 */
int main(int argc, char *argv[]) {
  if (argc!=2) {
    printf("Usage: %s <index>\n", argv[0]);
    return 1;
  }
  
  int a[5] = {1, 2, 3, 4, 5};
  int i = atoi(argv[1]);
  printf("%d\n", a[i]);

  return 0;

error:
  fprintf(stderr, "Out of index %d\n", i);
  return 1;
}
