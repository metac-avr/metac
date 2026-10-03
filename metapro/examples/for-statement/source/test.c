#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  if (argc!=2) {
    printf("Usage: %s <a>\n", argv[0]);
    return 1;
  }

  int a[5] = {1, 2, 3, 4, 5};
  
  for (int i=0;i < atoi(argv[1]);i++) {
    printf("%d ", a[i]); // Out-of-bounds when i >= 5
  }
  printf("\n");
  return 0;
}
