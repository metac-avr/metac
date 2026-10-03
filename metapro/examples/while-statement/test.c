#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  if (argc!=2) {
    printf("Usage: %s <a>\n", argv[0]);
    return 1;
  }
  
  int i=0;
  while (i < atoi(argv[1])) { // i < atoi(argv[1]) && i < 5
    printf("%d ", i);
    i++;
  }
  printf("\n");
  return 0;
}
