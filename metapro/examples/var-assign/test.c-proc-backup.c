#include <stdio.h>
#include <stdlib.h>

void func(int a){
  int b=a;

  // if (b < 0) b = 0;
  printf("%d\n", b);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <a>\n", argv[0]);
    return 1;
  }
  
  func(atoi(argv[1]));  
  return 0;
}
