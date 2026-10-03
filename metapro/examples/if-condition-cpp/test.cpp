#include <cstdio>
#include <cstdlib>

void func(int a, int b){
  if (a == 1 && b == 1) { // (a == 1 && b == 1) || b == 2
    printf("%d\n", 0);
  } else {
    printf("%d\n", 1);
  }
}

int main(int argc, char *argv[]) {
  if (argc!=3) {
    printf("Usage: %s <a> <b>\n", argv[0]);
    return 1;
  }
  
  func(atoi(argv[1]), atoi(argv[2]));
  return 0;
}
