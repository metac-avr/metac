#include <stdio.h>
#include <stdlib.h>

struct A {
  int ax;
  int ay;
  struct A* aptr;
};

struct B {
  struct A ba;
  int bx;
  struct A* baptr;
};

int main(int argc, char *argv[]) {
  if (argc!=3) {
    printf("Usage: %s <a> <b>\n", argv[0]);
    return 1;
  }
  
  struct A a = {atoi(argv[1]), atoi(argv[2]), NULL};
  struct B b;
  b.ba = a;
  b.baptr = &a;

  // Access A directly
  printf("a.ax = %d, a.ay = %d\n", a.ax, a.ay);

  // Access A with B.ba
  printf("b.ba.ax = %d, b.ba.ay = %d\n", b.ba.ax, b.ba.ay);

  // Access A with B.baptr
  printf("b.baptr->ax = %d, b.baptr->ay = %d\n", b.baptr->ax, b.baptr->ay);

  // Final field is null
  printf("a.aptr->ax = %d\n", a.aptr->ax);

  // Multiple pointer field
  struct A a2 = {atoi(argv[1]) * 100, atoi(argv[2]) * 100, NULL};
  a.aptr = &a2;
  printf("b->baptr->aptr->ax = %d\n", b.baptr->aptr->ax);
  return 0;
}
