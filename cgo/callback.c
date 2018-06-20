#include "callback.h"
#include <stdio.h>

// _cgo_export.h is auto-generated and has Go //export funcs
#include "_cgo_export.h"

void add(int x, int y, void (*result_callback)(int)) {
  printf("C says: adding %i and %i\n", x, y);
  int total = x + y;

  // Call function pointer
  result_callback(total);
}

void c_to_go_callback(int total) {
  printf("C callback got total %i\n", total);
  InitHandler();
  Hello();
  GoTotalCallback(total);
}

void add_with_go_callback(int x, int y) {
  printf("C passing Go function pointer..\n");
  // Within C you can pass an exported Go func as a pointer
  add(x, y, GoTotalCallback);
}