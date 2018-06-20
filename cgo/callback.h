#ifndef CALLBACK_H
#define CALLBACK_H

// This typedef is used by Go
typedef void (*callback_fn) ();

void c_to_go_callback(int total);

void add_with_go_callback(int x, int y);

void add(int x, int y, void (*result_callback)(int));

#endif