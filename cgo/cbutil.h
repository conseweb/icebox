#ifndef CALLBACK_UTIL_H
#define CALLBACK_UTIL_H

typedef void (*callback)(void *);

static callback _cb;
static void *_user_data;

static void register_callback(callback cb, void *user_data) {
    _cb = cb;
    _user_data = user_data;
}

static void wait_event() {
    _cb(_user_data);
}

void cb_proxy(void *v);

static void _register_callback(void *user_data) {
  register_callback(cb_proxy, user_data);
}

#endif