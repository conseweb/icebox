/* Created by "go tool cgo" - DO NOT EDIT. */

/* package command-line-arguments */


#line 1 "cgo-builtin-prolog"

#include <stddef.h> /* for ptrdiff_t below */

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

typedef struct { const char *p; ptrdiff_t n; } _GoString_;

#endif

/* Start of preamble from import "C" comments.  */


#line 3 "/Users/michael/gopath/src/github.com/conseweb/icebox/cgo/icebox.c.go"


// This typedef is used by Go
typedef void (*callback_fn) (void*, int);

extern void my_callback(void*);
extern int execute_cb(void*, int);
//extern GoSlice Hello(void*);

static void my_job(void *p) {
  my_callback(p);
  execute_cb(p, 20);
}


#line 1 "cgo-generated-wrapper"


/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef __SIZE_TYPE__ GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

typedef _GoString_ GoString;
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif


extern GoString CGetErrInfo();

extern GoSlice CEncodeIceboxMessage(GoInt32 p0, GoSlice p1);

extern GoSlice CEncodeIceboxMessageWithSID(GoInt32 p0, GoUint32 p1, GoSlice p2);

extern GoSlice CEncodeHiRequest(GoInt64 p0);

extern GoSlice CEncodeNegotiateRequest(GoString p0, GoString p1);

extern GoSlice CEncodeStartRequest();

extern GoSlice CEncodeCheckRequest();

extern GoSlice CEncodeInitRequest(GoString p0);

extern GoSlice CEncodePingRequest();

extern GoSlice CEncodeAddCoinRequest(GoUint32 p0, GoUint32 p1, GoString p2, GoString p3);

extern GoSlice CEncodeCreateAddressRequest(GoUint32 p0, GoString p1);

extern GoSlice CEncodeCreateSecretRequest(GoUint32 p0, GoUint32 p1, GoUint32 p2, GoString p3);

extern GoSlice CEncodeGetAddressRequest(GoUint32 p0, GoUint32 p1, GoString p2);

extern GoSlice CEncodeListAddressRequest(GoUint32 p0, GoUint32 p1, GoUint32 p2, GoString p3);

extern GoSlice CEncodeListSecretRequest(GoUint32 p0, GoUint32 p1, GoUint32 p2, GoUint32 p3, GoString p4);

extern GoSlice CEncodeDeleteAddressRequest(GoUint32 p0, GoUint32 p1, GoString p2);

extern GoSlice CEncodeSignTxRequest(GoUint32 p0, GoUint32 p1, GoUint64 p2, GoString p3, GoSlice p4, GoUint32 p5, GoString p6);

extern GoSlice CEncodeSignMsgRequest(GoUint32 p0, GoUint32 p1, GoSlice p2, GoString p3);

extern GoSlice CEncodeResetRequest();

extern GoSlice CEncodeHiReply(GoInt64 p0);

extern GoSlice CEncodeNegotiateReply(GoString p0, GoString p1);

extern GoSlice CEncodeCheckReply(GoInt32 p0, GoString* p1);

extern GoSlice CEncodeInitReply(GoSlice p0);

extern GoSlice CEncodePingReply();

extern GoSlice CEncodeStartReply();

extern GoSlice CEncodeAddCoinReply();

extern GoSlice CEncodeCreateAddressReply(GoUint32 p0, GoUint32 p1, GoString p2);

extern GoSlice CEncodeCreateSecretReply(GoUint32 p0, GoUint32 p1, GoUint32 p2, GoUint32 p3, GoSlice p4);

extern GoSlice CEncodeDeleteAddressReply(GoString p0);

extern GoSlice CEncodeSignTxReply(GoSlice p0);

extern GoSlice CEncodeSignMsgReply(GoSlice p0);

extern GoSlice CEncodeResetReply();

extern GoSlice Hello(void* p0);

extern void GoTotalCallback(int p0);

extern void my_callback(void* p0);

extern int execute_cb(void* p0, int p1);

#ifdef __cplusplus
}
#endif
