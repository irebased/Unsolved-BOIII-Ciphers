#ifndef LIBDEFS_H
#define LIBDEFS_H
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef unsigned char byte;
typedef uint32_t word32;
static inline word32 byteswap32(word32 x){return __builtin_bswap32(x);}
#define WIN32DLL_DEFINE
#endif
