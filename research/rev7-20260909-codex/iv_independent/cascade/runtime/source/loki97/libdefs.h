#ifndef LIBDEFS_H
#define LIBDEFS_H
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef unsigned char byte;
typedef uint16_t word16;
typedef uint32_t word32;
static inline word16 byteswap16(word16 x){return __builtin_bswap16(x);}
static inline word32 byteswap32(word32 x){return __builtin_bswap32(x);}
static inline word16 rotl16(word16 x,unsigned n){return (word16)((x<<n)|(x>>(16-n)));}
static inline word16 rotr16(word16 x,unsigned n){return (word16)((x>>n)|(x<<(16-n)));}
#define WIN32DLL_DEFINE
#endif
