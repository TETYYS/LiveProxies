#pragma once

#include "IPv6Map.h"
#include <stddef.h>
#include <math.h>
#include <sys/time.h>

#define VERSION "0.9.2"
#define CALLBACK
#define OUT
#define MEM_OUT

#define REQUEST_UA "LiveProxies Proxy Checker "VERSION" (tetyys.com/liveproxies)"

#define INTEGER_VISIBLE_SIZE(x) (floor(log10(abs(x))) + 1)
#define InterlockedIncrement(a, b) __sync_add_and_fetch(a, b)
#define InterlockedDecrement(a, b) __sync_sub_and_fetch(a, b)
#define msleep(a) ; int ms = a * 1000; struct timeval tv; tv.tv_sec = ms / 1000000; tv.tv_usec = ms % 1000000; select(0, NULL, NULL, NULL, &tv);

#define arrlen(a) sizeof(a)/sizeof(a[0])

#define CLEAR_BIT(m, x) (m & ~(1 << x))
#define GET_BIT(m, x) ((m >> x) & 1)
#define SET_BIT(m, x) (m | (1 << x))

size_t CurrentlyChecking;
uint8_t *SSLFingerPrint;

double GetUnixTimestampMilliseconds();
char *GetHost(IP_TYPE Preffered, bool SSL);
MEM_OUT char *FormatTime(uint64_t TimeMs);
bool MemEqual(void *A, void *B, size_t Size);
bool StrReplaceOrig(char **In, char *Search, char *Replace);
char *StrReplaceToNew(char *In, char *Search, char *Replace);
MEM_OUT bool HTTPFindHeader(char *In, char *Buff, char **Out, char **StartIndex, char **EndIndex);;