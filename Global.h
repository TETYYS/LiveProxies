#pragma once

#include "IPv6Map.h"
#include <stddef.h>

#define VERSION "0.7.5"
#define CALLBACK
#define OUT
#define MEM_OUT

#define REQUEST_UA "LiveProxies Proxy Checker "VERSION" (tetyys.com/liveproxies)"

#define INTEGER_VISIBLE_SIZE(x) (floor(log10(abs(x))) + 1)
#define InterlockedIncrement(a, b) __sync_add_and_fetch(a, b)
#define InterlockedDecrement(a, b) __sync_sub_and_fetch(a, b)
#define msleep(a) usleep(a*1000)

#define arrlen(a) sizeof(a)/sizeof(a[0])

#define CLEAR_BIT(m, x) (m & ~(1 << x))
#define GET_BIT(m, x) ((m >> x) & 1)
#define SET_BIT(m, x) (m | (1 << x))

size_t CurrentlyChecking;
uint8_t *SSLFingerPrint;

double GetUnixTimestampMilliseconds();
char *GetHost(IP_TYPE Preffered, bool SSL);
IP_TYPE GetIPTypePreffered(IP_TYPE Preffered);
MEM_OUT char *FormatTime(uint64_t TimeMs);
bool MemEqual(void *A, void *B, size_t Size);