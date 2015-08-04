#pragma once

#include "IPv6Map.h"
#include <stddef.h>

#define VERSION "0.5.1"
#define CALLBACK
#define OUT
#define MEM_OUT

#define INTEGER_VISIBLE_SIZE(x) (floor(log10(abs(x))) + 1)
#define InterlockedIncrement(a, b) __sync_add_and_fetch(a, b)
#define InterlockedDecrement(a, b) __sync_sub_and_fetch(a, b)
#define msleep(a) usleep(a*1000)

#define arrlen(a) sizeof(a)/sizeof(a[0])

size_t CurrentlyChecking;

double GetUnixTimestampMilliseconds();
char *GetHost(IP_TYPE Preffered, bool SSL);
IP_TYPE GetIPTypePreffered(IP_TYPE Preffered);