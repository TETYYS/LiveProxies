#pragma once

#include "IPv6Map.h"
#include <stddef.h>
#include <math.h>
#include <event2/bufferevent.h>

#ifdef __linux__
	#include <sys/time.h>
	#define LINUX_GLOBAL_HTML_PATH "/etc/liveproxies/html"
	#define LINUX_LOCAL_HTML_PATH "./html"
#elif defined _WIN32 || defined _WIN64
	#define WINDOWS_GLOBAL_HTML_PATH "\\liveproxies\\html"
	#define WINDOWS_LOCAL_HTML_PATH ".\\html"
#endif

#define VERSION "1.0.0"
#define OUT
#define MEM_OUT

#define REQUEST_UA "LiveProxies Proxy Checker "VERSION" (tetyys.com/liveproxies)"

#define INTEGER_VISIBLE_SIZE(x) (floor(log10(abs(x))) + 1)
#ifdef __linux__
	#define InterlockedIncrement(a) __sync_add_and_fetch(a, 1)
	#define InterlockedDecrement(a) __sync_sub_and_fetch(a, 1)
#endif

#ifdef __linux__
	#define msleep(a) ; int ms = a * 1000; struct timeval tv; tv.tv_sec = ms / 1000000; tv.tv_usec = ms % 1000000; select(0, NULL, NULL, NULL, &tv);
#elif defined _WIN32 || defined _WIN64
	#define msleep(a) ; Sleep(a);
#endif
#define zalloc(a) calloc(a, 1)
#define arrlen(a) sizeof(a)/sizeof(a[0])

#define CLEAR_BIT(m, x) (m & ~(1 << x))
#define GET_BIT(m, x) ((m >> x) & 1)
#define SET_BIT(m, x) (m | (1 << x))

size_t CurrentlyChecking;
uint8_t *SSLFingerPrint;

#if defined _WIN32 || defined _WIN64
char *WinAppData;
#endif

double GetUnixTimestampMilliseconds();
char *GetHost(IP_TYPE Preffered, bool SSL);
MEM_OUT char *FormatTime(uint64_t TimeMs);
bool MemEqual(void *A, void *B, size_t Size);
bool StrReplaceOrig(char **In, char *Search, char *Replace);
char *StrReplaceToNew(char *In, char *Search, char *Replace);
MEM_OUT bool HTTPFindHeader(char *In, char *Buff, char **Out, char **StartIndex, char **EndIndex);
void BufferEventFreeOnWrite(struct bufferevent *In);