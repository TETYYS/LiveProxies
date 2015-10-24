#pragma once

#include <stdint.h>
#include "CPH_Threads.h"

typedef struct _STATS_PROXY_COUNT {
	uint64_t UProxy;
	uint64_t Proxy;
	uint64_t Time;
} STATS_PROXY_COUNT;

STATS_PROXY_COUNT *StatsProxyCount;
size_t StatsProxyCountSize;
pthread_mutex_t LockStatsProxyCount;

void StatsCollection();