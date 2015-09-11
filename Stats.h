#pragma once

#include <pthread.h>
#include <stdint.h>

typedef struct _STATS_PROXY_COUNT {
	uint64_t UProxy;
	uint64_t Proxy;
	uint64_t Time;
} STATS_PROXY_COUNT;

STATS_PROXY_COUNT *StatsProxyCount;
size_t StatsProxyCountSize;
pthread_mutex_t LockStatsProxyCount;

void StatsCollection();