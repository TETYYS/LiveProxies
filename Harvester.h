#pragma once

#include <stdint.h>
#include <stddef.h>
#include "CPH_Threads.h"
#include "ProxyLists.h"

#define HARVEST_TIMEOUT 1000 * 60 * 30

typedef enum _HARVESTER_PROXY_SOURCE_TYPE {
	NONE = 0,
	SCRIPT = 1,
	STATIC = 2,
	URL = 3
} HARVESTER_PROXY_SOURCE_TYPE;

typedef struct _HARVESTER_PRXSRC_STATS_ENTRY {
	char *name;
	uint64_t added;
	uint64_t addedNew;
	HARVESTER_PROXY_SOURCE_TYPE type;
} HARVESTER_PRXSRC_STATS_ENTRY;

pthread_mutex_t LockStatsHarvesterPrxsrc;
HARVESTER_PRXSRC_STATS_ENTRY *HarvesterStatsPrxsrc;
size_t SizeStatsHarvesterPrxsrc;

void HarvestLoop();
char *ProxySourceTypeToString(HARVESTER_PROXY_SOURCE_TYPE In);
size_t AddProxyHarvesterFormat(char *In, PROXY_TYPE *CurrentType);