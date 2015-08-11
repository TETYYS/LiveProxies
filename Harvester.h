#pragma once

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#define HARVEST_TIMEOUT 1000 * 60 * 30

typedef struct _HARVESTER_PRXSRC_STATS {
	char *name;
	uint64_t added;
	uint64_t addedNew;
} HARVESTER_PRXSRC_STATS_ENTRY;

pthread_mutex_t LockHarvesterPrxsrcStats;
HARVESTER_PRXSRC_STATS_ENTRY *HarvesterPrxsrcStats;
size_t SizeHarvesterPrxsrcStats;

void HarvestLoop();