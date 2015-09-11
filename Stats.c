#include "Stats.h"
#include "Global.h"
#include "Config.h"
#include "ProxyLists.h"
#include "Logger.h"
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>

void StatsCollection()
{
	StatsProxyCountSize = 0;
	StatsProxyCount = NULL;
	for (;;) {
		msleep(StatsCollectionInterval);
		pthread_mutex_lock(&LockStatsProxyCount); {
			uint64_t uproxy, proxy;
			pthread_mutex_lock(&LockCheckedProxies); {
				proxy = SizeCheckedProxies;
			} pthread_mutex_unlock(&LockCheckedProxies);
			pthread_mutex_lock(&LockUncheckedProxies); {
				uproxy = SizeUncheckedProxies;
			} pthread_mutex_unlock(&LockUncheckedProxies);

			if (StatsProxyCountSize > 0) {
				if (StatsProxyCount[StatsProxyCountSize - 1].UProxy == uproxy && StatsProxyCount[StatsProxyCountSize - 1].Proxy == proxy) {
					pthread_mutex_unlock(&LockStatsProxyCount);
					continue;
				}
			}

			if (StatsProxyCountSize >= StatsMaxItems && StatsProxyCountSize > 0) {
				for (size_t x = StatsProxyCountSize;x > 0;x--)
					StatsProxyCount[x - 1] = StatsProxyCount[x];
			} else {
				StatsProxyCountSize++;
				StatsProxyCount = StatsProxyCount == NULL ? malloc(sizeof(STATS_PROXY_COUNT)) : realloc(StatsProxyCount, StatsProxyCountSize * sizeof(STATS_PROXY_COUNT));
			}
			STATS_PROXY_COUNT *entry = &(StatsProxyCount[StatsProxyCountSize - 1]);

			entry->UProxy = uproxy;
			entry->Proxy = proxy;
			entry->Time = GetUnixTimestampMilliseconds();
		} pthread_mutex_unlock(&LockStatsProxyCount);
		Log(LOG_LEVEL_DEBUG, "Collected stats");
	}
}