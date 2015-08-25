#include "Global.h"
#include "Config.h"
#include "ProxyRequest.h"
#include "IPv6Map.h"
#include <sys/time.h>
#include <stddef.h>
#include <assert.h>
#include <math.h>

double GetUnixTimestampMilliseconds()
{
	struct timeval tv;
	assert(gettimeofday(&tv, NULL) != -1);
	return (tv.tv_sec + (tv.tv_usec / 1000000.0)) * 1000.0;
}

char *GetHost(IP_TYPE Preffered, bool SSL)
{
	char *host4 = (SSL ? Host4SSL : Host4);
	char *host6 = (SSL ? Host6SSL : Host6);

	if (host4 != NULL && host6 != NULL)
		return Preffered == IPV4 ? host4 : host6;
	if (host4 == NULL)
		return host6;
	else
		return host4;
}

IP_TYPE GetIPTypePreffered(IP_TYPE Preffered)
{
	if (GlobalIp4 != NULL && GlobalIp6 != NULL)
		return Preffered == IPV4 ? IPV4 : IPV6;
	if (GlobalIp4 == NULL)
		return IPV6;
	else
		return IPV4;
}

MEM_OUT char *FormatTime(uint64_t TimeMs)
{
	char *timeBuff = malloc(20 * sizeof(char) + 1);
	memset(timeBuff, 0, 20 * sizeof(char) + 1);
	struct tm *timeinfo;
	time_t timeRaw = TimeMs / 1000;

	timeinfo = localtime(&timeRaw);
	strftime(timeBuff, 20, "%F %H:%M:%S", timeinfo);

	return timeBuff;
}

bool MemEqual(void *A, void *B, size_t Size)
{
	while (--Size) {
		if (*((uint8_t*)A) != *((uint8_t*)B))
			return false;
		A++;
		B++;
	}
	return true;
}