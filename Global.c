#include "Global.h"
#include "ProxyRequest.h"
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