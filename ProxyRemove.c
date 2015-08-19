#include "ProxyRemove.h"
#include "ProxyLists.h"
#include "Global.h"
#include "ProxyRequest.h"
#include "Config.h"
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

void RemoveThread()
{
	for (;;) {
		msleep(RemoveThreadInterval);
		continue; ////////////////////////////////////////////////
		PROXY *proxy = NULL;
		pthread_mutex_lock(&LockCheckedProxies); {
			uint64_t low = UINT64_MAX;
			for (uint64_t x = 0; x < SizeCheckedProxies; x++) {
				if (!CheckedProxies[x]->rechecking && CheckedProxies[x]->lastCheckedMs < low) {
					proxy = CheckedProxies[x];
					low = proxy->lastCheckedMs;
				}
			}
		} pthread_mutex_unlock(&LockCheckedProxies);
		if (proxy != NULL) {
			UNCHECKED_PROXY *UProxy = UProxyFromProxy(proxy);
			proxy->rechecking = true;
			RequestAsync(UProxy);
		}
	}
}

void UProxyFailUpdateParentInfo(UNCHECKED_PROXY *In)
{
	In->associatedProxy->timeoutMs = 0;
	In->associatedProxy->failedChecks++;
	In->associatedProxy->httpTimeoutMs = 0;
	In->associatedProxy->lastCheckedMs = GetUnixTimestampMilliseconds();
	In->associatedProxy->retries++;

	if (In->associatedProxy->retries >= AcceptableSequentialFails)
		ProxyRemove(In->associatedProxy);
}

void UProxySuccessUpdateParentInfo(UNCHECKED_PROXY *In)
{
	In->associatedProxy->lastCheckedMs = GetUnixTimestampMilliseconds();
	In->associatedProxy->httpTimeoutMs = GetUnixTimestampMilliseconds() - In->requestTimeHttpMs;
	In->associatedProxy->timeoutMs = GetUnixTimestampMilliseconds() - In->requestTimeMs;
	In->associatedProxy->retries = 0;
	In->associatedProxy->rechecking = false;
	In->associatedProxy->successfulChecks++;
}