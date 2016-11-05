#include "ProxyRemove.h"
#include "ProxyLists.h"
#include "Global.h"
#include "ProxyRequest.h"
#include "Config.h"
#include <stdint.h>
#include <stddef.h>
#ifdef __linux__
	#include <unistd.h>
#endif

void RemoveThread()
{
	for (;;) {
		if (RemoveThreadInterval == 0)
			return;
		msleep(RemoveThreadInterval);
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
			UProxy->targetIPv4 = GlobalIp4;
			UProxy->targetIPv6 = GlobalIp6;
			UProxy->targetPort = UProxy->type == PROXY_TYPE_SOCKS5_WITH_UDP ? ServerPortUDP : (ProxyIsSSL(UProxy->type) ? SSLServerPort : ServerPort);
			UProxyAdd(UProxy);
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
	In->associatedProxy->rechecking = false;

	if (In->associatedProxy->retries >= AcceptableSequentialFails) {
		ProxyRemove(In->associatedProxy);
		In->associatedProxy = NULL;
	}
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