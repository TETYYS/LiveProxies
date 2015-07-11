#include "ProxyLists.h"
#include "Global.h"
#include "Logger.h"
#include "IPv6Map.h"
#include "ProxyRequest.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <event2/event.h>

static bool MultiFlag(char Flag)
{
	return (Flag & (Flag - 1)) != 0 && Flag != 1;
}

bool ProxyAdd(PROXY *Proxy)
{
	pthread_mutex_lock(&lockCheckedProxies); {
		for (uint32_t x = 0; x < sizeCheckedProxies; x++) {
			if (memcmp(Proxy->ip->Data, checkedProxies[x]->ip->Data, IPV6_SIZE) == 0 && Proxy->port == checkedProxies[x]->port) {
				checkedProxies[x]->type |= Proxy->type;
				checkedProxies[x]->anonymity = Proxy->anonymity;
				checkedProxies[x]->failedChecks = Proxy->failedChecks;
				checkedProxies[x]->httpTimeoutMs = Proxy->httpTimeoutMs;
				checkedProxies[x]->lastChecked = Proxy->lastChecked;
				checkedProxies[x]->retries = Proxy->retries;
				checkedProxies[x]->successfulChecks = Proxy->successfulChecks;
				checkedProxies[x]->timeoutMs = Proxy->timeoutMs;
				free(Proxy);
				pthread_mutex_unlock(&lockCheckedProxies);
				return false;
			}
		}
		InterlockedIncrement(&sizeCheckedProxies, 1); // interlocked not needed?
		checkedProxies = (PROXY**)realloc(checkedProxies, sizeCheckedProxies * sizeof(checkedProxies));
		checkedProxies[sizeCheckedProxies - 1] = Proxy;
	} pthread_mutex_unlock(&lockCheckedProxies);
	return true;
}

bool UProxyAdd(UNCHECKED_PROXY *UProxy)
{
	pthread_mutex_lock(&lockUncheckedProxies); {
		for (uint32_t x = 0; x < sizeUncheckedProxies; x++) {
			if (memcmp(UProxy->hash, uncheckedProxies[x]->hash, 512 / 8) == 0) {
				char *ip = IPv6MapToString2(UProxy->ip); {
					Log(LOG_LEVEL_WARNING, "Warning: tried to add already added unchecked proxy (%s:%d)", ip, UProxy->port);
				} free(ip);
				pthread_mutex_unlock(&lockUncheckedProxies);
				return false;
			}
		}
	} pthread_mutex_unlock(&lockUncheckedProxies);
	Log(LOG_LEVEL_DEBUG, "UProxyAdd: size %d", sizeUncheckedProxies);

	if (MultiFlag(UProxy->type)) { // matches 0, 1, 2, 4, 8, 16...
		for (size_t x = 0; x < PROXY_TYPE_COUNT - 1 /* -1 because of type 1 */; x++) {
			if ((UProxy->type & (uint32_t)pow(2, x)) == (uint32_t)pow(2, x)) {
				UNCHECKED_PROXY *newProxy = malloc(sizeof(UNCHECKED_PROXY));
				memcpy(newProxy, UProxy, sizeof(UNCHECKED_PROXY));
				newProxy->type = (uint32_t)pow(2, x);
				UProxyAdd(newProxy);
			}
		}
	} else {
		pthread_mutex_lock(&lockUncheckedProxies); {
			sizeUncheckedProxies++;
			uncheckedProxies = (UNCHECKED_PROXY**)realloc(uncheckedProxies, sizeof(uncheckedProxies)* sizeUncheckedProxies);
			uncheckedProxies[sizeUncheckedProxies - 1] = UProxy;
		} pthread_mutex_unlock(&lockUncheckedProxies);
	}
	return true;
}

bool UProxyRemove(UNCHECKED_PROXY *UProxy)
{
	bool found = false;

	pthread_mutex_lock(&lockUncheckedProxies); {
		for (uint32_t x = 0; x < sizeUncheckedProxies; x++) {
			if (UProxy == uncheckedProxies[x]) {
				UProxyFree(uncheckedProxies[x]);
				sizeUncheckedProxies--;
				uncheckedProxies[x] = uncheckedProxies[sizeUncheckedProxies];
				uncheckedProxies = (UNCHECKED_PROXY**)realloc(uncheckedProxies, sizeUncheckedProxies * sizeof(uncheckedProxies));
				found = true;
				break;
			}
		}
	} pthread_mutex_unlock(&lockUncheckedProxies);
	Log(LOG_LEVEL_DEBUG, "UProxyRemove: size %d", sizeUncheckedProxies);
	return found;
}

bool ProxyRemove(PROXY *Proxy)
{
	bool found = false;

	pthread_mutex_lock(&lockCheckedProxies); {
		for (uint32_t x = 0; x < sizeCheckedProxies; x++) {
			if (Proxy == checkedProxies[x]) {
				ProxyFree(checkedProxies[x]);
				sizeCheckedProxies--;
				checkedProxies[x] = checkedProxies[sizeCheckedProxies];
				checkedProxies = (PROXY**)realloc(checkedProxies, sizeCheckedProxies * sizeof(checkedProxies));
				found = true;
				break;
			}
		}
	} pthread_mutex_unlock(&lockCheckedProxies);
	return found;
}

UNCHECKED_PROXY *UProxyFromProxy(PROXY *In)
{
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: In: %16x", In);
	UNCHECKED_PROXY *ret = malloc(sizeof(UNCHECKED_PROXY));
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: UProxy: %16x", ret);
	ret->ip = malloc(sizeof(IPv6Map));
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: UProxy->ip: %16x", ret->ip);

	memcpy(ret->ip->Data, In->ip->Data, IPV6_SIZE);
	ret->port = In->port;
	pthread_mutex_init(&(ret->processing), NULL);
	ret->requestTimeMs = ret->requestTimeHttpMs = 0;
	ret->checking = false;
	ret->type = In->type;
	GenerateHashForUProxy(ret);
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: UProxy->hash: %16x", ret->hash);
	ret->associatedProxy = In;
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: UProxy->associatedProxy: %16x", ret->associatedProxy);
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: UProxy: %16x", ret);

	return ret;
}

void GenerateHashForUProxy(UNCHECKED_PROXY *In)
{
	size_t dataSize = IPV6_SIZE + sizeof(uint16_t)+sizeof(In->type) + sizeof(hashSalt);

	char *data = malloc(dataSize); {
		memcpy(data, In->ip->Data, IPV6_SIZE);
		memcpy(data + IPV6_SIZE, &(In->port), sizeof(uint16_t));
		memcpy(data + IPV6_SIZE + sizeof(uint16_t), &(In->type), sizeof(In->type));
		memcpy(data + IPV6_SIZE + sizeof(uint16_t)+sizeof(In->type), hashSalt, sizeof(hashSalt));

		SHA512(data, dataSize, In->hash);
	} free(data);

	// 👌
}

void UProxyFree(UNCHECKED_PROXY *In)
{
	if (In->timeout != NULL) {
		pthread_mutex_lock(&lockRequestBase); {
			event_del(In->timeout);
		} pthread_mutex_unlock(&lockRequestBase);
		event_free(In->timeout);
	}

	pthread_mutex_destroy(&(In->processing));
	free(In->ip);
	free(In);
}

void ProxyFree(PROXY *In)
{
	free(In->ip);
	free(In);
}