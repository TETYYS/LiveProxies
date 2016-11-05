#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "IPv6Map.h"

#if defined _WIN32 || defined _WIN64
	#include <Winsock2.h>
#endif

uint64_t RemoveThreadInterval;
uint64_t CheckingInterval;
uint64_t GlobalTimeout;
uint64_t AcceptableSequentialFails;
uint16_t ServerPort;
uint16_t ServerPortUDP;
uint64_t SimultaneousChecks;
IPv6Map *GlobalIp4;
IPv6Map *GlobalIp6;
char *GlobalHostname;
char *HarvestersPath;
uint64_t AuthLoginExpiry;
bool EnableUDP;
uint64_t ProxySourcesBacklog;
bool SOCKS5ResolveDomainsRemotely;

char *HttpBLAccessKey;

struct timeval GlobalTimeoutTV;

/* SSL */
	bool SSLEnabled;
	char *SSLPublicKey;
	char *SSLPrivateKey;
	char *SSLCipherList;
	uint16_t SSLServerPort;
/* End SSL */

/* Stats */
	uint64_t StatsCollectionInterval;
	uint64_t StatsMaxItems;
/* End stats */

/* Websockets */
	uint64_t WSPingInterval;
	uint64_t WSMessageInterval;
/* End websockets */