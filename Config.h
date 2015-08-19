#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "IPv6Map.h"

uint64_t RemoveThreadInterval;
uint64_t CheckingInterval;
uint64_t GlobalTimeout;
uint64_t AcceptableSequentialFails;
uint16_t ServerPort;
uint16_t ServerPortUDP;
uint64_t SimultaneousChecks;
IPv6Map *GlobalIp4;
IPv6Map *GlobalIp6;
char *HarvestersPath;
uint64_t AuthLoginExpiry;
bool EnableUDP;
uint64_t ProxySourcesBacklog;

char *HttpBLAccessKey;

struct timeval GlobalTimeoutTV;

bool SSLEnabled;
char *SSLPublicKey;
char *SSLPrivateKey;
char *SSLCipherList;
uint16_t SSLServerPort;

uint64_t WSMessageIntervalMs;