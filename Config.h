#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "IPv6Map.h"

uint64_t RemoveThreadInterval;
uint64_t CheckingInterval;
uint64_t GlobalTimeout;
uint64_t AcceptableSequentialFails;
uint16_t ServerPort;
uint64_t SimultaneousChecks;
IPv6Map *GlobalIp4;
IPv6Map *GlobalIp6;
char *HarvestersPath;
bool DisableIPv6;
uint64_t AuthLoginExpiry;