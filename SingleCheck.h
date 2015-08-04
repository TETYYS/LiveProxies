#pragma once

#include "IPv6Map.h"
#include "ProxyLists.h"
#include "Global.h"

typedef enum _SPAMHAUS_ZEN_ANSWER {
	CLEAN,
	SBL,
	CSS,
	XBL,
	PBL
} SPAMHAUS_ZEN_ANSWER;

PROXY *Recheck(PROXY *In);
MEM_OUT char *ReverseDNS(IPv6Map *In);
SPAMHAUS_ZEN_ANSWER SpamhausZEN(IPv6Map *In);