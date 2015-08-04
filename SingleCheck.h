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

void Recheck(PROXY *In, void CALLBACK *FinishedCallback, void *Ex);
MEM_OUT char *ReverseDNS(IPv6Map *In);
SPAMHAUS_ZEN_ANSWER SpamhausZEN(IPv6Map *In);