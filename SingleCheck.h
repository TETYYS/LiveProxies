#pragma once

#include "IPv6Map.h"
#include "ProxyLists.h"
#include "Global.h"
#include <event2/bufferevent.h>

typedef enum _SPAMHAUS_ZEN_ANSWER {
	SPAMHAUS_ZEN_ANSWER_CLEAN,
	SPAMHAUS_ZEN_ANSWER_SBL,
	SPAMHAUS_ZEN_ANSWER_CSS,
	SPAMHAUS_ZEN_ANSWER_XBL,
	SPAMHAUS_ZEN_ANSWER_PBL
} SPAMHAUS_ZEN_ANSWER;

typedef enum _HTTPBL_CROOK_TYPE {
	HTTPBL_CROOK_TYPE_SUSPICIOUS = 1,
	HTTPBL_CROOK_TYPE_HARVESTER = 2,
	HTTPBL_CROOK_TYPE_COMMENT_SPAMMER = 4,
	HTTPBL_CROOK_TYPE_CLEAN = HTTPBL_CROOK_TYPE_COMMENT_SPAMMER | HTTPBL_CROOK_TYPE_HARVESTER | HTTPBL_CROOK_TYPE_SUSPICIOUS + 1
} HTTPBL_CROOK_TYPE;

typedef struct _HTTPBL_ANSWER {
	uint8_t days;
	uint8_t score;
	HTTPBL_CROOK_TYPE crookType;
} HTTPBL_ANSWER;

void Recheck(PROXY *In, void CALLBACK *FinishedCallback, void *Ex);
MEM_OUT char *ReverseDNS(IPv6Map *In);
SPAMHAUS_ZEN_ANSWER SpamhausZEN(IPv6Map *In);
void HTTP_BL(IPv6Map *In, char *AccessKey, HTTPBL_ANSWER OUT *Out);
void SpamhausZENAsync(IPv6Map *In, struct bufferevent *BuffEvent);
void HTTP_BLAsync(IPv6Map *In, char *AccessKey, struct bufferevent *BuffEvent);