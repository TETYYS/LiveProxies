#define _GNU_SOURCE

#include "SingleCheck.h"
#include "ProxyLists.h"
#include "Global.h"
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>
#include <string.h>
#include <event2/bufferevent.h>
#include "ProxyRequest.h"
#include "Logger.h"
#include "Config.h"

void PageRequest(PROXY *In, void CALLBACK *FinishedCallback, char *Page, void *Ex)
{
	bool success = false;
	UNCHECKED_PROXY *UProxy = UProxyFromProxy(In);
	UProxy->singleCheckCallback = FinishedCallback;
	UProxy->singleCheckCallbackExtraData = Ex;
	UProxy->pageTarget = Page;

	UProxyAdd(UProxy);
	RequestAsync(UProxy);
}

void Recheck(PROXY *In, void CALLBACK *FinishedCallback, void *Ex)
{
	bool success = false;
	UNCHECKED_PROXY *UProxy = UProxyFromProxy(In);
	UProxy->singleCheckCallback = FinishedCallback;
	UProxy->singleCheckCallbackExtraData = Ex;
	UProxy->targetIPv4 = GlobalIp4;
	UProxy->targetIPv6 = GlobalIp6;
	UProxy->targetPort = ProxyIsSSL(UProxy->type) ? ServerPort : SSLServerPort;

	UProxyAdd(UProxy);
	In->rechecking = true;
	RequestAsync(UProxy);
}

char *ReverseDNS(IPv6Map *In)
{
	struct hostent *hent = NULL;
	char *ret = NULL;
	IP_TYPE type = GetIPType(In);

	if ((hent = gethostbyaddr(type == IPV4 ? &(In->Data[3]) : In->Data, type == IPV4 ? IPV4_SIZE : IPV6_SIZE, type == IPV4 ? AF_INET : AF_INET6))) {
		ret = malloc((strlen(hent->h_name) * sizeof(char)) + 1);
		strcpy(ret, hent->h_name);
	}

	return ret;
}

typedef struct _ASYNC_DNS_LOOKUP_EX {
	struct bufferevent *buffEvent;
	struct gaicb *cb;
} ASYNC_DNS_LOOKUP_EX;

static void SpamhausZENAsyncStage2(sigval_t Ex)
{
	ASYNC_DNS_LOOKUP_EX *ex = Ex.sival_ptr;

	struct bufferevent *buffEvent = ex->buffEvent;
	struct gaicb *cb = ex->cb;

	free(cb->ar_name);

	if (cb->ar_result == NULL) {
		bufferevent_write(buffEvent, "cln", 3 * sizeof(char));
		bufferevent_flush(buffEvent, EV_WRITE, BEV_FINISHED);
		bufferevent_free(buffEvent);
		free(cb);
		free(ex);
		return;
	}

	struct sockaddr_in *addr = (struct sockaddr_in*)(cb->ar_result->ai_addr);
	uint8_t data = ((uint8_t*)(&(addr->sin_addr.s_addr)))[3];
	freeaddrinfo(cb->ar_result);
	switch (data) {
		case 2:
			bufferevent_write(buffEvent, "sbl", 3 * sizeof(char));
			break;
		case 3:
			bufferevent_write(buffEvent, "css", 3 * sizeof(char));
			break;
		case 10:
		case 11:
			bufferevent_write(buffEvent, "pbl", 3 * sizeof(char));
			break;
		default:
			bufferevent_write(buffEvent, "xbl", 3 * sizeof(char));
	}

	bufferevent_flush(buffEvent, EV_WRITE, BEV_FINISHED);
	bufferevent_free(buffEvent);
	free(cb);
	free(ex);
}

void SpamhausZENAsync(IPv6Map *In, struct bufferevent *BuffEvent)
{
	struct addrinfo *servinfo;
	IP_TYPE type = GetIPType(In);

	struct gaicb *cb = malloc(sizeof(struct gaicb));
	memset(cb, 0, sizeof(struct gaicb));

	cb->ar_name = malloc(type == IPV4 ? 33 : 82);
	memset(cb->ar_name, 0, type == IPV4 ? 33 : 82);
	if (type == IPV4) {
		uint8_t a, b, c, d;
		uint8_t *bytes = ((uint8_t*)&(In->Data[3]));
		a = bytes[0];
		b = bytes[1];
		c = bytes[2];
		d = bytes[3];
		sprintf(cb->ar_name, "%d.%d.%d.%d.zen.spamhaus.org.", d, c, b, a);
	} else {
		uint8_t *data = In->Data;
		for (size_t x = IPV6_SIZE;x >= 0;x++) {
			char format[2];
			sprintf(format, "%x.", data[x]);
			strcat(cb->ar_name, format);
		}
		strcat(cb->ar_name, ".zen.spamhaus.org.");
	}

	struct sigevent ev;
	memset(&ev, 0, sizeof(struct sigevent));
	ev.sigev_notify = SIGEV_THREAD;
	ASYNC_DNS_LOOKUP_EX *ex = malloc(sizeof(ASYNC_DNS_LOOKUP_EX));
	ex->buffEvent = BuffEvent;
	ex->cb = cb;
	ev.sigev_value.sival_ptr = ex;
	ev.sigev_notify_function = SpamhausZENAsyncStage2;

	Log(LOG_LEVEL_DEBUG, "Async getaddrinfo: %d", getaddrinfo_a(GAI_NOWAIT, &cb, 1, &ev));
}

SPAMHAUS_ZEN_ANSWER SpamhausZEN(IPv6Map *In)
{
	struct addrinfo *servinfo;
	IP_TYPE type = GetIPType(In);

	char *query = malloc(type == IPV4 ? 33 : 82); {
		memset(query, 0, type == IPV4 ? 33 : 82);
		if (type == IPV4) {
			uint8_t a, b, c, d;
			uint8_t *bytes = ((uint8_t*)&(In->Data[3]));
			a = bytes[0];
			b = bytes[1];
			c = bytes[2];
			d = bytes[3];
			sprintf(query, "%d.%d.%d.%d.zen.spamhaus.org.", d, c, b, a);
		} else {
			uint8_t *data = In->Data;
			for (size_t x = IPV6_SIZE;x >= 0;x++) {
				char format[2];
				sprintf(format, "%x.", data[x]);
				strcat(query, format);
			}
			strcat(query, ".zen.spamhaus.org.");
		}

		if (getaddrinfo(query, NULL, NULL, &servinfo) != 0)
			return SPAMHAUS_ZEN_ANSWER_CLEAN;
	} free(query);

	struct sockaddr_in *addr = (struct sockaddr_in*)(servinfo->ai_addr);
	uint8_t data = ((uint8_t*)(&(addr->sin_addr.s_addr)))[3];
	freeaddrinfo(servinfo);
	switch (data) {
		case 2:
			return SPAMHAUS_ZEN_ANSWER_SBL;
			break;
		case 3:
			return SPAMHAUS_ZEN_ANSWER_CSS;
			break;
		case 10:
		case 11:
			return SPAMHAUS_ZEN_ANSWER_PBL;
			break;
		default:
			return SPAMHAUS_ZEN_ANSWER_XBL;
	}
}

static void HTTP_BLAsyncStage2(sigval_t Ex)
{
	ASYNC_DNS_LOOKUP_EX *ex = Ex.sival_ptr;

	struct bufferevent *buffEvent = ex->buffEvent;
	struct gaicb *cb = ex->cb;

	free(cb->ar_name);

	if (cb->ar_result == NULL) {
		bufferevent_write(buffEvent, "1\r\nContent-Type: text/html\r\n\r\nl", 31 * sizeof(char));
		bufferevent_flush(buffEvent, EV_WRITE, BEV_FINISHED);
		bufferevent_free(buffEvent);
		free(cb);
		free(ex);
		return;
	}

	struct sockaddr_in *addr = (struct sockaddr_in*)(cb->ar_result->ai_addr);
	uint8_t days = ((uint8_t*)(&(addr->sin_addr.s_addr)))[1];
	uint8_t score = ((uint8_t*)(&(addr->sin_addr.s_addr)))[2];
	HTTPBL_CROOK_TYPE crookType = ((uint8_t*)(&(addr->sin_addr.s_addr)))[3];

	freeaddrinfo(cb->ar_result);

	if (crookType == 0) {
		bufferevent_write(buffEvent, "1\r\nContent-Type: text/html\r\n\r\nl", 31 * sizeof(char));
		bufferevent_flush(buffEvent, EV_WRITE, BEV_FINISHED);
		bufferevent_free(buffEvent);
		free(cb);
		free(ex);
	}

	char body[8];
	memset(body, 0, 8 * sizeof(char));

	if ((crookType & HTTPBL_CROOK_TYPE_COMMENT_SPAMMER) == HTTPBL_CROOK_TYPE_COMMENT_SPAMMER)
		strcat(body, "c");
	if ((crookType & HTTPBL_CROOK_TYPE_HARVESTER) == HTTPBL_CROOK_TYPE_HARVESTER)
		strcat(body, "h");
	if ((crookType & HTTPBL_CROOK_TYPE_SUSPICIOUS) == HTTPBL_CROOK_TYPE_SUSPICIOUS)
		strcat(body, "s");
	if (crookType == HTTPBL_CROOK_TYPE_CLEAN)
		strcat(body, "l");

	char sScore[4];
	sprintf(sScore, "%d", score);
	strcat(body, sScore);

	char sBodyLen[3];
	sprintf(sBodyLen, "%d", strlen(body) * sizeof(char));

	bufferevent_write(buffEvent, sBodyLen, strlen(sBodyLen) * sizeof(char));
	bufferevent_write(buffEvent, "\r\nContent-Type: text/html\r\n\r\n", 29 * sizeof(char));
	bufferevent_write(buffEvent, body, strlen(body) * sizeof(char));

	bufferevent_flush(buffEvent, EV_WRITE, BEV_FINISHED);
	bufferevent_free(buffEvent);
	free(cb);
	free(ex);
}

void HTTP_BLAsync(IPv6Map *In, char *AccessKey, struct bufferevent *BuffEvent)
{
	if (AccessKey[0] == 0x00) {
		bufferevent_write(BuffEvent, "1\r\nContent-Type: text/html\r\n\r\nN", 31 * sizeof(char));
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);
		bufferevent_free(BuffEvent);
		return;
	}

	struct addrinfo *servinfo;
	IP_TYPE type = GetIPType(In);

	struct gaicb *cb = malloc(sizeof(struct gaicb));
	memset(cb, 0, sizeof(struct gaicb));

	cb->ar_name = malloc(type == IPV4 ? 34 + strlen(AccessKey) : 83 + strlen(AccessKey));
	memset(cb->ar_name, 0, type == IPV4 ? 34 + strlen(AccessKey) : 83 + strlen(AccessKey));
	if (type == IPV4) {
		uint8_t a, b, c, d;
		uint8_t *bytes = ((uint8_t*)&(In->Data[3]));
		a = bytes[0];
		b = bytes[1];
		c = bytes[2];
		d = bytes[3];
		sprintf(cb->ar_name, "%s.%d.%d.%d.%d.dnsbl.httpbl.org.", AccessKey, d, c, b, a);
	} else {
		uint8_t *data = In->Data;
		for (size_t x = IPV6_SIZE;x >= 0;x++) {
			char format[2];
			sprintf(format, "%x.", data[x]);
			strcat(cb->ar_name, format);
		}
		strcat(cb->ar_name, ".dnsbl.httpbl.org.");
	}

	struct sigevent ev;
	memset(&ev, 0, sizeof(struct sigevent));
	ev.sigev_notify = SIGEV_THREAD;
	ASYNC_DNS_LOOKUP_EX *ex = malloc(sizeof(ASYNC_DNS_LOOKUP_EX));
	ex->buffEvent = BuffEvent;
	ex->cb = cb;
	ev.sigev_value.sival_ptr = ex;
	ev.sigev_notify_function = HTTP_BLAsyncStage2;

	Log(LOG_LEVEL_DEBUG, "Async getaddrinfo: %d", getaddrinfo_a(GAI_NOWAIT, &cb, 1, &ev));
}

void HTTP_BL(IPv6Map *In, char *AccessKey, HTTPBL_ANSWER OUT *Out)
{
	struct addrinfo *servinfo;
	IP_TYPE type = GetIPType(In);

	char *query = malloc(type == IPV4 ? 34 + strlen(AccessKey) : 83 + strlen(AccessKey)); {
		memset(query, 0, type == IPV4 ? 34 + strlen(AccessKey) : 83 + strlen(AccessKey));
		if (type == IPV4) {
			uint8_t a, b, c, d;
			uint8_t *bytes = ((uint8_t*)&(In->Data[3]));
			a = bytes[0];
			b = bytes[1];
			c = bytes[2];
			d = bytes[3];
			sprintf(query, "%s.%d.%d.%d.%d.dnsbl.httpbl.org.", AccessKey, d, c, b, a);
		} else {
			uint8_t *data = In->Data;
			for (size_t x = IPV6_SIZE;x >= 0;x++) {
				char format[2];
				sprintf(format, "%x.", data[x]);
				strcat(query, format);
			}
			strcat(query, ".dnsbl.httpbl.org.");
		}

		if (getaddrinfo(query, NULL, NULL, &servinfo) != 0)
			return HTTPBL_CROOK_TYPE_CLEAN;
	} free(query);

	struct sockaddr_in *addr = (struct sockaddr_in*)(servinfo->ai_addr);
	Out->days = ((uint8_t*)(&(addr->sin_addr.s_addr)))[1];
	Out->score = ((uint8_t*)(&(addr->sin_addr.s_addr)))[2];
	Out->crookType = ((uint8_t*)(&(addr->sin_addr.s_addr)))[3];
	if (Out->crookType == 0)
		Out->crookType = HTTPBL_CROOK_TYPE_CLEAN;
	freeaddrinfo(servinfo);
}