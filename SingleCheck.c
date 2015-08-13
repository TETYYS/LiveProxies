#include "SingleCheck.h"
#include "ProxyLists.h"
#include "Global.h"
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>
#include <string.h>
#include "ProxyRequest.h"

void Recheck(PROXY *In, void CALLBACK *FinishedCallback, void *Ex)
{
	bool success = false;
	UNCHECKED_PROXY *UProxy = UProxyFromProxy(In);
	UProxy->singleCheckCallback = FinishedCallback;
	UProxy->singleCheckCallbackExtraData = Ex;

	UProxyAdd(UProxy);
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