#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef enum _IPV6_TYPE {
	IPV4 = 0,
	IPV6 = 1
} IP_TYPE;

#include "Global.h"

enum _IP_SIZES {
	IPV4_SIZE = sizeof(uint32_t),
	IPV6_SIZE = sizeof(uint32_t) * 4
};

enum _IP_STRING_SIZES {
	IPV4_STRING_SIZE = 15,
	IPV6_STRING_SIZE = 39
};

typedef struct _IPv6Map {
	uint32_t Data[4];
} IPv6Map;

IPv6Map *StringToIPv6Map(char *In);
char *IPv6MapToString(IPv6Map *In);
char *IPv6MapToString2(IPv6Map *In);
IP_TYPE GetIPType(IPv6Map *In);
IPv6Map *GetIPFromHSock(int hSock);
struct sockaddr *IPv6MapToRaw(IPv6Map *In, uint16_t Port);
bool IPv6MapCompare(IPv6Map *a, IPv6Map *b);
IPv6Map *RawToIPv6Map(struct sockaddr *In);