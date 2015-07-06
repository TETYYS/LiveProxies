#include "IPv6Map.h"
#include "Global.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define zalloc(x) calloc(1, (x))

IPV6_TYPE GetIPType(IPv6Map *In) {
	bool found = false;

	// 2001:0db8:0000:0000:0000:ff00:0042:8329
	//							FFFF:IPv4:IPv4
	// IPV6_SIZEIPV6_SIZEIPV6_SIFFFFIPV4_SIZEI
	//						   ||  ||

	for (size_t x = 0; x < 5; x++) {
		if (((uint16_t*)In->Data)[x] != 0x0000) {
			found = true;
			break;
		}
	}
	if (!found && In->Data[2] != 0xFFFF0000 /* THAT WAY! */)
		found = true;
	return found ? IPV6 : IPV4;
}

MEM_OUT IPv6Map *StringToIPv6Map(char *In) {
	IPv6Map *ret = zalloc(sizeof(IPv6Map));

	IPV6_TYPE type = strchr(In, '.') == NULL ? IPV6 : IPV4;

	if (type == IPV4) {
		if (inet_pton(AF_INET, In, &(ret->Data[3])) != 1) {
			free(ret);
			return NULL;
		}
		ret->Data[2] = 0xFFFF0000; // THAT WAY!
	} else {
		if (inet_pton(AF_INET6, In, ret->Data) != 1) {
			free(ret);
			return NULL;
		}
	}

	return ret;
}

MEM_OUT char *IPv6MapToString(IPv6Map *In) {
	char *ret;
	if (GetIPType(In) == IPV4) {
		ret = malloc(sizeof(char)* INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(In->Data[3]), ret, INET_ADDRSTRLEN);
	}
	else if (GetIPType(In) == IPV6) {
		ret = malloc(sizeof(char)* INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, In->Data, ret, INET6_ADDRSTRLEN);
	}
	return ret;
}

MEM_OUT IPv6Map *GetIPFromHSock(int hSock) {
	socklen_t len;
	struct sockaddr_storage addr;

	len = sizeof(addr);
	getpeername(hSock, (struct sockaddr*)&addr, &len);

	IPv6Map *ret = zalloc(sizeof(IPv6Map));

	if (addr.ss_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)&addr;
		memcpy(&(ret->Data[3]), &(s->sin_addr.s_addr), IPV4_SIZE);
		ret->Data[2] = 0xFFFF0000; // THAT WAY!
	}
	else { // AF_INET6
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
		memcpy(ret->Data, s->sin6_addr.__in6_u.__u6_addr8, IPV6_SIZE);
	}

	return ret;
}