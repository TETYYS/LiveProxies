#include "IPv6Map.h"
#include "Global.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define zalloc(x) calloc(1, (x))

IP_TYPE GetIPType(IPv6Map *In)
{
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

MEM_OUT IPv6Map *StringToIPv6Map(char *In)
{
	IPv6Map *ret = zalloc(sizeof(IPv6Map));

	IP_TYPE type = strchr(In, '.') == NULL ? IPV6 : IPV4;

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

MEM_OUT char *IPv6MapToString(IPv6Map *In)
{
	char *ret;
	if (GetIPType(In) == IPV4) {
		ret = malloc(sizeof(char)* INET_ADDRSTRLEN + 1);
		inet_ntop(AF_INET, &(In->Data[3]), ret, INET_ADDRSTRLEN);
	} else if (GetIPType(In) == IPV6) {
		ret = malloc(sizeof(char)* INET6_ADDRSTRLEN + 1);
		inet_ntop(AF_INET6, In->Data, ret, INET6_ADDRSTRLEN);
	}
	return ret;
}

MEM_OUT char *IPv6MapToString2(IPv6Map *In)
{
	char *ret;
	if (GetIPType(In) == IPV4) {
		ret = malloc(sizeof(char)* INET_ADDRSTRLEN + 1);
		inet_ntop(AF_INET, &(In->Data[3]), ret, INET_ADDRSTRLEN);
	} else if (GetIPType(In) == IPV6) {
		ret = malloc(sizeof(char)* (INET6_ADDRSTRLEN + 2) + 1);//calloc((INET6_ADDRSTRLEN + 2) + 1, sizeof(char));
		memset(ret, 0, sizeof(char)* (INET6_ADDRSTRLEN + 2) + 1);
		inet_ntop(AF_INET6, In->Data, ret + 1, INET6_ADDRSTRLEN);
		ret[0] = '[';
		ret[strlen(ret)] = ']';
	}
	return ret;
}

MEM_OUT struct sockaddr *IPv6MapToRaw(IPv6Map *In, uint16_t Port)
{
	if (GetIPType(In) == IPV4) {
		struct sockaddr_in *sin = calloc(1, sizeof(struct sockaddr_in));
		*((uint32_t*)(&(sin->sin_addr.s_addr))) = In->Data[3];
		sin->sin_family = AF_INET;
		sin->sin_port = htons(Port);
		return (struct sockaddr*)sin;
	} else {
		/*struct sockaddr_in6 *sin = calloc(1, sizeof(struct sockaddr_in6)); // need sockaddr ??
		//sin->sin6_len = sizeof(sizeof(struct sockaddr_in6));
		sin->sin6_family = AF_INET6;
		sin->sin6_port = htons(Port);
		memcpy(&(sin->sin6_addr.__in6_u), In->Data, IPV6_SIZE);
		return (struct sockaddr*)sin;*/
		struct sockaddr_in6 *sin = calloc(1, sizeof(struct sockaddr_in6));
		char *ip = IPv6MapToString(In); {
			inet_pton(AF_INET6, ip, &(sin->sin6_addr));
		} free(ip);
		sin->sin6_family = AF_INET6;
		sin->sin6_port = htons(Port);
		return (struct sockaddr*)sin;
	}
}

MEM_OUT IPv6Map *RawToIPv6Map(struct sockaddr *In)
{
	IPv6Map *ret = malloc(sizeof(IPv6Map));
	if (In->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in*)In;
		memset(ret->Data, 0, IPV6_SIZE / 2);
		ret->Data[3] = sin->sin_addr.s_addr;
		ret->Data[2] = 0xFFFF0000; // THAT WAY!
	} else {
		struct sockaddr_in6 *sin = (struct sockaddr_in6*)In;
		memcpy(ret->Data, In->sa_data, IPV6_SIZE);
	}
	return ret;
}

MEM_OUT IPv6Map *GetIPFromHSock(int hSock)
{
	socklen_t len;
	struct sockaddr_storage addr;

	len = sizeof(addr);
	getpeername(hSock, (struct sockaddr*)&addr, &len);

	IPv6Map *ret = zalloc(sizeof(IPv6Map));

	if (addr.ss_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)&addr;
		memcpy(&(ret->Data[3]), &(s->sin_addr.s_addr), IPV4_SIZE);
		ret->Data[2] = 0xFFFF0000; // THAT WAY!
	} else { // AF_INET6
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
		memcpy(ret->Data, s->sin6_addr.__in6_u.__u6_addr8, IPV6_SIZE);
	}

	return ret;
}

bool IPv6MapCompare(IPv6Map *a, IPv6Map *b)
{
	IP_TYPE type;
	if (GetIPType(a) != GetIPType(b))
		return false;
	type = GetIPType(a);

	return memcmp(a->Data, b->Data, type == IPV4 ? IPV4_SIZE : IPV6_SIZE) == 0;
}