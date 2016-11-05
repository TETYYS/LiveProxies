#include "IPv6Map.h"
#include "Global.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#ifdef __linux__
	#include <sys/socket.h>
	#include <arpa/inet.h>
#elif defined _WIN32 || defined _WIN64
	#include <winsock2.h>
	#include <ws2tcpip.h>
#endif
#include <assert.h>

#ifdef __MINGW32__
#define NS_INADDRSZ  4
#define NS_IN6ADDRSZ 16
#define NS_INT16SZ   2

int inet_pton6(const char *src, char *dst)
{
	static const char xdigits[] = "0123456789abcdef";
	uint8_t tmp[NS_IN6ADDRSZ];

	uint8_t *tp = (uint8_t*)memset(tmp, '\0', NS_IN6ADDRSZ);
	uint8_t *endp = tp + NS_IN6ADDRSZ;
	uint8_t *colonp = NULL;

	/* Leading :: requires some special handling. */
	if (*src == ':') {
		if (*++src != ':')
			return 0;
	}

	const char *curtok = src;
	int saw_xdigit = 0;
	uint32_t val = 0;
	int ch;
	while ((ch = tolower(*src++)) != '\0') {
		const char *pch = strchr(xdigits, ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return 0;
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return 0;
				colonp = tp;
				continue;
			} else if (*src == '\0') {
				return 0;
			}
			if (tp + NS_INT16SZ > endp)
				return 0;
			*tp++ = (uint8_t)(val >> 8) & 0xff;
			*tp++ = (uint8_t)val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) &&
			inet_pton4(curtok, (char*)tp) > 0) {
			tp += NS_INADDRSZ;
			saw_xdigit = 0;
			break; /* '\0' was seen by inet_pton4(). */
		}
		return 0;
	}
	if (saw_xdigit) {
		if (tp + NS_INT16SZ > endp)
			return 0;
		*tp++ = (uint8_t)(val >> 8) & 0xff;
		*tp++ = (uint8_t)val & 0xff;
	}
	if (colonp != NULL) {
		/*
		* Since some memmove()'s erroneously fail to handle
		* overlapping regions, we'll do the shift by hand.
		*/
		const int n = tp - colonp;

		if (tp == endp)
			return 0;

		for (int i = 1; i <= n; i++) {
			endp[-i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return 0;

	memcpy(dst, tmp, NS_IN6ADDRSZ);

	return 1;
}

int inet_pton4(const char *src, char *dst)
{
	uint8_t tmp[NS_INADDRSZ], *tp;

	int saw_digit = 0;
	int octets = 0;
	*(tp = tmp) = 0;

	int ch;
	while ((ch = *src++) != '\0') {
		if (ch >= '0' && ch <= '9') {
			uint32_t n = *tp * 10 + (ch - '0');

			if (saw_digit && *tp == 0)
				return 0;

			if (n > 255)
				return 0;

			*tp = n;
			if (!saw_digit) {
				if (++octets > 4)
					return 0;
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return 0;
			*++tp = 0;
			saw_digit = 0;
		} else
			return 0;
	}
	if (octets < 4)
		return 0;

	memcpy(dst, tmp, NS_INADDRSZ);

	return 1;
}

int inet_pton(int af, const char *src, char *dst)
{
	switch (af) {
		case AF_INET:
			return inet_pton4(src, dst);
		case AF_INET6:
			return inet_pton6(src, dst);
		default:
			return -1;
	}
}

WINSOCK_API_LINKAGE const char WSAAPI inet_ntop(int af, const void *src, char *dst, socklen_t size);
#endif

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
	char *ret = NULL;
	if (GetIPType(In) == IPV4) {
		ret = malloc(sizeof(char)* INET_ADDRSTRLEN + 1);
		inet_ntop(AF_INET, &(In->Data[3]), ret, INET_ADDRSTRLEN);
	} else if (GetIPType(In) == IPV6) {
		ret = malloc(sizeof(char)* INET6_ADDRSTRLEN + 1);
		inet_ntop(AF_INET6, In->Data, ret, INET6_ADDRSTRLEN);
	} else
		assert(false);
	return ret;
}

MEM_OUT char *IPv6MapToString2(IPv6Map *In)
{
	char *ret = NULL;
	if (GetIPType(In) == IPV4) {
		ret = malloc(sizeof(char)* INET_ADDRSTRLEN + 1);
		inet_ntop(AF_INET, &(In->Data[3]), ret, INET_ADDRSTRLEN);
	} else if (GetIPType(In) == IPV6) {
		ret = zalloc(sizeof(char) * (INET6_ADDRSTRLEN + 2) + 1);//calloc((INET6_ADDRSTRLEN + 2) + 1, sizeof(char));
		inet_ntop(AF_INET6, In->Data, ret + 1, INET6_ADDRSTRLEN);
		ret[0] = '[';
		ret[strlen(ret)] = ']';
	} else
		assert(false);
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
	} else
		memcpy(ret->Data, In->sa_data, IPV6_SIZE);
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
#ifdef __linux__
		memcpy(ret->Data, s->sin6_addr.__in6_u.__u6_addr8, IPV6_SIZE);
#elif defined _WIN32 || defined _WIN64
		memcpy(ret->Data, s->sin6_addr.s6_addr, IPV6_SIZE);
#endif
	}

	return ret;
}

bool IPv6MapEqual(IPv6Map *a, IPv6Map *b)
{
	IP_TYPE type;
	if (GetIPType(a) != GetIPType(b))
		return false;
	type = GetIPType(a);

	if (type == IPV4) {
		return MemEqual((uint8_t*)(&(a->Data[3])), (uint8_t*)(&(b->Data[3])), IPV4_SIZE);
	}

	return MemEqual(a->Data, b->Data, IPV6_SIZE);
}