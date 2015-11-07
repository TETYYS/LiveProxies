#define _GNU_SOURCE

#include "Base64.h"
#include "Logger.h"
#include "IPv6Map.h"
#include "ProxyLists.h"
#include "Global.h"
#include <maxminddb.h>
#include "ProxyRequest.h"
#include "ProxyRemove.h"
#include "Interface.h"
#include "Config.h"
#include "CPH_Threads.h"
#include <openssl/ssl.h>
#include <pcre.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <event2/util.h>
#include "Server.h"
#include <event2/buffer.h>
#ifdef __linux__
#include <unistd.h>
#endif
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#include "HtmlTemplate.h"
#include "Websocket.h"
#include <stdio.h>
#if defined DEBUG && defined HAVE_VALGRIND
#include <valgrind/memcheck.h>
#endif
#include <openssl/rand.h>

static const char *GetCountryByIPv6Map(IPv6Map *In)
{
	int status;
	MMDB_lookup_result_s data;
	struct sockaddr* sa = IPv6MapToRaw(In, 0); {
		data = MMDB_lookup_sockaddr(&GeoIPDB, sa, &status);
	} free(sa);

	if (status != MMDB_SUCCESS) {
		char *ip = IPv6MapToString2(In); {
			Log(LOG_LEVEL_WARNING, "(1) Failed to lookup country for %s (%s)", ip, MMDB_strerror(status));
		} free(ip);
		return "--";
	}

	if (data.found_entry) {
		MMDB_entry_data_s entry;

		int status = MMDB_get_value(&data.entry, &entry, "country", "iso_code", NULL);
		if (status != MMDB_SUCCESS) {
			char *ip = IPv6MapToString2(In); {
				Log(LOG_LEVEL_WARNING, "(3) Failed to lookup country for %s (%s)", ip, MMDB_strerror(status));
			} free(ip);
			return "--";
		}
		if (entry.has_data)
			return entry.utf8_string;
		else {
			char *ip = IPv6MapToString2(In); {
				Log(LOG_LEVEL_DEBUG, "(4) Failed to lookup country for %s (%s)", ip, MMDB_strerror(status));
			} free(ip);
			return "--";
		}
	} else {
		char *ip = IPv6MapToString2(In); {
			Log(LOG_LEVEL_WARNING, "(2) Failed to lookup country for %s (%s)", ip, MMDB_strerror(status));
		} free(ip);
		return "--";
	}
}

void SendChunkPrintf(struct bufferevent *BuffEvent, char *Format, ...)
{
	char *body;
	char *all;

	va_list args;
	va_start(args, Format); {
		exit(1); // TODO: MINGW
		//vasprintf(&body, Format, args);
	} va_end(args);
	size_t bodyLen = strlen(body);

	char hex[8];
	sprintf(hex, "%x", bodyLen);

	all = malloc((strlen(hex) + 2 + bodyLen + 2) * sizeof(char) + 1); {
		sprintf(all, "%s\r\n%s\r\n", hex, body);
		bufferevent_write(BuffEvent, all, (strlen(hex) + 2 + bodyLen + 2) * sizeof(char));
	} free(all);
	free(body);
}

static void ProxyCheckLanding(struct bufferevent *BuffEvent, char **Buff)
{
	// Loose proxy is automatically free'd by EVWrite called timeout

	UNCHECKED_PROXY *UProxy = NULL;
	PROXY *proxy;
	char *keyRaw;

	char *lpKeyStart, *lpKeyEnd;
	size_t buffLen = strlen(*Buff);

	/* Get UProxy pointer */ {
		if (!HTTPFindHeader("LPKey: ", *Buff, &keyRaw, &lpKeyStart, &lpKeyEnd))
			return;

		char *key;
		size_t len; // trash
		if (!Base64Decode(keyRaw, (unsigned char**)(&key), &len)) {
			free(keyRaw);
			return;
		}

		pthread_mutex_lock(&LockUncheckedProxies); {
			for (uint64_t x = 0; x < SizeUncheckedProxies; x++) {
				if (MemEqual(key, UncheckedProxies[x]->identifier, PROXY_IDENTIFIER_LEN)) {
					UProxy = UncheckedProxies[x];
					pthread_mutex_lock(&(UProxy->processing));
				}
			}
		} pthread_mutex_unlock(&LockUncheckedProxies);
		free(key);

		if (UProxy == NULL) {
			free(keyRaw);
			return;
		}
	} /* End get UProxy pointer */

	/* Process headers */ {
		if (UProxy->associatedProxy == NULL) {
			proxy = malloc(sizeof(PROXY));
			proxy->ip = malloc(sizeof(IPv6Map));
			memcpy(proxy->ip->Data, UProxy->ip->Data, IPV6_SIZE);

			proxy->port = UProxy->port;
			proxy->type = UProxy->type;
			proxy->country = GetCountryByIPv6Map(proxy->ip);
			proxy->liveSinceMs = proxy->lastCheckedMs = GetUnixTimestampMilliseconds();
			proxy->failedChecks = 0;
			proxy->httpTimeoutMs = GetUnixTimestampMilliseconds() - UProxy->requestTimeHttpMs;
			proxy->timeoutMs = GetUnixTimestampMilliseconds() - UProxy->requestTimeMs;
			RAND_pseudo_bytes((unsigned char*)(&proxy->identifier), PROXY_IDENTIFIER_LEN);
			proxy->rechecking = false;
			proxy->retries = 0;
			proxy->successfulChecks = 1;
			proxy->anonymity = ANONYMITY_NONE;
		} else
			proxy = UProxy->associatedProxy;

		proxy->invalidCert = UProxy->invalidCert != NULL ? X509_dup(UProxy->invalidCert) : NULL;
		if (proxy->invalidCert != NULL)
			proxy->anonymity = ANONYMITY_TRANSPARENT;
		else {
			bool anonMax = true;

			char *host = GetHost(GetIPType(UProxy->ip), ProxyIsSSL(UProxy->type));
			if (!StrReplaceOrig(Buff, host, "{HOST}") || !StrReplaceOrig(Buff, "/prxchk", "{PAGE_PATH}"))
				anonMax = false;
			if (!StrReplaceOrig(Buff, keyRaw, "{KEY_VAL}")) {
				Log(LOG_LEVEL_ERROR, "StrReplaceOrig {KEY_VAL} failed");
				goto freeProxy;
			}

			buffLen = strlen(*Buff);

			if (RequestStringLen != buffLen || !MemEqual(*Buff, RequestString, buffLen))
				anonMax = false;

			if (!anonMax) {
				int subStrVec[256];
				for (size_t i = 0;i < 2;i++) {
					int regexRet = pcre_exec(i == 0 ? ipv4Regex : ipv6Regex, i == 0 ? ipv4RegexEx : ipv6RegexEx, *Buff, buffLen, 0, 0, subStrVec, 256);

					if (regexRet != PCRE_ERROR_NOMATCH) {
						if (regexRet < 0) {
							Log(LOG_LEVEL_ERROR, "Couldn't execute PCRE %s regex", (i == 0 ? "IPv4" : "IPv6"));
							free(keyRaw);
							goto freeProxy;
						} else {
							const char *foundIpStr;
							for (size_t x = 0; x < regexRet; x++) {
								pcre_get_substring(*Buff, subStrVec, regexRet, x, &foundIpStr);
								if (foundIpStr != NULL) {
									IPv6Map *foundIp = StringToIPv6Map((char*)foundIpStr);
									if (foundIp != NULL && IPv6MapEqual(i == 0 ? GlobalIp4 : GlobalIp6, foundIp)) {
										Log(LOG_LEVEL_DEBUG, "WServer: switch to transparent proxy on (type %d)", UProxy->type);
										proxy->anonymity = ANONYMITY_TRANSPARENT;
										free(foundIp);
										pcre_free_substring(foundIpStr);
										break;
									}
									free(foundIp);
								}
								pcre_free_substring(foundIpStr);
							}
						}
					}
				}

				if (proxy->anonymity == ANONYMITY_NONE)
					proxy->anonymity = ANONYMITY_ANONYMOUS;
			} else
				proxy->anonymity = ANONYMITY_MAX;
		}

		free(keyRaw);

		UProxy->checkSuccess = true;

		if (UProxy->associatedProxy == NULL) {
			Log(LOG_LEVEL_DEBUG, "WServer: Final proxy add type %d anonimity %d", proxy->type, proxy->anonymity);
			ProxyAdd(proxy);
		} else
			UProxy->associatedProxy->rechecking = false;
	} /* End process headers */

	if (UProxy->timeout != NULL)
		event_active(UProxy->timeout, EV_TIMEOUT, 0);

	pthread_mutex_unlock(&(UProxy->processing));

	/* Output */ {
		bufferevent_write(BuffEvent, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", 46 * sizeof(char));
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);
	}

	return;
freeProxy:
	pthread_mutex_unlock(&(UProxy->processing));
	if (UProxy->associatedProxy == NULL) {
		free(proxy->ip);
		free(proxy);
	}
}

void ServerEvent(struct bufferevent *BuffEvent, short Event, void *Ctx)
{
	if ((Event & BEV_EVENT_CONNECTED) != BEV_EVENT_CONNECTED)
		bufferevent_free(BuffEvent);
}

static void ServerLanding(struct bufferevent *BuffEvent, char **Buff, bool IsSSL)
{
	UNCHECKED_PROXY *UProxy = NULL;
	bool freeBufferEvent = true;

	bufferevent_set_timeouts(BuffEvent, NULL, NULL);

	Log(LOG_LEVEL_DEBUG, "Server landing");
	/* Page dispatch */ {
		char *firstIndex = strchr(*Buff, ' ');

		if (firstIndex == NULL)
			goto free;

		char *secondIndex = strchr(firstIndex + 1, ' ');

		if (secondIndex == NULL)
			goto free;

		size_t pathLen = secondIndex - (firstIndex + 1);

		char *path = malloc(pathLen * sizeof(char) + 1); {
			memcpy(path, firstIndex + 1, pathLen * sizeof(char) + 1);
			path[pathLen] = 0x00;

			Log(LOG_LEVEL_DEBUG, "Server -> %s", path);

			bufferevent_setcb(BuffEvent, NULL, NULL, NULL, NULL);

			if (pathLen == 7 && strncmp(path, "/prxchk", 7) == 0) {
				bufferevent_set_timeouts(BuffEvent, &GlobalTimeoutTV, &GlobalTimeoutTV);
				ProxyCheckLanding(BuffEvent, Buff);
			} else if (pathLen == 7 && strncmp(path, "/ifaceu", 7) == 0)
				InterfaceUncheckedProxies(BuffEvent, *Buff);
			else if (pathLen == 6 && strncmp(path, "/iface", 6) == 0)
				InterfaceProxies(BuffEvent, *Buff);
			else if (pathLen == 7 && strncmp(path, "/prxsrc", 7) == 0)
				InterfaceProxySources(BuffEvent, *Buff);
			else if (pathLen == 6 && strncmp(path, "/stats", 6) == 0)
				InterfaceStats(BuffEvent, *Buff);
			else if (pathLen > 4 && strncmp(path, "/zen", 4) == 0) {
				freeBufferEvent = false; // Free'd in second stage of ZEN DNS lookup
				InterfaceRawSpamhausZen(BuffEvent, *Buff);
			} else if (pathLen > 7 && strncmp(path, "/httpbl", 7) == 0) {
				freeBufferEvent = false; // Free'd in second stage of Http:BL DNS lookup
				InterfaceRawHttpBL(BuffEvent, *Buff);
			} else if (pathLen > 5 && strncmp(path, "/rdns", 5) == 0)
				InterfaceRawReverseDNS(BuffEvent, *Buff);
			else if (pathLen >= 4 && strncmp(path, "/add", 4) == 0) {
				freeBufferEvent = false; // Needed by POST
				InterfaceRawUProxyAdd(BuffEvent, *Buff);
			} else if (pathLen > 12 && strncmp(path, "/cpagerender", 12) == 0) {
				freeBufferEvent = false; // Free'd in second stage of custom page request
				InterfaceRawGetCustomPage(BuffEvent, *Buff, true);
			} else if (pathLen == 14 && strncmp(path, "/getallproxies", 14) == 0) {
				InterfaceRawGetAllProxies(BuffEvent, *Buff);
			} else if (pathLen > 6 && strncmp(path, "/cpage", 6) == 0) {
				freeBufferEvent = false; // Free'd in second stage of custom page request
				InterfaceRawGetCustomPage(BuffEvent, *Buff, false);
			} else if (pathLen == 6 && strncmp(path, "/tools", 6) == 0)
				InterfaceTools(BuffEvent, *Buff);
			else if (pathLen >= 9 && strncmp(path, "/settings", 9) == 0)
				InterfaceSettings(BuffEvent, *Buff);
#if DEBUG
			else if (pathLen == 24 && strncmp(path, "/tools?action=tmplreload", 24) == 0)
				InterfaceHtmlTemplatesReload(BuffEvent, *Buff);
#endif
			else if (pathLen > 6 && strncmp(path, "/check", 6) == 0) {
				Log(LOG_LEVEL_DEBUG, "/check on %p", BuffEvent);
				freeBufferEvent = false; // Free'd in second stage of raw recheck
				InterfaceRawRecheck(BuffEvent, *Buff);
			} else if (pathLen == 1 && strncmp(path, "/", 1) == 0)
				InterfaceHome(BuffEvent, *Buff);
			else if (pathLen > 8 && strncmp(path, "/recheck", 8) == 0) {
				if (HtmlTemplateUseStock)
					freeBufferEvent = false; // Free'd in second stage of stock html recheck
				InterfaceProxyRecheck(BuffEvent, *Buff);
			} else if (pathLen == 4 && strncmp(path, "/wsn", 4) == 0) {
				// Websocket notifications
				WebsocketSwitch(BuffEvent, *Buff);
				freeBufferEvent = false; // Handled by websocket file
			} else {
				if (HtmlTemplateUseStock)
					goto free;
				/* Ruse filter */ {
					// We don't resolve unicode or http %hex so we don't care
					// Absolute path traversal doesn't apply

					if (strstr(path, "..") != 0) {
						// no
						goto free;
					}
				} /* End ruse filter */
				
#if defined _WIN32 || defined _WIN64
				StrReplaceOrig(&path, "/", "\\");
#endif

#ifdef __linux__
				char *filePath = malloc((pathLen + (strlen(LINUX_LOCAL_HTML_PATH) + 13)) * sizeof(char) + 1); {
					strcpy(filePath, LINUX_LOCAL_HTML_PATH"/files");
					strcat(filePath, path);
#elif defined _WIN32 || defined _WIN64
				char *filePath = malloc((pathLen + (strlen(WINDOWS_LOCAL_HTML_PATH) + 13)) * sizeof(char) + 1); {
					strcpy(filePath, WINDOWS_LOCAL_HTML_PATH"\\files");
					strcat(filePath, path);
#endif

					FILE *hFile;
					if ((hFile = fopen(filePath, "r")) == NULL) {
						Log(LOG_LEVEL_DEBUG, "Can't open file %s", filePath);
						free(filePath);
#ifdef __linux__
						filePath = malloc((pathLen + (strlen(LINUX_GLOBAL_HTML_PATH) + 13)) * sizeof(char) + 1);
						strcpy(filePath, LINUX_GLOBAL_HTML_PATH"/files");
						strcat(filePath, path);
#elif defined _WIN32 || defined _WIN64
						filePath = malloc((pathLen + strlen(WinAppData) + strlen(WINDOWS_GLOBAL_HTML_PATH) + 13) * sizeof(char) + 1);
						strcpy(filePath, WinAppData);
						strcat(filePath, WINDOWS_GLOBAL_HTML_PATH"\\files");
						strcat(filePath, path);
#endif
						hFile = fopen(filePath, "r"); // uwaga
					}
					if (hFile != NULL) {
						Log(LOG_LEVEL_DEBUG, "Pushing file %s...", filePath);
						fseek(hFile, 0, SEEK_END);
						size_t size = ftell(hFile);
						fseek(hFile, 0, SEEK_SET);

						char *mime = "text/plain";

						for (size_t x = 0;x < HtmlTemplateMimeTypesSize;x++) {
							if (strcmp(&(path[pathLen - strlen(HtmlTemplateMimeTypes[x].extension)]), HtmlTemplateMimeTypes[x].extension) == 0) {
								mime = HtmlTemplateMimeTypes[x].type;
								break;
							}
						}

						size_t intSize = INTEGER_VISIBLE_SIZE(size);

						char *header = malloc(((53 + intSize + strlen(mime)) * sizeof(char)) + 1); {
							sprintf(header, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: %s\r\n\r\n", size, mime);
							bufferevent_write(BuffEvent, header, (53 + intSize + strlen(mime)) * sizeof(char));
						} free(header);

						evbuffer_add_file(bufferevent_get_output(BuffEvent), fileno(hFile), 0, size);
						bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);
					} else {
						Log(LOG_LEVEL_DEBUG, "Can't open file %s", filePath);
#if defined _WIN32 || defined _WIN64
						Log(LOG_LEVEL_DEBUG, "WIN: %d", GetLastError());
#endif
					}
				} free(filePath);
			}
		} free(path);
	} /* End page dispatch */

free:
	if (freeBufferEvent)
		BufferEventFreeOnWrite(BuffEvent);
}

typedef enum _SERVER_TYPE {
	HTTP4,
	HTTP6,
	SSL4,
	SSL6
} SERVER_TYPE;

void ServerRead(struct bufferevent *BuffEvent, void *Ctx)
{
	struct evbuffer *evBuff = bufferevent_get_input(BuffEvent);

	size_t len = evbuffer_get_length(evBuff);
	if (len <= 3) {
		bufferevent_free(BuffEvent);
		return;
	}

	char *buff = malloc(len + 1);
	evbuffer_copyout(evBuff, buff, len);

#if defined DEBUG && defined HAVE_VALGRIND
	VALGRIND_MAKE_MEM_DEFINED(buff, len + 1);
#endif

	// Websockets
	if (!HtmlTemplateUseStock) {
		uint8_t opcode = (*buff & 0xF); // get rid of 4 bits on left
		if ((opcode == WEBSOCKET_OPCODE_CONTINUATION || opcode == WEBSOCKET_OPCODE_CLOSE || opcode == WEBSOCKET_OPCODE_PING || opcode == WEBSOCKET_OPCODE_PONG || opcode == WEBSOCKET_OPCODE_UNICODE) &&
			!GET_BIT(*buff, 6) && !GET_BIT(*buff, 5) && !GET_BIT(*buff, 4)) {
			// Websocket message (probably)
			evbuffer_drain(evBuff, len); // No clear data function?
			buff = realloc(buff, len);
			WebsocketLanding(BuffEvent, buff, len);
			free(buff);
			return;
		}
	}

	for (size_t x = 0;x < len;x++) {
		// Stop the Ruse man
		if (buff[x] == 0x00) {
			free(buff);
			bufferevent_free(BuffEvent);
			return;
		}
	}

	if (buff[0] != 'G' && buff[0] != 'P' && buff[1] != 'O') {
		free(buff);
		bufferevent_free(BuffEvent);
		return;
	}

	if (buff[0] == 'G') {
		bool valid = false;
		if (buff[len - 1] == '\n' && buff[len - 2] == '\r' && buff[len - 3] == '\n' && buff[len - 4] == '\r')
			valid = true;
		if (!valid) {
			if (buff[len - 1] != '\n' || buff[len - 2] != '\n') {
				// Not a full header
				// We got data in evbuffer, just return and wait for remaining data
				free(buff);
				return;
			}
		}
	} else {
		if (strstr(buff, "\r\n\r\n") == NULL && strstr(buff, "\n\n") == NULL) {
			free(buff);
			return;
		}
	}

	buff[len] = 0x00;
	evbuffer_drain(evBuff, len); // No clear data function?

	ServerLanding(BuffEvent, &buff, Ctx);

	free(buff);
}

int sslCreated = 0;

static void ServerAccept(struct evconnlistener *List, evutil_socket_t Fd, struct sockaddr *Address, int Socklen, void *Ctx)
{
	SERVER_TYPE type = (SERVER_TYPE)Ctx;
	struct event_base *base = evconnlistener_get_base(List);

	switch (type) {
		case HTTP4:
		case HTTP6:
		{
			struct bufferevent *bev = bufferevent_socket_new(base, Fd, BEV_OPT_CLOSE_ON_FREE);
			bufferevent_set_timeouts(bev, &GlobalTimeoutTV, &GlobalTimeoutTV);
			bufferevent_setcb(bev, ServerRead, NULL, (bufferevent_event_cb)ServerEvent, false);
			bufferevent_enable(bev, EV_READ | EV_WRITE);
			break;
		}
		case SSL4:
		case SSL6:
		{
			struct bufferevent *bev = bufferevent_openssl_socket_new(base, Fd, SSL_new(levServerSSL), BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
			bufferevent_set_timeouts(bev, &GlobalTimeoutTV, &GlobalTimeoutTV);
			bufferevent_setcb(bev, ServerRead, NULL, (bufferevent_event_cb)ServerEvent, (void*)true);
			bufferevent_enable(bev, EV_READ | EV_WRITE);
			break;
		}
	}
}

static struct evconnlistener *LevConnListenerBindCustom(struct event_base *Base, evconnlistener_cb Cb, void *Arg, IPv6Map *Ip, uint16_t Port)
{
	struct evconnlistener *listener;
	evutil_socket_t fd;
	int on = 1;
	int family = GetIPType(Ip) == IPV4 ? AF_INET : AF_INET6;
#if defined LEV_OPT_REUSEABLE_PORT && defined LEV_OPT_DEFERRED_ACCEPT
	int flags = LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE | LEV_OPT_REUSEABLE_PORT | LEV_OPT_DEFERRED_ACCEPT;
#else
	int flags = LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE;
#endif

	fd = socket(family, SOCK_STREAM, 0);

	if (fd == -1)
		return NULL;

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void*)&on, sizeof(on)) < 0)
		goto err;

	if (evutil_make_socket_nonblocking(fd) < 0 ||
		evutil_make_listen_socket_reuseable(fd) < 0 ||
		evutil_make_listen_socket_reuseable_port(fd) < 0 ||
		evutil_make_tcp_listen_socket_deferred(fd) < 0)
		goto err;

	if (family == AF_INET6) {
#ifdef IPV6_V6ONLY
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on)) < 0)
			goto err;
#endif
	}

	struct sockaddr *sin = IPv6MapToRaw(Ip, Port); {
		if (bind(fd, sin, family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0) {
			free(sin);
			goto err;
		}
	} free(sin);

	listener = evconnlistener_new(Base, Cb, Arg, flags, -1, fd);
	if (!listener)
		goto err;

	return listener;
err:
	evutil_closesocket(fd);
	return NULL;
}

void ServerBaseSSL()
{
	if (!SSLEnabled)
		return;

	levServerBaseSSL = event_base_new();

	IPv6Map map;
	memset(&map, 0, IPV6_SIZE);

	if (GlobalIp4 != NULL) {
		map.Data[2] = 0xFFFF0000;

		levServerListSSL4 = LevConnListenerBindCustom(levServerBaseSSL, ServerAccept, (void*)SSL4, &map, SSLServerPort);
		if (!levServerListSSL4) {
			Log(LOG_LEVEL_ERROR, "Failed to listen on %d (SSL4)\n", ServerPort);
			exit(EXIT_FAILURE);
		}
	}
	if (GlobalIp6 != NULL) {
		memset(&map, 0, IPV6_SIZE);

		levServerListSSL6 = LevConnListenerBindCustom(levServerBaseSSL, ServerAccept, (void*)SSL6, &map, SSLServerPort);
		if (!levServerListSSL6) {
			Log(LOG_LEVEL_ERROR, "Failed to listen on %d (SSL6)\n", ServerPort);
			exit(EXIT_FAILURE);
		}
	}

	event_base_dispatch(levServerBaseSSL);
}

void ServerBase()
{
	levServerBase = event_base_new();

	IPv6Map map;
	memset(&map, 0, IPV6_SIZE);

	if (GlobalIp4 != NULL) {
		map.Data[2] = 0xFFFF0000;

		levServerList4 = LevConnListenerBindCustom(levServerBase, ServerAccept, HTTP4, &map, ServerPort);
		if (!levServerList4) {
			Log(LOG_LEVEL_ERROR, "Failed to listen on %d (HTTP4)\n", ServerPort);
			exit(EXIT_FAILURE);
		}
	}
	if (GlobalIp6 != NULL) {
		memset(&map, 0, IPV6_SIZE);

		levServerList6 = LevConnListenerBindCustom(levServerBase, ServerAccept, (void*)HTTP6, &map, ServerPort);
		if (!levServerList6) {
			Log(LOG_LEVEL_ERROR, "Failed to listen on %d (HTTP6)\n", ServerPort);
			exit(EXIT_FAILURE);
		}
	}

	event_base_dispatch(levServerBase);
}

static void ServerUDP(int hSock)
{
	char *buff = malloc(PROXY_IDENTIFIER_LEN);
	struct sockaddr_in6 remote;
	socklen_t len;
	size_t size;

	for (;;) {
		len = sizeof(struct sockaddr_in6);
		Log(LOG_LEVEL_DEBUG, "WServerUDP: Waiting...");
		size = recvfrom(hSock, buff, PROXY_IDENTIFIER_LEN, 0, &remote, &len);
		Log(LOG_LEVEL_DEBUG, "WServerUDP: Got data");
		if (size != PROXY_IDENTIFIER_LEN) {
			Log(LOG_LEVEL_DEBUG, "WServerUDP: Drop on len (%d)", size);
			continue;
		}

		UNCHECKED_PROXY *UProxy = NULL;

		IPv6Map *ip = RawToIPv6Map(&remote); {
			pthread_mutex_lock(&LockUncheckedProxies); {
				for (uint64_t x = 0; x < SizeUncheckedProxies; x++) {
					if (MemEqual(buff, UncheckedProxies[x]->identifier, PROXY_IDENTIFIER_LEN) && IPv6MapEqual(ip, UncheckedProxies[x]->ip)) {
						UProxy = UncheckedProxies[x];
						pthread_mutex_lock(&(UProxy->processing));
					}
				}
			} pthread_mutex_unlock(&LockUncheckedProxies);
		} free(ip);

		if (UProxy == NULL) {
			Log(LOG_LEVEL_DEBUG, "WServerUDP: Drop on proxy");
			continue;
		}

		PROXY *proxy;

		if (UProxy->associatedProxy == NULL) {
			proxy = malloc(sizeof(PROXY));
			proxy->ip = malloc(sizeof(IPv6Map));
			memcpy(proxy->ip->Data, UProxy->ip->Data, IPV6_SIZE);

			proxy->port = UProxy->port;
			proxy->type = UProxy->type;
			proxy->country = GetCountryByIPv6Map(proxy->ip);
			proxy->liveSinceMs = proxy->lastCheckedMs = GetUnixTimestampMilliseconds();
			proxy->failedChecks = 0;
			proxy->httpTimeoutMs = GetUnixTimestampMilliseconds() - UProxy->requestTimeHttpMs;
			proxy->timeoutMs = GetUnixTimestampMilliseconds() - UProxy->requestTimeMs;
			proxy->rechecking = false;
			proxy->retries = 0;
			proxy->successfulChecks = 1;
			proxy->anonymity = ANONYMITY_NONE;
			proxy->invalidCert = NULL;
		} else
			proxy = UProxy->associatedProxy;

		UProxy->checkSuccess = true;

		if (UProxy->associatedProxy == NULL) {
			Log(LOG_LEVEL_DEBUG, "WServerUDP: Final proxy");
			ProxyAdd(proxy);
		} else
			UProxy->associatedProxy->rechecking = false;

		if (UProxy->timeout != NULL)
			event_active(UProxy->timeout, EV_TIMEOUT, 0);

		pthread_mutex_unlock(&(UProxy->processing));
	}
}

void ServerUDP4()
{
	size_t hSock;
	struct sockaddr_in local;

	hSock = socket(AF_INET, SOCK_DGRAM, 0);
	int yes = 1;
	setsockopt(hSock, SOL_SOCKET, SO_REUSEADDR, (void *)&yes, sizeof(yes));
#if defined __linux__ && defined SO_REUSEPORT
	setsockopt(hSock, SOL_SOCKET, SO_REUSEPORT, (void *)&yes, sizeof(yes));
#endif

	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_port = htons(ServerPortUDP);
	bind(hSock, (struct sockaddr *)&local, sizeof(local));

	pthread_t wServerUDP;
	int status;
	if ((status = pthread_create(&wServerUDP, NULL, (void*)ServerUDP, (void*)hSock)) != 0) {
		Log(LOG_LEVEL_ERROR, "WServerUDP thread creation error, return code: %d\n", status);
		return;
	}
	pthread_detach(wServerUDP);
}

void ServerUDP6()
{
	size_t hSock;
	struct sockaddr_in6 local;

	hSock = socket(AF_INET6, SOCK_DGRAM, 0);
	int yes = 1;
	setsockopt(hSock, SOL_SOCKET, SO_REUSEADDR, (void *)&yes, sizeof(yes));
#if defined __linux__ && defined SO_REUSEPORT
	setsockopt(hSock, SOL_SOCKET, SO_REUSEPORT, (void *)&yes, sizeof(yes));
#endif
#ifdef IPV6_V6ONLY
	setsockopt(hSock, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&yes, sizeof(yes));
#endif

	memset(&local, 0, sizeof(local));
	local.sin6_family = AF_INET6;
	local.sin6_port = htons(ServerPortUDP);
	bind(hSock, (struct sockaddr *)&local, sizeof(local));

	pthread_t wServerUDP;
	int status;
	if ((status = pthread_create(&wServerUDP, NULL, (void*)ServerUDP, (void*)hSock)) != 0) {
		Log(LOG_LEVEL_ERROR, "WServerUDP thread creation error, return code: %d\n", status);
		return;
	}
	pthread_detach(wServerUDP);
}