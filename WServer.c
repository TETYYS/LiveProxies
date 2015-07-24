#include "Base64.h"
#include "Logger.h"
#include "IPv6Map.h"
#include "ProxyLists.h"
#include "Global.h"
#include "GeoIP.h"
#include "WServer.h"
#include "ProxyRequest.h"
#include "ProxyRemove.h"
#include "Interface.h"
#include "Config.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pcre.h>
#include <assert.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <evhtp.h>
#include <assert.h>

static char *GetCountryByIPv6Map(IPv6Map *In)
{
	if (GetIPType(In) == IPV4) {
		if (GeoIPDB == NULL)
			GeoIPDB = GeoIP_open("/usr/local/share/GeoIP/GeoIP.dat", GEOIP_MEMORY_CACHE);
		assert(GeoIPDB != NULL);
	} else {
		if (GeoIPDB6 == NULL)
			GeoIPDB6 = GeoIP_open("/usr/local/share/GeoIP/GeoIPv6.dat", GEOIP_MEMORY_CACHE);
		assert(GeoIPDB6 != NULL);
	}

	char *ret;
	if (GetIPType(In) == IPV4) {
		ret = GeoIP_country_name_by_ipnum(GeoIPDB, In->Data[3]);
	} else {
		geoipv6_t ip;
		memcpy(ip.s6_addr, In->Data, IPV6_SIZE);
		ret = GeoIP_country_name_by_ipnum_v6(GeoIPDB6, ip);
	}

	return ret == NULL ? "--" : ret;
}

void WServerLanding(evhtp_request_t *evRequest, void *arg)
{
	Log(LOG_LEVEL_DEBUG, "WServer landing at your services!");
	UNCHECKED_PROXY *UProxy = NULL;

	/* Get UProxy pointer */ {
		char *keyRaw = evhtp_header_find(evRequest->headers_in, "LPKey");

		if (keyRaw == NULL) {
			return;
			// Loose proxy is automatically free'd by EVWrite called timeout
		}

		char *key;
		char *hVal = malloc(sizeof(keyRaw)); {
			size_t len; // trash
			if (!Base64Decode(keyRaw, &key, &len))
				return;
		} free(hVal);

		pthread_mutex_lock(&lockUncheckedProxies); {
			for (size_t x = 0; x < sizeUncheckedProxies; x++) {
				if (memcmp(key, uncheckedProxies[x]->hash, 512 / 8) == 0)
					UProxy = uncheckedProxies[x];
			}
		} pthread_mutex_unlock(&lockUncheckedProxies);
		free(key);

		if (UProxy == NULL) {
			return;
			// Loose proxy is automatically free'd by EVWrite called timeout
		}
		pthread_mutex_lock(&(UProxy->processing));
	} /* End get UProxy pointer */

	/* Process headers */ {
		PROXY *proxy;

		if (UProxy->associatedProxy == NULL) {
			proxy = malloc(sizeof(PROXY));
			proxy->ip = malloc(sizeof(IPv6Map));
			memcpy(proxy->ip->Data, UProxy->ip->Data, IPV6_SIZE);

			proxy->port = UProxy->port;
			proxy->type = UProxy->type;
			proxy->country = GetCountryByIPv6Map(proxy->ip);
			proxy->liveSinceMs = proxy->lastChecked = GetUnixTimestampMilliseconds();
			proxy->failedChecks = 0;
			proxy->httpTimeoutMs = GetUnixTimestampMilliseconds() - UProxy->requestTimeHttpMs;
			proxy->timeoutMs = GetUnixTimestampMilliseconds() - UProxy->requestTimeMs;
			proxy->rechecking = false;
			proxy->retries = 0;
			proxy->successfulChecks = 1;
			proxy->anonymity = ANONYMITY_NONE;
		}

		evhtp_kvs_t *headers = evRequest->headers_in;
		evhtp_kv_t *header;
		bool anonMax = true;

		for (header = headers->tqh_first; header; header = header->next.tqe_next) {
			char *val = evhtp_header_find(RequestHeaders, header->key);

			if (strncmp("Host", header->key, header->klen) == 0) {
				// this case needs special treatment
				if (strncmp(header->val, GetHost(GetIPType(proxy->ip), ProxyIsSSL(proxy->type)), header->vlen) != 0) {
					Log(LOG_LEVEL_DEBUG, "WServer: switch to anonymous proxy on host %.*s=%.*s (type %d)", header->klen, header->key, header->vlen, header->val, UProxy->type);
					anonMax = false;
				}
				continue;
			} else {
				if ((val == NULL || strncmp(val, header->val, header->vlen) != 0) && strncmp(header->key, "LPKey", header->klen) != 0) {
					Log(LOG_LEVEL_DEBUG, "WServer: switch to anonymous proxy on %.*s=%.*s (type %d)", header->klen, header->key, header->vlen, header->val, UProxy->type);
					anonMax = false;
				}
			}

			if (proxy->anonymity != ANONYMITY_NONE)
				break;

			int subStrVec[256];
			for (size_t i = 0;i < 2;i++) {
				int regexRet = pcre_exec(i == 0 ? ipv4Regex : ipv6Regex, i == 0 ? ipv4RegexEx : ipv6RegexEx, header->val, header->vlen, 0, 0, subStrVec, 256);

				if (regexRet != PCRE_ERROR_NOMATCH) {
					if (regexRet < 0) {
						Log(LOG_LEVEL_ERROR, "Couldn't execute PCRE %s regex", (i == 0 ? "IPv4" : "IPv6"));
						free(proxy->ip);
						free(proxy);
						pthread_mutex_unlock(&(UProxy->processing));
						continue;
					} else {
						char *foundIpStr;
						for (size_t x = 0; x < regexRet; x++) {
							char *headerValNul = malloc(header->vlen * sizeof(char)+1); {
								memcpy(headerValNul, header->val, header->vlen);
								headerValNul[header->vlen] = 0x00;
								pcre_get_substring(headerValNul, subStrVec, regexRet, x, &(foundIpStr));
								IPv6Map *foundIp = StringToIPv6Map(foundIpStr); {
									if (foundIp != NULL && IPv6MapCompare(i == 0 ? GlobalIp4 : GlobalIp6, foundIp)) {
										Log(LOG_LEVEL_DEBUG, "WServer: switch to trensparent proxy on %.*s=%.*s (type %d)", header->klen, header->key, header->vlen, header->val, UProxy->type);
										proxy->anonymity = ANONYMITY_TRANSPARENT;
										free(foundIp);
										break;
									}
								} free(foundIp);
							} free(headerValNul);
						}
						pcre_free_substring(foundIpStr);
					}
				}
			}
		}

		if (proxy->anonymity == ANONYMITY_NONE && anonMax)
			proxy->anonymity = ANONYMITY_MAX;
		else if (proxy->anonymity == ANONYMITY_NONE)
			proxy->anonymity = ANONYMITY_ANONYMOUS;

		UProxy->checkSuccess = true;

		if (UProxy->associatedProxy == NULL) {
			Log(LOG_LEVEL_DEBUG, "WServer: Final proxy add type %d anonimity %d", proxy->type, proxy->anonymity);
			ProxyAdd(proxy);
		} else
			UProxySuccessUpdateParentInfo(UProxy);

	} /* End process headers */

	pthread_mutex_unlock(&(UProxy->processing));

	/* Output */ {
		evbuffer_add_reference(evRequest->buffer_out, "OK", 2, NULL, NULL);
		evhtp_send_reply(evRequest, EVHTP_RES_OK);
	}
}

void GenericCb(evhtp_request_t *evRequest, void *arg)
{
	evbuffer_add_reference(evRequest->buffer_out, "Not Found", 9, NULL, NULL);
	evhtp_send_reply(evRequest, EVHTP_RES_NOTFOUND);
}

struct bufferevent *WServerSSLNewSocket(struct event_base *EvBase, SSL_CTX *Arg)
{
	Log(LOG_LEVEL_DEBUG, "SSL CONNECT==========================================");
	return bufferevent_openssl_socket_new(EvBase, -1, SSL_new(Arg), BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
}

void WServerBaseSSL()
{
	struct timeval timeout;
	timeout.tv_sec = GlobalTimeout / 1000;
	timeout.tv_usec = (GlobalTimeout % 1000) * 1000;

	if (!DisableIPv6) {
		evWServerHTTPSSL6 = evhtp_new(evWServerBase, NULL);

		evhtp_set_gencb(evWServerHTTP6, GenericCb, NULL);
		evhtp_set_cb(evWServerHTTPSSL6, "/ifaceu", InterfaceWebUnchecked, NULL);
		evhtp_set_cb(evWServerHTTPSSL6, "/iface", InterfaceWeb, NULL);
		evhtp_set_cb(evWServerHTTPSSL6, "/prxchk", WServerLanding, NULL);

		evhtp_set_timeouts(evWServerHTTPSSL6, &timeout, &timeout);

		if (evhtp_bind_socket(evWServerHTTPSSL6, "ipv6:::", SSLServerPort, -1) != 0) {
			Log(LOG_LEVEL_ERROR, "Failed to bind to :::%d (%d), exiting...", SSLServerPort, EVUTIL_SOCKET_ERROR());
			exit(EXIT_FAILURE);
		}
	}

	evhtp_set_gencb(evWServerHTTPSSL4, GenericCb, NULL);
	evhtp_set_cb(evWServerHTTPSSL4, "/ifaceu", InterfaceWebUnchecked, NULL);
	evhtp_set_cb(evWServerHTTPSSL4, "/iface", InterfaceWeb, NULL);
	evhtp_set_cb(evWServerHTTPSSL4, "/prxchk", WServerLanding, NULL);

	AuthWebList = NULL;
	pthread_mutex_init(&AuthWebLock, NULL);
	AuthWebCount = 0;

	evhtp_set_timeouts(evWServerHTTP4, &timeout, &timeout);

	if (evhtp_bind_socket(evWServerHTTPSSL4, "ipv4:0.0.0.0", SSLServerPort, -1) != 0) {
		Log(LOG_LEVEL_ERROR, "Failed to bind to 0.0.0.0:%d, exiting...", SSLServerPort);
		exit(EXIT_FAILURE);
	}

	Log(LOG_LEVEL_DEBUG, "WServerSSL base dispatch");
	event_base_dispatch(evWServerBaseSSL);
	Log(LOG_LEVEL_DEBUG, "WServerSSL base dispatch end");
}

void WServerBase()
{
	struct timeval timeout;
	timeout.tv_sec = GlobalTimeout / 1000;
	timeout.tv_usec = (GlobalTimeout % 1000) * 1000;
	evWServerBase = event_base_new();

	evWServerHTTP4 = evhtp_new(evWServerBase, NULL);

	evhtp_set_gencb(evWServerHTTP4, GenericCb, NULL);
	evhtp_set_cb(evWServerHTTP4, "/ifaceu", InterfaceWebUnchecked, NULL);
	evhtp_set_cb(evWServerHTTP4, "/iface", InterfaceWeb, NULL);
	evhtp_set_cb(evWServerHTTP4, "/prxchk", WServerLanding, NULL);

	AuthWebList = NULL;
	pthread_mutex_init(&AuthWebLock, NULL);
	AuthWebCount = 0;

	evhtp_set_timeouts(evWServerHTTP4, &timeout, &timeout);

	if (evhtp_bind_socket(evWServerHTTP4, "ipv4:0.0.0.0", ServerPort, -1) != 0) {
		Log(LOG_LEVEL_ERROR, "Failed to bind to 0.0.0.0:%d (%d), exiting...", ServerPort, EVUTIL_SOCKET_ERROR());
		exit(EXIT_FAILURE);
	}

	if (!DisableIPv6) {
		evWServerHTTP6 = evhtp_new(evWServerBase, NULL);

		evhtp_set_gencb(evWServerHTTP6, GenericCb, NULL);
		evhtp_set_cb(evWServerHTTP6, "/ifaceu", InterfaceWebUnchecked, NULL);
		evhtp_set_cb(evWServerHTTP6, "/iface", InterfaceWeb, NULL);
		evhtp_set_cb(evWServerHTTP6, "/prxchk", WServerLanding, NULL);

		evhtp_set_timeouts(evWServerHTTP6, &timeout, &timeout);

		if (evhtp_bind_socket(evWServerHTTP6, "ipv6:::", ServerPort, -1) != 0) {
			Log(LOG_LEVEL_ERROR, "Failed to bind to :::%d (%d), exiting...", ServerPort, EVUTIL_SOCKET_ERROR());
			exit(EXIT_FAILURE);
		}
	}

	Log(LOG_LEVEL_DEBUG, "WServer base dispatch");
	event_base_dispatch(evWServerBase);
	Log(LOG_LEVEL_DEBUG, "WServer base dispatch end");
}