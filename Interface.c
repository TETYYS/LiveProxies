#include "Interface.h"
#include "ProxyLists.h"
#include "IPv6Map.h"
#include "Global.h"
#include "Logger.h"
#include "Config.h"
#include <event2/buffer.h>
#include <stdlib.h>

void InterfaceWeb(struct evhttp_request *evRequest, void *arg) {
	struct evbuffer *buff = evbuffer_new(); {
		evbuffer_add_printf(buff, "<html><head><title>LiveProxies %s interface: Checked proxies</title></head><body>", VERSION);

		sem_wait(&lockCheckedProxies); {
			evbuffer_add_printf(buff, "<center>Checked proxies: %d, currently checking: %d</center><br />", sizeUncheckedProxies, CurrentlyChecking);
			for (size_t x = 0; x < sizeCheckedProxies; x++) {
				char *ip = IPv6MapToString2(checkedProxies[x]->ip); {
					evbuffer_add_printf(buff, "Proxy %s:%d, country %s, timeout %d, HTTP timeout %d, anonimity %s<br />",
						ip,
						checkedProxies[x]->port,
						checkedProxies[x]->country,
						checkedProxies[x]->timeoutMs,
						checkedProxies[x]->httpTimeoutMs,
						(checkedProxies[x]->anonymity == ANONYMITY_TRANSPARENT ? "transparent" :
						(checkedProxies[x]->anonymity == ANONYMITY_ANONYMOUS ? "anonymous" : "max")));
				} free(ip);
			}
		} sem_post(&lockCheckedProxies);

		evbuffer_add_reference(buff, "</body></html>\n", 15, NULL, NULL);

		evhttp_send_reply(evRequest, HTTP_OK, "OK", buff);
	} evbuffer_free(buff);
}

static void IntBlock3(size_t In, size_t *Out1, size_t *Out2) {
	*Out1 = In / 3;
	*Out2 = (In / 3) * 2;
}

void InterfaceWebUnchecked(struct evhttp_request *evRequest, void *arg) {
	struct evbuffer *buff = evbuffer_new(); {
		evbuffer_add_printf(buff, "<html><head><title>LiveProxies %s interface: Unchecked proxies</title></head><body>", VERSION);

		sem_wait(&lockUncheckedProxies); {
			evbuffer_add_printf(buff, "<center>Unchecked proxies: %d, currently checking: %d</center><br />", sizeUncheckedProxies, CurrentlyChecking);
			for (size_t x = 0; x < sizeUncheckedProxies; x++) {
				int lockVal;
				sem_getvalue(&(uncheckedProxies[x]->processing), &lockVal);
				if (lockVal == LOCK_BLOCKED)
					evbuffer_add_reference(buff, "<font color=\"green\">", 20, NULL, NULL);
				else {
					size_t block[2];
					IntBlock3(AcceptableSequentialFails, &(block[0]), &(block[1]));
					if (uncheckedProxies[x]->retries < block[0])
						evbuffer_add_reference(buff, "<font color=\"green\">", 20, NULL, NULL);
					else if (uncheckedProxies[x]->retries > block[0] && uncheckedProxies[x]->retries < block[1])
						evbuffer_add_reference(buff, "<font color=\"yellow\">", 20, NULL, NULL);
					else
						evbuffer_add_reference(buff, "<font color=\"red\">", 17, NULL, NULL);
				}

				char *ip = IPv6MapToString2(uncheckedProxies[x]->ip); {
					evbuffer_add_printf(buff, "Proxy %s:%d, type->%s, checking->%d, retries->%d",
						ip,
						uncheckedProxies[x]->port,
						(uncheckedProxies[x]->type == PROXY_TYPE_HTTP ? "HTTP" :
						(uncheckedProxies[x]->type == PROXY_TYPE_SOCKS4 || uncheckedProxies[x]->type == PROXY_TYPE_SOCKS4A ? "SOCKS4" : "SOCKS5")),
						uncheckedProxies[x]->checking,
						uncheckedProxies[x]->retries);
				} free(ip);

				/*char timeBuff[21];
				memset(timeBuff, 0, 21);
				struct tm *timeinfo;
				time_t timeRaw;*/

				/*if (uncheckedProxies[x]->checking && uncheckedProxies[x]->requestTimeMs != 0) {
					/*timeRaw = uncheckedProxies[x]->requestTimeMs / 1000;

					Log(LOG_LEVEL_DEBUG, "WServer: time_t %d", timeRaw);

					timeinfo = localtime(&timeRaw);

					strftime(timeBuff, 20, "%F %H:%M:%S", timeinfo);
					
					//evbuffer_add_reference(buff, ", requestTime: ", 15, NULL, NULL);
					//evbuffer_add_reference(buff, timeBuff, 20, NULL, NULL);
					evbuffer_add_printf(buff, ", requestTime: %s", timeBuff);*
				}
				if (uncheckedProxies[x]->requestTimeHttpMs != 0) {
					/*timeRaw = uncheckedProxies[x]->requestTimeHttpMs / 1000;

					localtime_r(&timeRaw, timeinfo);

					strftime(timeBuff, 20, "%F %H:%M:%S", timeinfo);
					evbuffer_add_printf(buff, ", requestTimeHttp: %s", timeBuff);*
				}*/

				if (lockVal == LOCK_BLOCKED)
					evbuffer_add_reference(buff, " <b>PROCESSING</b>", 18, NULL, NULL);

				evbuffer_add_reference(buff, "</font><br />", 13, NULL, NULL);
			}
		} sem_post(&lockUncheckedProxies);

		evbuffer_add_reference(buff, "</body></html>\n", 15, NULL, NULL);

		evhttp_send_reply(evRequest, HTTP_OK, "OK", buff);
	} evbuffer_free(buff);
}