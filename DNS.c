#include "DNS.h"
#include "Logger.h"
#include <stdlib.h>
#include <event2/event.h>
#ifdef __linux__
	#include <unistd.h>
#endif
#include <stdbool.h>
#include "ProxyRequest.h"
#include "Config.h"

static void DNSResolveCallError(DNS_LOOKUP_ASYNC_EX *Ex)
{
	// void *context, DNS_RR_TYPE qtype, const char *name, const unsigned char *addr, size_t addrlen
	struct dns_cb_data data;
	data.name = NULL;
	data.addr = NULL;
	data.addr_len = 0;
	data.context = Ex;
	data.error = DNS_ERROR;
	data.query_type = 0;
	Ex->fxDone(&data);
}

static void DNSResolveLevEventToDNSProcess(evutil_socket_t fd, short what, void *arg)
{
	DNS_LOOKUP_ASYNC_EX *ex = (DNS_LOOKUP_ASYNC_EX*)arg;
	Log(LOG_LEVEL_DEBUG, "DNS process WHAT %d", what);
	if (what == EV_TIMEOUT) {
		DNSResolveCallError(ex);
		goto free;
	}

	dns_poll(ex->dnsCtx);

	if (ex->resolveDone)
		goto free;

	Log(LOG_LEVEL_DEBUG, "DNS process WHAT %d END", what);

	return;
free:
	dns_fini(ex->dnsCtx);
	if (ex->evDNS != NULL)
		event_del(ex->evDNS);
	free(ex);
}

void DNSResolveAsync(void *Ex, char *Domain, bool IPv6, dns_callback_t fxDone)
{
	DNS_LOOKUP_ASYNC_EX *ex = malloc(sizeof(DNS_LOOKUP_ASYNC_EX));
	ex->object = Ex;
	ex->dnsCtx = NULL;
	ex->evDNS = NULL;
	ex->resolveDone = false;
	ex->fxDone = fxDone;
	Log(LOG_LEVEL_DEBUG, "DNSResolveAsync EX: obj %p fx %p", Ex, fxDone);

	struct dns *dnsCtx = dns_init();
	if (!dnsCtx) {
		Log(LOG_LEVEL_ERROR, "Failed to initialize tadns context");
		DNSResolveCallError(ex);
		free(ex);
		return;
	}
	ex->dnsCtx = dnsCtx;
	Log(LOG_LEVEL_DEBUG, "DNSResolveAsync EX: ctx %p", dnsCtx);

	dns_queue(dnsCtx, ex, Domain, IPv6 ? DNS_RR_TYPE_AAAA : DNS_RR_TYPE_A, fxDone);

	Log(LOG_LEVEL_DEBUG, "DNS FD %d", dns_get_fd(dnsCtx));

	struct event *fdEvent = event_new(levRequestBase, dns_get_fd(dnsCtx), EV_READ | EV_PERSIST, DNSResolveLevEventToDNSProcess, ex);
	ex->evDNS = fdEvent;
	Log(LOG_LEVEL_DEBUG, "DNSResolveAsync EX: ev %p", fdEvent);
	event_add(fdEvent, &GlobalTimeoutTV);
}