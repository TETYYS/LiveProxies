#pragma once

#include <event2/event.h>
#include <event2/keyvalq_struct.h>
#include <stdint.h>
#include "ProxyLists.h"

char *RequestString;
struct evkeyvalq *RequestHeaders;
struct event_base *levRequestBase;
sem_t semRequestBase;

void RequestAsync(UNCHECKED_PROXY *UProxy);