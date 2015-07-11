#pragma once

#include <event2/event.h>
#include <event2/keyvalq_struct.h>
#include <stdint.h>
#include <pthread.h>
#include "ProxyLists.h"

char *RequestString;
struct evkeyvalq *RequestHeaders;
char *Host4;
char *Host6;

struct event_base *levRequestBase;
pthread_mutex_t lockRequestBase;

void RequestAsync(UNCHECKED_PROXY *UProxy);