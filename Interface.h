#pragma once

#include <evhttp.h>

void InterfaceWeb(struct evhttp_request *evRequest, void *arg);
void InterfaceWebUnchecked(struct evhttp_request *evRequest, void *arg);