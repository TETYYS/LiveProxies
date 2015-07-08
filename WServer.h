#pragma once

#include <evhttp.h>
#include <pcre.h>
#include <stdbool.h>
#include "GeoIP.h"

GeoIP *GeoIPDB;
GeoIP *GeoIPDB6;
pcre *ipv6Regex;
pcre_extra *ipv6RegexEx;
pcre *ipv4Regex;
pcre_extra *ipv4RegexEx;

struct event_base *evWServerBase;
struct evhttp *evWServerHTTP;

void WServerLanding(struct evhttp_request *evRequest, void *arg);
void WServerBase();