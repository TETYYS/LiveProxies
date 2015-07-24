#pragma once

#include <evhtp.h>
#include <pcre.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include "GeoIP.h"

GeoIP *GeoIPDB;
GeoIP *GeoIPDB6;
pcre *ipv6Regex;
pcre_extra *ipv6RegexEx;
pcre *ipv4Regex;
pcre_extra *ipv4RegexEx;

evbase_t *evWServerBase;
evhtp_t *evWServerHTTP4;
evhtp_t *evWServerHTTP6;

evbase_t *evWServerBaseSSL;
evhtp_t *evWServerHTTPSSL4;
evhtp_t *evWServerHTTPSSL6;

void WServerLanding(evhtp_request_t *evRequest, void *arg);
void GenericCb(evhtp_request_t *evRequest, void *arg);
void WServerBase();
void WServerBaseSSL();
struct bufferevent *WServerSSLNewSocket(struct event_base *EvBase, SSL_CTX *Arg);
