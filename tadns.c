/*
* Copyright (c) 2004-2005 Sergey Lyubka <valenok@gmail.com>
*
* "THE BEER-WARE LICENSE" (Revision 42):
* Sergey Lyubka wrote this file.  As long as you retain this notice you
* can do whatever you want with this stuff. If we meet some day, and you think
* this stuff is worth it, you can buy me a beer in return.
*/

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"advapi32")
#include <winsock.h>
typedef	int		socklen_t;
typedef	unsigned char	uint8_t;
typedef	unsigned short	uint16_t;
typedef	unsigned int	uint32_t;
#else
#define	closesocket(x)	close(x)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>
#endif /* _WIN32 */

#include "tadns.h"
#include "llist.h"

#define	DNS_MAX			1025	/* Maximum host name		*/
#define	DNS_PACKET_LEN		2048	/* Buffer size for DNS packet	*/
#define	MAX_CACHE_ENTRIES	10000	/* Dont cache more than that	*/

/*
* User query. Holds mapping from application-level ID to DNS transaction id,
* and user defined callback function.
*/
struct query {
	struct llhead	link;		/* Link				*/
	time_t		expire;		/* Time when this query expire	*/
	uint16_t	tid;		/* UDP DNS transaction ID	*/
	uint16_t	qtype;		/* Query type			*/
	char		name[DNS_MAX];	/* Host name			*/
	void		*ctx;		/* Application context		*/
	dns_callback_t	callback;	/* User callback routine	*/
	unsigned char	addr[DNS_MAX];	/* Host address			*/
	size_t		addrlen;	/* Address length		*/
};

/*
* Resolver descriptor.
*/
struct dns {
	int		sock;		/* UDP socket used for queries	*/
	struct sockaddr_in sa;		/* DNS server socket address	*/
	uint16_t	tid;		/* Latest tid used		*/

	struct llhead	active;		/* Active queries, MRU order	*/
	struct llhead	cached;		/* Cached queries		*/
	int		num_cached;	/* Number of cached queries	*/
};

/*
* DNS network packet
*/
struct header {
	uint16_t	tid;		/* Transaction ID		*/
	uint16_t	flags;		/* Flags			*/
	uint16_t	nqueries;	/* Questions			*/
	uint16_t	nanswers;	/* Answers			*/
	uint16_t	nauth;		/* Authority PRs		*/
	uint16_t	nother;		/* Other PRs			*/
	unsigned char	data[1];	/* Data, variable length	*/
};

/*
* Return UDP socket used by a resolver
*/
int
dns_get_fd(struct dns *dns)
{
	return (dns->sock);
}

/*
* Fetch name from DNS packet
*/
static void
fetch(const uint8_t *pkt, const uint8_t *s, int pktsiz, char *dst, int dstlen)
{
	const uint8_t	*e = pkt + pktsiz;
	int		j, i = 0, n = 0;


	while (*s != 0 && s < e) {
		if (n > 0)
			dst[i++] = '.';

		if (i >= dstlen)
			break;

		if ((n = *s++) == 0xc0) {
			s = pkt + *s;	/* New offset */
			n = 0;
		} else {
			for (j = 0; j < n && i < dstlen; j++)
				dst[i++] = *s++;
		}
	}

	dst[i] = '\0';
}

/*
* Case-insensitive string comparison, a-la strcmp()
*/
static int
casecmp(register const char *s1, register const char *s2)
{
	for (; *s1 != '\0' && *s2 != '\0'; s1++, s2++)
		if (tolower(*s1) != tolower(*s2))
			break;

	return (*s1 - *s2);
}

/*
* Put given file descriptor in non-blocking mode. return 0 if success, or -1
*/
static int
nonblock(int fd)
{
#ifdef	_WIN32
	unsigned long	on = 1;
	return (ioctlsocket(fd, FIONBIO, &on));
#else
	int	flags;

	flags = fcntl(fd, F_GETFL, 0);

	return (fcntl(fd, F_SETFL, flags | O_NONBLOCK));
#endif /* _WIN32 */
}

/*
* Find what DNS server to use. Return 0 if OK, -1 if error
*/
static int
getdnsip(struct dns *dns)
{
	int	ret = 0;

#ifdef _WIN32
	int	i;
	LONG	err;
	HKEY	hKey, hSub;
	char	subkey[512], dhcpns[512], ns[512], value[128], *key =
		"SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces";

	if ((err = RegOpenKey(HKEY_LOCAL_MACHINE,
						  key, &hKey)) != ERROR_SUCCESS) {
		fprintf(stderr, "cannot open reg key %s: %d\n", key, err);
		ret--;
	} else {
		for (ret--, i = 0; RegEnumKey(hKey, i, subkey,
									  sizeof(subkey)) == ERROR_SUCCESS; i++) {
			DWORD type, len = sizeof(value);
			if (RegOpenKey(hKey, subkey, &hSub) == ERROR_SUCCESS &&
				(RegQueryValueEx(hSub, "NameServer", 0,
								 &type, value, &len) == ERROR_SUCCESS ||
				 RegQueryValueEx(hSub, "DhcpNameServer", 0,
								 &type, value, &len) == ERROR_SUCCESS)) {
				dns->sa.sin_addr.s_addr = inet_addr(value);
				ret++;
				RegCloseKey(hSub);
				break;
			}
		}
		RegCloseKey(hKey);
	}
#else
	FILE	*fp;
	char	line[512];
	int	a, b, c, d;

	if ((fp = fopen("/etc/resolv.conf", "r")) == NULL) {
		ret--;
	} else {
		/* Try to figure out what DNS server to use */
		for (ret--; fgets(line, sizeof(line), fp) != NULL; ) {
			if (sscanf(line, "nameserver %d.%d.%d.%d",
					   &a, &b, &c, &d) == 4) {
				dns->sa.sin_addr.s_addr =
					htonl(a << 24 | b << 16 | c << 8 | d);
				ret++;
				break;
			}
		}
		(void)fclose(fp);
	}
#endif /* _WIN32 */

	return (ret);
}

struct dns *
	dns_init(void)
{
	struct dns	*dns;
	int		rcvbufsiz = 128 * 1024;

#ifdef _WIN32
	{ WSADATA data; WSAStartup(MAKEWORD(2, 2), &data); }
#endif /* _WIN32 */

	/* FIXME resource leak here */
	if ((dns = (struct dns *) calloc(1, sizeof(*dns))) == NULL)
		return (NULL);
	else if ((dns->sock = socket(PF_INET, SOCK_DGRAM, 17)) == -1)
		return (NULL);
	else if (nonblock(dns->sock) != 0)
		return (NULL);
	else if (getdnsip(dns) != 0)
		return (NULL);

	dns->sa.sin_family = AF_INET;
	dns->sa.sin_port = htons(53);

	/* Increase socket's receive buffer */
	(void)setsockopt(dns->sock, SOL_SOCKET, SO_RCVBUF,
					 (char *)&rcvbufsiz, sizeof(rcvbufsiz));

	LL_INIT(&dns->active);
	LL_INIT(&dns->cached);

	return (dns);
}

static void
destroy_query(struct query *query)
{
	LL_DEL(&query->link);
	free(query);
}

/*
* Find host in host cache. Add it if not found.
*/
static struct query *
find_cached_query(struct dns *dns, enum dns_query_type qtype, const char *name)
{
	struct llhead	*lp, *tmp;
	struct query	*query;

	LL_FOREACH_SAFE(&dns->cached, lp, tmp)
	{
		query = LL_ENTRY(lp, struct query, link);

		if (query->qtype == qtype && casecmp(name, query->name) == 0) {
			/* Keep sorted by LRU: move to the head */
			LL_DEL(&query->link);
			LL_ADD(&dns->cached, &query->link);
			return (query);
		}
	}

	return (NULL);
}

static struct query *
find_active_query(struct dns *dns, uint16_t tid)
{
	struct llhead	*lp;
	struct query	*query;

	LL_FOREACH(&dns->active, lp)
	{
		query = LL_ENTRY(lp, struct query, link);
		if (tid == query->tid)
			return (query);
	}

	return (NULL);
}

/*
* User wants to cancel query
*/
void
dns_cancel(struct dns *dns, const void *context)
{
	struct llhead	*lp, *tmp;
	struct query	*query;

	LL_FOREACH_SAFE(&dns->active, lp, tmp)
	{
		query = LL_ENTRY(lp, struct query, link);

		if (query->ctx == context) {
			destroy_query(query);
			break;
		}
	}
}

static void
call_user(struct dns *dns, struct query *query, enum dns_error error)
{
	struct dns_cb_data	cbd;

	cbd.context = query->ctx;
	cbd.query_type = (enum dns_query_type) query->qtype;
	cbd.error = error;
	cbd.name = query->name;
	cbd.addr = query->addr;
	cbd.addr_len = query->addrlen;

	query->callback(&cbd);

	/* Move query to cache */
	LL_DEL(&query->link);
	LL_ADD(&dns->cached, &query->link);
	dns->num_cached++;
	if (dns->num_cached >= MAX_CACHE_ENTRIES) {
		query = LL_ENTRY(dns->cached.prev, struct query, link);
		destroy_query(query);
		dns->num_cached--;
	}
}

static void
parse_udp(struct dns *dns, const unsigned char *pkt, int len)
{
	struct header		*header;
	const unsigned char	*p, *e, *s;
	struct query		*q;
	uint32_t		ttl;
	uint16_t		type;
	char			name[1025];
	int			found, stop, dlen, nlen;

	/* We sent 1 query. We want to see more that 1 answer. */
	header = (struct header *) pkt;
	if (ntohs(header->nqueries) != 1)
		return;

	/* Return if we did not send that query */
	if ((q = find_active_query(dns, header->tid)) == NULL)
		return;

	/* Received 0 answers */
	if (header->nanswers == 0) {
		q->addrlen = 0;
		call_user(dns, q, DNS_DOES_NOT_EXIST);
		return;
	}

	/* Skip host name */
	for (e = pkt + len, nlen = 0, s = p = &header->data[0];
	p < e && *p != '\0'; p++)
		nlen++;

#define	NTOHS(p)	(((p)[0] << 8) | (p)[1])

	/* We sent query class 1, query type 1 */
	if (&p[5] > e || NTOHS(p + 1) != q->qtype)
		return;

	/* Go to the first answer section */
	p += 5;

	/* Loop through the answers, we want A type answer */
	for (found = stop = 0; !stop && &p[12] < e; ) {

		/* Skip possible name in CNAME answer */
		if (*p != 0xc0) {
			while (*p && &p[12] < e)
				p++;
			p--;
		}

		type = htons(((uint16_t *)p)[1]);

		if (type == 5) {
			/* CNAME answer. shift to the next section */
			dlen = htons(((uint16_t *)p)[5]);
			p += 12 + dlen;
		} else if (type == q->qtype) {
			found = stop = 1;
		} else {
			stop = 1;
		}
	}

	if (found && &p[12] < e) {
		dlen = htons(((uint16_t *)p)[5]);
		p += 12;

		if (p + dlen <= e) {
			/* Add to the cache */
			(void)memcpy(&ttl, p - 6, sizeof(ttl));
			q->expire = time(NULL) + (time_t)ntohl(ttl);

			/* Call user */
			if (q->qtype == DNS_MX_RECORD) {
				fetch((uint8_t *)header, p + 2,
					  len, name, sizeof(name) - 1);
				p = (const unsigned char *)name;
				dlen = strlen(name);
			}
			q->addrlen = dlen;
			if (q->addrlen > sizeof(q->addr))
				q->addrlen = sizeof(q->addr);
			(void)memcpy(q->addr, p, q->addrlen);
			call_user(dns, q, DNS_OK);
		}
	}
}

int
dns_poll(struct dns *dns)
{
	struct llhead		*lp, *tmp;
	struct query		*query;
	struct sockaddr_in	sa;
	socklen_t		len = sizeof(sa);
	int			n, num_packets = 0;
	unsigned char		pkt[DNS_PACKET_LEN];
	time_t			now;

	now = time(NULL);

	/* Check our socket for new stuff */
	while ((n = recvfrom(dns->sock, pkt, sizeof(pkt), 0,
						 (struct sockaddr *) &sa, &len)) > 0 &&
		   n > (int) sizeof(struct header)) {
		parse_udp(dns, pkt, n);
		num_packets++;
	}

	/* Cleanup expired active queries */
	LL_FOREACH_SAFE(&dns->active, lp, tmp)
	{
		query = LL_ENTRY(lp, struct query, link);

		if (query->expire < now) {
			query->addrlen = 0;
			call_user(dns, query, DNS_TIMEOUT);
			destroy_query(query);
		}
	}

	/* Cleanup cached queries */
	LL_FOREACH_SAFE(&dns->cached, lp, tmp)
	{
		query = LL_ENTRY(lp, struct query, link);
		if (query->expire < now) {
			destroy_query(query);
			dns->num_cached--;
		}
	}

	return (num_packets);
}

/*
* Cleanup
*/
void
dns_fini(struct dns *dns)
{
	struct llhead	*lp, *tmp;
	struct query	*query;

	if (dns->sock != -1)
		(void) closesocket(dns->sock);

	LL_FOREACH_SAFE(&dns->active, lp, tmp)
	{
		query = LL_ENTRY(lp, struct query, link);
		destroy_query(query);
	}

	LL_FOREACH_SAFE(&dns->cached, lp, tmp)
	{
		query = LL_ENTRY(lp, struct query, link);
		destroy_query(query);
		dns->num_cached--;
	}

	free(dns);
}

/*
* Queue the resolution
*/
void
dns_queue(struct dns *dns, void *ctx, const char *name,
enum dns_query_type qtype, dns_callback_t callback)
{
	struct query	*query;
	struct header	*header;
	int		i, n, name_len;
	char		pkt[DNS_PACKET_LEN], *p;
	const char 	*s;
	time_t		now = time(NULL);
	struct dns_cb_data cbd;

	/* XXX Search the cache first */
	if ((query = find_cached_query(dns, qtype, name)) != NULL) {
		query->ctx = ctx;
		call_user(dns, query, DNS_OK);
		if (query->expire < now) {
			destroy_query(query);
			dns->num_cached--;
		}
		return;
	}

	/* Allocate new query */
	if ((query = (struct query *) calloc(1, sizeof(*query))) == NULL) {
		(void)memset(&cbd, 0, sizeof(cbd));
		cbd.error = DNS_ERROR;
		callback(&cbd);
		return;
	}

	/* Init query structure */
	query->ctx = ctx;
	query->qtype = (uint16_t)qtype;
	query->tid = ++dns->tid;
	query->callback = callback;
	query->expire = now + DNS_QUERY_TIMEOUT;
	for (p = query->name; *name &&
		 p < query->name + sizeof(query->name) - 1; name++, p++)
		*p = tolower(*name);
	*p = '\0';
	name = query->name;

	/* Prepare DNS packet header */
	header = (struct header *) pkt;
	header->tid = query->tid;
	header->flags = htons(0x100);		/* Haha. guess what it is */
	header->nqueries = htons(1);		/* Just one query */
	header->nanswers = 0;
	header->nauth = 0;
	header->nother = 0;

	/* Encode DNS name */

	name_len = strlen(name);
	p = (char *)&header->data;	/* For encoding host name into packet */

	do {
		if ((s = strchr(name, '.')) == NULL)
			s = name + name_len;

		n = s - name;			/* Chunk length */
		*p++ = n;			/* Copy length */
		for (i = 0; i < n; i++)		/* Copy chunk */
			*p++ = name[i];

		if (*s == '.')
			n++;

		name += n;
		name_len -= n;

	} while (*s != '\0');

	*p++ = 0;			/* Mark end of host name */
	*p++ = 0;			/* Well, lets put this byte as well */
	*p++ = (unsigned char)qtype;	/* Query Type */

	*p++ = 0;
	*p++ = 1;			/* Class: inet, 0x0001 */

	assert(p < pkt + sizeof(pkt));
	n = p - pkt;			/* Total packet length */

	if (sendto(dns->sock, pkt, n, 0,
			   (struct sockaddr *) &dns->sa, sizeof(dns->sa)) != n) {
		(void)memset(&cbd, 0, sizeof(cbd));
		cbd.error = DNS_ERROR;
		callback(&cbd);
		destroy_query(query);
	}

	LL_TAIL(&dns->active, &query->link);
}

#ifdef ADIG

static void
usage(const char *prog)
{
	(void)fprintf(stderr,
				  "usage: %s [@server] <domain> [q-type] [q-class]\n", prog);
	exit(EXIT_FAILURE);
}

static void
callback(struct dns_cb_data *cbd)
{
	switch (cbd->error) {
		case DNS_OK:
			switch (cbd->query_type) {
				case DNS_A_RECORD:
					printf("%s: %u.%u.%u.%u\n", cbd->name,
						   cbd->addr[0], cbd->addr[1],
						   cbd->addr[2], cbd->addr[3]);
					break;
				case DNS_MX_RECORD:
					printf("%s\n", cbd->addr);
					break;
				default:
					(void)fprintf(stderr, "Unexpected query type: %u\n",
								  cbd->query_type);
					exit(EXIT_FAILURE);
					/* NOTREACHED */
					break;
			}
			break;
		case DNS_TIMEOUT:
			(void)fprintf(stderr, "Query timeout for [%s]\n", cbd->name);
			break;
		case DNS_DOES_NOT_EXIST:
			(void)fprintf(stderr, "No such address: [%s]\n", cbd->name);
			break;
		case DNS_ERROR:
			(void)fprintf(stderr, "System error occured\n");
			break;
	}

	exit(EXIT_SUCCESS);
}

int
main(int argc, char *argv[])
{
	const char		*domain, *server = NULL, *prog = argv[0];
	enum dns_query_type	qtype = DNS_A_RECORD;
	struct dns		*dns;
	fd_set			set;
	struct timeval		tv = { 5, 0 };

	if (argc == 1 || (argc == 2 && argv[1][0] == '@'))
		usage(prog);

	if (argv[1][0] == '@') {
		server = &argv[1][1];
		argv++;
		argc--;
	}

	/* Init the vector that represents host to be resolved */
	domain = argv[1];

	if (argc > 2 && !strcmp(argv[2], "mx"))
		qtype = DNS_MX_RECORD;

	if ((dns = dns_init()) == NULL) {
		(void)fprintf(stderr, "failed to init resolver\n");
		exit(EXIT_FAILURE);
	}

	dns_queue(dns, &domain, domain, qtype, callback);

	/* Select on resolver socket */
	FD_ZERO(&set);
	FD_SET(dns_get_fd(dns), &set);

	if (select(dns_get_fd(dns) + 1, &set, NULL, NULL, &tv) == 1)
		dns_poll(dns);

	dns_fini(dns);

	return (EXIT_SUCCESS);
}
#endif /* ADIG */
