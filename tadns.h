/*
* Copyright (c) 2004-2005 Sergey Lyubka <valenok@gmail.com>
*
* "THE BEER-WARE LICENSE" (Revision 42):
* Sergey Lyubka wrote this file.  As long as you retain this notice you
* can do whatever you want with this stuff. If we meet some day, and you think
* this stuff is worth it, you can buy me a beer in return.
*/

/*
* Simple asynchronous DNS resolver.
* Can resolve A records (IP addresses for a given name),
* and MX records (IP addresses of mail exchanges for a given domain).
* It holds resolved IP addresses in a cache.
*
* Can be used as a library, and be compiled into C/C++ program.
* Can be compiled as stand-alone program similar to `dig' utility.
*
* Compilation:
*	cc -DADIG dns.c		(UNIX)
*	cl dns.c /DADIG		(Windows, MSVS)
*/

#ifndef DNS_HEADER_INCLUDED
#define DNS_HEADER_INCLUDED

#include <stddef.h>

enum dns_query_type {
	DNS_A_RECORD = 0x01,		/* Lookup IP adress for host	*/
	DNS_MX_RECORD = 0x0f		/* Lookup MX for domain		*/
};

/*
* User defined function that will be called when DNS reply arrives for
* requested hostname. "struct dns_cb_data" is passed to the user callback,
* which has an error indicator, resolved address, etc.
*/

enum dns_error {
	DNS_OK,				/* No error			*/
	DNS_DOES_NOT_EXIST,		/* Error: adress does not exist	*/
	DNS_TIMEOUT,			/* Lookup time expired		*/
	DNS_ERROR,			/* No memory or other error	*/
	DNS_SERVER_FAILURE              /* Server failure               */
};

enum dns_rcode {
	RCODE_OK = 0x01,
	RCODE_SERVER_FAILURE = 0x02,
	RCODE_NO_SUCH_ADDRESS = 0x03
};

struct dns_cb_data {
	void			*context;
	enum dns_error		error;
	enum dns_query_type	query_type;
	const char		*name;		/* Requested host name	*/
	const unsigned char	*addr;		/* Resolved address	*/
	size_t			addr_len;	/* Resolved address len	*/
};

typedef void(*dns_callback_t)(struct dns_cb_data *);

#define	DNS_QUERY_TIMEOUT	30	/* Query timeout, seconds	*/

/*
* The API
*/
struct dns;
extern struct dns *dns_init(void);
extern void	dns_fini(struct dns *);
extern int	dns_get_fd(struct dns *);
extern void	dns_queue(struct dns *, void *context, const char *host,
enum dns_query_type type, dns_callback_t callback);
extern void	dns_cancel(struct dns *, const void *context);
extern int	dns_poll(struct dns *);

#endif /* DNS_HEADER_INCLUDED */