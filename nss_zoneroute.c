/*
 * libnss_zoneroute - send host lookups for chosen DNS zones straight to
 * chosen (authoritative) servers, bypassing the nameservers in
 * /etc/resolv.conf.  Names and addresses outside those zones are not
 * touched; the module answers NOTFOUND immediately and NSS moves on.
 *
 * /etc/nss-zoneroute.conf holds one or more { } blocks, each with its own
 * nameservers and the zones they answer for:
 *
 *     {
 *         // our LAN, served by tinydns
 *         nameserver 192.168.2.3        # IPv4 only, up to 3 per block
 *         nameserver 151.197.53.124
 *         zone 2.168.192.in-addr.arpa   # reverse (PTR) lookups
 *     },
 *     {
 *         nameserver 10.0.0.1
 *         zone example.com              # forward (A/AAAA) lookups
 *     }
 *
 * Lines outside any block form one more block, so a flat file of
 * nameserver/zone lines also works.  # and // start comments.  When
 * zones in different blocks match, the longest (most specific) wins.
 *
 * /etc/nsswitch.conf:
 *     hosts: files zoneroute dns
 *
 * NSS_ZONEROUTE_CONF overrides the config path (ignored for setuid).
 */

#define _GNU_SOURCE
#include <nss.h>
#include <netdb.h>
#include <resolv.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdint.h>

#define CONF_FILE   "/etc/nss-zoneroute.conf"
#define MAX_GROUPS  16
#define MAX_ZONES   64
#define ZONE_LEN    256
#define MAX_ADDRS   16
#define ANS_LEN     4096

/* one { } block's nameservers */
struct group {
    int nns;
    struct sockaddr_in ns[MAXNS];
};

struct conf {
    int ngroups;
    struct group groups[MAX_GROUPS];
    int nzones;
    struct {
        int group;
        char name[ZONE_LEN];
    } zones[MAX_ZONES];
};

static int new_group(struct conf *c)
{
    return c->ngroups < MAX_GROUPS ? c->ngroups++ : -1;
}

static void add_directive(struct conf *c, int g, const char *key, char *val)
{
    if (g < 0)
        return;

    if (!strcmp(key, "nameserver")) {
        struct group *gr = &c->groups[g];
        struct sockaddr_in *sa;

        if (gr->nns >= MAXNS)
            return;
        sa = &gr->ns[gr->nns];
        if (inet_pton(AF_INET, val, &sa->sin_addr) == 1) {
            sa->sin_family = AF_INET;
            sa->sin_port = htons(NAMESERVER_PORT);
            gr->nns++;
        }
    } else if (!strcmp(key, "zone") && c->nzones < MAX_ZONES) {
        size_t n = strlen(val);

        while (n > 0 && val[n - 1] == '.')
            val[--n] = '\0';
        if (n == 0 || n >= ZONE_LEN)
            return;
        c->zones[c->nzones].group = g;
        memcpy(c->zones[c->nzones++].name, val, n + 1);
    }
}

static int load_conf(struct conf *c)
{
    const char *path = secure_getenv("NSS_ZONEROUTE_CONF");
    char line[512], buf[3 * sizeof(line)], key[32], *p, *q, *tok, *save;
    int top = -1, cur = -1;   /* implicit top-level block, current block */
    int in_block = 0;
    FILE *f;

    memset(c, 0, sizeof(*c));
    if (!(f = fopen(path ? path : CONF_FILE, "re")))
        return -1;

    while (fgets(line, sizeof(line), f)) {
        if ((p = strchr(line, '#')))
            *p = '\0';
        if ((p = strstr(line, "//")))
            *p = '\0';

        /* make braces their own tokens; commas are just separators */
        for (p = line, q = buf; *p; p++) {
            if (*p == '{' || *p == '}') {
                *q++ = ' ';
                *q++ = *p;
                *q++ = ' ';
            } else {
                *q++ = (*p == ',') ? ' ' : *p;
            }
        }
        *q = '\0';

        key[0] = '\0';
        for (tok = strtok_r(buf, " \t\r\n", &save); tok;
             tok = strtok_r(NULL, " \t\r\n", &save)) {
            if (!strcmp(tok, "{")) {
                in_block = 1;
                cur = new_group(c);   /* -1 if full: block is ignored */
            } else if (!strcmp(tok, "}")) {
                in_block = 0;
                cur = -1;
            } else if (!key[0]) {
                snprintf(key, sizeof(key), "%s", tok);
            } else {
                if (!in_block && top < 0)
                    top = new_group(c);
                add_directive(c, in_block ? cur : top, key, tok);
                key[0] = '\0';
            }
        }
    }
    fclose(f);

    return 0;
}

/* pick the block whose zone most specifically contains name; 0 = found */
static int route(const char *name, struct group *g)
{
    struct conf *c;
    size_t nl = strlen(name), best = 0;
    int i, found = -1;

    if (!(c = malloc(sizeof(*c))))
        return -1;
    if (load_conf(c) < 0) {
        free(c);
        return -1;
    }

    while (nl > 0 && name[nl - 1] == '.')
        nl--;

    for (i = 0; i < c->nzones; i++) {
        const char *z = c->zones[i].name;
        size_t zl = strlen(z);

        if (found >= 0 && zl <= best)
            continue;
        if (c->groups[c->zones[i].group].nns == 0)
            continue;
        if ((nl == zl && !strncasecmp(name, z, zl)) ||
            (nl > zl && name[nl - zl - 1] == '.' &&
             !strncasecmp(name + nl - zl, z, zl))) {
            best = zl;
            found = c->zones[i].group;
        }
    }

    if (found >= 0)
        *g = c->groups[found];
    free(c);
    return found >= 0 ? 0 : -1;
}

/* query the block's servers only; returns answer length or -1 */
static int zr_query(const struct group *g, const char *name, int type,
                    unsigned char *ans, int anslen, int *herr)
{
    struct __res_state st;
    int i, n;

    memset(&st, 0, sizeof(st));
    if (res_ninit(&st) < 0) {
        *herr = NO_RECOVERY;
        return -1;
    }

    for (i = 0; i < g->nns; i++)
        st.nsaddr_list[i] = g->ns[i];
    st.nscount = g->nns;
    st.retrans = 1;   /* seconds per try */
    st.retry = 1;     /* tries per server */
    st.options &= ~(RES_DNSRCH | RES_DEFNAMES);

    n = res_nquery(&st, name, ns_c_in, type, ans, anslen);
    *herr = st.res_h_errno;
    res_nclose(&st);

    return n;
}

static enum nss_status not_ours(int *errnop, int *h_errnop)
{
    *errnop = ENOENT;
    *h_errnop = HOST_NOT_FOUND;
    return NSS_STATUS_NOTFOUND;
}

static enum nss_status failed(int herr, int *errnop, int *h_errnop)
{
    if (herr == HOST_NOT_FOUND || herr == NO_DATA)
        return not_ours(errnop, h_errnop);

    /* servers unreachable or broken: let the next NSS service try */
    *errnop = EAGAIN;
    *h_errnop = herr ? herr : NO_RECOVERY;
    return NSS_STATUS_UNAVAIL;
}

/* carve aligned space out of the caller's buffer */
static void *carve(char **buf, size_t *left, size_t n, size_t align)
{
    uintptr_t p = (uintptr_t)*buf;
    size_t pad = (align - p % align) % align;

    if (*left < pad + n)
        return NULL;
    *buf += pad + n;
    *left -= pad + n;
    return (void *)(p + pad);
}

static enum nss_status fill(struct hostent *h, const char *name, int af,
                            int alen, unsigned char addrs[][16], int naddr,
                            char *buf, size_t buflen,
                            int *errnop, int *h_errnop)
{
    size_t nl = strlen(name) + 1;
    char *nm, **aliases, **list;
    int i;

    if (!(nm = carve(&buf, &buflen, nl, 1)) ||
        !(aliases = carve(&buf, &buflen, sizeof(char *), sizeof(char *))) ||
        !(list = carve(&buf, &buflen, (naddr + 1) * sizeof(char *),
                       sizeof(char *))))
        goto erange;

    for (i = 0; i < naddr; i++) {
        if (!(list[i] = carve(&buf, &buflen, alen, sizeof(uint32_t))))
            goto erange;
        memcpy(list[i], addrs[i], alen);
    }
    list[naddr] = NULL;
    memcpy(nm, name, nl);
    aliases[0] = NULL;

    h->h_name = nm;
    h->h_aliases = aliases;
    h->h_addrtype = af;
    h->h_length = alen;
    h->h_addr_list = list;
    return NSS_STATUS_SUCCESS;

erange:
    /* glibc retries with a bigger buffer */
    *errnop = ERANGE;
    *h_errnop = NETDB_INTERNAL;
    return NSS_STATUS_TRYAGAIN;
}

static int ptr_name(const unsigned char *a, socklen_t len, int af,
                    char *out, size_t outlen)
{
    int i;

    if (af == AF_INET && len == 4) {
        snprintf(out, outlen, "%u.%u.%u.%u.in-addr.arpa",
                 a[3], a[2], a[1], a[0]);
        return 0;
    }
    if (af == AF_INET6 && len == 16 && outlen >= 74) {
        char *p = out;
        for (i = 15; i >= 0; i--)
            p += sprintf(p, "%x.%x.", a[i] & 0xf, a[i] >> 4);
        strcpy(p, "ip6.arpa");
        return 0;
    }
    return -1;
}

enum nss_status _nss_zoneroute_gethostbyaddr2_r(const void *addr,
        socklen_t len, int af, struct hostent *result, char *buffer,
        size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp)
{
    struct group g;
    unsigned char ans[ANS_LEN], abuf[1][16];
    char qname[80], host[NS_MAXDNAME];
    ns_msg m;
    ns_rr rr;
    int n, i, herr;

    if (ptr_name(addr, len, af, qname, sizeof(qname)) < 0)
        return not_ours(errnop, h_errnop);
    if (route(qname, &g) < 0)
        return not_ours(errnop, h_errnop);

    if ((n = zr_query(&g, qname, ns_t_ptr, ans, sizeof(ans), &herr)) < 0)
        return failed(herr, errnop, h_errnop);
    if (ns_initparse(ans, n, &m) < 0)
        return failed(NO_RECOVERY, errnop, h_errnop);

    /* first PTR wins; skips any CNAME from classless delegation */
    for (i = 0; i < ns_msg_count(m, ns_s_an); i++) {
        if (ns_parserr(&m, ns_s_an, i, &rr) < 0)
            break;
        if (ns_rr_type(rr) != ns_t_ptr)
            continue;
        if (ns_name_uncompress(ns_msg_base(m), ns_msg_end(m),
                               ns_rr_rdata(rr), host, sizeof(host)) < 0)
            continue;

        if (ttlp)
            *ttlp = ns_rr_ttl(rr);
        memcpy(abuf[0], addr, len);
        return fill(result, host, af, len, abuf, 1, buffer, buflen,
                    errnop, h_errnop);
    }
    return failed(NO_DATA, errnop, h_errnop);
}

enum nss_status _nss_zoneroute_gethostbyaddr_r(const void *addr,
        socklen_t len, int af, struct hostent *result, char *buffer,
        size_t buflen, int *errnop, int *h_errnop)
{
    return _nss_zoneroute_gethostbyaddr2_r(addr, len, af, result, buffer,
                                           buflen, errnop, h_errnop, NULL);
}

enum nss_status _nss_zoneroute_gethostbyname3_r(const char *name, int af,
        struct hostent *result, char *buffer, size_t buflen, int *errnop,
        int *h_errnop, int32_t *ttlp, char **canonp)
{
    struct group g;
    unsigned char ans[ANS_LEN], addrs[MAX_ADDRS][16];
    char canon[NS_MAXDNAME];
    int type, alen, n, i, herr, naddr = 0;
    enum nss_status s;
    ns_msg m;
    ns_rr rr;

    if (af == AF_INET) {
        type = ns_t_a;
        alen = 4;
    } else if (af == AF_INET6) {
        type = ns_t_aaaa;
        alen = 16;
    } else {
        return not_ours(errnop, h_errnop);
    }

    if (route(name, &g) < 0)
        return not_ours(errnop, h_errnop);

    if ((n = zr_query(&g, name, type, ans, sizeof(ans), &herr)) < 0)
        return failed(herr, errnop, h_errnop);
    if (ns_initparse(ans, n, &m) < 0)
        return failed(NO_RECOVERY, errnop, h_errnop);

    snprintf(canon, sizeof(canon), "%s", name);
    for (i = 0; i < ns_msg_count(m, ns_s_an) && naddr < MAX_ADDRS; i++) {
        if (ns_parserr(&m, ns_s_an, i, &rr) < 0)
            break;
        if ((int)ns_rr_type(rr) != type || ns_rr_rdlen(rr) != alen)
            continue;

        if (naddr == 0) {
            /* owner of the first address record is the canonical name */
            snprintf(canon, sizeof(canon), "%s", ns_rr_name(rr));
            if (ttlp)
                *ttlp = ns_rr_ttl(rr);
        }
        memcpy(addrs[naddr++], ns_rr_rdata(rr), alen);
    }
    if (naddr == 0)
        return failed(NO_DATA, errnop, h_errnop);

    s = fill(result, canon, af, alen, addrs, naddr, buffer, buflen,
             errnop, h_errnop);
    if (s == NSS_STATUS_SUCCESS && canonp)
        *canonp = result->h_name;
    return s;
}

enum nss_status _nss_zoneroute_gethostbyname2_r(const char *name, int af,
        struct hostent *result, char *buffer, size_t buflen, int *errnop,
        int *h_errnop)
{
    return _nss_zoneroute_gethostbyname3_r(name, af, result, buffer, buflen,
                                           errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_zoneroute_gethostbyname_r(const char *name,
        struct hostent *result, char *buffer, size_t buflen, int *errnop,
        int *h_errnop)
{
    return _nss_zoneroute_gethostbyname3_r(name, AF_INET, result, buffer,
                                           buflen, errnop, h_errnop,
                                           NULL, NULL);
}
