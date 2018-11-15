#ifndef ICMP6_PROXY_FDB_H__
#define ICMP6_PROXY_FDB_H__

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ether.h>

struct fdb_entry_t {
    struct ether_addr mac;
    struct in6_addr addr;
    uint8_t port_index;
};

struct fdb_t {};

extern int add_fdb_entry(struct fdb_t*, uint8_t, struct in6_addr*, struct ether_addr*);
extern void clear_fdb(struct fdb_t*);

#endif
