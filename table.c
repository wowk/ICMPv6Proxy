#include "table.h"
#include <error.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <stdio.h>
#include <netinet/in.h>


int add_nd_table_entry(struct nd_table_t* nd_table, struct in6_addr* addr, struct ether_addr* mac)
{
    struct nd_table_entry_t* pentry = NULL;

    char ip6addr[INET6_ADDRSTRLEN] = "";
    char macaddr[18] = "";
    inet_ntop(PF_INET6, addr, ip6addr, sizeof(ip6addr));
    ether_ntoa_r(mac, macaddr);

    find_nd_table_entry(nd_table, addr, &pentry);
    if( !pentry ) {
        pentry = (struct nd_table_entry_t*)malloc(sizeof(struct nd_table_entry_t));
        if( !pentry ) {
            error(0, 1, "\t\tfailed to create new nd_table entry");
            return -errno;
        }
        memcpy(&pentry->addr, addr, sizeof(pentry->addr));
        memcpy(&pentry->mac, mac, sizeof(pentry->mac));
        printf("\t\tlog new entry: %s,    %s\n", ip6addr, macaddr);
        LIST_INSERT_HEAD(nd_table, pentry, entry);
    } else {
        memcpy(&pentry->mac, mac, sizeof(pentry->mac));
        printf("\t\tupdate old entry: %s,    %s\n", ip6addr, macaddr);
    }

    return 0;
}

int find_nd_table_entry(struct nd_table_t* nd_table, struct in6_addr* addr, struct nd_table_entry_t** pentry)
{
    struct nd_table_entry_t* p;

    *pentry = NULL;
    LIST_FOREACH(p, nd_table, entry) {
        if( IN6_ARE_ADDR_EQUAL(addr, &p->addr) ) {
            printf("\t\tfound\n");
            *pentry = p;
            return 0;
        }
    }

    return 0;
}

void dump_nd_table(struct nd_table_t* nd_table)
{
    struct nd_table_entry_t* p;
    char ip6addr[INET6_ADDRSTRLEN] = "";
    char ethaddr[18] = "";

    LIST_FOREACH(p, nd_table, entry) {
        inet_ntop(PF_INET6, &p->addr, ip6addr, sizeof(ip6addr));
        ether_ntoa_r(&p->mac, ethaddr);
        printf("\t\tip: %s, mac: %s\n", ip6addr, ethaddr);
    }
}

int update_nd_table(struct nd_table_t* nd_table)
{
    return 0;
}

void clear_nd_table(struct nd_table_t* nd_table)
{
    struct nd_table_entry_t* p;
    struct nd_table_entry_t* del;

    del = NULL;
    LIST_FOREACH(p, nd_table, entry) {
        if( del ) {
            free(del);
            del = NULL;
        }
        if( p ) {
            del = p;
        }
    }
    if( del ) {
        free(del);
    }
}
