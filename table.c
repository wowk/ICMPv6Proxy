#include "table.h"
#include <error.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>


int add_nd_table_entry(struct nd_table_t* nd_table, struct in6_addr* addr, struct ether_addr* mac)
{
    struct nd_table_entry_t* entry = NULL;

    find_nd_table_entry(nd_table, addr, &entry);
    if( !entry ){
        entry = (struct nd_table_entry_t*)malloc(sizeof(struct nd_table_entry_t));
        if( !entry ){
            error(0, 1, "failed to create new nd_table entry");
            return -errno;
        }
        memcpy(&entry->addr, addr, sizeof(entry->addr));
        memcpy(&entry->mac, mac, sizeof(entry->mac));
    }else{
        memcpy(&entry->mac, mac, sizeof(entry->mac));
    }

    return 0;
}

int find_nd_table_entry(struct nd_table_t* nd_table, struct in6_addr* addr, struct nd_table_entry_t** pentry)
{
    struct nd_table_entry_t* p;

    *pentry = NULL;
    LIST_FOREACH(p, nd_table, entry){
        if( IN6_ARE_ADDR_EQUAL(addr, &p->addr) ){
            *pentry = p;
            return 0;
        }
    }

    return 0;
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
    LIST_FOREACH(p, nd_table, entry){
        if( del ){
            free(del);
            del = NULL;
        }
        if( p ){
            del = p;
        }
    }
    if( del ){
        free(del);
    }
}
