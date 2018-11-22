#include "table.h"
#include "debug.h"
#include "proxy.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/route.h>


int add_host_route_rule(struct port_t* port, struct in6_addr* addr)
{
    if( port->type != LAN_PORT ){
        return 0;
    }

    char hostaddr[INET6_ADDRSTRLEN] = "";
    char cmd[256] = "";
    inet_ntop(PF_INET6, addr, hostaddr, sizeof(hostaddr));
    snprintf(cmd, sizeof(cmd), "ip -6 route add %s dev %s >/dev/null", hostaddr, port->ifname);
    info("add new host route rule: %s", cmd);

    return system(cmd);
}

int delete_host_route_rule(struct port_t* port, struct in6_addr* addr)
{
    if( port->type != LAN_PORT ){
        return 0;
    }

    char hostaddr[INET6_ADDRSTRLEN] = "";
    char cmd[256] = "";
    inet_ntop(PF_INET6, addr, hostaddr, sizeof(hostaddr));
    snprintf(cmd, sizeof(cmd), "ip -6 route del %s dev %s >/dev/null", hostaddr, port->ifname);
    info("delete host route rule: %s", cmd);
    return system(cmd);
}

int add_nd_table_entry(struct port_t* port, struct in6_addr* addr, struct ether_addr* mac, unsigned lifetime)
{
    struct nd_table_entry_t* pentry = NULL;

    char ip6addr[INET6_ADDRSTRLEN] = "";
    char macaddr[18] = "";
    inet_ntop(PF_INET6, addr, ip6addr, sizeof(ip6addr));
    ether_ntoa_r(mac, macaddr);

    find_nd_table_entry(port, addr, &pentry);
    if( !pentry ) {
        pentry = (struct nd_table_entry_t*)calloc(1,sizeof(struct nd_table_entry_t));
        if( !pentry ) {
            error(0, 1, "\t\tfailed to create new nd_table entry");
            return -errno;
        }
        memcpy(&pentry->addr, addr, sizeof(pentry->addr));
        memcpy(&pentry->mac, mac, sizeof(pentry->mac));
        info("\t\tlog new entry: %s,    %s", ip6addr, macaddr);
        LIST_INSERT_HEAD(&port->nd_table, pentry, entry);
        add_host_route_rule(port, addr);
    } else {
        memcpy(&pentry->mac, mac, sizeof(pentry->mac));
        info("\t\tupdate old entry: %s,    %s, lifetime: %u", ip6addr, macaddr, pentry->expired_time);
    }

    pentry->expired_time = lifetime;

    return 0;
}

int find_nd_table_entry(struct port_t* port, struct in6_addr* addr, struct nd_table_entry_t** pentry)
{
    struct nd_table_entry_t* p;

    *pentry = NULL;
    LIST_FOREACH(p, &port->nd_table, entry) {
        if( IN6_ARE_ADDR_EQUAL(addr, &p->addr) ) {
            *pentry = p;
            return 0;
        }
    }

    return 0;
}

void dump_nd_table(struct port_t* port)
{
    struct nd_table_entry_t* p;
    char ip6addr[INET6_ADDRSTRLEN] = "";
    char ethaddr[18] = "";

    LIST_FOREACH(p, &port->nd_table, entry) {
        inet_ntop(PF_INET6, &p->addr, ip6addr, sizeof(ip6addr));
        ether_ntoa_r(&p->mac, ethaddr);
        info("\t\tip: %s, mac: %s, lifetime: %u", ip6addr, ethaddr, p->expired_time);
    }
}

int update_nd_table(struct port_t* port, unsigned passed_time)
{
    struct nd_table_entry_t* pentry;
    struct nd_table_entry_t* deleted;

    deleted = NULL;
    LIST_FOREACH(pentry, &port->nd_table, entry){
        if( deleted ){
            LIST_REMOVE(deleted, entry);
            delete_host_route_rule(port, &deleted->addr);
            free(deleted);
            deleted = NULL;
        }

        if( pentry->expired_time < passed_time ){
            deleted = pentry;
            char ip6addr[INET6_ADDRSTRLEN] = "";
            char ethaddr[18] = "";
            inet_ntop(PF_INET6, &pentry->addr, ip6addr, sizeof(ip6addr));
            ether_ntoa_r(&pentry->mac, ethaddr);
            info("\t\texpired: ip: %s, mac: %s\n", ip6addr, ethaddr);
        }else{
            pentry->expired_time -= passed_time;
        }
    }

    if( deleted ){
        LIST_REMOVE(deleted, entry);
        delete_host_route_rule(port, &deleted->addr);
        free(deleted);
        deleted = NULL;
    }

    return 0;
}

void clear_nd_table(struct port_t* port)
{
    struct nd_table_entry_t* pentry;
    struct nd_table_entry_t* deleted;

    deleted = NULL;
    LIST_FOREACH(pentry, &port->nd_table, entry) {
        if( deleted ) {
            LIST_REMOVE(deleted, entry);
            delete_host_route_rule(port, &deleted->addr);
            free(deleted);
            deleted = NULL;
        }
        if( pentry ) {
            deleted = pentry;
        }
    }
    if( deleted ) {
        LIST_REMOVE(deleted, entry);
        delete_host_route_rule(port, &deleted->addr);
        free(deleted);
        deleted = NULL;
    }
}
