#include "icmp6.h"
#include "lib.h"
#include "fdb.h"
#include "proxy.h"
#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <errno.h>   
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/timerfd.h>
#include <sys/queue.h>
#include <sys/sysinfo.h>


static struct prefix_info_t* find_prefix_info(struct port_t* port, struct nd_opt_prefix_info* info)
{
    struct prefix_info_t* pi;

    TAILQ_FOREACH(pi, &port->prefix_list, entry){
        if( pi->info.nd_opt_pi_prefix_len != info->nd_opt_pi_prefix_len ){
            continue;
        }
        if( !IN6_ARE_ADDR_EQUAL(&pi->info.nd_opt_pi_prefix, &info->nd_opt_pi_prefix) ){
            continue;
        }
        break;
    }

    return pi;
}

static struct prefix_info_t* add_prefix_info(struct port_t* port, struct nd_opt_prefix_info* info)
{
    size_t size;
    struct prefix_info_t* pi;

    pi = find_prefix_info(port, info);
    if( !pi ){
        size = sizeof(struct prefix_info_t);
        pi = (struct prefix_info_t*)malloc(size);
        if( !pi ){
            error(0, errno, "failed to create new prefix info node");
            return NULL;
        }
        TAILQ_INSERT_HEAD(&port->prefix_list, pi, entry);
    }

    struct sysinfo si;
    sysinfo(&si);
    memcpy(&pi->info, info, sizeof(pi->info));
    pi->expired_time = si.uptime + info->nd_opt_pi_valid_time;

    return pi;
}

static void delete_prefix_info(struct port_t* port, struct prefix_info_t* info)
{
    TAILQ_REMOVE(&port->prefix_list, info, entry);
    free(info);
}

static void update_prefix_info(struct port_t* port)
{
    struct sysinfo si;
    struct prefix_info_t* pi;
    struct prefix_info_t* deleted;

    sysinfo(&si);
    deleted = NULL;

    TAILQ_FOREACH(pi, &port->prefix_list, entry){
        if( deleted ){
            delete_prefix_info(port, deleted);
            deleted = NULL;
        }
        if( si.uptime > pi->expired_time){
            deleted = pi;
        }
    }
    if( deleted ){
        delete_prefix_info(port, deleted);
    }
}

static void clear_prefix_info(struct port_t* port)
{
    struct prefix_info_t* pi;
    struct prefix_info_t* deleted;

    deleted = NULL;
    TAILQ_FOREACH(pi, &port->prefix_list, entry){
        if( deleted ){
            delete_prefix_info(port, deleted);
            deleted = NULL;
        }
        pi = deleted;
    }
}

static void dump_icmp_pkt(struct port_t* port, struct icmp6_hdr* hdr, struct in6_addr* from, struct in6_addr* to)
{
    char saddr[INET6_ADDRSTRLEN] = "";
    char daddr[INET6_ADDRSTRLEN] = "";

    if(  !inet_ntop(PF_INET6, from, saddr, sizeof(saddr)) )
        error(0, errno,"failed to parse src s6addr");

    if( !inet_ntop(PF_INET6, to, daddr, sizeof(daddr)) ){
        error(0, errno,"failed to parse dst s6addr");
    }

    char* type;
    switch( hdr->icmp6_type ){
    case ND_ROUTER_ADVERT:
        type = "RA";
        break;
    case ND_ROUTER_SOLICIT:
        type = "RS";
        break;
    case ND_NEIGHBOR_ADVERT:
        type = "NA";
        break;
    case ND_NEIGHBOR_SOLICIT:
        type = "NS";
        break;
    case ND_REDIRECT:
        type = "REDIRECT";
        break;
    default:
        type = "Other";
        break;
    }

    printf("if: %s, from: %s, to: %s, type: %s\n", port->ifname, saddr, daddr, type);
}

static struct nd_opt_hdr* find_nd_option(struct icmp6_hdr* hdr, size_t len, uint32_t option)
{
    size_t offset;

    switch(hdr->icmp6_type){
    case ND_ROUTER_ADVERT:
        offset = sizeof(struct nd_router_advert);
        break;
    case ND_ROUTER_SOLICIT:
        offset = sizeof(struct nd_router_solicit);
        break;
    case ND_NEIGHBOR_ADVERT:
        offset = sizeof(struct nd_neighbor_advert);
        break;
    case ND_NEIGHBOR_SOLICIT:
        offset = sizeof(struct nd_neighbor_solicit);
        break;
    default:
        printf("do not care\n");
        return NULL;
    }

    struct nd_opt_hdr* opthdr = (struct nd_opt_hdr*)((void*)hdr + offset);
    while( offset < len && opthdr->nd_opt_type != option ){
        offset += opthdr->nd_opt_len;
        opthdr = (struct nd_opt_hdr*)((void*)hdr + offset);
    }

    if( offset >= len ){
        return NULL;
    }

    return opthdr;
}

int send_ra(struct port_t* port, struct prefix_info_t* pi, struct in6_addr* addr)
{
    int ret;
    struct nd_router_advert hdr;

    hdr.nd_ra_type  = ND_ROUTER_ADVERT;
    hdr.nd_ra_code  = 0;
    hdr.nd_ra_cksum = 0;
    hdr.nd_ra_curhoplimit = 64;
    hdr.nd_ra_flags_reserved = ND_RA_FLAG_MANAGED;
    hdr.nd_ra_flags_reserved |= ND_RA_FLAG_OTHER;
    hdr.nd_ra_router_lifetime = 1800;
    hdr.nd_ra_reachable = 0;
    hdr.nd_ra_retransmit = 0;

    struct nd_opt_mtu mtu;
    mtu.nd_opt_mtu_mtu = 1500;
    mtu.nd_opt_mtu_type = ND_OPT_MTU;
    mtu.nd_opt_mtu_len = sizeof(mtu);
    mtu.nd_opt_mtu_reserved = 0;

    struct nd_opt_source_link_addr {
        uint8_t type;
        uint8_t len;
        struct ether_addr mac;
    } __attribute__((packed)) opt_linkaddr;

    opt_linkaddr.type = ND_OPT_SOURCE_LINKADDR;
    opt_linkaddr.len  = sizeof(struct nd_opt_source_link_addr);
    memcpy(&opt_linkaddr.mac, &port->mac, sizeof(port->mac));

    ret = send_pkt(port, addr, 4, &hdr, sizeof(hdr), &mtu, sizeof(mtu),
                    &opt_linkaddr, sizeof(opt_linkaddr), &pi->info, sizeof(pi->info));

    return ret;
}


int handle_wan_side(struct icmp6_proxy_t* proxy, struct icmp6_hdr* hdr, size_t len, 
                            struct in6_addr* from, struct in6_addr* to)
{
    dump_icmp_pkt(&proxy->wan, hdr, from, to);

    /* proxy RA packet from wan side */
    if( hdr->icmp6_type == ND_ROUTER_ADVERT ){
        if( !proxy->ra_proxy ){
            return 0;
        }

        struct nd_opt_hdr* opthdr;
        struct nd_opt_prefix_info* pref;

        opthdr = find_nd_option(hdr, len, ND_OPT_PREFIX_INFORMATION);
        /* dont interset in RA packet without prefix option */
        if( !opthdr ){
            return 0;
        }
        pref = (struct nd_opt_prefix_info*)opthdr;

        /* remove timeout prefix item */
        update_prefix_info(&proxy->lan);
        update_prefix_info(&proxy->wan);

        /* add new incoming prefix*/
        add_prefix_info(&proxy->wan, pref);

        /* forward it to LAN side */
        opthdr = find_nd_option(hdr, len, ND_OPT_SOURCE_LINKADDR);
        if( !opthdr ){
            return 0;
        }

        void* linkaddr_pos = (void*)(opthdr) + opthdr->nd_opt_len;
        memcpy(linkaddr_pos, &proxy->lan.mac, sizeof(proxy->lan.mac));

        send_pkt(&proxy->lan, to, 1, hdr, len);

        return 0;
    }

    if( hdr->icmp6_type == ND_NEIGHBOR_SOLICIT ){

    }

    return 0;
}



int handle_lan_side(struct icmp6_proxy_t* proxy, struct icmp6_hdr* hdr, size_t len, 
                            struct in6_addr* from, struct in6_addr* to)
{
    dump_icmp_pkt(&proxy->lan, hdr, from, to);

    if( hdr->icmp6_type == ND_ROUTER_ADVERT ){
        /* if ra_proxy is disabled or has gotten same prefix, ignore this pkt */
        if( !proxy->ra_proxy || proxy->got_same_prefix_at_both_side){
            return 0;
        }

        struct nd_opt_hdr* opthdr;
        struct nd_opt_prefix_info* pref;

        opthdr = find_nd_option(hdr, len, ND_OPT_PREFIX_INFORMATION);
        /* dont interset in RA packet without prefix option */
        if( !opthdr ){
            return 0;
        }
        pref = (struct nd_opt_prefix_info*)opthdr;

        /* remove timeout prefix item */
        update_prefix_info(&proxy->lan);
        update_prefix_info(&proxy->wan);

        /* add new incoming prefix*/
        add_prefix_info(&proxy->lan, pref);

        if( find_prefix_info(&proxy->wan, pref) ){
            proxy->got_same_prefix_at_both_side = true;
            return 0;
        }

        return 0;
    }

    if( hdr->icmp6_type == ND_ROUTER_SOLICIT ){
        if( !proxy->ra_proxy || proxy->got_same_prefix_at_both_side ){
            return 0;
        }

        struct prefix_info_t* pi;
        TAILQ_FOREACH(pi, &proxy->wan.prefix_list, entry){
            send_ra(&proxy->wan, pi, from);
        }

        return 0;
    }

    if( hdr->icmp6_type == ND_NEIGHBOR_SOLICIT ){
        struct nd_neighbor_solicit* ns = (struct nd_neighbor_solicit*)hdr;
        struct in6_addr* target_v6addr = (struct in6_addr*)(ns + 1);

        if( IN6_IS_ADDR_UNSPECIFIED(from) && IN6_IS_ADDR_MULTICAST(to) ){
            add_fdb_entry(proxy->fdb, &proxy->lan, target_v6addr, linkaddr);
        }

        struct nd_opt_hdr* opthdr = (struct nd_opt_hdr*)(target_v6addr + 1);
        if( opthdr->nd_opt_type != ND_OPT_SOURCE_LINKADDR ){
            return 0;
        }
        struct ether_addr* linkaddr = (struct ether_addr*)(opthdr + 1);
        //

        return 0;
    }

    return 0;
}
