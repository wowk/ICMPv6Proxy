#include "ndisc.h"
#include "lib.h"
#include "table.h"
#include "debug.h"
#include "proxy.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/timerfd.h>
#include <sys/queue.h>

#include <netinet/ip6.h>


static void dump_icmp_pkt(struct port_t* port, struct icmp6* icmp6)
{
    char saddr[INET6_ADDRSTRLEN] = "";
    char daddr[INET6_ADDRSTRLEN] = "";

    if(  !inet_ntop(PF_INET6, &icmp6->ip6hdr.ip6_src, saddr, sizeof(saddr)) )
        error(0, errno,"failed to parse src s6addr");

    if( !inet_ntop(PF_INET6, &icmp6->ip6hdr.ip6_dst, daddr, sizeof(daddr)) ) {
        error(0, errno,"failed to parse dst s6addr");
    }

    const char* type;
    switch( icmp6->comm.icmp6_type ) {
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

    char linkaddr[INET6_ADDRSTRLEN] = "";
    inet_ntop(PF_INET6, &port->localip6addr, linkaddr, sizeof(linkaddr));
    info("if: %s, portaddr: %s, from: %s, to: %s, type: %s", port->ifname, linkaddr, saddr, daddr, type);
    char src_mac[18] = "";
    char dst_mac[18] = "";
    ether_ntoa_r((struct ether_addr*)icmp6->ethdr.ether_shost, src_mac);
    ether_ntoa_r((struct ether_addr*)icmp6->ethdr.ether_dhost, dst_mac);
    info("\tsrc mac: %s, dst mac: %s", src_mac, dst_mac);
}

static inline bool is_dad_packet(struct icmp6* icmp6)
{
    return IN6_IS_ADDR_UNSPECIFIED(&icmp6->ip6hdr.ip6_src) && IN6_IS_ADDR_MULTICAST(&icmp6->ip6hdr.ip6_dst) ? true : false;
}

static bool acceptable(struct nd_proxy_t* proxy, struct icmp6* icmp6)
{
    switch (icmp6->comm.icmp6_type) {
    case ND_NEIGHBOR_SOLICIT:
    case ND_NEIGHBOR_ADVERT:
    case ND_ROUTER_SOLICIT:
    case ND_ROUTER_ADVERT:
        break;
    default:
        return false;
    }

    if(!memcmp(&proxy->lan.ethaddr, icmp6->ethdr.ether_shost, sizeof(icmp6->ethdr.ether_shost))){
        return false;
    }else if(!memcmp(&proxy->wan.ethaddr, icmp6->ethdr.ether_shost, sizeof(icmp6->ethdr.ether_shost))){
        return false;
    }else if(icmp6->ethdr.ether_shost[0] == 0x33 && icmp6->ethdr.ether_shost[1] == 0x33){
        return false;
    }

    return true;
}

static bool need_forward(struct port_t* port, struct icmp6* icmp6)
{
    struct in6_addr allnotes;
    struct in6_addr solicitednodes;

    inet_pton(PF_INET6, "ff02::1", &allnotes);
    inet_pton(PF_INET6, "ff02::2", &solicitednodes);

    if(!memcmp(&icmp6->ip6hdr.ip6_dst, &solicitednodes, sizeof(solicitednodes))) {
        return true;
    }else if(!memcmp(&icmp6->ip6hdr.ip6_dst, &allnotes, sizeof(allnotes))) {
        return true;
    }else if(!memcmp(&icmp6->ethdr.ether_dhost, &port->ethaddr, sizeof(port->ethaddr))){
        return true;
    }else if(!memcpy(&icmp6->ethdr.ether_dhost, &port->mc_ethaddr, sizeof(port->mc_ethaddr))){
        return true;
    }

    return false;
}

static struct icmp6* parse_icmp6(void* pkt, size_t len)
{
    size_t tmp;
    size_t hdrlen;
    size_t offset;
    struct ether_header* ethdr = eth_header(pkt, &offset);
    struct ip6_hdr* ip6hdr = ipv6_header(ethdr, &offset);
    struct icmp6_hdr* icmp6hdr = icmp6_header(ip6hdr, &offset);
    static uint8_t buffer[1520];

    if( icmp6hdr->icmp6_type == ND_ROUTER_ADVERT ) {
        hdrlen = sizeof(struct nd_router_advert);
    } else if( icmp6hdr->icmp6_type == ND_ROUTER_SOLICIT) {
        hdrlen = sizeof(struct nd_router_solicit);
    } else if( icmp6hdr->icmp6_type == ND_NEIGHBOR_ADVERT) {
        hdrlen = sizeof(struct nd_neighbor_advert);
    } else if( icmp6hdr->icmp6_type == ND_NEIGHBOR_SOLICIT) {
        hdrlen = sizeof(struct nd_neighbor_solicit);
    } else {
        return NULL;
    }

    offset += hdrlen;
    tmp = offset;
    union icmp6_opt* opt = (union icmp6_opt*)(pkt + offset);
    size_t count = 0;
    while (offset < len && opt->comm.nd_opt_type) {
        count += 1;
        opt = (union icmp6_opt*)((void*)opt + opt->comm.nd_opt_len * 8);
        offset += opt->comm.nd_opt_len * 8;
    }

    struct icmp6* icmp6 = (struct icmp6*)buffer;

    icmp6->opt_cnt = count;
    if( !icmp6 ) {
        error(0, errno, "cant create icmp6 object\n");
        return NULL;
    }

    offset = tmp;
    memcpy(&icmp6->comm, icmp6hdr, hdrlen);
    for( size_t i = 0 ; i < count ; i ++ ) {
        opt = (union icmp6_opt*)(pkt + offset);
        memcpy(&icmp6->opt[i], opt, opt->comm.nd_opt_len * 8);
        offset += opt->comm.nd_opt_len * 8;
    }

    memcpy(&icmp6->ethdr, ethdr, sizeof(*ethdr));
    memcpy(&icmp6->ip6hdr, ip6hdr, sizeof(*ip6hdr));

    return icmp6;
}

static int disable_ra_if_got_same_prefix(struct icmp6* icmp6)
{

    return 0;
}

static int replace_src_linkaddr(struct icmp6* icmp6, struct ether_addr* mac)
{
    union icmp6_opt* opt = NULL;

    for(size_t i = 0 ; i < icmp6->opt_cnt ; i ++) {
        if(icmp6->opt[i].comm.nd_opt_type != ND_OPT_SOURCE_LINKADDR) {
            continue;
        }
        opt = &icmp6->opt[i];
        break;
    }

    if( opt ) {
        memcpy(&opt->slinkaddr.addr, mac, sizeof(*mac));
    }

    return 0;
}

static int send_ra(struct port_t* port, struct icmp6* icmp6)
{
    disable_ra_if_got_same_prefix(icmp6);
    replace_src_linkaddr(icmp6, &port->ethaddr);

    struct iovec iovec[icmp6->opt_cnt + 1];

    iovec[0].iov_base   = &icmp6->ra;
    iovec[0].iov_len    = sizeof(icmp6->ra);

    for( size_t i = 0 ; i < icmp6->opt_cnt ; i ++ ) {
        iovec[i+1].iov_base = &icmp6->opt[i];
        iovec[i+1].iov_len  = icmp6->opt[i].comm.nd_opt_len * 8;
//        if( icmp6->opt[i].comm.nd_opt_type == ND_OPT_PREFIX_INFORMATION ){
//            char ip6addr[INET6_ADDRSTRLEN] = "";
//            inet_ntop(PF_INET6, &icmp6->opt[i].prefix.nd_opt_pi_prefix, ip6addr, sizeof(ip6addr));
//            char command[256] = "";
//            snprintf(command, sizeof(command), "ip -6 route add %s/%u dev br0", ip6addr, icmp6->opt[i].prefix.nd_opt_pi_prefix_len);
//            system(command);
//        }
    }

    struct sockaddr_in6 si6;
    memset(&si6, 0, sizeof(si6));
    si6.sin6_family     = PF_INET6;
    inet_pton(PF_INET6, "ff02::1", &si6.sin6_addr);

    struct msghdr msghdr;
    memset(&msghdr, 0, sizeof(msghdr));
    msghdr.msg_name     = &si6;
    msghdr.msg_namelen  = sizeof(si6);
    msghdr.msg_iov      = iovec;
    msghdr.msg_iovlen   = sizeof(iovec)/sizeof(iovec[0]);

    /* must set to 255, or the LAN host will not accept this RA packet */
    unsigned hops = 255;
    if( 0 > setsockopt(port->icmp6sock, SOL_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) ) {
        error(0, errno, "failed to set multicast hops");
        return -errno;
    }

    ssize_t retlen;
    while( 0 > (retlen = sendmsg(port->icmp6sock, &msghdr, 0)) && errno == EINTR);
    if( retlen < 0 ) {
        error(0, errno, "failed to forward ICMPv6 packet\n");
    }

    return retlen;
}

static int send_na(struct port_t* port, struct icmp6* icmp6, struct in6_addr* target, struct ether_addr* linkaddr)
{
    struct ether_header ethdr;
    struct ip6_hdr ip6hdr;
    struct nd_neighbor_advert na;
    struct nd_opt_linkaddr opt_linkaddr;

    /* make ethernet header */
    ethdr.ether_type    = htons(ETHERTYPE_IPV6);
    memcpy(&ethdr.ether_shost, linkaddr, sizeof(*linkaddr));
    memcpy(&ethdr.ether_dhost, &icmp6->ethdr.ether_shost, sizeof(icmp6->ethdr.ether_shost));

    /* make ipv6 header */
    memset(&ip6hdr, 0, sizeof(ip6hdr));
    ip6hdr.ip6_vfc      = icmp6->ip6hdr.ip6_vfc;
    ip6hdr.ip6_flow     = icmp6->ip6hdr.ip6_flow;
    ip6hdr.ip6_plen     = htons(sizeof(na) + sizeof(opt_linkaddr));
    ip6hdr.ip6_nxt      = IPPROTO_ICMPV6;
    ip6hdr.ip6_hlim     = 255;
    memcpy(&ip6hdr.ip6_dst, &icmp6->ip6hdr.ip6_src, sizeof(icmp6->ip6hdr.ip6_src));
    memcpy(&ip6hdr.ip6_src, target, sizeof(*target));

    /* make icmpv6 header */
    na.nd_na_type   = ND_NEIGHBOR_ADVERT;
    na.nd_na_code   = 0;
    na.nd_na_cksum  = 0;
    na.nd_na_flags_reserved |= ND_NA_FLAG_ROUTER|ND_NA_FLAG_OVERRIDE;
    if( IN6_IS_ADDR_MULTICAST(target) ){
        na.nd_na_flags_reserved |= ND_NA_FLAG_SOLICITED;
    }
    memcpy(&na.nd_na_target, target, sizeof(*target));

    /* add target link option */
    opt_linkaddr.nd_opt_type    = ND_OPT_TARGET_LINKADDR;
    opt_linkaddr.nd_opt_len     = sizeof(opt_linkaddr) >> 3;
    memcpy(&opt_linkaddr.addr, linkaddr, sizeof(*linkaddr));

    /*
     * calculate ICMPv6's checksum
     * [RFC 2460 Section 8.1 ] fake header
     * [RFC 4443 Section 2.3 ] Message Checksum Calculation
    */
    struct{
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t plen;
        uint8_t pad[3];
        uint8_t nxthdr;
    } __attribute__((__packed__)) pseudo_hdr;
    memcpy(&pseudo_hdr.src , &ip6hdr.ip6_src, sizeof(ip6hdr.ip6_src));
    memcpy(&pseudo_hdr.dst, &ip6hdr.ip6_dst, sizeof(ip6hdr.ip6_dst));
    pseudo_hdr.plen    = htonl(sizeof(na) + sizeof(opt_linkaddr));
    pseudo_hdr.nxthdr  = IPPROTO_ICMPV6;
    pseudo_hdr.pad[0] = pseudo_hdr.pad[1] = pseudo_hdr.pad[2] = 0;

    struct {
        struct nd_neighbor_advert na;
        struct nd_opt_linkaddr linkaddr;
    } __attribute__((__packed__)) payload;
    memcpy(&payload.na, &na, sizeof(na));
    memcpy(&payload.linkaddr, &opt_linkaddr, sizeof(opt_linkaddr));

    uint64_t sum = checksum_partial(&pseudo_hdr, sizeof(pseudo_hdr), 0);
    sum = checksum_partial(&payload, sizeof(payload), sum);
    na.nd_na_cksum = checksum_fold(sum);

    /* send packet to link layer */
    int ret = send_raw_pkt(port, 4,
                    &ethdr, sizeof(ethdr),
                    &ip6hdr, sizeof(ip6hdr),
                    &na, sizeof(na),
                    &opt_linkaddr, sizeof(opt_linkaddr));
    if( ret < 0 ){
        error(0, errno, "failed to send RA packet");
    }

    return ret;
}

static int send_ns(struct port_t* port, struct icmp6* icmp6, struct in6_addr* target)
{
    struct nd_neighbor_solicit ns;
    struct nd_opt_linkaddr opt_linkaddr;

    ns.nd_ns_type   = ND_NEIGHBOR_SOLICIT;
    ns.nd_ns_code   = 0;
    ns.nd_ns_cksum  = 0;
    ns.nd_ns_reserved   = 0;
    memcpy(&ns.nd_ns_target, target, sizeof(*target));
    opt_linkaddr.nd_opt_type    = ND_OPT_SOURCE_LINKADDR;
    opt_linkaddr.nd_opt_len     = sizeof(opt_linkaddr) >> 3;
    memcpy(&opt_linkaddr.addr, &port->ethaddr, sizeof(port->ethaddr));

    struct in6_addr dstaddr;
#if 1
    inet_pton(PF_INET6, "ff02::01:ff:00:00:00", &dstaddr);
    memcpy(dstaddr.s6_addr + 13, target->s6_addr + 13, 3);
#else
    inet_pton(PF_INET6, "ff02::01", &dstaddr);
#endif

    /* must set to 255, or the LAN/WAN host will not accept this RA packet */
    unsigned hops = 255;
    if( 0 > setsockopt(port->icmp6sock, SOL_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) ) {
        error(0, errno, "failed to set multicast hops");
        return -errno;
    }

    int ret = send_icmp6_pkt(port, &dstaddr, 2, &ns, sizeof(ns), &opt_linkaddr, sizeof(opt_linkaddr));
    if( ret < 0 ){
        error(0, errno, "failed to send NS packet");
    }

    return ret;
}

int handle_wan_side(struct nd_proxy_t* proxy, void* pkt, size_t len)
{
    struct icmp6* icmp6 = parse_icmp6(pkt, len);
    if( !icmp6 ) {
        goto RETURN;
    }

    if(!acceptable(proxy, icmp6)) {
        goto RETURN;
    }

    dump_icmp_pkt(&proxy->wan, icmp6);

    int ret = 0;
    if( icmp6->comm.icmp6_type == ND_ROUTER_ADVERT ) {
        if(!proxy->ra_proxy ){
            goto RETURN;
        }
        if(!need_forward(&proxy->wan, icmp6)) {
            info("\tignore this RA packet");
            goto RETURN;
        }
        info("\tforward this RA packet");
        ret = send_ra(&proxy->lan, icmp6);
    } else if( icmp6->comm.icmp6_type == ND_NEIGHBOR_SOLICIT) {
        if(!proxy->dad_proxy) {
            goto RETURN;
        }

        /* icmp6->ns.nd_ns_target is at wan side, we dont care */
        struct nd_table_entry_t* pentry;
        dump_nd_table(&proxy->wan);
        ret = find_nd_table_entry(&proxy->wan, &icmp6->ns.nd_ns_target, &pentry);
        if( pentry ) {
            info("\ttarget found at wan side, ignore this NS packet");
            goto RETURN;
        }

        if( is_dad_packet(icmp6) ) {
            info("\tThis is a DAD packet");
            ret = find_nd_table_entry(&proxy->lan, &icmp6->ns.nd_ns_target, &pentry);
            if( pentry ) {
                info("\t\tfound target at LAN side, duplicated, send NA to WAN side");
                send_na(&proxy->wan, icmp6, &icmp6->ns.nd_ns_target, &proxy->wan.ethaddr);
            } else {
                info("\t\tno target at LAN side, add target to WAN side");
                add_nd_table_entry(&proxy->wan, &icmp6->ns.nd_ns_target, (struct ether_addr*)icmp6->ethdr.ether_shost, proxy->aging_time);
            }
        } else {
            info("\tThis is a Normal NS packet");
            ret = find_nd_table_entry(&proxy->lan, &icmp6->ns.nd_ns_target, &pentry);
            if( pentry ) {
                info("\t\tfound target at LAN side, send NA to WAN side");
                send_na(&proxy->wan, icmp6, &icmp6->ns.nd_ns_target, &proxy->wan.ethaddr);
            } else {
                info("\t\tno target at LAN side, try to find it by sending NS to LAN side");
                send_ns(&proxy->lan, icmp6, &icmp6->ns.nd_ns_target);
            }
        }
    } else if( icmp6->comm.icmp6_type == ND_NEIGHBOR_ADVERT ) {
        if(!proxy->dad_proxy) {
            goto RETURN;
        }

        dump_icmp_pkt(&proxy->wan, icmp6);
        union icmp6_opt* opt = NULL;
        for(size_t i = 0 ; i < icmp6->opt_cnt ; i ++ ) {
            if( icmp6->opt[i].comm.nd_opt_type != ND_OPT_TARGET_LINKADDR ) {
                continue;
            }
            opt = &icmp6->opt[i];
            break;
        }
        if( opt ) {
            info("\tadd target to WAN side with target option value");
            add_nd_table_entry(&proxy->wan, &icmp6->na.nd_na_target, &opt->tlinkaddr.addr, proxy->aging_time);
        } else {
            info("\tadd target to WAN side with source mac address");
            add_nd_table_entry(&proxy->wan, &icmp6->na.nd_na_target, (struct ether_addr*)icmp6->ethdr.ether_shost, proxy->aging_time);
        }
    } else {
        /* dont care about RS packet */
        goto RETURN;
    }

    info("\n\n");

RETURN:
    return ret;
}

int handle_lan_side(struct nd_proxy_t* proxy, void* pkt, size_t len)
{
    union icmp6_opt* opt = NULL;

    struct icmp6* icmp6 = parse_icmp6(pkt, len);
    if( !icmp6 ) {
        goto RETURN;
    }

    if(!acceptable(proxy, icmp6)) {
        goto RETURN;
    }

    dump_icmp_pkt(&proxy->lan, icmp6);

    if(icmp6->comm.icmp6_type == ND_NEIGHBOR_SOLICIT ) {
        if(!proxy->dad_proxy) {
            goto RETURN;
        }

        struct nd_table_entry_t* pentry = NULL;
        dump_nd_table(&proxy->wan);
        find_nd_table_entry(&proxy->lan, &icmp6->ns.nd_ns_target, &pentry);
        if( pentry ) {
            printf("\ttarget found at LAN side, ignore this NS packet");
            return 0;
        }

        if(is_dad_packet(icmp6)) {
            info("\tThis is a DAD packet");
            find_nd_table_entry(&proxy->wan, &icmp6->ns.nd_ns_target, &pentry);
            if( pentry ) {
                info("\tfound target at WAN side, duplicated, send NA to lan side");
                send_na(&proxy->lan, icmp6, &icmp6->ns.nd_ns_target, &proxy->lan.ethaddr);
            } else {
                info("\t\tno target at WAN side, add target to LAN side");
                add_nd_table_entry(&proxy->lan, &icmp6->ns.nd_ns_target, (struct ether_addr*)icmp6->ethdr.ether_shost, proxy->aging_time);
            }
        } else {
            info("\tThis is a Normal NS packet");
            find_nd_table_entry(&proxy->wan, &icmp6->ns.nd_ns_target, &pentry);
            if( pentry) {
                info("\t\tfound target at LAN side, send NA to LAN side");
                send_na(&proxy->lan, icmp6, &icmp6->ns.nd_ns_target, &proxy->lan.ethaddr);
            } else {
                info("\t\tno target at WAN side, try to find it by sending NS to WAN side");
                send_ns(&proxy->wan, icmp6, &icmp6->ns.nd_ns_target);
            }
        }
    } else if(icmp6->comm.icmp6_type == ND_NEIGHBOR_ADVERT) {
        if(!proxy->dad_proxy) {
            return 0;
        }

        for(size_t i = 0 ; i < icmp6->opt_cnt ; i ++ ) {
            if( icmp6->opt[i].comm.nd_opt_type != ND_OPT_TARGET_LINKADDR )
                continue;
            opt = &icmp6->opt[i];
            break;
        }
        if( opt ) {
            info("\tadd target to LAN side with target option value");
            add_nd_table_entry(&proxy->lan, &icmp6->na.nd_na_target, &opt->tlinkaddr.addr, proxy->aging_time);
        } else {
            info("\tadd target to LAN side with source mac address");
            add_nd_table_entry(&proxy->lan, &icmp6->na.nd_na_target, (struct ether_addr*)icmp6->ethdr.ether_shost, proxy->aging_time);
        }
    } else {
        /* dont care, RADVD will deal with it */
        goto RETURN;
    }

    info("\n\n");

RETURN:
    return 0;
}
