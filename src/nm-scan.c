#include "nm-scan.h"
#include "nm-common.h"

static scan_state scan = {
    .opt_poll_thread_work_ms = 10,
};

static GMutex scan_stat_lock;
static GMutex scan_run_lock;


static const scan_port scan_port_list[] = {
    //rfc 2616
    {   .method = SCAN_TCP_CONNECT, .port = 80, .service = "http", .required = 1, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 5357, .service = "wsd", .required = 1, .host_type = HOST_TYPE_PC_WIN},
    /* --netbios-dgm @ 138/udp, smb@139 */
    {
        .method = SCAN_UDP_SENDRECV, .port = 137, .service = "netbios-ns", .required = 1, .host_type = HOST_TYPE_PC,
        .query_payload = { .length = sizeof(PROTO_NBS_QUERY), .message = PROTO_NBS_QUERY }
    },
    {
        .method = SCAN_UDP_SENDRECV, .port = 53, .service = "dns", .required = 1, .host_type = HOST_TYPE_ROUTER,
        .query_cb = probe_dns_generate_query_targetptr, .protocol = &proto_dns_definition
    },
    {   .method = SCAN_TCP_CONNECT, .port = 22, .service = "ssh", .required = 1, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 443, .service = "https", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 445, .service = "smb-ds", .required = 0, .host_type = HOST_TYPE_PC},
    //iphone, usually no ACK
    {   .method = SCAN_TCP_CONNECT, .port = 62078, .service = "itunes", .required = 0, .host_type = HOST_TYPE_PHONE},
    //rfc 2910, sometimes 633?
    {   .method = SCAN_TCP_CONNECT, .port = 631, .service = "ipp", .required = 0, .host_type = HOST_TYPE_PRINTER},
    {   .method = SCAN_TCP_CONNECT, .port = 4070, .service = "alexa-spotify", .required = 0, .host_type = HOST_TYPE_DEVICE},
    /* Additional services */
    {   .method = SCAN_TCP_CONNECT, .port = 9100, .service = "hp-print", .required = 0, .host_type = HOST_TYPE_PRINTER},
    {   .method = SCAN_TCP_CONNECT, .port = 3306, .service = "mysql", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 21, .service = "ftp", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 6668, .service = "tuya", .required = 0, .host_type = HOST_TYPE_DEVICE},
    /* Obscure services and non-standard ports */
    {   .method = SCAN_TCP_CONNECT, .port = 5900, .service = "vnc", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 25, .service = "smtp", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 88, .service = "kerberos", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 110, .service = "pop3", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 995, .service = "pop3s", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 123, .service = "ntp", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 143, .service = "imap", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 993, .service = "imaps", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 389, .service = "ldap", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 636, .service = "ldaps", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 70, .service = "gopher", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 79, .service = "finger", .required = 0, .host_type = HOST_TYPE_PC},

    /* http alternatives */
    {   .method = SCAN_TCP_CONNECT, .port = 1080, .service = "http", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 8080, .service = "http", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 8000, .service = "http", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = SCAN_TCP_CONNECT, .port = 8888, .service = "http", .required = 0, .host_type = HOST_TYPE_PC},
    /* amazon echo - maybe even alexa-40317 */
    {   .method = SCAN_TCP_CONNECT, .port = 55442, .service = "alexa", .required = 0, .host_type = HOST_TYPE_DEVICE},
    {   .method = SCAN_TCP_CONNECT, .port = 55443, .service = "alexa", .required = 0, .host_type = HOST_TYPE_DEVICE},
    /* apple ports */
    {   .method = SCAN_TCP_CONNECT, .port = 548, .service = "afp", .required = 0, .host_type = HOST_TYPE_PC_MAC},
    {   .method = SCAN_TCP_CONNECT, .port = 2195, .service = "apns", .required = 0, .host_type = HOST_TYPE_PC_MAC},
    {   .method = SCAN_TCP_CONNECT, .port = 2196, .service = "apns", .required = 0, .host_type = HOST_TYPE_PC_MAC},
    {   .method = SCAN_TCP_CONNECT, .port = 2197, .service = "apns", .required = 0, .host_type = HOST_TYPE_PC_MAC},
    /* unknown ports - */
    //{.method = SCAN_UDP_SENDRECV, .port = 192, .service = "osu-nms", .required = 0, .host_type = HOST_TYPE_PC},
    //Line Printer (LPR), Line Printer Daemon (LPD)
    //{.method = SCAN_TCP_CONNECT, .port = 515, .service = "lpr", .required = 0, .host_type = HOST_TYPE_PRINTER},
    //Real Time Streaming Protocol (RTSP), rfc 2326
    //{.method = SCAN_TCP_CONNECT, .port = 554, .service = "rtsp", .required = 0, .host_type = HOST_TYPE_PC},
    //NAT Port Mapping Protocol Announcements
    //{.method = SCAN_UDP_SENDRECV, .port = 5350, .service = "nat-annouce", .required = 0, .host_type = HOST_TYPE_PC},
    //NAT Port Mapping Protocol
    //{.method = SCAN_UDP_SENDRECV, .port = 5351, .service = "nat-pmp", .required = 0, .host_type = HOST_TYPE_PC},
};


static const scan_port scan_listen_list[] = {
    {
        .method = SCAN_UDP_SENDRECV, .port = 1900, .service = "ssdp", .required = 1,
        .bind_port = 0, .mc_join = 1, .mc_ip = "239.255.255.250", .send_ip = "239.255.255.250",
        .min_time = 100, .max_time = 60000,
        .query_cb = probe_string_generate_query, .response_cb = probe_ssdp_response,
        .protocol = &proto_ssdp_definition,
    },
    {
        .method = SCAN_UDP_RECV, .port = 1900, .service = "ssdp", .required = 1,
        .bind_port = 1900, .mc_join = 0, .mc_ip = "239.255.255.250", .bind_fail_confirms = 1,
        .min_time = 100, .max_time = 60000,
        .query_cb = NULL, .response_cb = probe_ssdp_response,
        .protocol = &proto_ssdp_definition,
    },
    {
        .method = SCAN_UDP_SENDRECV, .port = 5353, .service = "mdns", .required = 1, .family = SCAN_FAMILY_INET6,
        //.bind_port = 5353, .mc_join = 1, .mc_ip = "ff02::fb", .send_ip = "ff02::fb",
        .bind_port = 5353, .mc_join = 1, .mc_ip = "ff02::fb", .send_ip = "ff02::fb",
        .min_time = 100, .max_time = 60000,
        .query_cb = probe_mdns_generate_query, .response_cb = probe_mdns_response,
        .protocol = &proto_mdns_definition,
    },
    {
        .method = SCAN_UDP_SENDRECV, .port = 5353, .service = "mdns", .required = 1,
        .bind_port = 0, .mc_join = 1, .mc_ip = "224.0.0.251", .send_ip = "224.0.0.251",
        .min_time = 100, .max_time = 60000,
        .query_cb = probe_mdns_generate_query, .response_cb = probe_mdns_response,
        .protocol = &proto_mdns_definition,
    },
    {
        .method = SCAN_UDP_RECV, .port = 5353, .service = "mdns", .required = 1,
        .bind_port = 5353, .mc_join = 0, .mc_ip = "224.0.0.251", .bind_fail_confirms = 1,
        .min_time = 100, .max_time = 60000,
        .query_cb = NULL, .response_cb = probe_mdns_response,
        .protocol = &proto_mdns_definition,
    },
    {
        .method = SCAN_UDP_RECV, .port = 6771, .service = "bt-lsd", .required = 1,
        .bind_port = 6771, .mc_join = 1, .mc_ip = "239.192.152.143", .bind_fail_confirms = 1,
        .min_time = 200, .max_time = 60000,
        .query_cb = NULL, .response_cb = scan_response_ack,
    },
    {
        .method = SCAN_UDP_RECV, .port = 6666, .service = "tuya", .required = 1, .host_type = HOST_TYPE_DEVICE,
        .bind_port = 6666, .mc_join = 0,
        .min_time = 200, .max_time = 10000,
        .query_cb = NULL, .response_cb = scan_response_ack,
    },
    {
        .method = SCAN_UDP_RECV, .port = 6667, .service = "tuya", .required = 1, .host_type = HOST_TYPE_DEVICE,
        .bind_port = 6667, .mc_join = 0,
        .min_time = 200, .max_time = 10000,
        .query_cb = NULL, .response_cb = scan_response_ack,
    },
    {
        .method = SCAN_UDP_RECV, .port = 138, .service = "netbios-ds", .required = 1, .host_type = HOST_TYPE_DEVICE,
        .bind_port = 138, .mc_join = 0,
        .min_time = 200, .max_time = 30000,
        .query_cb = NULL, .response_cb = scan_response_ack,
    },
};



struct scan_nlrt_request {
    struct nlmsghdr header;
    struct ndmsg neigh;
};



bool scan_util_is_running()
{
    bool ret = false;
    g_mutex_lock(&scan_run_lock);
    if (scan.running)
        ret = true;
    g_mutex_unlock(&scan_run_lock);
    return ret;
}


bool scan_util_addr_seen(const in_addr_t target, const in_addr_t *list, const int list_len)
{
    for (int i = 0; i < list_len; i++) {
        if (list[i] == target)
            return true;
    }
    return false;
}

int scan_util_get_sock_error(int sd)
{
    int so_error = 0;
    socklen_t len = sizeof so_error;
    if (!getsockopt(sd, SOL_SOCKET, SO_ERROR, &so_error, &len))
        return so_error;
    else {
        log_info("scan_util_get_sock_error: error getting socket error");
        return -1;
    }
}


bool scan_util_calc_subnet_range(const char *ip, const char *netmask, scan_range *range)
{
    if (ip == NULL || netmask == NULL || strlen(ip) == 0 || strlen(netmask) == 0)
        return false;

    memset(range, 0, sizeof(scan_range));
    struct in_addr host_addr, mask_addr;
    inet_aton(ip, &host_addr);
    inet_aton(netmask, &mask_addr);

    if (mask_addr.s_addr < NL_MIN_NETMASK_VALUE)
        mask_addr.s_addr = NL_MIN_NETMASK_VALUE;

    range->start_addr.s_addr = (host_addr.s_addr & mask_addr.s_addr) | 0x01000000;
    range->stop_addr.s_addr = (host_addr.s_addr | ~mask_addr.s_addr) & 0xFEFFFFFF;
    range->start_num = ntohl(range->start_addr.s_addr);
    range->stop_num = ntohl(range->stop_addr.s_addr);

    if (scan.opt_subnet_offset) {
        range->start_num += scan.opt_subnet_offset;
        range->start_addr.s_addr = htonl(range->start_num);
    }

    if (scan.opt_max_hosts > 0) {
        range->stop_num = range->start_num + scan.opt_max_hosts;
        range->stop_addr.s_addr = htonl(range->stop_num);
    }
    range->length = range->stop_num - range->start_num + 1;

    return true;
}

// scan_result *scan_result_init(enum scan_host_state resp, in_addr_t addr, uint16_t port) {
//
//     scan_result *result = malloc(sizeof(scan_result));
//     memset(result, 0, sizeof(scan_result));
//
//     result->response = resp;
//     result->target_addr.s_addr = addr;
//     result->port = port;
//     return result;
// }

void scan_result_destroy(scan_result *result)
{
    if (result == NULL)
        return;
    if (result->hostname)
        free(result->hostname);
    if (result->services) {
        nm_list_free(result->services, true);
    }
    free(result);
}

void scan_print_mates(nmlist *hosts, bool showtotal)
{
    if (hosts == NULL)
        return;

    uint numentries = 0;
    nm_list_foreach(entry, hosts) {
        numentries++;
        if (scan.opt_print_list)
            nm_host_print_long((nm_host *)entry->data);
        else
            nm_host_print_wide((nm_host *)entry->data);
    }
    if (showtotal)
        printf("\n%sTotal Network Mates: %d%s\n", nm_clr_light, numentries, nm_clr_off);
}

// int scan_resolve_hostname_from_inaddr(uint32_t ip_addr, char *hostname_buffer, size_t buffer_size) {
//     assert(ip_addr != 0);
//     assert(hostname_buffer != NULL);
//
//     char host[NM_HOST_STRLEN];
//     char service[32];
//     struct sockaddr_in addr;
//
//     addr.sin_port = 0;
//     addr.sin_family = AF_INET;
//     addr.sin_addr.s_addr = ip_addr;
//     if(getnameinfo((struct sockaddr *) &addr,sizeof(addr), host, sizeof(host),
//                    service, sizeof(service), NI_NUMERICSERV) != 0){
//         return 0;
//     }
//     strncpy(hostname_buffer, host, buffer_size);
//
//     return 1;
// }


int scan_resolve_saddr_hostname(struct sockaddr *saddr, enum scan_family family, char *hostname_buffer, size_t buffer_size)
{
    assert(saddr != NULL);
    assert(hostname_buffer != NULL);

    char host[NM_HOST_STRLEN];
    char ipbuff[INET6_ADDRSTRLEN];
    char service[32];

    ssize_t saddrsize = (family == SCAN_FAMILY_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    if (getnameinfo((struct sockaddr *) saddr, saddrsize, host, sizeof(host), service, sizeof(service), NI_NUMERICSERV) != 0) {
        return 0;
    }

    inet_ntop(SCAN_FAMILY_TO_AF(family), saddr, ipbuff, sizeof(ipbuff));
    log_debug("scan_resolve_saddr_hostname: host: %s, ip: %s", host, ipbuff);
    if (strncmp(ipbuff, host, strlen(ipbuff) > sizeof(host) ? strlen(ipbuff) : sizeof(host)))
        strncpy(hostname_buffer, host, buffer_size);
    else
        hostname_buffer[0] = 0;
    return saddrsize;
}


int scan_resolve_hostname_new(enum scan_family family, char *ip, char *hostname_buffer, size_t buffer_size)
{
    assert(ip != NULL);
    assert(hostname_buffer != NULL);

    char host[NM_HOST_STRLEN];
    char service[32];

    if (family == SCAN_FAMILY_INET4) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        inet_pton(AF_INET, ip, &addr.sin_addr);
        if (getnameinfo((struct sockaddr *) &addr, sizeof(addr), host, sizeof(host),
                        service, sizeof(service), NI_NUMERICSERV) != 0) {
            return 0;
        }
    } else {
        struct sockaddr_in6 addr;
        addr.sin6_family = AF_INET6;
        addr.sin6_port = 0;
        inet_pton(AF_INET6, ip, &addr.sin6_addr);
        if (getnameinfo((struct sockaddr *) &addr, sizeof(addr), host, sizeof(host),
                        service, sizeof(service), NI_NUMERICSERV) != 0) {
            return 0;
        }
    }

    //if(strncmp(ip, host, strlen(ip) < sizeof(host) ? strlen(ip) : sizeof(host))){
    if (strncmp(ip, host, strlen(ip))) {
        strncpy(hostname_buffer, host, buffer_size);
        return 1;
    } else
        hostname_buffer[0] = 0;
//     if(strncmp(ip, host, sizeof(host))){
//         strncpy(hostname_buffer, host, buffer_size);
//         return 1;
//     }
    return 0;
}


// int scan_resolve_hostname(char *ip, char *hostname_buffer, size_t buffer_size) {
//     assert(ip != NULL);
//     assert(hostname_buffer != NULL);
//
//     char host[NM_HOST_STRLEN];
//     char service[32];
//     struct sockaddr_in addr;
//     addr.sin_port = 0;
//     addr.sin_family = AF_INET;
//     addr.sin_addr.s_addr = inet_addr(ip);
//     if(getnameinfo((struct sockaddr *) &addr,sizeof(addr), host, sizeof(host),
//                    service, sizeof(service), NI_NUMERICSERV) != 0){
//         return 0;
//     }
//     if(strncmp(ip, host, sizeof(host)) != 0){
//         strncpy(hostname_buffer, host, buffer_size);
//         return 1;
//     }
//     return 0;
// }
//
// int scan_resolve_hostname6(char *ip, char *hostname_buffer, size_t buffer_size) {
//     assert(ip != NULL);
//     assert(hostname_buffer != NULL);
//
//     char host[NM_HOST_STRLEN];
//     char service[32];
//     struct sockaddr_in6 addr;
//     addr.sin6_port = 0;
//     addr.sin6_family = AF_INET6;
//     inet_pton(AF_INET6, ip, &addr.sin6_addr);
//     if(getnameinfo((struct sockaddr *) &addr,sizeof(addr), host, sizeof(host),
//                    service, sizeof(service), NI_NUMERICSERV) != 0){
//         return 0;
//     }
//     if(strncmp(ip, host, sizeof(host)) != 0){
//         strncpy(hostname_buffer, host, buffer_size);
//         return 1;
//     }
//     return 0;
// }


void scan_socket_log_ip(int sd)
{
    char ipbuff[INET6_ADDRSTRLEN];
    struct sockaddr_storage saddr;
    socklen_t saddrsize = sizeof(saddr);

    int ret = getsockname(sd, (struct sockaddr *)&saddr, &saddrsize);
    if (ret == -1) {
        log_debug("Could not lookup address for this socket");
        return;
    }

    if (saddr.ss_family == AF_INET6) {
        struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)&saddr;
        inet_ntop(AF_INET6, &saddr6->sin6_addr, ipbuff, sizeof(ipbuff));
        log_debug("IPv6 address: %s, port: %hu, sized: %i/%i",
                  ipbuff, saddr6->sin6_port, saddrsize, sizeof(struct sockaddr_storage));
        nm_log_trace_bytes("trace", (const unsigned char *)&saddr6->sin6_addr, sizeof(struct in6_addr));
        return;
    }

    struct sockaddr_in *saddr4 = (struct sockaddr_in *)&saddr;
    inet_ntop(AF_INET, &saddr4->sin_addr, ipbuff, sizeof(ipbuff));
    log_debug("IPv4 address: %s, port: %hu, sized: %i/%i",
              ipbuff, saddr4->sin_port, saddrsize, sizeof(struct sockaddr_storage));
    nm_log_trace_bytes("trace", (const unsigned char *)&saddr4->sin_addr, sizeof(struct in_addr));
}


void scan_socket_log_saddr(struct sockaddr *saddr, const char *logsign, const char *action)
{
    char ipbuff[INET6_ADDRSTRLEN];

    if (saddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)saddr;
        inet_ntop(AF_INET6, &saddr6->sin6_addr, ipbuff, sizeof(ipbuff));
        log_debug("%s %s: Socket6 address: %s, port: %hu", logsign, action, ipbuff, ntohs(saddr6->sin6_port));
    } else if (saddr->sa_family == AF_INET) {
        struct sockaddr_in *saddr4 = (struct sockaddr_in *)saddr;
        inet_ntop(AF_INET, &saddr4->sin_addr, ipbuff, sizeof(ipbuff));
        log_debug("%s %s: Socket4 address: %s, port: %hu",  logsign, action, ipbuff, ntohs(saddr4->sin_port));
    }

}


int scan_socket_bind(int sd, enum scan_family family, uint16_t port, char *logsign)
{
    log_trace("%s Binding to port %i", logsign, port);
    struct sockaddr_in saddr4;
    struct sockaddr_in6 saddr6;
    struct sockaddr *saddr = NULL;
    ssize_t saddrsize = 0;

    //addr.sin6_family = SCAN_FAMILY_TO_AF(family);
    if (family == SCAN_FAMILY_INET4) {
        saddr4.sin_family = AF_INET;
        saddr4.sin_addr.s_addr = INADDR_ANY;
        saddr4.sin_port = htons(port);
        saddr = (struct sockaddr *)&saddr4;
        saddrsize = sizeof(saddr4);
    } else if (family == SCAN_FAMILY_INET6) {
        saddr6.sin6_family = AF_INET6;
        saddr6.sin6_addr = in6addr_any;
        saddr6.sin6_port = htons(port);
        saddr = (struct sockaddr *)&saddr6;
        saddrsize = sizeof(saddr6);
    }

    int reuse = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) == -1 ||
            setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1)
        log_debug("%s socket not set to reuse port/addr: %hu", logsign, port);

    //scan_socket_log_saddr(saddr, logsign, "bind_to");
    if (bind(sd, saddr, saddrsize) < 0) {
        log_info("%s Could not bind to port %i, err: %i, %s", logsign, port, errno, strerror(errno));
        return errno;
    }
    return 0;
}

int scan_socket_join_mc(int sd, enum scan_family family, const char *mcip, const char *logsign)
{
    assert(mcip != NULL);
    log_trace("%s Joining multicast group %s", logsign, mcip);

    int mc_loop = 0;

    if (family == SCAN_FAMILY_INET6) {
        struct ipv6_mreq mcast_mem6;
        struct in6_addr addr6;
        inet_pton(AF_INET6, mcip, &addr6);
        mcast_mem6.ipv6mr_interface = 0;
        mcast_mem6.ipv6mr_multiaddr = addr6;

        if (setsockopt(sd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mcast_mem6, sizeof(struct ipv6_mreq)) == -1) {
            return errno;
        }
        if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &mc_loop, sizeof(mc_loop)) == -1)
            log_debug("%s socket set option mc loop err: %i, %s ", logsign, errno, strerror(errno));

    } else {
        struct ip_mreqn mcast_mem4;
        struct in_addr addr4;
        inet_pton(AF_INET, mcip, &addr4);
        mcast_mem4.imr_ifindex = 0;
        mcast_mem4.imr_address.s_addr = INADDR_ANY;
        mcast_mem4.imr_multiaddr = addr4;

        if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mcast_mem4, sizeof(struct ip_mreqn)) == -1) {
            return errno;
        }
        if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &mc_loop, sizeof(mc_loop)) == -1)
            log_debug("%s socket set option mc loop err: %i, %s ", logsign, errno, strerror(errno));
    }

    return 0;
}

ssize_t scan_socket_set_saddr(struct sockaddr *saddr, enum scan_family family, struct in_addr *inaddr, uint16_t port)
{
    saddr->sa_family = SCAN_FAMILY_TO_AF(family);

    if (family == SCAN_FAMILY_INET6) {
        struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)saddr;
        memcpy(&saddr6->sin6_addr, ((struct sockaddr_in6 *)inaddr), sizeof(struct in6_addr));
        saddr6->sin6_port = htons(port);
        return sizeof(struct sockaddr_in6);
    }

    struct sockaddr_in *saddr4 = (struct sockaddr_in *)saddr;
    memcpy(&saddr4->sin_addr, inaddr, sizeof(struct in_addr));
    saddr4->sin_port = htons(port);
    return sizeof(struct sockaddr_in);
}


ssize_t scan_socket_addr_from_ip(struct sockaddr *saddr, enum scan_family family, const char *ip, uint16_t port)
{
    saddr->sa_family = SCAN_FAMILY_TO_AF(family);

    if (saddr->sa_family == AF_INET) {
        struct sockaddr_in *saddr4 = (struct sockaddr_in *)saddr;
        saddr4->sin_port = htons(port);
        inet_pton(AF_INET, ip, &saddr4->sin_addr);
        return sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)saddr;
        saddr6->sin6_port = htons(port);
        inet_pton(AF_INET6, ip, &saddr6->sin6_addr);
        return sizeof(struct sockaddr_in6);
    }
}


bool probe_send_proto_query(int sd, scan_port *sp, const char *logsign)
{
    assert(sd > 0);

    log_trace("%s Sending protocol queries", logsign);

    size_t msgsize;
    int queries_sent = 0;
    ssize_t bytes_sent;
    char buff[NM_GEN_BUFFSIZE];
    proto_def *proto = sp->protocol;
    proto_query *query = proto->queries;
    struct sockaddr_in6 saddr;

    ssize_t saddrsize = scan_socket_addr_from_ip((struct sockaddr *)&saddr, sp->family, sp->send_ip, sp->port);
    log_debug("%s probe_send_proto_query: family: %i, port: %hu, saddrsize: %zi",
              logsign, saddr.sin6_family, ntohs(saddr.sin6_port), saddrsize);
    nm_log_trace_bytes(logsign, (const uint8_t *)&saddr.sin6_addr, 16);
    while (query->message) {

        msgsize = sp->query_cb((void *)buff, sizeof(buff), query->message, (struct sockaddr *)&saddr);
        if (!msgsize)
            log_debug("%s Protocol message empty", logsign);

        log_debug("%s probe_send_proto_query: sd: %i, msgsize: %zi", logsign, sd, msgsize);
        bytes_sent = sendto(sd, buff, msgsize, 0, (const struct sockaddr *)&saddr, saddrsize);
        if (bytes_sent < 0) {
            log_debug("%s Could not send probe query, err %i, %s", logsign, errno, strerror(errno));
            //scan_socket_log_saddr((struct sockaddr*)&saddr, logsign, "send_to");
            //return false;
        }
        log_trace("%s Sent query with %li bytes", logsign, bytes_sent);
        query = query + 1;
        queries_sent++;
        //TODO: remove me
        break;
    }

    log_debug("%s probe_send_proto_query: sent %i queries", logsign, queries_sent);
    return true;
}


int probe_connect_tcp(const char *thread_id, scan_result *result,
                      scan_port *port_def, struct in_addr *inaddr)
{
    int sd, cnct_ret, poll_ret, so_error;
    struct sockaddr_in6 saddr6;
    ssize_t saddrsize = 0;
    struct pollfd poll_arg;


    sd = socket(SCAN_FAMILY_TO_AF(port_def->family), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_IP);
    if (sd < 0) {
        log_debug("%s\t socket errno: %i, errdesc: %s", thread_id, errno, strerror(errno));
        result->response = SCAN_HSTATE_ERROR;
        return -EIO;
    }

    saddrsize = scan_socket_set_saddr((struct sockaddr *)&saddr6, port_def->family, inaddr, port_def->port);

    //log_debug("%s connecting to port %hu", thread_id, port_def->port);
    cnct_ret = connect(sd, (struct sockaddr *)&saddr6, saddrsize);
    if (cnct_ret != -1 || errno != EINPROGRESS) {
        log_debug("%s\t connect unexpected error on port %i, errno: %i, errdesc: %s\n", thread_id, port_def->port,
                  errno, strerror(errno));
        result->response = SCAN_HSTATE_ERROR;
        close(sd);
        return -EIO;
    }

    poll_arg.fd = sd;
    /* include err event as open connect_ports can be too quick */
    poll_arg.events = POLL_IN | POLL_OUT | POLL_ERR;
    poll_ret = poll(&poll_arg, 1, scan.opt_connect_timeout_ms);
    //log_trace("%s poll on port %hu returned %i", thread_id, port_def->port, poll_ret);
    so_error = scan_util_get_sock_error(sd);

    /* check poll result and socket state */
    if (poll_ret > 0) {
        //poll has connect() success or error is connection refused, both mean host is live
        if (so_error == 0 || so_error == ECONNREFUSED) {
            result->response = SCAN_HSTATE_LIVE;
            if (so_error == 0) {
                result->host_type = port_def->host_type;
                result->port = port_def->port;
                result->method = port_def->method;
                result->family = port_def->family;
                result->port_open = true;
                result->services = nm_list_add(result->services, strdup(port_def->service));
                log_trace("%s host found, connect port %hu open",
                          thread_id, port_def->port);
            } else {
                log_trace("%s host found, connect port %hu passive",
                          thread_id, port_def->port);
            }
        }
    }

    close(sd);
    return 0;
}


int probe_sendrecv_udp(const char *thread_id, scan_result *result,
                       scan_port *port_def, struct in_addr *inaddr)
{
    int sd, send_ret, recv_ret, poll_ret;
    struct sockaddr_in target_addr;
    socklen_t addr_size;
    struct pollfd poll_arg;
    char *bufftosend = NULL;
    int sizetosend = 0;
    char sendbuffer[NM_GEN_BUFFSIZE];
    char recvbuffer[NM_GEN_BUFFSIZE];
    recvbuffer[0] = 0;


    sd = socket(SCAN_FAMILY_TO_AF(port_def->family), SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_IP);
    if (sd < 0) {
        log_debug("%s\t socket errno: %i, errdesc: %s", thread_id, errno, strerror(errno));
        result->response = SCAN_HSTATE_ERROR;
        return -EIO;
    }

    addr_size = scan_socket_set_saddr((struct sockaddr *)&target_addr, port_def->family, inaddr, port_def->port);

    if (port_def->query_payload.length) {
        bufftosend = port_def->query_payload.message;
        sizetosend = port_def->query_payload.length;
        log_trace("%s\t Selecting query buffer for port %hu, size %i", thread_id, port_def->port, sizetosend);
    } else if (port_def->query_cb && port_def->protocol && port_def->protocol->queries) {
        sizetosend = port_def->query_cb((void *)sendbuffer, sizeof(sendbuffer),
                                        port_def->protocol->queries->message, (struct sockaddr *)&target_addr);
        bufftosend = sendbuffer;
        log_trace("%s\t Selecting query callback for port %hu, size %i", thread_id, port_def->port, sizetosend);
    } else {
        log_trace("%s\t Invalid query definition, port %i\n", thread_id, port_def->port);
        return -EIO;
    }
    // send the buffer
    send_ret = sendto(sd, bufftosend, sizetosend, 0,
                      (struct sockaddr *)&target_addr, addr_size);

    if (send_ret == -1) {
        log_trace("%s\t sendto unexpected error on port %i, errno: %i, errdesc: %s\n",
                  thread_id, port_def->port, errno, strerror(errno));
        result->response = SCAN_HSTATE_ERROR;
        close(sd);
        return -EIO;
    }

    // request non-blocking response
    recv_ret = recvfrom(sd, recvbuffer, sizeof(recvbuffer),
                        0, (struct sockaddr *)&target_addr, &addr_size);
    //log_trace("%s\t recvfrom returned: %i\n", thread_id, recv_ret);
    if (recv_ret == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
        log_trace("%s\t recvfrom unexpected error on port %i, errno: %i, errdesc: %s\n",
                  thread_id, port_def->port, errno, strerror(errno));
        result->response = SCAN_HSTATE_ERROR;
        close(sd);
        return -EIO;
    }

    // wait for response
    poll_arg.fd = sd;
    poll_arg.events = POLL_IN;

    poll_ret = poll(&poll_arg, 1, scan.opt_connect_timeout_ms);
    /* check poll result and socket state */
    if (poll_ret > 0 && poll_arg.revents & POLL_IN) {
        //poll has data from recvfrom
        result->response = SCAN_HSTATE_LIVE;
        result->host_type = port_def->host_type;
        result->port = port_def->port;
        result->port_open = true;
        result->method = port_def->method;
        result->family = port_def->family;
        result->services = nm_list_add(result->services, strdup(port_def->service));
        log_trace("%s host found, receive from port %hu",
                  thread_id, port_def->port);
    }

    close(sd);
    return 0;
}

bool scan_response_ack(scan_result *result, const uint8_t *in_buffer, ssize_t in_size)
{
    result->response = SCAN_HSTATE_LIVE;
    if (result->port_def) {
        result->services = nm_list_add(result->services, strdup(result->port_def->service));
    }
    return true;
}

bool scan_response_log(scan_result *result, const uint8_t *in_buffer, ssize_t in_size)
{
    result->response = SCAN_HSTATE_LIVE;
    nm_log_trace_bytes("scan_log_response", in_buffer, in_size);
    return true;
}

void scan_process_result(scan_result *result, int *live_counter)
{
    assert(result != NULL);
    assert(live_counter != NULL);
    assert(result->response != SCAN_HSTATE_UNKNOWN);

    nm_host *host;
    //char portbuff[SCAN_PORT_METHOD_BUFFER_LEN];
    char ip[INET6_ADDRSTRLEN];
    inet_ntop(SCAN_FAMILY_TO_AF(result->family), &result->target, ip, sizeof(ip));

    //ignore Dead and show Live and Error only
    if (result->response != SCAN_HSTATE_LIVE) {
        //log_trace("scan_process_result: received non-live result: %i, %s", result->response, ip);
        scan_result_destroy(result);
        return;
    }

    (*live_counter)++;

    host = nm_host_init(result->host_type);
    if (result->family == SCAN_FAMILY_INET6)
        nm_host_set_attributes(host, NULL, ip, NULL, HW_IFACE_NULL, result->hostname);
    else
        nm_host_set_attributes(host, ip, NULL, NULL, HW_IFACE_NULL, result->hostname);

    if (result->services)
        nm_host_add_services(host, result->services);

    if (result->port && result->port_open) {
        nm_host_add_port(host, result->port, scan_method_label[result->method]);
    }

    scan.hosts = nm_host_merge_in_list(scan.hosts, host);
    scan_result_destroy(result);
}


gpointer scan_main_listen_thread(gpointer data)
{
    log_trace("scan_main_listen_thread starting");
    unsigned long start_time = nm_time_ms();


    int num_listen_ports = sizeof(scan_listen_list) / sizeof(scan_listen_list[0]);
    int num_results = 0, num_live = 0;
    int scan_timeout_ms = scan.opt_scan_timeout_ms;
    GThreadPool *thread_pool;
    GAsyncQueue *results_queue;
    GError *error = NULL;

    if (!scan_util_is_running())
        return NULL;
    log_info("scan_main_listen_thread: range of %i ports", num_listen_ports);

    results_queue = g_async_queue_new();
    thread_pool = g_thread_pool_new(scan_listen_thread, results_queue,
                                    scan.opt_listen_threads, false, &error);
    if (error != NULL) {
        log_error("scan_main_listen_thread: error starting threads, %i, %s \n", error->code, error->message);
        g_error_free(error);
        return NULL;
    }

    // push work to the thread pool
    for (int i = 0; i < num_listen_ports; i++) {
        if (!scan_util_is_running())
            break;
        g_thread_pool_push(thread_pool, (gpointer)&scan_listen_list[i], &error);
        if (error != NULL) {
            log_warn("scan_main_listen_thread: error pushing entry %i \n", i);
            g_error_free(error);
        }
    }

    //poll status of received results
    log_trace("scan_main_listen_thread, polling results");
    scan_result *result;
    uint32_t unused_work, running_threads, returned_count;
    for (;;) {
        if (!scan_util_is_running())
            break;

        //check work done by the thread pool
        unused_work = g_thread_pool_unprocessed(thread_pool);
        running_threads = g_thread_pool_get_num_threads(thread_pool);
        if (unused_work == 0 && running_threads == 0)
            break;
        //check if results are pending, process some
        while ((result = g_async_queue_try_pop(results_queue))) {
            scan_process_result(result, &num_live);
            num_results++;
        }
        //log_trace("scan_main_listen_thread, going to sleep: num_results: %i", num_results);
        usleep(scan.opt_poll_thread_work_ms * 1000);
        if (scan_timeout_ms && nm_time_ms_diff(start_time) > scan_timeout_ms) {
            log_debug("scan_main_listen_thread: Subnet scan timeout reached %u ms", scan_timeout_ms);
            scan.running = 0;
            break;
        }
    }
    running_threads = g_thread_pool_get_num_threads(thread_pool);
    log_trace("scan_main_listen_thread, about to free pool: running_threads: %i", running_threads);
    g_thread_pool_free(thread_pool, false, true);

    usleep(scan.opt_poll_thread_work_ms * 1000);
    log_trace("scan_main_listen_thread final queue processing...");
    returned_count = g_async_queue_length(results_queue);
    log_trace("scan_main_listen_thread       queue length: %i", returned_count);
    for (int i = 0; i < returned_count; i++) {
        if (!scan_util_is_running())
            break;
        result = g_async_queue_pop(results_queue);
        scan_process_result(result, &num_live);
        num_results++;
    }

    log_info("scan_main_listen_thread: discovery summary: total ports %i found %i results in %lus",
             num_listen_ports, num_live, nm_time_ms_diff(start_time) / 1000);

    g_async_queue_unref(results_queue);

    //log_trace("scan_main_listen_thread: ending");
    return NULL;
}

void scan_listen_thread(gpointer target_data, gpointer results_data)
{
    int sd, max_wait_time, min_wait_time, bind_ret = 0;
    long int recv_ret, poll_ret, actual_size;
    unsigned long thread_start;
    char threadsign[64];
    char sender_ip[INET6_ADDRSTRLEN];
    char hostname_buffer[NM_HOST_STRLEN];
    char recv_buffer[NM_LARGE_BUFFSIZE];
    char querybuff[1024];
    uint16_t port_num, sender_port;
    struct pollfd poll_arg;
//     struct sockaddr_in recv_addr4;
//     struct sockaddr_in6 recv_addr6;
//     struct sockaddr *recv_addr;
    proto_query *query;
    struct sockaddr_in6 recvaddr;
    socklen_t recv_saddrsize = sizeof(struct sockaddr_in6);

    nmlist *resolved_ip_list = NULL;
    scan_port *port_def;
    scan_result *result;
    GAsyncQueue *results_queue = results_data;

    thread_start = nm_time_ms();
    if (!scan_util_is_running())
        return;

    //prepare results and listen port
    port_def = target_data;
    min_wait_time = port_def->min_time;
    max_wait_time = port_def->max_time;
    port_num = (uint16_t)port_def->port;

    sprintf(threadsign, "[ListTh<%lx>, Port<%u>]", (intptr_t)g_thread_self(), port_num);
    log_trace("%s New thread, family: %i, port: %hu, bindport: %hu",
              threadsign, port_def->family, port_def->port, port_def->bind_port);

    sd = socket(SCAN_FAMILY_TO_AF(port_def->family), SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_IP);
    if (sd < 0) {
        log_info("%s socket errno: %i, errdesc: %s", threadsign, errno, strerror(errno));
        log_debug("%s End listen thread [time: %lu ms]!", threadsign, nm_time_ms_diff(thread_start));
        return;
    }

    //bind if we have a bind_port
    if (port_def->bind_port)
        bind_ret = scan_socket_bind(sd, port_def->family, port_def->bind_port, threadsign);

    if (bind_ret && port_def->bind_fail_confirms) {
        nm_host_add_service(scan.localhost, port_def->service);
        nm_host_add_port(scan.localhost, port_def->bind_port, scan_method_label[port_def->method]);
    }

    //set multicast membership if needed
    if (port_def->mc_join && scan_socket_join_mc(sd, port_def->family, port_def->mc_ip, threadsign)) {
        log_warn("%s socket failed to join multicast errno: %i, errdesc: %s",
                 threadsign, errno, strerror(errno));
    }

    if (port_def->query_cb && port_def->protocol) {
        struct sockaddr_in6 send_addr;
        scan_socket_addr_from_ip((struct sockaddr *)&send_addr, port_def->family, port_def->send_ip, port_def->port);
        scan_socket_log_saddr((struct sockaddr *)&send_addr, threadsign, "send_to");

        query = port_def->protocol->queries;
        while (query->message) {

            size_t msgsize = port_def->query_cb((void *)querybuff, sizeof(querybuff),
                                                query->message, (struct sockaddr *)&send_addr);

            ssize_t bytes_sent = sendto(sd, querybuff, msgsize, 0, (struct sockaddr *)&send_addr, sizeof(send_addr));
            if (bytes_sent < 0) {
                log_debug("%s Could not send probe query, err %i, %s", threadsign, errno, strerror(errno));
                scan_socket_log_saddr((struct sockaddr *)&send_addr, threadsign, "send_to");
            }
            log_trace("%s Sent query with %li bytes", threadsign, bytes_sent);
            query = query + 1;
        }
    }

    if (!scan_util_is_running())
        return;

    poll_arg.events = POLLIN;
    poll_arg.fd = sd;
    log_debug("%s Listening on port %hi", threadsign, port_num);
//     //prepare recv_addr
//     if(port_def->family == SCAN_FAMILY_INET4) {
//         recv_addr = (struct sockaddr*)&recv_addr4;
//         recv_saddrsize = sizeof(struct sockaddr_in);
//     }else if(port_def->family == SCAN_FAMILY_INET6) {
//         recv_addr = (struct sockaddr*)&recv_addr6;
//         recv_saddrsize = sizeof(struct sockaddr_in6);
//     }

    while (nm_time_ms_diff(thread_start) <= max_wait_time) {
        if (!scan_util_is_running())
            break;

        recv_ret = recvfrom(sd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&recvaddr, &recv_saddrsize);
        if (recv_ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            poll_ret = poll(&poll_arg, 1, min_wait_time);
            if (poll_ret >= 0) {
                continue;
            }
        } else if (recv_ret == -1) {
            log_trace("%s recvfrom unexpected error on port %i, errno: %i, errdesc: %s",
                      threadsign, port_num, errno, strerror(errno));
            break;
        }

        //now check the data received
        scan_socket_log_saddr((struct sockaddr *)&recvaddr, threadsign, "recv_from");
        if (recvaddr.sin6_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)&recvaddr)->sin_addr, sender_ip, sizeof(sender_ip));
            sender_port = ntohs(((struct sockaddr_in *)&recvaddr)->sin_port);
//             inet_ntop(recvaddr.sin6_family, (struct sockaddr*)&recvaddr, sender_ip, sizeof(sender_ip));
//             sender_port = recvaddr.sin6_family == AF_INET ?
//                     ntohs(((struct sockaddr_in*)&recvaddr)->sin_port) :
//                     ntohs(recvaddr.sin6_port);
        } else {
            inet_ntop(AF_INET6, &recvaddr.sin6_addr, sender_ip, sizeof(sender_ip));
            sender_port = ntohs(recvaddr.sin6_port);
        }
//         if(port_def->family == SCAN_FAMILY_INET6){
//             inet_ntop(AF_INET6, &recv_addr6.sin6_addr, sender_ip, sizeof(sender_ip));
//             sender_port = ntohs(recv_addr6.sin6_port);
//         }else if(port_def->family == SCAN_FAMILY_INET4){
//             inet_ntop(AF_INET, &recv_addr4.sin_addr, sender_ip, sizeof(sender_ip));
//             sender_port = ntohs(recv_addr4.sin_port);
//         }else{
//             log_debug("%s data from unknown address type address size %zi",
//                   threadsign, recv_saddrsize);
//         }

        actual_size = recv_ret < sizeof(recv_buffer) ? recv_ret : (long)sizeof(recv_buffer);
        log_trace("%s data on port %i, size %li from [%s]:%hu",
                  threadsign, port_num, actual_size, sender_ip, sender_port);

        result = malloc(sizeof(scan_result));
        memset(result, 0, sizeof(scan_result));
        result->response = SCAN_HSTATE_LIVE;
        result->host_type = port_def->host_type;
        result->port = port_def->port;
        result->method = port_def->method;
        result->family = port_def->family;
        result->port_def = port_def;
        if (port_def->family == SCAN_FAMILY_INET6)
            result->target.inaddr6 = recvaddr.sin6_addr;
        else
            result->target.inaddr = ((struct sockaddr_in *)&recvaddr)->sin_addr;
//         if(port_def->family == SCAN_FAMILY_INET6)
//             result->target.inaddr6 = recv_addr6.sin6_addr;
//         else
//             result->target.inaddr = recv_addr4.sin_addr;
        //result->target_addr = recv_addr.sin_addr;
        //result->target.inaddr = recv_addr.sin_addr;
        //result->target.inaddr = recv_addr.sin_addr;

//         //resolve hostname if it's not yet, else leave it empty
//         if(!scan.opt_skip_resolve &&
//             nm_table_get_num(response_ip_hostname, result->target_addr.s_addr) == NULL) {
//
//             scan_resolve_hostname_from_inaddr(result->target_addr.s_addr,
//                                                 hostname_buffer, sizeof(hostname_buffer));
//             result->hostname = strdup(hostname_buffer);
//             nm_table_set_num(response_ip_hostname, result->target_addr.s_addr, result->hostname);
//         }
        //resolve hostname if it's not yet, else leave it empty
        if (!scan.opt_skip_resolve && !nm_list_find_string(resolved_ip_list, sender_ip)) {
            //TODO: review hostname resolves and comeback
            scan_resolve_saddr_hostname((struct sockaddr *)&recvaddr, port_def->family,
                                        hostname_buffer, sizeof(hostname_buffer));
            //scan_resolve_hostname_from_inaddr(result->target.inaddr.s_addr,
            //                                    hostname_buffer, sizeof(hostname_buffer));
            result->hostname = strdup(hostname_buffer);
            resolved_ip_list = nm_list_add(resolved_ip_list, strdup(sender_ip));
        }
        //port-specific response processing
        if (port_def->response_cb != NULL) {
            log_trace("%s Executing response callback", threadsign);
            if (!(port_def->response_cb)(result, (uint8_t *)recv_buffer, actual_size))
                log_trace("%s Error with response callback", threadsign);
            else
                result->port_open = true;
        }

        g_async_queue_push(results_queue, result);
    }

    g_mutex_lock(&scan_stat_lock);
    scan.stat_list_ports++;
    g_mutex_unlock(&scan_stat_lock);

    nm_list_free(resolved_ip_list, true);

    //nm_table_free(response_ip_hostname);
    log_debug("%s End listen thread [time: %lu ms]!", threadsign, nm_time_ms_diff(thread_start));
}

gpointer scan_main_connect_thread(gpointer data)
{
    log_trace("scan_main_connect_thread: starting");
    unsigned long start_time = nm_time_ms();

    uint32_t curr_addr, curr_num;
    int num_results = 0, num_live = 0;
    int scan_timeout_ms = scan.opt_scan_timeout_ms;

    GThreadPool *thread_pool;
    GAsyncQueue *results_queue;
    GError *error = NULL;

    if (!scan_util_is_running())
        return NULL;

    if (scan.localhost == NULL || scan.localhost->type != HOST_TYPE_LOCALHOST) {
        log_info("scan_main_connect_thread: Error localhost was not resolved");
        return NULL;
    }

    nm_host *localhost = scan.localhost;
    scan_range range;
    char start_ip[INET_ADDRSTRLEN];
    char end_ip[INET_ADDRSTRLEN];
    if (!scan_util_calc_subnet_range(localhost->ip, localhost->netmask, &range)) {
        return NULL;
    }

    inet_ntop(AF_INET, &range.start_addr, start_ip, sizeof(start_ip));
    inet_ntop(AF_INET, &range.stop_addr, end_ip, sizeof(end_ip));
    int ports_to_scan = sizeof(scan_port_list) / sizeof(scan_port_list[0]);
    int time_per_host = ports_to_scan * scan.opt_connect_timeout_ms;
    int full_scan_time = time_per_host * (range.length / scan.opt_connect_threads);
    log_info("scan_main_connect_thread: range of %i hosts: [%s to %s] and %i ports",
             range.length, start_ip, end_ip, ports_to_scan);
    log_info("scan_main_connect_thread: thread timeout of %i(ms) requires max %i(s) using %i threads",
             scan.opt_connect_timeout_ms, full_scan_time / 1000, scan.opt_connect_threads);


    results_queue = g_async_queue_new();
    thread_pool = g_thread_pool_new(scan_connect_thread, results_queue,
                                    scan.opt_connect_threads, false, &error);
    if (error != NULL) {
        log_error("scan_main_connect_thread: error starting threads, %i, %s", error->code, error->message);
        g_error_free(error);
        return NULL;
    }

    // push work to the thread pool
    for (curr_num = range.start_num; curr_num <= range.stop_num; curr_num++) {
        if (!scan_util_is_running())
            break;

        curr_addr = ntohl(curr_num);

        g_thread_pool_push(thread_pool, (gpointer)(intptr_t)curr_addr, &error);
        if (error != NULL) {
            log_warn("scan_main_connect_thread: error pushing entry %u", curr_num);
            g_error_free(error);
        }
    }

    //poll status of received results
    scan_result *result;
    uint32_t unused_work, running_threads, returned_count;
    for (;;) {
        if (!scan_util_is_running())
            break;

        //check work done by the thread pool
        unused_work = g_thread_pool_unprocessed(thread_pool);
        running_threads = g_thread_pool_get_num_threads(thread_pool);
        if (unused_work == 0 && running_threads == 0)
            break;
        //check if results are pending, process some
        while ((result = g_async_queue_try_pop(results_queue))) {
            scan_process_result(result, &num_live);
            num_results++;
        }
        usleep(scan.opt_poll_thread_work_ms * 1000);
        if (scan_timeout_ms && nm_time_ms_diff(start_time) > scan_timeout_ms) {
            scan.running = 0;
            log_info("scan_main_connect_thread: Subnet scan timeout reached %u ms", scan_timeout_ms);
            break;
        }
    }

    unused_work = g_thread_pool_unprocessed(thread_pool);
    running_threads = g_thread_pool_get_num_threads(thread_pool);
    g_thread_pool_free(thread_pool, true, true);

    while ((result = g_async_queue_try_pop(results_queue))) {
        scan_process_result(result, &num_live);
        num_results++;
    }
//     returned_count = g_async_queue_length(results_queue);
//     for(int i=0; i<returned_count; i++){
//         if(!scan_util_is_running())
//             break;
//         result = g_async_queue_pop(results_queue);
//         scan_process_result(result, &num_live);
//         num_results++;
//     }

    log_info("Connect Summary: total targets %i, " \
             "%i results from %i hosts with %i found live in %lus]",
             range.length, num_results, scan.stat_conn_hosts, num_live, nm_time_ms_diff(start_time) / 1000);

    g_async_queue_unref(results_queue);

    //log_trace("scan_main_connect_thread: ending");
    return NULL;
}


void scan_connect_thread(gpointer target_data, gpointer results_data)
{
    int port_index, ports_to_scan, ret = 0;
    char thread_id[64];
    char hostname_buffer[NM_HOST_STRLEN];
    char ipbuff[INET_ADDRSTRLEN];
    struct in_addr ip_addr;
    scan_port port_def;
    scan_result *result = NULL;
    enum scan_host_state host_state = SCAN_HSTATE_UNKNOWN;
    GAsyncQueue *results_queue = results_data;

    if (!scan_util_is_running())
        return;

    //time this thread
    long unsigned thread_start = nm_time_ms();
    //target data and thread id
    ip_addr.s_addr = (uint32_t)(intptr_t)target_data;
    inet_ntop(AF_INET, &ip_addr, ipbuff, sizeof(ipbuff));

    sprintf(thread_id, "[ConnTh<%lx>, IP<%s>]", (intptr_t)g_thread_self(), ipbuff);


    //prepare connect_ports and address
    ports_to_scan = sizeof(scan_port_list) / sizeof(scan_port_list[0]);

    log_trace("%s Starting scan for %i ports", thread_id, ports_to_scan);
    port_index = 0;
    for (; port_index < ports_to_scan; port_index++) {
        if (!scan_util_is_running())
            break;

        port_def = scan_port_list[port_index];
        //check host state
        if (host_state == SCAN_HSTATE_LIVE && port_def.required == 0 &&
                !scan.opt_scan_all)
            continue;

        //prepare result structure and queue
        if (!result) {
            result = malloc(sizeof(scan_result));
            memset(result, 0, sizeof(scan_result));
        }
        //result->target_addr = ip_addr;
        result->target.inaddr = ip_addr;
        result->response = SCAN_HSTATE_UNKNOWN;
        result->port = port_def.port;
        result->method = port_def.method;
        result->family = port_def.family;

        if (port_def.method == SCAN_TCP_CONNECT)
            ret = probe_connect_tcp(thread_id, result, &port_def, &ip_addr);
        else if (port_def.method == SCAN_UDP_SENDRECV)
            ret = probe_sendrecv_udp(thread_id, result, &port_def, &ip_addr);

        if (ret)
            break;

        if (result->response == SCAN_HSTATE_LIVE && host_state == SCAN_HSTATE_UNKNOWN) {
            host_state = SCAN_HSTATE_LIVE;
            log_debug("%s Marking host %s Live", thread_id, ipbuff);
            if (!scan.opt_skip_resolve &&
                    scan_resolve_hostname_new(result->family, ipbuff, hostname_buffer, sizeof(hostname_buffer)))
                result->hostname = strdup(hostname_buffer);
        }

        if (result->response == SCAN_HSTATE_LIVE) {
            g_async_queue_push(results_queue, result);
            result = NULL;
        }
    }

    if (port_index >= 0 && host_state != SCAN_HSTATE_LIVE) {
        //log_trace("%s host dead, ", thread_id);
        log_debug("%s Marking host %s dead", thread_id, ipbuff);
        host_state = SCAN_HSTATE_DEAD;
        if (!result) {
            result = malloc(sizeof(scan_result));
            memset(result, 0, sizeof(scan_result));
        }
        result->response = SCAN_HSTATE_DEAD;
        //result->target_addr = ip_addr;
        result->target.inaddr = ip_addr;
        result->port = port_def.port;
        result->method = port_def.method;
        result->family = port_def.family;
        g_async_queue_push(results_queue, result);
    }

    g_mutex_lock(&scan_stat_lock);
    scan.stat_conn_hosts++;
    g_mutex_unlock(&scan_stat_lock);

    log_trace("%s End scan thread [time: %lu ms]!", thread_id, nm_time_ms_diff(thread_start));
}

bool scan_discover_subnet(int connect, int listen)
{
    log_trace("scan_discover_subnet_hosts starting, connect: %i, listen: %i",
              connect, listen);

    if (!connect && !listen)
        return false;

    GThread *conn_thread, *list_thread;
    GError *conn_err = NULL, *list_err = NULL;

    if (connect) {
        conn_thread = g_thread_try_new("ConnectMainThread", scan_main_connect_thread, NULL, &conn_err);
        if (conn_err != NULL)
            log_error("Error starting the main connect thread, code %i, %s", conn_err->code, conn_err->message);
    }
    if (listen) {
        list_thread = g_thread_try_new("ListenMainThread", scan_main_listen_thread, NULL, &list_err);
        if (list_err != NULL)
            log_error("Error starting the main listen thread, code %i, %s", list_err->code, list_err->message);
    }

    //wait for all the scans to end
    log_trace("scan_discover_subnet_hosts: start waiting for connect");
    if (connect)
        g_thread_join(conn_thread);

    log_trace("scan_discover_subnet_hosts: start waiting for listen");
    if (listen)
        g_thread_join(list_thread);

    log_trace("scan_discover_subnet_hosts ending");
    return true;

}


int scan_list_arp_hosts()
{
    log_trace("scan_list_arp_hosts: called");

    FILE *arp_fd;
    nm_host *entry;

    char line[NM_GEN_BUFFSIZE];
    char ip_buffer[INET_ADDRSTRLEN];
    char host_buffer[NM_HOST_STRLEN];
    char hw_addr[NM_HWADDR_STRLEN];
    char hw_vendor[NM_SMALL_BUFFSIZE];
    int num_tokens, type, flags, num_lines, num_found = 0;

    hw_details hw_if;
    hw_if.addr = hw_addr;
    hw_if.vendor = hw_vendor;

    if ((arp_fd = fopen("/proc/net/arp", "r")) == NULL) {
        perror("Error opening arp table");
        return 0;
    }
    // ignore header
    if (fgets(line, sizeof(line), arp_fd) == NULL) {
        perror("Nothing in arp table files");
        return 0;
    }

    for (num_lines = 0; fgets(line, sizeof(line), arp_fd); num_lines++) {
        memset(hw_addr, 0, sizeof(hw_addr));
        memset(hw_vendor, 0, sizeof(hw_vendor));

        num_tokens = sscanf(line, "%s 0x%x 0x%x %17s %*99s* %*99s\n", ip_buffer, &type, &flags, hw_addr);
        if (num_tokens < 4)
            break;
        //line
        if (!nm_validate_hw_address(hw_addr, 1))
            continue;

        if (!scan.opt_skip_resolve) {
            nm_update_hw_vendor(hw_vendor, sizeof(hw_vendor), hw_addr);
            if (strlen(hw_vendor))
                hw_if.vendor = hw_vendor;
            else
                hw_if.vendor = NULL;
        }

        entry = nm_host_init(HOST_TYPE_KNOWN);
        //entry->ip_addr = inet_addr(ip_buffer);
        if (!scan.opt_skip_resolve &&
                scan_resolve_hostname_new(SCAN_FAMILY_INET4, ip_buffer, host_buffer, sizeof(host_buffer)))
            nm_host_set_attributes(entry, ip_buffer, NULL, NULL, hw_if, host_buffer);
        else
            nm_host_set_attributes(entry, ip_buffer, NULL, NULL, hw_if, NULL);

        nm_host_add_port(entry, 0, "arpcache");
        scan.hosts = nm_host_merge_in_list(scan.hosts, entry);
        num_found++;
    }
    fclose(arp_fd);

    log_trace("scan_list_arp_hosts: ending");
    return num_found;
}


int scan_list_gateways()
{
    log_trace("scan_list_gateways: called");

    int num_ip4_found = 0, num_ip6_found = 0, tokens;
    char line[NM_GEN_BUFFSIZE];
    char ip[INET_ADDRSTRLEN];
    char ip6[INET6_ADDRSTRLEN];
    char host_buffer[NM_HOST_STRLEN];
    char iface[64], *token;
    FILE *fp;
    nm_host *gw_host, *gw_host6;
    struct in_addr dest, gateway;
    struct in6_addr gateway6;

    /* read IPv4 route file first */
    if ((fp = fopen("/proc/net/route", "r")) == NULL) {
        log_error("Error opening route table");
        return 0;
    }
    // found a header?
    if (fgets(line, sizeof(line), fp) != NULL) {
        for (; fgets(line, sizeof(line), fp);) {
            tokens = sscanf(line, "%s %X %X %*i %*i %*i %*i %*x %*i %*i %*i \n",
                            iface, &dest.s_addr, &gateway.s_addr);
            if (tokens < 3)
                break;
            if (dest.s_addr == 0 && gateway.s_addr != 0) {
                gw_host = nm_host_init(HOST_TYPE_ROUTER);
                inet_ntop(AF_INET, &gateway.s_addr, ip, sizeof(ip));
                if (!scan.opt_skip_resolve &&
                        scan_resolve_hostname_new(SCAN_FAMILY_INET4, ip, host_buffer, sizeof(host_buffer)))
                    nm_host_set_attributes(gw_host, ip, NULL, NULL, HW_IFACE_NULL, host_buffer);
                else
                    nm_host_set_attributes(gw_host, ip, NULL, NULL, HW_IFACE_NULL, NULL);

                nm_host_add_port(gw_host, 0, "route");
                scan.hosts = nm_host_merge_in_list(scan.hosts, gw_host);
                num_ip4_found++;
            }
        }
    }
    fclose(fp);

    /* read IPv6 route file next */
    if ((fp = fopen("/proc/net/ipv6_route", "r")) == NULL) {
        log_warn("Error opening ipv6_route table");
        return num_ip4_found;
    }
    //no header, lines directly
    for (; fgets(line, sizeof(line), fp);) {
        token = nm_string_extract_token(line, ' ', 4);
        if (strlen(token) < 32)
            continue;

        for (int i = 0; i < 16; i++) {
            sscanf(&token[i * 2], "%2hhx", &gateway6.__in6_u.__u6_addr8[i]);
        }

        if (gateway6.__in6_u.__u6_addr32[0] != 0 || gateway6.__in6_u.__u6_addr32[1] != 0 ||
                gateway6.__in6_u.__u6_addr32[2] != 0 || gateway6.__in6_u.__u6_addr32[3] != 0) {

            gw_host6 = nm_host_init(HOST_TYPE_ROUTER);
            inet_ntop(AF_INET6, &gateway6.__in6_u, ip6, sizeof(ip6));
            // log_trace("Printing IPv6 %s", ip6_buffer);

            if (!scan.opt_skip_resolve &&
                    scan_resolve_hostname_new(SCAN_FAMILY_INET6, ip6, host_buffer, sizeof(host_buffer)))
                nm_host_set_attributes(gw_host6, NULL, ip6, NULL, HW_IFACE_NULL, host_buffer);
            else
                nm_host_set_attributes(gw_host6, NULL, ip6, NULL, HW_IFACE_NULL, NULL);

            nm_host_add_port(gw_host6, 0, "route6");
            scan.hosts = nm_host_merge_in_list(scan.hosts, gw_host6);

            num_ip6_found++;
        }
    }
    fclose(fp);

    log_trace("scan_list_gateways: ending with ip4: %i, ip6: %i", num_ip4_found, num_ip6_found);
    return num_ip4_found + num_ip6_found;
}


int scan_list_neighbours()
{
    log_trace("scan_list_neighbours: called");

    char recvbuff[1024 * 64];
    struct msghdr recv_hdr;
    struct iovec iodata;
    unsigned int nmseq = 0xFF1234;
    struct scan_nlrt_request rtrequest;
    struct nlmsghdr *nh;
    struct ndmsg *recvdata;
    struct rtattr *rta;

    nm_host *entry;
    enum scan_family family;
    char ip_buffer[INET6_ADDRSTRLEN];
    char host_buffer[NM_HOST_STRLEN];
    char hw_addr[NM_HWADDR_STRLEN];
    char hw_vendor[NM_SMALL_BUFFSIZE];
    hw_details hw_if;
    hw_if.addr = hw_addr;
    hw_if.vendor = hw_vendor;
    int num_found = 0;


    int sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sd == -1) {
        log_warn("Neighbours: netlink socket errno: %i, errdesc: %s", errno, strerror(errno));
        return 0;
    }

    memset(&rtrequest, 0, sizeof(rtrequest));
    rtrequest.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    rtrequest.header.nlmsg_type = RTM_GETNEIGH;
    rtrequest.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    rtrequest.header.nlmsg_seq = nmseq;

    int sendret = sendto(sd, &rtrequest, sizeof(rtrequest), 0, 0, 0);
    if (sendret <= 0) {
        log_warn("Neighbours: netlink send errno: %i, errdesc: %s", errno, strerror(errno));
        close(sd);
        return 0;
    }

    memset(&recv_hdr, 0, sizeof(struct msghdr));
    memset(&iodata, 0, sizeof(struct iovec));
    iodata.iov_base = &recvbuff;
    iodata.iov_len = sizeof(recvbuff);
    recv_hdr.msg_iov = &iodata;
    recv_hdr.msg_iovlen = 1;

    int recvret = recvmsg(sd, &recv_hdr, MSG_WAITALL);
    if (recvret <= 0) {
        log_warn("Neighbours: netlink recv errno: %i, errdesc: %s", errno, strerror(errno));
        close(sd);
        return 0;
    }


    struct rtattr *attr;
    ssize_t ndsize, attrsize, attrvalsize;

    for (nh = (struct nlmsghdr *)recvbuff; NLMSG_OK(nh, recvret); nh = NLMSG_NEXT(nh, recvret)) {

        if (nh->nlmsg_seq != nmseq) {
            log_error("Neighbours: received wrong data, won't try again, refresh.");
            break;
        }
        if (nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR)
            break;
        if (nh->nlmsg_type != RTM_NEWNEIGH)
            continue;

        recvdata = NLMSG_DATA(nh);
        if (recvdata->ndm_type != RTN_UNICAST)
            continue;

        memset(ip_buffer, 0, sizeof(ip_buffer));
        memset(host_buffer, 0, sizeof(host_buffer));
        memset(hw_addr, 0, sizeof(hw_addr));
        memset(hw_vendor, 0, sizeof(hw_vendor));

        ndsize = NLMSG_PAYLOAD(nh, 0);
        attrsize = ndsize - sizeof(recvdata);
        rta = ((struct rtattr *)(((char *)(recvdata)) + NLMSG_ALIGN(sizeof(struct ndmsg))));
        for (; RTA_OK(rta, attrsize); rta = RTA_NEXT(rta, attrsize)) {

            if (rta->rta_type != NDA_DST && rta->rta_type != NDA_LLADDR)
                continue;

            attrvalsize = RTA_PAYLOAD(rta);
            if (rta->rta_type == NDA_DST) {
                if (recvdata->ndm_family == AF_INET6 && attrvalsize == sizeof(struct in6_addr)) {
                    family = SCAN_FAMILY_INET6;
                    inet_ntop(AF_INET6, RTA_DATA(rta), ip_buffer, sizeof(ip_buffer));
                    if (!scan.opt_skip_resolve)
                        scan_resolve_hostname_new(SCAN_FAMILY_INET6, ip_buffer, host_buffer, sizeof(host_buffer));
                } else if (recvdata->ndm_family == AF_INET && attrvalsize == sizeof(struct in_addr)) {
                    family = SCAN_FAMILY_INET4;
                    inet_ntop(AF_INET, RTA_DATA(rta), ip_buffer, sizeof(ip_buffer));
                    if (!scan.opt_skip_resolve)
                        scan_resolve_hostname_new(SCAN_FAMILY_INET4, ip_buffer, host_buffer, sizeof(host_buffer));
                }
            } else if (rta->rta_type == NDA_LLADDR && attrvalsize == 6) {
                nm_format_hw_address_direct(hw_addr, RTA_DATA(rta));
            }
        }

        if (!strlen(ip_buffer) || !nm_validate_hw_address(hw_addr, true)) {
            log_trace("scan_list_neighbours: skipping host with possible invalid ip/hw");
            continue;
        }

        if (!scan.opt_skip_resolve) {
            nm_update_hw_vendor(hw_vendor, sizeof(hw_vendor), hw_addr);
            if (strlen(hw_vendor))
                hw_if.vendor = hw_vendor;
            else
                hw_if.vendor = NULL;
        }

        entry = nm_host_init(HOST_TYPE_KNOWN);
        if (family == SCAN_FAMILY_INET6)
            nm_host_set_attributes(entry, NULL, ip_buffer, NULL, hw_if, host_buffer);
        else
            nm_host_set_attributes(entry, ip_buffer, NULL, NULL, hw_if, host_buffer);
        nm_host_add_port(entry, 0, "neighbour");
        //nm_host_add_service(entry, "NEIGHBOR");

        scan.hosts = nm_host_merge_in_list(scan.hosts, entry);
        num_found++;

    }

    close(sd);

    log_trace("scan_list_neighbours: ending");
    return num_found;
}

bool scan_list_localhost()
{
    int family;
    struct ifaddrs *if_addr, *ifa;
    char ip[INET_ADDRSTRLEN];
    char ip6[INET6_ADDRSTRLEN];
    char host_buff[NM_HOST_STRLEN];
    char netmask[INET_ADDRSTRLEN];
    //hwaddr and vendor allow multiple interfaces for localhost
    char hwaddr_buffer[NM_MID_BUFFSIZE];
    char hwvendor_buffer[NM_MID_BUFFSIZE];
    hw_details hw_if = {hwaddr_buffer, hwvendor_buffer};

    assert(scan.localhost == NULL);
    scan.localhost = nm_host_init(HOST_TYPE_LOCALHOST);

    if (getifaddrs(&if_addr) == -1) {
        log_error("Could not get getifaddrs");
        return false;
    }
    for (ifa = if_addr; ifa != NULL; ifa = ifa->ifa_next) {
        memset(hwaddr_buffer, 0, sizeof(hwaddr_buffer));
        memset(hwvendor_buffer, 0, sizeof(hwvendor_buffer));

        //skip loopback and anything not connected (e.g cable)
        if (ifa->ifa_addr == NULL || (ifa->ifa_flags & IFF_LOOPBACK) ||
                !(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_RUNNING)) {
            continue;
        }
        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            //scan.localhost->ip_addr = ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr.s_addr;
            inet_ntop(AF_INET, &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr, ip, sizeof(ip));

            //update ip and hostname, where hostname is host or ip, whichever we have
            if (!scan.opt_skip_resolve &&
                    scan_resolve_hostname_new(SCAN_FAMILY_INET4, ip, host_buff, sizeof(host_buff)))
                nm_host_set_attributes(scan.localhost, ip, NULL, NULL, HW_IFACE_NULL, host_buff);
            else
                nm_host_set_attributes(scan.localhost, ip, NULL, NULL, HW_IFACE_NULL, NULL);

            if (ifa->ifa_netmask != NULL) {
                struct sockaddr_in *nmv = (struct sockaddr_in *)ifa->ifa_netmask;
                inet_ntop(AF_INET, &nmv->sin_addr, netmask, sizeof(netmask));
                nm_host_set_attributes(scan.localhost, NULL, NULL, netmask, HW_IFACE_NULL, NULL);
            }

        } else if (family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr, ip6, sizeof(ip6));
            nm_host_set_attributes(scan.localhost, NULL, ip6, NULL, HW_IFACE_NULL, NULL);
        } else if (family == AF_PACKET) {
            nm_format_hw_address(hwaddr_buffer, sizeof(hwaddr_buffer), (struct sockaddr_ll *) ifa->ifa_addr);
            if (!scan.opt_skip_resolve)
                nm_update_hw_vendor(hwvendor_buffer, sizeof(hwvendor_buffer), hwaddr_buffer);
            nm_host_set_attributes(scan.localhost, NULL, NULL, NULL, hw_if, NULL);
        }
    }
    freeifaddrs(if_addr);

    scan.hosts = nm_host_merge_in_list(scan.hosts, scan.localhost);

    return true;

}

void scan_clear()
{
    if (scan.hosts) {
        nm_list_foreach(host, scan.hosts)
        nm_host_destroy(host->data);
        nm_list_free(scan.hosts, false);
        scan.hosts = NULL;
    }
    if (scan.localhost)
        scan.localhost = NULL;

    g_mutex_clear(&scan_stat_lock);
    g_mutex_clear(&scan_run_lock);
    scan.stat_list_ports = 0;
    scan.stat_conn_hosts = 0;
}


void scan_start()
{
    log_trace("scan_start: called");
    assert(scan.init == 1);

    if (scan_util_is_running()) {
        puts("scan_start: already running");
        return;
    }
    scan.running = 1;
    unsigned long starttime = nm_time_ms();

    scan_clear();

    if (!scan_list_localhost())
        log_error("Could not resolve localhost address details");

    if (!scan.opt_scan_only) {
        int neighbours_found = scan_list_neighbours();
        log_info("Neighbour entries found: %d", neighbours_found);
        int routers_found = scan_list_gateways();
        log_info("Router entries found: %d", routers_found);
        int arps_found = scan_list_arp_hosts();
        log_info("ARP entries found: %d", arps_found);
    }

    if (scan.opt_print && (scan.opt_known_first || scan.opt_known_only)) {
        printf("%sKnown Lists:%s\n", nm_clr_title, nm_clr_off);
        scan_print_mates(scan.hosts, false);
        if (scan.opt_known_only)
            return;
    }

    if (!scan.opt_known_only) {
        printf("%sStarting scan%s, timeout %.1fs\n", nm_clr_title, nm_clr_off, (float)scan.opt_scan_timeout_ms / 1000);

        scan_discover_subnet(scan.opt_connect_threads > 0, scan.opt_listen_threads > 0);
        //refresh ARP tables
        int arps_found = scan_list_arp_hosts();
        log_info("Updated ARP entries found: %d", arps_found);
        scan.hosts = nm_host_sort_list(scan.hosts);
        if (scan.opt_print) {
            printf("%sResults:%s\n", nm_clr_title, nm_clr_off);
            scan_print_mates(scan.hosts, true);
        }
    }

    scan.running = 0;
    if (scan.opt_print) {
        printf("%sScan done in %.1fs with %i hosts found.%s (%i hosts scanned, %i ports listened)\n",
               nm_clr_title, nm_time_ms_diff(starttime) / 1000.0f,  nm_list_len(scan.hosts),
               nm_clr_off, scan.stat_conn_hosts, scan.stat_list_ports);

    }
}

void scan_stop()
{
    if (scan.running)
        scan.running = false;
}

void scan_init()
{
    if (scan.init)
        return;

    if (!scan.opt_skip_resolve)
        vendor_db_init();
    scan.running = 0;
    scan.init = 1;

    log_debug("Scan initialised with options: ");
    log_debug("  print_stdout:  %i", scan.opt_print);
    log_debug("  skip_resolve:  %i", scan.opt_skip_resolve);
    log_debug("  known_first:   %i", scan.opt_known_first);
    log_debug("  known_only:    %i", scan.opt_known_only);
    log_debug("  scan_only:     %i", scan.opt_scan_only);
    log_debug("  scan_all:      %i", scan.opt_scan_all);
    log_debug("  scan_timeout:  %i (ms)", scan.opt_scan_timeout_ms);
    log_debug("  conn_thread:   %i", scan.opt_connect_threads);
    log_debug("  conn_timeout:  %i (ms)", scan.opt_connect_timeout_ms);
    log_debug("  list_thread:   %i", scan.opt_listen_threads);
    log_debug("  max_hosts:     %i", scan.opt_max_hosts);
    log_debug("  subnet_offset: %i", scan.opt_subnet_offset);

}

void scan_destroy(void)
{
    if (!scan.init)
        return;

    scan.running = 0;
    vendor_db_destroy();

    nm_list_foreach(host, scan.hosts)
    nm_host_destroy(host->data);
    nm_list_free(scan.hosts, false);

    scan.init = 0;
}

scan_state *scan_getstate()
{
    return &scan;
}
