#include "nm-scan.h"
#include "nm-common.h"

static scan_state scan = {
        .init = 0,
        .running = 0,
        .quit_now = 0,
        .opt_print = 0,
        .opt_print_known_first = 0,
        .opt_scan_known_only = 0,
        .opt_skip_resolve = 0,
        .opt_connect_threads = 50,
        .opt_connect_timeout_ms = 500,
        .opt_listen_threads = 10,
        .opt_subnet_timeout_ms = 10000,
        .opt_poll_thread_work_us = 10000,
        .opt_max_hosts = 0,
        .opt_subnet_offset = 0,
        .event_cb = NULL,
        .hosts = 0,
        .localhost = 0
};

// // 5357/tcp open  wsdapi
// // 137/udp open  netbios-ns
// 5040/tcp open  unknown
// 5357/tcp open  wsdapi
// 5948/tcp open  unknown
// 7680/tcp open  pando-pub

#define UDP_QUERY_DNS "\x71\x80\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x08\x61\x6f\x75" \
"\x72\x67\x61\x74\x65\x03\x6c\x61\x6e\x00\x00\x01\x00\x01\x00\x00" \
"\x29\x02\x00\x00\x00\x00\x00\x00\x00"


#define UDP_QUERY_NBS "\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21" \
"\x00\x01"

static const scan_port scan_port_list[] = {
    {.port = 80, .service = "http", .protocol = SCAN_PROTO_TCP, .required = 1,
        .device_type = HOST_TYPE_PC},
    {.port = 443, .service = "https", .protocol = SCAN_PROTO_TCP, .required = 1,
        .device_type = HOST_TYPE_PC},
    {.port = 8000, .service = "http-8000", .protocol = SCAN_PROTO_TCP, .required = 1,
        .device_type = HOST_TYPE_PC},
    {.port = 8080, .service = "http-8080", .protocol = SCAN_PROTO_TCP, .required = 1,
        .device_type = HOST_TYPE_PC},
    {.port = 1080, .service = "http-1080", .protocol = SCAN_PROTO_TCP, .required = 1,
        .device_type = HOST_TYPE_PC},
    {.port = 8888, .service = "http-8888", .protocol = SCAN_PROTO_TCP, .required = 1,
        .device_type = HOST_TYPE_PC},
    {.port = 137, .service = "nbs", .protocol = SCAN_PROTO_UDP, .required = 1,
        .device_type = HOST_TYPE_PC, .query_payload = {sizeof(UDP_QUERY_NBS), UDP_QUERY_NBS} },
    {.port = 445, .service = "smb", .protocol = SCAN_PROTO_TCP, .required = 1,
        .device_type = HOST_TYPE_PC},
    {.port = 53, .service = "dns", .protocol = SCAN_PROTO_UDP, .required = 1,
        .device_type = HOST_TYPE_ROUTER, .query_payload = {sizeof(UDP_QUERY_DNS), UDP_QUERY_DNS} },
    {.port = 62078, .service = "itunes", .protocol = SCAN_PROTO_TCP, .required = 1,
        .device_type = HOST_TYPE_PHONE},
    {.port = 60000, .service = "amazon", .protocol = SCAN_PROTO_TCP, .required = 1,
        .device_type = HOST_TYPE_SMART_TV},
    {.port = 22, .service = "ssh", .protocol = SCAN_PROTO_TCP, .required = 1,
        .device_type = HOST_TYPE_PC},
    {.port = 6668, .service = "tuya", .protocol = SCAN_PROTO_TCP, .required = 0,
        .device_type = HOST_TYPE_SMART_DEVICE},
    {.port = 5353, .service = "mdns", .protocol = SCAN_PROTO_TCP, .required = 0,
        .device_type = HOST_TYPE_PC},
    {.port = 5357, .service = "wsd", .protocol = SCAN_PROTO_TCP, .required = 0,
        .device_type = HOST_TYPE_PC_WIN},
    {.port = 5040, .service = "?", .protocol = SCAN_PROTO_TCP, .required = 0,
        .device_type = HOST_TYPE_PC},
    {.port = 5948, .service = "?", .protocol = SCAN_PROTO_TCP, .required = 0, 
        .device_type = HOST_TYPE_PC},
    {.port = 7680, .service = "?", .protocol = SCAN_PROTO_TCP, .required = 0,
        .device_type = HOST_TYPE_PC},
};


static const scan_listen_port scan_listen_list[] = {
        {.port.port = 1900, .port.service = "ssdp", .port.required = 1,
                .port.device_type = HOST_TYPE_UNKNOWN, //TODO: Fix me after checking SSDP
                .min_time = 5000, .max_time = 30000, .bind_port = 0,
                .mc_join = 1, .mc_ip = "239.255.255.250",
                .query_cb = scan_proto_ssdp_query, .response_cb = scan_proto_ssdp_response},
/*        {.port.port = 6667, .port.service = "tuya", .port.required = 1,
                .port.device_type = HOST_TYPE_SMART_DEVICE,
                .min_time = 5000, .max_time = 25000, .bind_port = 6667},
        {.port.port = 5353, .port.service = "mdns", .port.required = 1,
                .port.device_type = HOST_TYPE_UNKNOWN, //TODO: Fix me after checking SSDP
                .min_time = 5000, .max_time = 5000, .bind_port = 0,
                .mc_join = 1, .mc_ip = "224.0.0.251",
                .query_cb = scan_proto_mdns_query, .response_cb = scan_proto_mdns_response}
*/
};


struct proto_sdp {
    char *send_ip;
    char *query_message;
    char *header_start_search;
    char *header_start_notify;
    char *header_start_response;
    char *key_notify_type;
    char *key_search_type;
} proto_ssdp = {
        .send_ip = "239.255.255.250",
        .query_message = "M-SEARCH * HTTP/1.1\r\n"
                         "HOST: 239.255.255.250:1900\r\n"
                         "MAN: \"ssdp:discover\"\r\n"
                         "MX: 1\r\n"
                         "ST: ssdp:all\r\n\r\n",
        .header_start_search = "M-SEARCH * HTTP/1.1",
        .header_start_notify = "NOTIFY * HTTP/1.1",
        .header_start_response = "HTTP/1.1 200 OK",
        .key_notify_type = "NT:",
        .key_search_type = "ST:",
};

service_record ssdp_service_map[] = {
        {.signature = "upnp:rootdevice", .service_name = "upnp", .host_type = HOST_TYPE_UNKNOWN},
        {.signature = "urn:dial-multiscreen-org:device:dial", .service_name = "DIAL", .host_type = HOST_TYPE_SMART_TV},
        {.signature = "urn:mdx-netflix-com:service:target", .service_name = "Netflix", .host_type = HOST_TYPE_UNKNOWN},
        {.signature = "FIRETVSTICK", .service_name = NULL, .host_type = HOST_TYPE_SMART_TV},
        {.signature = "urn:schemas-upnp-org:device:InternetGatewayDevice", .service_name = NULL, .host_type = HOST_TYPE_ROUTER},
};


bool scan_util_is_running(){

    if(scan.running && !scan.quit_now)
        return true;

    return false;
}

// void scan_util_format_ip_address(uint32_t ip_addr, char *ip_buffer, ssize_t ip_len){
//     struct in_addr addr;
//     addr.s_addr = ip_addr;
// 
//     inet_ntop(AF_INET, &addr, ip_buffer, ip_len);
// 
// }
// 
// void scan_util_format_hw_address(char *buff, size_t buff_len, struct sockaddr_ll *sa_ll){
//     if(sa_ll == NULL)
//         return;
// 
//     int len = 0;
//     for(int i=0; i < sa_ll->sll_halen && (len + 3) < buff_len; i++)
//         len += sprintf(&buff[len], "%02x%s", sa_ll->sll_addr[i], i + 1 < sa_ll->sll_halen ? ":" : "");
// 
// }
// 
// bool scan_util_validate_hw_address(char *address, int real_address) {
//     if(address == NULL || strlen(address) != 17)
//         return false;
// 
//     //ab:bc:cd:de:ef:ff
//     uint32_t segment[6];
//     char buffer[64];
//     int num_tokens = sscanf(address, "%2x:%2x:%2x:%2x:%2x:%2x%s",
//                             &segment[0], &segment[1], &segment[2], &segment[3], &segment[4], &segment[5], buffer);
//     if(num_tokens != 6)
//         return false;
//     for(int i=0; i<6; i++){
//         if((segment[i] & 0xFFFFFF00) != 0)
//             return false;
//     }
//     if(real_address){
//         int count_zeros = 0;
//         for(int i=0; i<6; i++){
//             if(segment[i] == 0)
//                 count_zeros++;
//         }
//         if(count_zeros > 3)
//             return false;
//     }
//     return true;
// }

// void scan_util_update_hw_vendor(char *hw_addr, int size) {
//     if(hw_addr == NULL || strlen(hw_addr) == 0)
//         return;
// 
//     size_t len = strlen(hw_addr);
//     size_t free_space = size - len - 1;
//     if(free_space < 12)
//         return;
// 
//     int tokens;
//     char addr_buffer[32];
//     tokens = sscanf(hw_addr, "%c%c:%c%c:%c%c:%*s", &addr_buffer[0], &addr_buffer[1],
//                             &addr_buffer[2], &addr_buffer[3], &addr_buffer[4], &addr_buffer[5]);
//     addr_buffer[6] = 0;
//     if(tokens != 6 || strlen(addr_buffer) != 6)
//         return;
// 
//     const char *vendor_org = vendor_db_query(addr_buffer);
//     if(vendor_org != NULL)
//         snprintf(hw_addr+len, free_space, " [%s]", vendor_org);
// }

bool scan_util_addr_seen(const in_addr_t target, const in_addr_t *list, const int list_len){
    for(int i = 0; i < list_len; i++){
        if(list[i] == target)
            return true;
    }
    return false;
}

int scan_util_get_sock_error(int sd){
    int so_error = 0;
    socklen_t len = sizeof so_error;
    if(!getsockopt(sd, SOL_SOCKET, SO_ERROR, &so_error, &len))
        return so_error;
    else{
        log_warn("scan_util_get_sock_error: error getting socket error");
        return -1;
    }
}

int scan_util_get_sock_info(int sd){
    struct tcp_info info;
    socklen_t len = sizeof (info);
    if(!getsockopt(sd, IPPROTO_TCP, TCP_INFO, &info, &len))
        return info.tcpi_state;
    else{
        log_warn("scan_util_get_sock_info: error getting socket info");
        return -1;
    }
}


bool scan_util_calc_subnet_range(const char *ip, const char *netmask, scan_range *range) {
    if(ip == NULL || netmask == NULL || strlen(ip) == 0 || strlen(netmask) == 0)
        return false;

    memset(range, 0, sizeof(scan_range));
    struct in_addr host_addr, mask_addr;
    inet_aton(ip, &host_addr);
    inet_aton(netmask, &mask_addr);

    if(mask_addr.s_addr < NL_MIN_NETMASK_VALUE)
        mask_addr.s_addr = NL_MIN_NETMASK_VALUE;
//    if(range->length > NL_MAX_RANGE_LENGTH)
//        return false;

    range->start_addr.s_addr = (host_addr.s_addr & mask_addr.s_addr) | 0x01000000;
    range->stop_addr.s_addr = (host_addr.s_addr | ~mask_addr.s_addr) & 0xFEFFFFFF;
    range->start_num = ntohl(range->start_addr.s_addr);
    range->stop_num = ntohl(range->stop_addr.s_addr);

    if(scan.opt_subnet_offset) {
        range->start_num += scan.opt_subnet_offset;
        range->start_addr.s_addr = htonl(range->start_num);
    }
    
    if(scan.opt_max_hosts > 0){
        range->stop_num = range->start_num + scan.opt_max_hosts;
        range->stop_addr.s_addr = htonl(range->stop_num);
    }
    range->length = range->stop_num - range->start_num + 1;

    return true;
}

scan_result *scan_result_init(enum scan_direction dir, enum scan_host_state resp, in_addr_t addr, uint16_t port) {

    scan_result *result = malloc(sizeof(scan_result));
    memset(result, 0, sizeof(scan_result));

    result->direction = dir;
    result->response = resp;
    result->target_addr.s_addr = addr;
    result->port = port;
    return result;
}

void scan_result_destroy(scan_result *result) {
    if(result == NULL)
        return;
    if(result->hostname)
        free(result->hostname);
    if(result->services){
        g_list_free(result->services);
    }
    free(result);

}


void scan_print_mates(nmlist *hosts) {
    if(hosts == NULL)
        return;

    uint numentries = 0;
    nm_list_foreach(entry, hosts) {
        numentries++;
//         nm_host *entry;
//         for(int i=0; i < hosts->len; i++){
//             entry = nm_host_array_index(hosts, i);
            nm_host_print((nm_host *)entry->data);
//         }
    }
    printf("Total Network Mates: %d  \n", numentries);

}

int scan_list_arp_hosts(){
    log_trace("scan_list_arp_hosts: called");
    
    FILE *arp_fd;
    nm_host *entry;

    char line[NL_GEN_BUFF], ip_buffer[NM_MAX_BUFF_IP], host_buffer[NM_MAX_BUFF_HOST];
    char hw_addr[NM_MAX_BUFF_HWADDR];
    int num_tokens, type, flags, num_lines, num_found = 0;

    if ((arp_fd = fopen("/proc/net/arp", "r")) == NULL) {
        perror("Error opening arp table");
        return 0;
    }
    // ignore header
    if(fgets(line, sizeof(line), arp_fd) == NULL){
        perror("Nothing in arp table files");
        return 0;
    }

    //entries = nm_host_array_new();
    for (num_lines = 0; fgets(line, sizeof(line), arp_fd); num_lines++) {
        if(scan.quit_now)
            return 0;

        num_tokens = sscanf(line, "%s 0x%x 0x%x %99s %*99s* %*99s\n", ip_buffer, &type, &flags, hw_addr);
        if (num_tokens < 4)
            break;
        if(!nm_validate_hw_address(hw_addr, 1))
            continue;

        if(!scan.opt_skip_resolve)
            nm_update_hw_vendor(hw_addr, sizeof(hw_addr));

        entry = nm_host_init(HOST_TYPE_UNKNOWN);
        entry->ip_addr = inet_addr(ip_buffer);
        if(!scan.opt_skip_resolve && scan_resolve_hostname(ip_buffer, host_buffer, sizeof(host_buffer)))
            nm_host_set_attributes(entry, ip_buffer, NULL, NULL, hw_addr, host_buffer);
        else
            nm_host_set_attributes(entry, ip_buffer, NULL, NULL, hw_addr, NULL);

        scan.hosts = nm_host_merge_in_list(scan.hosts, entry);
        num_found++;
    }
    fclose(arp_fd);
    
    log_trace("scan_list_arp_hosts: ending");
    return num_found;
}


int scan_list_gateways() {
    log_trace("scan_list_gateways: called");
    
    int num_ip4_found = 0, num_ip6_found = 0, tokens;
    char line[NL_GEN_BUFF], ip_buffer[NM_MAX_BUFF_IP], host_buffer[NM_MAX_BUFF_HOST];
    char ip6_buffer[NM_MAX_BUFF_IP6], iface[64], *token;
    FILE *fp;
    nm_host *gw_host = NULL, *gw_host6;
    struct in_addr dest, gateway;
    struct in6_addr gateway6;

    /* read IPv4 route file first */
    if ((fp = fopen("/proc/net/route", "r")) == NULL) {
        log_info("Error opening route table");
        return 0;
    }
    // found a header?
    if (fgets(line, sizeof(line), fp) != NULL) {
        for (; fgets(line, sizeof(line), fp);) {
            tokens = sscanf(line, "%s %X %X %*i %*i %*i %*i %*x %*i %*i %*i \n",
                            iface, &dest.s_addr, &gateway.s_addr);
            if (tokens < 3)
                break;
            if(dest.s_addr == 0 && gateway.s_addr != 0){
                gw_host = nm_host_init(HOST_TYPE_ROUTER);
                inet_ntop(AF_INET, &gateway.s_addr, ip_buffer, sizeof(ip_buffer));
                if(!scan.opt_skip_resolve && scan_resolve_hostname(ip_buffer, host_buffer, sizeof(host_buffer)))
                    nm_host_set_attributes(gw_host, ip_buffer, NULL, NULL, NULL, host_buffer);
                else
                    nm_host_set_attributes(gw_host, ip_buffer, NULL, NULL, NULL, NULL);

                scan.hosts = nm_host_merge_in_list(scan.hosts, gw_host);
                num_ip4_found++;
            }
        }
//     }else{
        //log_info("No header in route table");
    }
    fclose(fp);

    /* read IPv6 route file next */
    if ((fp = fopen("/proc/net/ipv6_route", "r")) == NULL) {
        log_info("Error opening ipv6_route table");
        return num_ip4_found;
    }
    //no header, lines directly
    for (; fgets(line, sizeof(line), fp);) {
        token = nm_string_extract_token(line, ' ', 4);
        if(strlen(token) < 32)
            continue;

        for(int i=0; i<16; i++){
            sscanf(&token[i*2], "%2hhx", &gateway6.__in6_u.__u6_addr8[i]);
        }

        if(gateway6.__in6_u.__u6_addr32[0] != 0 || gateway6.__in6_u.__u6_addr32[1] != 0 ||
                gateway6.__in6_u.__u6_addr32[2] != 0 || gateway6.__in6_u.__u6_addr32[3] != 0){

            gw_host6 = nm_host_init(HOST_TYPE_ROUTER);
            /* if there is only 1 ipv4 gateway, likely all ipv6 addresses belong to it */
//             if(num_ip4_found != 1)
//                 gw_host6 = gw_host;
//             else
//                 gw_host6 = nm_host_init(HOST_TYPE_ROUTER);

            inet_ntop(AF_INET6, &gateway6.__in6_u, ip6_buffer, sizeof(ip6_buffer));
            // log_trace("Printing IPv6 %s", ip6_buffer);

            if(!scan.opt_skip_resolve && scan_resolve_hostname6(ip6_buffer, host_buffer, sizeof(host_buffer)))
                nm_host_set_attributes(gw_host6, NULL, ip6_buffer, NULL, NULL, host_buffer);
            else
                nm_host_set_attributes(gw_host6, NULL, ip6_buffer, NULL, NULL, NULL);

            scan.hosts = nm_host_merge_in_list(scan.hosts, gw_host6);

            num_ip6_found++;
        }
    }
    fclose(fp);

    log_trace("scan_list_gateways: ending with ip4: %i, ip6: %i", num_ip4_found, num_ip6_found);
    return num_ip4_found + num_ip6_found;
}

bool scan_list_localhost() {
    int family;
    struct ifaddrs *if_addr, *ifa;
    char ip_buffer[NM_MAX_BUFF_IP], host_buff[NM_MAX_BUFF_HOST];
    char ip6_buffer[NM_MAX_BUFF_IP6], hwaddr_buffer[NM_MAX_BUFF_HWADDR];

    assert(scan.localhost == NULL);
    scan.localhost = nm_host_init(HOST_TYPE_LOCALHOST);

    if (getifaddrs(&if_addr) == -1) {
        log_warn("Could not get getifaddrs");
        return false;
    }
    for (ifa = if_addr; ifa != NULL; ifa = ifa->ifa_next) {
        //skip loopback and anything not connected (e.g cable)
        if (ifa->ifa_addr == NULL || (ifa->ifa_flags & IFF_LOOPBACK) || !(ifa->ifa_flags & IFF_UP) ||
            !(ifa->ifa_flags & IFF_RUNNING)) {
            continue;
        }
        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            scan.localhost->ip_addr = ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr.s_addr;
            inet_ntop(AF_INET, &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr, ip_buffer, sizeof(ip_buffer));
//            if(strlen(entry->ip) == 0)
//                strncpy(entry->ip, buff, sizeof(entry->ip));
//            else
//                entry->list_ip = nm_host_other_add_unique(entry->list_ip, buff);

            //update ip and hostname, where hostname is host or ip, whichever we have
            if(!scan.opt_skip_resolve && scan_resolve_hostname(ip_buffer, host_buff, sizeof(host_buff)))
                nm_host_set_attributes(scan.localhost, ip_buffer, NULL, NULL, NULL, host_buff);
            else
                nm_host_set_attributes(scan.localhost, ip_buffer, NULL, NULL, NULL, NULL);
            
//            if(strlen(entry->hostname) == 0){
//                strncpy(entry->hostname, host_buff, sizeof(entry->hostname));
//            }else if(strcmp(buff, entry->hostname) != 0){
//                printf("Conflict in hostname, tracking %s but found %s", entry->hostname, buff);
//            }
            if(ifa->ifa_netmask != NULL){
                struct sockaddr_in *nmv = (struct sockaddr_in*)ifa->ifa_netmask;
                nm_host_set_attributes(scan.localhost, NULL, NULL, inet_ntoa(nmv->sin_addr), NULL, NULL);
//                strncpy(entry->netmask, inet_ntoa(nmv->sin_addr), sizeof(entry->netmask));
            }

        } else if (family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr, ip6_buffer, sizeof(ip6_buffer));
            nm_host_set_attributes(scan.localhost, NULL, ip6_buffer, NULL, NULL, NULL);
//            if(strlen(entry->ip6) == 0)
//                strncpy(entry->ip6, buff, sizeof(entry->ip6));
//            else
//                entry->list_ip6 = nm_host_other_add_unique(entry->list_ip6, buff);
        } else if (family == AF_PACKET) {
            nm_format_hw_address(hwaddr_buffer, sizeof(hwaddr_buffer), (struct sockaddr_ll *) ifa->ifa_addr);
            nm_update_hw_vendor(hwaddr_buffer, sizeof(hwaddr_buffer));
            nm_host_set_attributes(scan.localhost, NULL, NULL, NULL, hwaddr_buffer, NULL);
//            if(!strlen(entry->hw_addr))
//                strncpy(entry->hw_addr, buff, sizeof(entry->hw_addr));
//            else
//                entry->list_hw_addr = nm_host_other_add_unique(entry->list_hw_addr, buff);
        }
    }
    freeifaddrs(if_addr);
    
    scan.hosts = nm_host_merge_in_list(scan.hosts, scan.localhost);
    
    return true;

}


int scan_resolve_hostname_from_inaddr(uint32_t ip_addr, char *hostname_buffer, size_t buffer_size) {
    assert(ip_addr != 0);
    assert(hostname_buffer != NULL);

    char ip_str[NM_MAX_BUFF_IP];
    char host[NM_MAX_BUFF_HOST];
    char service[32];
    struct sockaddr_in addr;

    addr.sin_port = 0;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip_addr;
    if(getnameinfo((struct sockaddr *) &addr,sizeof(addr), host, sizeof(host),
                   service, sizeof(service), NI_NUMERICSERV) != 0){
        return 0;
    }
    strncpy(hostname_buffer, host, buffer_size);
    return 1;
}

int scan_resolve_hostname(char *ip, char *hostname_buffer, size_t buffer_size) {
    assert(ip != NULL);
    assert(hostname_buffer != NULL);

    char host[NM_MAX_BUFF_HOST];
    char service[32];
    struct sockaddr_in addr;
    addr.sin_port = 0;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    if(getnameinfo((struct sockaddr *) &addr,sizeof(addr), host, sizeof(host),
                   service, sizeof(service), NI_NUMERICSERV) != 0){
        return 0;
    }
    if(strncmp(ip, host, sizeof(host)) != 0){
        strncpy(hostname_buffer, host, buffer_size);
        return 1;
    }
    return 0;
}


int scan_resolve_hostname6(char *ip, char *hostname_buffer, size_t buffer_size) {
    assert(ip != NULL);
    assert(hostname_buffer != NULL);

    char host[NM_MAX_BUFF_HOST];
    char service[32];
    struct sockaddr_in addr;
    addr.sin_port = 0;
    addr.sin_family = AF_INET6;
    addr.sin_addr.s_addr = inet_addr(ip);
    if(getnameinfo((struct sockaddr *) &addr,sizeof(addr), host, sizeof(host),
                   service, sizeof(service), NI_NUMERICSERV) != 0){
        return 0;
    }
    if(strncmp(ip, host, sizeof(host)) != 0){
        strncpy(hostname_buffer, host, buffer_size);
        return 1;
    }
    return 0;
}


void scan_process_result(scan_result *result, int *live_counter) {
    assert(result != NULL);
    assert(live_counter != NULL);
    assert(result->response != SCAN_HSTATE_UNKNOWN);

    nm_host *host;
    char *ip;
    char *dir = "connect";
    if(result->direction != SCAN_DIR_CONNECT)
        dir = "listen";

    //log_debug("scan_process_result result %s dir as %i response", dir, result->response);
    //ignore Dead and show Live and Error only
    if (result->response == SCAN_HSTATE_LIVE) {
        (*live_counter)++;
        ip = inet_ntoa(result->target_addr);
        host = nm_host_init(result->host_type);
        if(result->hostname != NULL) {
            nm_host_set_attributes(host, ip, NULL, NULL, NULL, result->hostname);
            //printf("  --> SCAN %s, found Live host [%s] [%s]\n", dir, ip, result->hostname);
        }else {
            nm_host_set_attributes(host, ip, NULL, NULL, NULL, ip);
            //printf("  --> SCAN %s, found Live host [%s]\n", dir, ip);
        }
        if(result->services)
            nm_host_add_services(host, result->services);
        
        scan.hosts = nm_host_merge_in_list(scan.hosts, host);

        if(scan.event_cb)
            scan.event_cb(SCAN_EVENT_UPDATE, host);
    }else if (result->response == SCAN_HSTATE_ERROR) {
        printf("  --> SCAN %s Error with [%s]\n", dir, inet_ntoa(result->target_addr));
    }
    scan_result_destroy(result);
}


void scan_notify_start(void *callback){
    log_debug("SCAN: Starting");
    scan.running = 1;
    if(callback != NULL)
        ((scanner_callback)callback)(SCAN_EVENT_START, NULL);
}

void scan_notify_host_update(void *callback, nm_host *host){
    if(callback != NULL)
        ((scanner_callback)callback)(SCAN_EVENT_UPDATE, host);
}

void scan_notify_hosts(void *callback){
    if(callback == NULL)
        return;

    nm_list_foreach(entry, scan.hosts)
        ((scanner_callback) callback)(SCAN_EVENT_UPDATE, entry);
    
//     nm_host *entry;
//     for(int i=0; i < scan.hosts->len; i++) {
//         entry = nm_host_array_index(scan.hosts, i);
//         ((scanner_callback) callback)(SCAN_EVENT_UPDATE, entry);
//     }
}

void scan_notify_stop(void *callback){
    log_debug("SCAN: Stop");
    scan.running = 0;
    if(callback != NULL)
        ((scanner_callback)callback)(SCAN_EVENT_END, NULL);
}

gpointer scan_main_listen_thread(gpointer data){
    log_debug("scan_main_listen_thread Starting...");
    unsigned long start_time = nm_time_ms();

    if(scan.quit_now)
        return NULL;

    int num_listen_ports = sizeof(scan_listen_list) / sizeof(scan_listen_list[0]);
    int num_results = 0, num_live = 0;
    int scan_timeout_ms = scan.opt_subnet_timeout_ms;
    GThreadPool *thread_pool;
    GAsyncQueue *results_queue;
    GError *error = NULL;

    log_info("scan_main_listen_thread: range of %i ports", num_listen_ports);

    results_queue = g_async_queue_new();
    thread_pool = g_thread_pool_new(scan_listen_thread, results_queue,
                                     scan.opt_listen_threads, false, &error);
    if(error != NULL){
        log_warn("scan_main_listen_thread: error starting threads, %i, %s \n", error->code, error->message);
        g_error_free(error);
        return NULL;
    }

    // push work to the thread pool
    for(int i = 0; i < num_listen_ports; i++) {
        if(scan.quit_now)
            return false;

        g_thread_pool_push(thread_pool, (gpointer)&scan_listen_list[i], &error);
        if(error != NULL){
            log_info("scan_main_listen_thread: error pushing entry %i \n", i);
            g_error_free(error);
        }
    }

    //poll status of received results
    scan_result *result;
    uint32_t unused_work, running_threads, returned_count;
    for(;;) {
        if(scan.quit_now)
            return false;

        //check work done by the thread pool
        unused_work = g_thread_pool_unprocessed(thread_pool);
        running_threads = g_thread_pool_get_num_threads(thread_pool);
        if(unused_work == 0 && running_threads == 0)
            break;
        //check if results are pending, process some
        while((result = g_async_queue_try_pop(results_queue))){
            if(scan.quit_now)
                return false;
            scan_process_result(result, &num_live);
            num_results++;
        }
        usleep(scan.opt_poll_thread_work_us);
        if(nm_time_ms_diff(start_time) > scan_timeout_ms){
            log_info("scan_main_listen_thread: Subnet scan timeout reached %u ms \n", scan_timeout_ms);
            break;
        }
    }
    g_thread_pool_free(thread_pool, false, true);

    returned_count = g_async_queue_length(results_queue);
    for(int i=0; i<returned_count; i++){
        if(scan.quit_now)
            return false;
        result = g_async_queue_pop(results_queue);
        scan_process_result(result, &num_live);
        num_results++;
    }

    log_info("scan_main_listen_thread: discovery summary: total ports %i found %i hosts in %lus]\n",
              num_listen_ports, num_live, nm_time_ms_diff(start_time) / 1000);

    g_async_queue_unref(results_queue);

    log_debug("scan_main_listen_thread: ending");
    return NULL;
}

void scan_listen_thread(gpointer target_data, gpointer results_data) {
    log_debug("scan_listen_thread called");

    int sd, max_wait_time, min_wait_time, mc_loop;
    long int recv_ret, poll_ret, actual_size;
    unsigned long thread_start;
    char thread_signature[64];
    char sender_ip_buffer[NM_MAX_BUFF_IP], hostname_buffer[NM_MAX_BUFF_HOST], recv_buffer[NL_LARGE_BUFF];
    uint16_t port_num, sender_port;
    socklen_t recv_addr_size;
    struct pollfd poll_arg;
    struct sockaddr_in bind_addr, recv_addr;
    struct ip_mreqn mcast_membership;

    nmtable *sender_results;
    scan_listen_port *listen_port;
    scan_result *result;
    GAsyncQueue *results_queue;

    thread_start = nm_time_ms();
    if(!scan_util_is_running()) {
        log_debug("scan_listen_thread: not running?");
        return;
    }

    //prepare results and listen port
    //sender_results = scan_result_dict_new();
    sender_results = nm_table_new();
    results_queue = results_data;
    listen_port = target_data;
    min_wait_time = listen_port->min_time;
    max_wait_time = listen_port->max_time;
    port_num = (uint16_t)listen_port->port.port;
    sprintf(thread_signature, "[ListTh<%lx>, Port<%u>]", (intptr_t)g_thread_self(), port_num);

    sd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_IP);
    if(sd < 0){
        log_info("%s socket errno: %i, errdesc: %s", thread_signature, errno, strerror(errno));
        log_debug("%s End listen thread [time: %lu ms]!", thread_signature, nm_time_ms_diff(thread_start));
        return;
    }

    //set multicast membership if needed
    if(listen_port->mc_join){
        assert(listen_port->mc_ip != NULL);
        mcast_membership.imr_ifindex = 0;
        mcast_membership.imr_address.s_addr = INADDR_ANY;
        mcast_membership.imr_multiaddr.s_addr = inet_addr(listen_port->mc_ip);
        if(setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                      &mcast_membership, sizeof(mcast_membership)) == -1){
            log_debug("%s socket set option mc membership errno: %i, errdesc: %s", thread_signature, errno, strerror(errno));
        }else{
            log_debug("%s Will join membership of multicast %s", thread_signature, listen_port->mc_ip);
        }
        mc_loop = 0;
        if(setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &mc_loop, sizeof(mc_loop)) == -1)
            log_debug("%s socket set option mc loop errno: %i, errdesc: %s", thread_signature, errno, strerror(errno));
    }

    log_debug("%s Binding to port %i", thread_signature, listen_port->bind_port);
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons(listen_port->bind_port);
    if(bind(sd, (struct sockaddr *) & bind_addr, sizeof(bind_addr)) < 0){
        log_debug("%s Could not bind to port %i, errno: %i, errdesc: %s \n", thread_signature, port_num, errno, strerror(errno));
        log_debug("%s End listen thread [time: %lu ms]!", thread_signature, nm_time_ms_diff(thread_start));
        return;
    }

    if(!scan_util_is_running())
        return;

    if(listen_port->query_cb){
        log_debug("%s Executing query callback", thread_signature);
        if(!(listen_port->query_cb)(sd, listen_port))
            log_debug("%s Error with query callback", thread_signature);

    }

    poll_arg.events = POLLIN;
    poll_arg.fd = sd;
    log_debug("%s Listening on port %hi", thread_signature, port_num);

    while (nm_time_ms_diff(thread_start) <= max_wait_time){
        if(!scan_util_is_running())
            break;

        //TODO: Poll first before recv;
        memset(&recv_addr, 0, sizeof(recv_addr));
        recv_addr_size = sizeof(recv_addr);
        recv_ret = recvfrom(sd, recv_buffer, sizeof(recv_buffer), 0,
                            (struct sockaddr*)&recv_addr, &recv_addr_size);
        if(recv_ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)){
            poll_ret = poll(&poll_arg, 1, min_wait_time);
            //on event or timeout, try reading again
            if(poll_ret > 0 || poll_ret == 0){
                //TODO: do not mix the two conditions
                //log_debug("%s Poll ready or timeout: %li, port %i, errno: %i, errdesc: %s",
                //        thread_signature, poll_ret, port_num, errno, strerror(errno));
                continue;
            }
            //else report the error
            log_debug("%s Poll error on port %i, errno: %i, errdesc: %s", thread_signature, port_num, errno, strerror(errno));
        }else{
            //now check the data received
            inet_ntop(AF_INET, &recv_addr.sin_addr, sender_ip_buffer, sizeof(sender_ip_buffer));
            sender_port = ntohs(recv_addr.sin_port);
            actual_size = recv_ret < sizeof(recv_buffer) ? recv_ret : (long)sizeof(recv_buffer);
            log_debug("%s Data on port %i, size %li from %s:%hu", thread_signature, port_num, actual_size, sender_ip_buffer, sender_port);

            //result = scan_result_dict_get(sender_results, recv_addr.sin_addr.s_addr);
            result = nm_table_get_num(sender_results, recv_addr.sin_addr.s_addr);
            if(result == NULL){
                result = scan_result_init(SCAN_DIR_LISTEN, SCAN_HSTATE_LIVE, recv_addr.sin_addr.s_addr, port_num);
                result->host_type = listen_port->port.device_type;
                //scan_result_dict_set(sender_results, recv_addr.sin_addr.s_addr, result);
                nm_table_set_num(sender_results, recv_addr.sin_addr.s_addr, result);
            }
            //port-specific response processing
            if(listen_port->response_cb != NULL){
                log_debug("%s Executing response callback", thread_signature);
                if(!(listen_port->response_cb)(result, recv_buffer, actual_size))
                    log_debug("%s Error with response callback", thread_signature);
            }
        }
    }

    if(!scan_util_is_running())
        return;

    //loop over dict and resolve hostnames;
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init (&iter, sender_results);
    while (g_hash_table_iter_next (&iter, &key, &value)){
        result = value;
        if(!scan.opt_skip_resolve && scan_resolve_hostname_from_inaddr(result->target_addr.s_addr,
                                                                       hostname_buffer, sizeof(hostname_buffer)))
            result->hostname = strdup(hostname_buffer);
        g_async_queue_push(results_queue, value);
    }
    log_debug("%s End listen thread [time: %lu ms]!", thread_signature, nm_time_ms_diff(thread_start));
}

gpointer scan_main_connect_thread(gpointer data){
    log_trace("scan_main_connect_thread: starting");
    unsigned long start_time = nm_time_ms();

    uint32_t curr_addr, curr_num;
    int num_scanned = 0, num_live = 0;
    int scan_timeout_ms = scan.opt_subnet_timeout_ms;

    GThreadPool *thread_pool;
    GAsyncQueue *results_queue;
    GError *error = NULL;

    if(scan.quit_now)
        return NULL;

    if (scan.localhost == NULL || scan.localhost->type != HOST_TYPE_LOCALHOST){
        log_info("scan_main_connect_thread: Error localhost was not resolved");
        return NULL;
    }

    nm_host *localhost = scan.localhost;
    scan_range range;
    char start_ip[NM_MAX_BUFF_IP], end_ip[NM_MAX_BUFF_IP];
    if(!scan_util_calc_subnet_range(localhost->ip, localhost->netmask, &range)){
        return NULL;
    }
    
    inet_ntop(AF_INET, &range.start_addr, start_ip, NM_MAX_BUFF_IP);
    inet_ntop(AF_INET, &range.stop_addr, end_ip, NM_MAX_BUFF_IP);
    log_info("scan_main_connect_thread: range of %i hosts: [%s to %s]", range.length, start_ip, end_ip);


    results_queue = g_async_queue_new();
    thread_pool = g_thread_pool_new(scan_connect_thread, results_queue,
                                     scan.opt_connect_threads, false, &error);
    if(error != NULL){
        log_warn("scan_main_connect_thread: error starting threads, %i, %s \n", error->code, error->message);
        g_error_free(error);
        return NULL;
    }

    // push work to the thread pool
    for(curr_num = range.start_num; curr_num <= range.stop_num; curr_num++){
        if(scan.quit_now)
            return false;

        curr_addr = ntohl(curr_num);
        if(curr_addr == scan.localhost->ip_addr)
            continue;

        g_thread_pool_push(thread_pool, (gpointer)(intptr_t)curr_addr, &error);
        if(error != NULL){
            log_info("scan_main_connect_thread: error pushing entry %u \n", curr_num);
            g_error_free(error);
        }
    }

    //poll status of received results
    scan_result *result;
    uint32_t unused_work, running_threads, returned_count;
    for(;;) {
        if(scan.quit_now)
            return false;

        //check work done by the thread pool
        unused_work = g_thread_pool_unprocessed(thread_pool);
        running_threads = g_thread_pool_get_num_threads(thread_pool);
        if(unused_work == 0 && running_threads == 0)
            break;
        //check if results are pending, process some
        while((result = g_async_queue_try_pop(results_queue))){
            if(scan.quit_now)
                return false;
            scan_process_result(result, &num_live);
            num_scanned++;
        }
        usleep(scan.opt_poll_thread_work_us);
        if(nm_time_ms_diff(start_time) > scan_timeout_ms){
            log_info("scan_main_connect_thread: Subnet scan timeout reached %u ms \n", scan_timeout_ms);
            break;
        }
    }
    g_thread_pool_free(thread_pool, false, true);

    returned_count = g_async_queue_length(results_queue);
    for(int i=0; i<returned_count; i++){
        if(scan.quit_now)
            return false;
        result = g_async_queue_pop(results_queue);
        scan_process_result(result, &num_live);
        num_scanned++;
    }

    log_info(   "scan_main_connect_thread: discovery summary: total targets %i, " \
                "actual scanned %i with %i Live in %lus]\n",
                range.length, num_scanned, num_live, nm_time_ms_diff(start_time) / 1000);

    g_async_queue_unref(results_queue);

    log_trace("scan_main_connect_thread: ending");
    return NULL;


}

int scan_probe_send_tcp(const char *thread_id, scan_result *result, 
                          scan_port *port_def, struct in_addr ip_addr) {

    int sd, cnct_ret, poll_ret, so_error;
    struct sockaddr_in target_addr;
    struct pollfd poll_arg;

    sd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_IP);
    if(sd < 0){
        log_debug("%s\t socket errno: %i, errdesc: %s", thread_id, errno, strerror(errno));
        result->response = SCAN_HSTATE_ERROR;
        return -EIO;
    }

    target_addr.sin_family = AF_INET;
    target_addr.sin_addr = ip_addr;
    target_addr.sin_port = htons(port_def->port);

    cnct_ret = connect(sd, (struct sockaddr*)&target_addr, sizeof(target_addr));
    if(cnct_ret != -1 || errno != EINPROGRESS){
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

    so_error = scan_util_get_sock_error(sd);
    //so_state = scan_util_get_sock_info(sd);
    //log_debug("%s\t connect after_poll - [%lu ms] poll_revents %hu, socket_state: %i, socket_error errno: %i, errdesc: %s",
    //thread_id, connect_diff, poll_arg.revents, so_state, so_error, strerror(so_error));

    /* check poll result and socket state */
    if(poll_ret > 0){
        //poll has connect() success or error is connection refused, both mean host is live
        if(so_error == 0 || so_error == ECONNREFUSED){
            result->response = SCAN_HSTATE_LIVE;
            if(so_error == 0) {
                result->host_type = port_def->device_type;
                result->services = nm_list_add(result->services, port_def->service);
                log_trace("%s host found, connect port %hu open", 
                          thread_id, port_def->port);
            }else {
                log_trace("%s host found, connect port %hu passive",
                          thread_id, port_def->port);
            }
        }
    }else if(poll_ret == 0){
        //poll timed out
        so_error = scan_util_get_sock_error(sd);
        log_trace("%s\t poll - timeout, port %i, sockerrno %i, errdesc: %s",
                  thread_id, port_def->port, so_error, strerror(so_error));
    }else{
        //poll error
        log_trace("%s\t poll - error with port %i, error errno: %i, errdesc: %s", 
                 thread_id, port_def->port, errno, strerror(errno));
    }
    
    close(sd);
    return 0;
}


int scan_probe_send_udp(const char *thread_id, scan_result *result, 
                          scan_port *port_def, struct in_addr ip_addr) {

    int sd, send_ret, recv_ret, poll_ret;
    struct sockaddr_in target_addr;
    socklen_t addr_size;
    struct pollfd poll_arg;
    char recvbuffer[NL_GEN_BUFF];
    recvbuffer[0] = 0;
    
    sd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_IP);
    if(sd < 0){
        log_debug("%s\t socket errno: %i, errdesc: %s", thread_id, errno, strerror(errno));
        result->response = SCAN_HSTATE_ERROR;
        return -EIO;
    }

    target_addr.sin_family = AF_INET;
    target_addr.sin_addr = ip_addr;
    target_addr.sin_port = htons(port_def->port);
    addr_size = sizeof(target_addr);

    // send the buffer
    send_ret = sendto(sd, port_def->query_payload.buffer, port_def->query_payload.length-1, 0,
                      (struct sockaddr*)&target_addr, sizeof(target_addr));
    
    if(send_ret == -1){
        log_trace("%s\t sendto unexpected error on port %i, errno: %i, errdesc: %s\n", 
                  thread_id, port_def->port, errno, strerror(errno));
        result->response = SCAN_HSTATE_ERROR;
        close(sd);
        return -EIO;
    }
    
    
    // request non-blocking response
    recv_ret = recvfrom(sd, recvbuffer, sizeof(recvbuffer),
                        0, (struct sockaddr*)&target_addr, &addr_size);
    if(recv_ret == -1 && errno != EAGAIN && errno != EWOULDBLOCK){
        log_trace("%s\t recvfrom unexpected error on port %i, errno: %i, errdesc: %s\n", 
                  thread_id, port_def->port, errno, strerror(errno));
        result->response = SCAN_HSTATE_ERROR;
        close(sd);
        return -EIO;
    }
    
    // wait for response
    poll_arg.fd = sd;
    /* include err event as open connect_ports can be too quick */
    poll_arg.events = POLL_IN;
    poll_ret = poll(&poll_arg, 1, scan.opt_connect_timeout_ms);

    /* check poll result and socket state */
    if(poll_ret > 0 && poll_arg.revents & POLL_IN){
        //poll has data from recvfrom
        result->response = SCAN_HSTATE_LIVE;
        result->host_type = port_def->device_type;
        result->services = nm_list_add(result->services, port_def->service);
        log_trace("%s host found, receive from port %hu", 
                    thread_id, port_def->port);
    }else if(poll_ret == 0){    //poll timed out
        log_trace("%s\t poll-udp - timeout, port %i",
                  thread_id, port_def->port);
    }else{      //poll error
        log_trace("%s\t poll-udp - error with port %i, error errno: %i, errdesc: %s", 
                 thread_id, port_def->port, errno, strerror(errno));
    }
    
    close(sd);
    return 0;
}


void scan_connect_thread(gpointer target_data, gpointer results_data) {
    log_trace("scan_run_dir_connect_thread called");
    int port_index, ports_to_scan, ret = 0;
    char *ip_str, thread_id[64], hostname_buffer[NM_MAX_BUFF_HOST];
    long unsigned thread_start;
    struct in_addr ip_addr;
    scan_port port_def;
    scan_result *result;
    GAsyncQueue *results_queue;

    //time this thread
    thread_start = nm_time_ms();
    //target data and thread id
    ip_addr.s_addr = (uint32_t)(intptr_t)target_data;
    ip_str = inet_ntoa(ip_addr);
    sprintf(thread_id, "[ConnTh<%lx>, IP<%s>]", (intptr_t)g_thread_self(), ip_str);

    //prepare result structure and queue
    results_queue = results_data;
    result = malloc(sizeof(scan_result));
    memset(result, 0, sizeof(scan_result));
    result->target_addr = ip_addr;
    result->response = SCAN_HSTATE_UNKNOWN;
    result->direction = SCAN_DIR_CONNECT;
    result->host_type = HOST_TYPE_UNKNOWN;

    //prepare connect_ports and address
    //ports_to_scan = sizeof(scan.connect_ports) / sizeof(scan.connect_ports[0]);
    ports_to_scan = sizeof(scan_port_list) / sizeof(scan_port_list[0]);

    log_trace("%s Starting scan for %i ports", thread_id, ports_to_scan);
    port_index = 0;
    for(; port_index < ports_to_scan; port_index++){
        if(scan.quit_now)
            break;

        port_def = scan_port_list[port_index];
        if(result->response == SCAN_HSTATE_LIVE && port_def.required == 0)
            break;
        
        //connect_start = nm_time_ms();
        
        if(port_def.protocol == SCAN_PROTO_TCP)
            ret = scan_probe_send_tcp(thread_id, result, &port_def, ip_addr);
        else if(port_def.protocol == SCAN_PROTO_UDP)
            ret = scan_probe_send_udp(thread_id, result, &port_def, ip_addr);
        
        if(ret)
            break;
        
        //TODO: time used?
        //connect_diff = nm_time_ms_diff(connect_start);

    }

    if(port_index > 0 && result->response == SCAN_HSTATE_UNKNOWN){
        log_trace("%s host dead, ", thread_id);
        result->response = SCAN_HSTATE_DEAD;
    }else if(result->response == SCAN_HSTATE_LIVE){
        if(!scan.opt_skip_resolve && scan_resolve_hostname(ip_str, hostname_buffer, sizeof(hostname_buffer)))
            result->hostname = strdup(hostname_buffer);
    }

    g_async_queue_push(results_queue, result);

    log_trace("%s End scan thread [time: %lu ms]!", thread_id, nm_time_ms_diff(thread_start));
}


bool scan_discover_subnet_hosts(int connect, int listen) {
    log_trace("scan_discover_subnet_hosts starting...");
    if(!connect && !listen)
        return false;

    GThread *conn_thread, *list_thread;
    GError *conn_err = NULL, *list_err = NULL;

    if(connect){
        conn_thread = g_thread_try_new("ConnectMainThread", scan_main_connect_thread, NULL, &conn_err);
        if(conn_err != NULL)
            log_error("Error starting the main connect thread, code %i, %s", conn_err->code, conn_err->message);
    }
    if(listen){
        list_thread = g_thread_try_new("ListenMainThread", scan_main_listen_thread, NULL, &list_err);
        if(list_err != NULL)
            log_error("Error starting the main listen thread, code %i, %s", list_err->code, list_err->message);
    }

    //wait for all the scans to end
    if(connect)
        g_thread_join(conn_thread);

    if(listen)
        g_thread_join(list_thread);

    log_trace("scan_discover_subnet_hosts ending");
    return true;

//
//    thread = g_thread_try_new("ScanThread", scan_start_ui_thread, on_scan_event, &error);
//    if(error == NULL){
//        puts("Error starting the scan thread");
//        return;
//    }
//    //g_thread_unref(thread);
//
//    g_info("scan_discover_subnet_hosts called");
//    if(scan.quit_now)
//        return false;
//
//
//
//
//
//    if (scan.localhost == NULL || scan.localhost->type != HOST_TYPE_LOCALHOST){
//        log_info("Error scanning subnet as localhost was not resolved");
//        return false;
//    }
//    unsigned long discover_start = nm_time_ms();
//
//    nm_host *localhost = scan.localhost;
//    scan_range range;
//    if(!scan_util_calc_subnet_range(localhost->ip, localhost->netmask, &range)){
//        scan_util_destroy_subnet_range(&range);
//        return false;
//    }
//    g_info("Scan Range for %i hosts: [%s to %s]", range.length, range.start_ipstr, range.stop_ipstr);
//
//    uint32_t curr_addr, curr_num;
//    int num_scanned = 0, num_live = 0;
//    int scan_timeout_ms = scan.opt_subnet_timeout_ms;
//    unsigned long start_time = nm_time_ms();
//    int num_listen_ports = sizeof(scan_listen_list) / sizeof(scan_listen_list[0]);
//
//
//    GThreadPool *connect_pool, *listen_pool;
//    GAsyncQueue *results_queue;
//    GError *error = NULL;
//
//    results_queue = g_async_queue_new();
//    connect_pool = g_thread_pool_new(scan_run_dir_connect_thread, results_queue,
//                                     scan.opt_connect_threads, false, &error);
//    if(error != NULL){
//        log_warn("Error starting connect threads, %i, %s \n", error->code, error->message);
//        g_error_free(error);
//    }
//    listen_pool = g_thread_pool_new(scan_run_dir_listen_thread, results_queue,
//                                    scan.opt_listen_threads, false, &error);
//    if(error != NULL){
//        log_warn("Error starting listen threads, %i, %s \n", error->code, error->message);
//        g_error_free(error);
//    }
//
//    // push work to the thread pool
//    // first the listener threads
//    for(int i = 0; i < num_listen_ports; i++) {
//        if(scan.quit_now)
//            return false;
//
//        g_thread_pool_push(listen_pool, (gpointer)&scan_listen_list[i], &error);
//        if(error != NULL){
//            log_info("Error pushing listen entry %i \n", i);
//            g_error_free(error);
//        }
//    }
//
//    //then connecting threads
//    for(curr_num = range.start_num; curr_num <= range.stop_num; curr_num++){
//        if(scan.quit_now)
//            return false;
//
//        curr_addr = ntohl(curr_num);
//        if(curr_addr == scan.localhost->ip_addr){
//            continue;
//        }
//        g_thread_pool_push(connect_pool, (gpointer)(intptr_t)curr_addr, &error);
//        if(error != NULL){
//            log_info("Error pushing entry %u \n", curr_num);
//            g_error_free(error);
//        }
//    }
//
//    //poll status of received results
//    scan_result *result;
//    uint32_t unused_work, running_threads, returned_count;
//    for(;;) {
//        if(scan.quit_now)
//            return false;
//
//        //check work done by the thread pool
//        unused_work = g_thread_pool_unprocessed(connect_pool) + g_thread_pool_unprocessed(listen_pool);
//        running_threads = g_thread_pool_get_num_threads(connect_pool) + g_thread_pool_get_num_threads(listen_pool);
//        if(unused_work == 0 && running_threads == 0)
//            break;
//        //check if results are pending, process some
//        while((result = g_async_queue_try_pop(results_queue))){
//            if(scan.quit_now)
//                return false;
//            scan_process_result(result, &num_live);
//            num_scanned++;
//        }
//        usleep(scan.opt_poll_thread_work_us);
//        if(nm_time_ms_diff(start_time) > scan_timeout_ms){
//            log_info("Subnet scan timeout reached %u ms \n", scan_timeout_ms);
//            break;
//        }
//    }
//    g_thread_pool_free(connect_pool, false, true);
//    g_thread_pool_free(listen_pool, false, true);
//
//    returned_count = g_async_queue_length(results_queue);
//    for(int i=0; i<returned_count; i++){
//        if(scan.quit_now)
//            return false;
//        result = g_async_queue_pop(results_queue);
//        scan_process_result(result, &num_live);
//        num_scanned++;
//    }
//
//    printf("Discovery on subnet: total targets %i, actual scanned %i with %i Live in %lus]\n",
//           range.length, num_scanned, num_live, nm_time_ms_diff(discover_start)/1000);
//
//    scan_util_destroy_subnet_range(&range);
//    g_async_queue_unref(results_queue);
//
//    g_info("scan_discover_subnet_hosts ending");
//    return true;
}



bool scan_proto_ssdp_query(int sd, void *lp){
    assert(sd > 0);

    struct sockaddr_in send_addr;
    send_addr.sin_addr.s_addr = inet_addr(proto_ssdp.send_ip);
    send_addr.sin_family = AF_INET;
    send_addr.sin_port = htons(1900);
    ssize_t bytes_sent = sendto(sd, proto_ssdp.query_message, strlen(proto_ssdp.query_message), 0,
                                 (struct sockaddr*)&send_addr, sizeof(send_addr));
    if(bytes_sent < 0){
        log_debug("scan_proto_ssdp_query: could not send query, err %i, %s", errno, strerror(errno));
        return false;
    }
    log_debug("scan_proto_ssdp_query: send query with %li bytes", bytes_sent);
    return true;
}

void scan_proto_ssdp_response_process(scan_result *result, char *in_buffer, ssize_t in_size, char *key, int num_lines) {
    char line[256], key_token[64], value_token[256];
    service_record *record;
    int num_records = sizeof(ssdp_service_map) / sizeof(ssdp_service_map[0]);

    log_debug("scan_proto_ssdp_response_process: processing response");

    for(int i=0; i<num_lines; i++){
        nm_string_copy_line(in_buffer, in_size, i, line, sizeof(line));
        key_token[0] = 0; value_token[0] = 0;
        sscanf(line, "%[a-zA-Z0-9:-] %s", key_token, value_token);
//        log_debug("scan_proto_ssdp_response_process: scanf of line '%s' gives key '%s' and value '%s'",
//                    line, key_token, value_token);
        if(strlen(key_token) && !strcmp(key_token, key)){
            for(int j=0; j < num_records; j++){
                if(strstr(value_token, ssdp_service_map[j].signature)){
//                    log_debug("scan_proto_ssdp_response_process: found host type %i and service %s",
//                            ssdp_service_map[j].host_type, ssdp_service_map[j].service_name);
                    if(ssdp_service_map[j].service_name)
                        result->services = g_list_append(result->services, ssdp_service_map[j].service_name);
                    if(ssdp_service_map[j].host_type != HOST_TYPE_UNKNOWN)
                        result->host_type = ssdp_service_map[j].host_type;
                    break;
                }
            }
            break;
        }
    }
}

bool scan_proto_ssdp_response(scan_result *result, char *in_buffer, ssize_t in_size){
    assert(result != NULL);
    assert(in_buffer != NULL);

    log_debug("scan_proto_ssdp_response - received buffer len %zu", strnlen(in_buffer, in_size));
    char line[256];
    char *key_type = NULL;

    int num_lines = nm_string_count_lines(in_buffer, in_size);
    if(num_lines < 5){
        log_debug("scan_proto_ssdp_response - not enough lines to begin checking, skipping");
        return false;
    }

    nm_string_copy_line(in_buffer, in_size, 0, line, sizeof(line));
    //log_debug("scan_proto_ssdp_response - start lines: %s", line);
    if(!strncmp(line, proto_ssdp.header_start_notify, strlen(proto_ssdp.header_start_notify))){
        key_type = proto_ssdp.key_notify_type;
    }else if(!strncmp(line, proto_ssdp.header_start_response, strlen(proto_ssdp.header_start_response))){
        key_type = proto_ssdp.key_search_type;
    }
    if(key_type){
        log_debug("scan_proto_ssdp_response - looking for key: %s", key_type);
        scan_proto_ssdp_response_process(result, in_buffer, in_size, key_type, num_lines);
    }

    return true;
}


bool scan_proto_mdns_query(int sd, void *lp){
    return true;

}

bool scan_proto_mdns_response(scan_result *result, char *in_buffer, ssize_t in_size){
    log_debug("scan_proto_mdns_response - Port<TODO> received buffer len %zu", strnlen(in_buffer, in_size));

    return true;
}

bool scan_discover_known_hosts(){

    if(!scan_list_localhost()){
        log_info("Could not resolve localhost address details");
        return false;
    }
    if(scan.quit_now)
        return false;
    int routers_found = scan_list_gateways();
    log_info("Gateway entries found: %d", routers_found);

    if(scan.quit_now)
        return false;
    int arps_found = scan_list_arp_hosts();
    log_info("ARP entries found: %d", arps_found);

    return true;
}

void *scan_start_cli_thread(gpointer callback) {
    log_debug("scan_start_cli_thread called");
    assert(scan.init == 1);

    if(scan_util_is_running()){
        puts("SCAN: Already running");
        return (void *) 1;
    }
    scan.event_cb = callback;
    scan_notify_start(callback);

    if(scan.opt_print) puts("> Checking Known Lists first");
    if(scan_discover_known_hosts()){

        scan_notify_host_update(callback, scan.localhost);
        scan_notify_hosts(callback);

        if(scan.opt_print && (scan.opt_print_known_first || scan.opt_scan_known_only)){
            nm_host_print(scan.localhost);
            scan_print_mates(scan.hosts);
        }
        if(!scan.opt_scan_known_only){
            if(scan.opt_print) puts("> Known List Done, switching to scan");
            scan_discover_subnet_hosts(scan.opt_connect_threads > 0, scan.opt_listen_threads > 0);
            scan_notify_hosts(callback);
            if(scan.opt_print) {
                puts("> Scan Done, complete results...");
                puts("------------------------------");
                scan_print_mates(scan.hosts);
            }
        }
    }

    scan_notify_stop(callback);
    scan.event_cb = NULL;
    log_debug("scan_start_cli_thread ending");

    return NULL;
}


void scan_start() {
    log_debug("scan_start: called");
    assert(scan.init == 1);

    if(scan_util_is_running()){
        puts("scan_start: Already running");
        return;
    }
    scan.running = 1;
    

    if(!scan_list_localhost())
        log_info("Could not resolve localhost address details");
    //nm_host_print(scan.localhost);
    
    int routers_found = scan_list_gateways();
    log_debug("Router entries found: %d", routers_found);
    int arps_found = scan_list_arp_hosts();
    log_debug("ARP entries found: %d", arps_found);
    
    if(scan.opt_print_known_first || scan.opt_scan_known_only){
        puts("----- Known Lists ----->");
        scan_print_mates(scan.hosts);
    }
    
    if(!scan.opt_scan_known_only){
        printf("> Starting scan...");
        scan_discover_subnet_hosts(scan.opt_connect_threads > 0, scan.opt_listen_threads > 0);
        
        puts("Done!");
        puts("Scan Results: ------------------------------");
        scan_print_mates(scan.hosts);
    }
    
    scan.running = 0;

    log_debug("scan_start: end");

}


void scan_stop_threads(){
    if(scan.running){
        scan.quit_now = 1;
        scan_notify_stop(NULL);
    }
}

void scan_init(int print_known_first, int print_known_only, int skip_resolve,
               int conn_threads, int conn_timeout, int max_hosts, 
               int list_threads, int subnet_timeout, int subnet_offset) {
    if(scan.init)
        return;

    //if(print_stdout) scan.opt_print = true;
    scan.opt_print = true;
    if(print_known_first) scan.opt_print_known_first = true;
    if(print_known_only) scan.opt_scan_known_only = true;
    if(skip_resolve) scan.opt_skip_resolve = true;
    if(conn_threads > -1) scan.opt_connect_threads = conn_threads;
    if(conn_timeout > -1) scan.opt_connect_timeout_ms = conn_timeout;
    if(max_hosts > -1) scan.opt_max_hosts = max_hosts;
    if(list_threads > -1) scan.opt_listen_threads = list_threads;
    if(subnet_timeout > -1) scan.opt_subnet_timeout_ms = subnet_timeout;
    if(subnet_offset > -1) scan.opt_subnet_offset = subnet_offset;


    vendor_db_init();
    scan.quit_now = 0;
    scan.running = 0;
    scan.init = 1;

    log_debug("Scan initialised with options: ");
    log_debug("  print_stdout:  %i", scan.opt_print);
    log_debug("  known_first:   %i", scan.opt_print_known_first);
    log_debug("  known_only:    %i", scan.opt_scan_known_only);
    log_debug("  skip_resolve:  %i", scan.opt_skip_resolve);
    log_debug("  conn_thread:   %2i", scan.opt_connect_threads);
    log_debug("  conn_timeout:  %2i (ms)", scan.opt_connect_timeout_ms);
    log_debug("  list_thread:   %2i", scan.opt_listen_threads);
    log_debug("  max_hosts:     %i", scan.opt_max_hosts);
    log_debug("  scan_timeout:  %i (ms)", scan.opt_subnet_timeout_ms);
    
    
}

void scan_destroy(void) {
    if(!scan.init)
        return;

    scan.running = 0;
    vendor_db_destroy();

    //nm_host_destroy(scan.localhost);
    nm_list_foreach(host, scan.hosts)
        nm_host_destroy(host->data);
    nm_list_free(scan.hosts, false);
    
    scan.init = 0;
}

