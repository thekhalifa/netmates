#include "nm-scan.h"
#include "nm-common.h"

static scan_state scan = {
    .opt_poll_thread_work_ms = 10,
//         .opt_connect_threads = 8,
//         .opt_connect_timeout_ms = 100,
//         .opt_listen_threads = 10,
//         .opt_scan_timeout_ms = 10000,
};

/*Alexa
  Output TCP: *, 80, 8080, 443, 40317, 67, 68
* Output UDP: *, 53, 123, 40317, 49317, 33434, 1900, 5000, 5353
* Input TCP: 8080, 443, 40317
* Input UDP: 53, 67, 68, 1900, 50000, 5353, 33434, 49317, 40317
Other Checks:
- Amazon, port 60000
- UPnP, port 5000
Other ports:
- 5040
- 5948
- 7680
5357/tcp open  wsdapi, 137/udp open  netbios-ns, 5040/tcp open  unknown
5357/tcp open  wsdapi, 5948/tcp open  unknown, 7680/tcp open  pando-pub
*/


static const scan_port scan_port_list[] = {
    {.method = SCAN_TCP_CONNECT, .port = 21,
        .service = "ftp", .required = 1, .host_type = HOST_TYPE_PC},
    {.method = SCAN_TCP_CONNECT, .port = 80,
        .service = "http", .required = 1, .host_type = HOST_TYPE_PC},
    {.method = SCAN_TCP_CONNECT, .port = 443,
        .service = "https", .required = 1, .host_type = HOST_TYPE_PC},
    {.method = SCAN_UDP_SENDRECV, .port = 137,
        .service = "netbios-ns", .required = 1, .host_type = HOST_TYPE_PC,
        .query_payload = { .length = sizeof(UDP_QUERY_NBS), .message = UDP_QUERY_NBS } },
    {.method = SCAN_TCP_CONNECT, .port = 5357,
        .service = "wsd", .required = 1, .host_type = HOST_TYPE_PC},
    {.method = SCAN_UDP_SENDRECV, .port = 53,
        .service = "dns", .required = 1, .host_type = HOST_TYPE_ROUTER,
        .query_cb = probe_dns_generate_query_targetptr, .protocol = &proto_dns_definition },
    {.method = SCAN_TCP_CONNECT, .port = 22,
        .service = "ssh", .required = 1, .host_type = HOST_TYPE_PC},
    /* http alternatives */
    {.method = SCAN_TCP_CONNECT, .port = 1080,
        .service = "http-1080", .required = 0, .host_type = HOST_TYPE_PC},
    {.method = SCAN_TCP_CONNECT, .port = 8080,
        .service = "http-8080", .required = 0, .host_type = HOST_TYPE_PC},
    {.method = SCAN_TCP_CONNECT, .port = 8000,
        .service = "http-8000", .required = 0, .host_type = HOST_TYPE_PC},
    {.method = SCAN_TCP_CONNECT, .port = 8888,
        .service = "http-8888", .required = 0, .host_type = HOST_TYPE_PC},
    /* other */
    {.method = SCAN_TCP_CONNECT, .port = 445,
        .service = "smb", .required = 1, .host_type = HOST_TYPE_PC},
    {.method = SCAN_TCP_CONNECT, .port = 4070,
        .service = "alexa-4070", .required = 1, .host_type = HOST_TYPE_SMART_DEVICE},
    {.method = SCAN_TCP_CONNECT, .port = 62078,
        .service = "itunes-sync", .required = 1, .host_type = HOST_TYPE_PHONE},
    {.method = SCAN_TCP_CONNECT, .port = 633,
        .service = "ipp", .required = 1, .host_type = HOST_TYPE_PRINTER},
    {.method = SCAN_TCP_CONNECT, .port = 3306,
        .service = "mysql", .required = 0, .host_type = HOST_TYPE_PRINTER},
    /* -- */
    {.method = SCAN_TCP_CONNECT, .port = 6668,
        .service = "tuya", .required = 1, .host_type = HOST_TYPE_PRINTER},
    /* -- 
    {.method = SCAN_TCP_CONNECT, .port = 70,
        .service = "gopher", .required = 0, .host_type = HOST_TYPE_PC},
    {.method = SCAN_TCP_CONNECT, .port = 67,
        .service = "alexa-67", .required = 1, .host_type = HOST_TYPE_SMART_DEVICE},
    {.method = SCAN_TCP_CONNECT, .port = 68,
        .service = "alexa-68", .required = 1, .host_type = HOST_TYPE_SMART_DEVICE},
    {.method = SCAN_TCP_CONNECT, .port = 40317,
        .service = "alexa-40317", .required = 1, .host_type = HOST_TYPE_SMART_DEVICE},
    {.method = SCAN_TCP_CONNECT, .port = 55442,
        .service = "alexa-55442", .required = 1, .host_type = HOST_TYPE_SMART_DEVICE},
    {.method = SCAN_TCP_CONNECT, .port = 55443,
        .service = "alexa-55443", .required = 1, .host_type = HOST_TYPE_SMART_DEVICE},
    -- */
};

    //experimenting, never contacted -dgm before
//     {.port = 5040, .service = "?-5040", .protocol = SCAN_PROTO_TCP, .required = 0,
//         .device_type = HOST_TYPE_PC},
//     {.port = 5948, .service = "?-5948", .protocol = SCAN_PROTO_TCP, .required = 0, 
//         .device_type = HOST_TYPE_PC},
//     {.port = 7680, .service = "?-7680", .protocol = SCAN_PROTO_TCP, .required = 0,
//         .device_type = HOST_TYPE_PC},
// };


static const scan_port scan_listen_list[] = {
//     {.port.port = 5353, .port.service = "mdns", .port.required = 1,
//         .min_time = 100, .max_time = 2000, .bind_port = 0,
//         .mc_join = 0, .mc_ip = "224.0.0.251",
//         .query_cb = probe_mdns_query, .response_cb = probe_mdns_response
//     },
    {.method = SCAN_UDP_SENDRECV, .port = 5353,
        .service = "mdns", .required = 1,
        .bind_port = 0, .mc_join = 0, .mc_ip = "224.0.0.251",
        .min_time = 100, .max_time = 2000, 
        .query_cb = probe_mdns_generate_query, .response_cb = probe_mdns_response,
        .protocol = &proto_mdns_definition,
    },
//     {.method = SCAN_UDP_SENDRECV, .port = 5353,
//         .service = "mdns-mc", .required = 1,
//         .bind_port = 5353, .mc_join = 1, .mc_ip = "224.0.0.251",
//         .min_time = 200, .max_time = 30000, 
//         .query_cb = NULL, .response_cb = NULL,
//         .protocol = &proto_mdns_definition,
//     },

//     {.port.port = 1900, .port.service = "ssdp", .port.required = 1,
//         .min_time = 100, .max_time = 2000, .bind_port = 0,
//         .mc_join = 1, .mc_ip = "239.255.255.250",
//         .query_cb = probe_ssdp_query, .response_cb = probe_ssdp_response
//     },
//     {.port.port = 6771, .port.service = "bittorrent-lsd", .port.required = 1,
//         .min_time = 200, .max_time = 2000, .bind_port = 6771,
//         .mc_join = 1, .mc_ip = "239.192.152.143",
//         .query_cb = NULL, .response_cb = NULL
//     },
//     {.port.port = 6667, .port.service = "tuya-bc", .port.required = 1,
//         .port.device_type = HOST_TYPE_SMART_DEVICE,
//         .min_time = 200, .max_time = 2000, .bind_port = 6667,
//         .mc_join = 0,
//         .query_cb = NULL, .response_cb = scan_response_ack
//     },
};


bool scan_util_is_running(){

    if(scan.running && !scan.quit_now)
        return true;

    return false;
}


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


bool scan_util_calc_subnet_range(const char *ip, const char *netmask, scan_range *range) {
    if(ip == NULL || netmask == NULL || strlen(ip) == 0 || strlen(netmask) == 0)
        return false;

    memset(range, 0, sizeof(scan_range));
    struct in_addr host_addr, mask_addr;
    inet_aton(ip, &host_addr);
    inet_aton(netmask, &mask_addr);

    if(mask_addr.s_addr < NL_MIN_NETMASK_VALUE)
        mask_addr.s_addr = NL_MIN_NETMASK_VALUE;

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

scan_result *scan_result_init(enum scan_host_state resp, in_addr_t addr, uint16_t port) {

    scan_result *result = malloc(sizeof(scan_result));
    memset(result, 0, sizeof(scan_result));

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
        nm_list_free(result->services, true);
    }
    free(result);
}

void scan_print_mates(nmlist *hosts, bool showtotal) {
    if(hosts == NULL)
        return;

    uint numentries = 0;
    nm_list_foreach(entry, hosts) {
        numentries++;
        //nm_host_print((nm_host *)entry->data);
        nm_host_print_wide((nm_host *)entry->data);
    }
    if(showtotal)
        printf("\n- Total Network Mates: %d  \n", numentries);
}

int scan_resolve_hostname_from_inaddr(uint32_t ip_addr, char *hostname_buffer, size_t buffer_size) {
    assert(ip_addr != 0);
    assert(hostname_buffer != NULL);

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
    struct sockaddr_in6 addr;
    addr.sin6_port = 0;
    addr.sin6_family = AF_INET6;
    //addr.sin6_addr.s_addr = inet_addr(ip);
    inet_pton(AF_INET6, ip, &addr.sin6_addr);
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

int scan_socket_bind(int sd, uint16_t port, char *logsign) {
    
    log_trace("%s Binding to port %i", logsign, port);
    struct sockaddr_in addr;
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if(bind(sd, (struct sockaddr *) & addr, sizeof(addr)) < 0){
        log_debug("%s Could not bind to port %i, err: %i, %s \n",
                  logsign, port, errno, strerror(errno));
        return errno;
    }
    return 0;
}

int scan_socket_join_mc(int sd, const char *mcip, const char *logsign) {
    
    assert(mcip != NULL);
    log_trace("%s Joining multicast group %s", logsign, mcip);
    
    struct ip_mreqn mcast_membership;
    int mc_loop = 0;
    
    mcast_membership.imr_ifindex = 0;
    mcast_membership.imr_address.s_addr = INADDR_ANY;
    mcast_membership.imr_multiaddr.s_addr = inet_addr(mcip);
    if(setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
        &mcast_membership, sizeof(mcast_membership)) == -1){
        return errno;
    }
    
    if(setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &mc_loop, sizeof(mc_loop)) == -1)
        log_debug("%s socket set option mc loop err: %i, %s ",
                    logsign, errno, strerror(errno));
    return 0;
}

struct sockaddr_in scan_socket_new_addr4(uint16_t port, const char *ip) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    return addr;
}

bool probe_send_proto_query(int sd, scan_port *sp, const char *logsign){
    assert(sd > 0);

    log_trace("%s Sending protocol queries", logsign);
    
    size_t msgsize;
    int queries_sent = 0;
    ssize_t bytes_sent;
    char buff[NM_GEN_BUFFSIZE];
    proto_def *proto = sp->protocol;
    proto_query *query = proto->queries;

    struct sockaddr_in send_addr = scan_socket_new_addr4(sp->port, proto->send_ip);
    
    while(query->message) {

        msgsize = sp->query_cb((void *)buff, sizeof(buff), query->message, send_addr.sin_addr);
        if(!msgsize)
            log_debug("%s Protocol message empty", logsign);
        
        bytes_sent = sendto(sd, buff, msgsize, 0, (struct sockaddr*)&send_addr, sizeof(send_addr));
        if(bytes_sent < 0){
            log_debug("%s Could not send probe query, err %i, %s",
                      logsign, errno, strerror(errno));
            return false;
        }
        log_trace("%s Sent query with %li bytes", logsign, bytes_sent);
        query = query + 1;
        queries_sent++;
    }
    
    log_debug("%s probe_send_proto_query: sent %i queries", logsign, queries_sent);
    
    return true;
}


int probe_connect_tcp(const char *thread_id, scan_result *result, 
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

    /* check poll result and socket state */
    if(poll_ret > 0){
        //poll has connect() success or error is connection refused, both mean host is live
        if(so_error == 0 || so_error == ECONNREFUSED){
            result->response = SCAN_HSTATE_LIVE;
            if(so_error == 0) {
                result->host_type = port_def->host_type;
                result->services = nm_list_add(result->services, strdup(port_def->service));
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
        //-- log_trace("%s\t poll - timeout, port %i, sockerrno %i, errdesc: %s",
        //--          thread_id, port_def->port, so_error, strerror(so_error));
    }else{
        //poll error
        //-- log_trace("%s\t poll - error with port %i, error errno: %i, errdesc: %s", 
        //--         thread_id, port_def->port, errno, strerror(errno));
    }
    
    close(sd);
    return 0;
}


int probe_sendrecv_udp(const char *thread_id, scan_result *result, 
                          scan_port *port_def, struct in_addr ip_addr) {

    int sd, send_ret, recv_ret, poll_ret;
    struct sockaddr_in target_addr;
    socklen_t addr_size;
    struct pollfd poll_arg;
    char *bufftosend = NULL;
    int sizetosend = 0;
    char sendbuffer[NM_GEN_BUFFSIZE];
    char recvbuffer[NM_GEN_BUFFSIZE];
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
    

    if(port_def->query_payload.length){
        bufftosend = port_def->query_payload.message;
        sizetosend = port_def->query_payload.length;
        log_trace("%s\t Selecting query buffer for port %hu, size %i", thread_id, port_def->port, sizetosend);
    }else if(port_def->query_cb && port_def->protocol && port_def->protocol->queries){
        sizetosend = port_def->query_cb((void *)sendbuffer, sizeof(sendbuffer), 
                                        port_def->protocol->queries->message, ip_addr);
        bufftosend = sendbuffer;
        log_trace("%s\t Selecting query callback for port %hu, size %i", thread_id, port_def->port, sizetosend);
    }else{
        log_trace("%s\t Invalid query definition, port %i\n", thread_id, port_def->port);
        return -EIO;
    }
    // send the buffer
    //TODO: This thing keeps sending 2 bytes. Is it the sizetosend? what?
    nm_log_trace_bytes("probe_sendrecv_udp", bufftosend, sizetosend);
    send_ret = sendto(sd, bufftosend, sizetosend, 0,
                      (struct sockaddr*)&target_addr, addr_size);
    
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
    log_trace("%s\t recvfrom returned: %i\n", thread_id, recv_ret);
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
    log_trace("%s\t poll returned: %i\n", thread_id, poll_ret);
    /* check poll result and socket state */
    if(poll_ret > 0 && poll_arg.revents & POLL_IN){
        //poll has data from recvfrom
        result->response = SCAN_HSTATE_LIVE;
        result->host_type = port_def->host_type;
        result->services = nm_list_add(result->services, strdup(port_def->service));
        log_trace("%s host found, receive from port %hu", 
                    thread_id, port_def->port);
    }
    
    close(sd);
    return 0;
}

bool scan_response_ack(scan_result *result, const uint8_t *in_buffer, ssize_t in_size) {
    //log_trace("scan_response_ack: host type: %i", result->host_type);
    result->response = SCAN_HSTATE_LIVE;
    return true;
}

bool scan_response_log(scan_result *result, const uint8_t *in_buffer, ssize_t in_size) {
    result->response = SCAN_HSTATE_LIVE;
    nm_log_trace_bytes("scan_log_response", in_buffer, in_size);
    return true;
}

void scan_process_result(scan_result *result, int *live_counter) {
    assert(result != NULL);
    assert(live_counter != NULL);
    assert(result->response != SCAN_HSTATE_UNKNOWN);

    nm_host *host;
    char *ip;

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

    }else
        log_trace("scan_process_result: received non-live result: %i, %s",
                  result->response, inet_ntoa(result->target_addr));
    
    scan_result_destroy(result);
}


gpointer scan_main_listen_thread(gpointer data){
    log_trace("scan_main_listen_thread starting");
    unsigned long start_time = nm_time_ms();


    int num_listen_ports = sizeof(scan_listen_list) / sizeof(scan_listen_list[0]);
    int num_results = 0, num_live = 0;
    int scan_timeout_ms = scan.opt_scan_timeout_ms;
    GThreadPool *thread_pool;
    GAsyncQueue *results_queue;
    GError *error = NULL;

    if(!scan_util_is_running() || scan.quit_now)
        return NULL;
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
            return NULL;
        if(!scan_util_is_running())
            break;
        log_trace("scan_main_listen_thread, pushing work: %i", i);
        g_thread_pool_push(thread_pool, (gpointer)&scan_listen_list[i], &error);
        if(error != NULL){
            log_info("scan_main_listen_thread: error pushing entry %i \n", i);
            g_error_free(error);
        }
    }

    //poll status of received results
    log_trace("scan_main_listen_thread, polling results");
    scan_result *result;
    uint32_t unused_work, running_threads, returned_count;
    for(;;) {
        if(scan.quit_now)
            return NULL;
        if(!scan_util_is_running())
            break;

        //check work done by the thread pool
        unused_work = g_thread_pool_unprocessed(thread_pool);
        running_threads = g_thread_pool_get_num_threads(thread_pool);
        if(unused_work == 0 && running_threads == 0)
            break;
        //check if results are pending, process some
        while((result = g_async_queue_try_pop(results_queue))){
            scan_process_result(result, &num_live);
            num_results++;
        }
        //log_trace("scan_main_listen_thread, going to sleep: num_results: %i", num_results);
        usleep(scan.opt_poll_thread_work_ms * 1000);
        if(nm_time_ms_diff(start_time) > scan_timeout_ms){
            log_info("scan_main_listen_thread: Subnet scan timeout reached %u ms \n", scan_timeout_ms);
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
    for(int i=0; i<returned_count; i++){
        if(scan.quit_now)
            return NULL;
        if(!scan_util_is_running())
            break;
        result = g_async_queue_pop(results_queue);
        scan_process_result(result, &num_live);
        num_results++;
    }

    log_info("scan_main_listen_thread: discovery summary: total ports %i found %i results in %lus]\n",
              num_listen_ports, num_live, nm_time_ms_diff(start_time) / 1000);

    g_async_queue_unref(results_queue);

    log_trace("scan_main_listen_thread: ending");
    return NULL;
}

void scan_listen_thread(gpointer target_data, gpointer results_data) {
    log_trace("scan_listen_thread called");

    int sd, max_wait_time, min_wait_time;
    long int recv_ret, poll_ret, actual_size;
    unsigned long thread_start;
    char thread_signature[64];
    char sender_ip_buffer[NM_MAX_BUFF_IP6];
    char hostname_buffer[NM_MAX_BUFF_HOST];
    char recv_buffer[NM_LARGE_BUFFSIZE];
    uint16_t port_num, sender_port;
    socklen_t recv_addr_size;
    struct pollfd poll_arg;
    struct sockaddr_in recv_addr;

    nmtable *response_ip_hostname = nm_table_new();
    scan_port *port_def;
    scan_result *result;
    GAsyncQueue *results_queue = results_data;

    thread_start = nm_time_ms();
    if(!scan_util_is_running() || scan.quit_now)
        return;

    //prepare results and listen port
    port_def = target_data;
    min_wait_time = port_def->min_time;
    max_wait_time = port_def->max_time;
    port_num = (uint16_t)port_def->port;
    sprintf(thread_signature, "[ListTh<%lx>, Port<%u>]", (intptr_t)g_thread_self(), port_num);

    sd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_IP);
    if(sd < 0){
        log_info("%s socket errno: %i, errdesc: %s", thread_signature, errno, strerror(errno));
        log_debug("%s End listen thread [time: %lu ms]!", thread_signature, nm_time_ms_diff(thread_start));
        return;
    }

    //set multicast membership if needed
    if(port_def->mc_join && scan_socket_join_mc(sd, port_def->mc_ip, thread_signature)){
        log_warn("%s socket failed to join multicast errno: %i, errdesc: %s",
                    thread_signature, errno, strerror(errno));
    }

    if(port_def->bind_port && scan_socket_bind(sd, port_def->bind_port, thread_signature)){
        log_debug("%s End listen thread [time: %lu ms]!",
                    thread_signature, nm_time_ms_diff(thread_start));
        return;
    }

    if(!scan_util_is_running() || scan.quit_now)
        return;

    if(port_def->query_cb){
        probe_send_proto_query(sd, port_def, thread_signature);
//         log_debug("%s Executing query callback", thread_signature);
//         if(!(listen_port->query_cb)(sd, listen_port))
//             log_debug("%s Error with query callback", thread_signature);
    }

    poll_arg.events = POLLIN;
    poll_arg.fd = sd;
    log_debug("%s Listening on port %hi", thread_signature, port_num);

    while (nm_time_ms_diff(thread_start) <= max_wait_time){
        if(scan.quit_now)
            return;
        if(!scan_util_is_running())
            break;

        memset(&recv_addr, 0, sizeof(struct sockaddr_in));
        recv_addr_size = sizeof(recv_addr);
        recv_ret = recvfrom(sd, recv_buffer, sizeof(recv_buffer), 0,
                            (struct sockaddr*)&recv_addr, &recv_addr_size);
        
        if(recv_ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)){
            poll_ret = poll(&poll_arg, 1, min_wait_time);
            if(poll_ret >= 0){
                continue;
            }
            //else report the error
            log_trace("%s Poll error on port %i, errno: %i, errdesc: %s",
                      thread_signature, port_num, errno, strerror(errno));
        }else if(recv_ret == -1) {
            //else report the error
            log_trace("%s recvfrom unexpected error on port %i, errno: %i, errdesc: %s",
                      thread_signature, port_num, errno, strerror(errno));
            break;
        }
        
        //now check the data received
        inet_ntop(AF_INET, &recv_addr.sin_addr, sender_ip_buffer, sizeof(sender_ip_buffer));
        sender_port = ntohs(recv_addr.sin_port);
        actual_size = recv_ret < sizeof(recv_buffer) ? recv_ret : (long)sizeof(recv_buffer);
        log_debug("%s data on port %i, size %li from %s:%hu",
                  thread_signature, port_num, actual_size, sender_ip_buffer, sender_port);
        
        result = malloc(sizeof(scan_result));
        memset(result, 0, sizeof(scan_result));
        result->target_addr = recv_addr.sin_addr;
        result->response = SCAN_HSTATE_LIVE;
        //result->direction = SCAN_DIR_LISTEN;
        result->host_type = port_def->host_type;
        
        //resolve hostname if it's not yet, else leave it empty
        if(!scan.opt_skip_resolve && 
            nm_table_get_num(response_ip_hostname, result->target_addr.s_addr) == NULL) {
            
            scan_resolve_hostname_from_inaddr(result->target_addr.s_addr,
                                                hostname_buffer, sizeof(hostname_buffer));
            result->hostname = strdup(hostname_buffer);
            nm_table_set_num(response_ip_hostname, result->target_addr.s_addr, result->hostname);
        }
        //port-specific response processing
        if(port_def->response_cb != NULL){
            log_trace("%s Executing response callback", thread_signature);
            //TODO: process probe results
            if(!(port_def->response_cb)(result, (uint8_t*)recv_buffer, actual_size))
                log_trace("%s Error with response callback", thread_signature);
        }
        
        g_async_queue_push(results_queue, result);
    }
    
    nm_table_free(response_ip_hostname);
    log_debug("%s End listen thread [time: %lu ms]!", thread_signature, nm_time_ms_diff(thread_start));
}

gpointer scan_main_connect_thread(gpointer data){
    log_trace("scan_main_connect_thread: starting");
    unsigned long start_time = nm_time_ms();

    uint32_t curr_addr, curr_num;
    int num_scanned = 0, num_live = 0;
    int scan_timeout_ms = scan.opt_scan_timeout_ms;

    GThreadPool *thread_pool;
    GAsyncQueue *results_queue;
    GError *error = NULL;

    if(!scan_util_is_running() || scan.quit_now)
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
            return NULL;
        if(!scan_util_is_running())
            break;

        curr_addr = ntohl(curr_num);

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
            return NULL;
        if(!scan_util_is_running())
            break;

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
        usleep(scan.opt_poll_thread_work_ms * 1000);
        if(nm_time_ms_diff(start_time) > scan_timeout_ms){
            scan.running = 0;
            log_info("scan_main_connect_thread: Subnet scan timeout reached %u ms \n", scan_timeout_ms);
            break;
        }
    }
    g_thread_pool_free(thread_pool, false, true);

    returned_count = g_async_queue_length(results_queue);
    for(int i=0; i<returned_count; i++){
        if(scan.quit_now)
            return NULL;
        if(!scan_util_is_running())
            break;
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


void scan_connect_thread(gpointer target_data, gpointer results_data) {
    
    log_trace("scan_connect_thread called");
    int port_index, ports_to_scan, ret = 0;
    char *ip_str, thread_id[64], hostname_buffer[NM_MAX_BUFF_HOST];
    struct in_addr ip_addr;
    scan_port port_def;
    scan_result *result;
    GAsyncQueue *results_queue;

    //time this thread
    long unsigned thread_start = nm_time_ms();
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
    result->host_type = HOST_TYPE_UNKNOWN;

    //prepare connect_ports and address
    ports_to_scan = sizeof(scan_port_list) / sizeof(scan_port_list[0]);

    log_trace("%s Starting scan for %i ports", thread_id, ports_to_scan);
    port_index = 0;
    for(; port_index < ports_to_scan; port_index++){
        if(scan.quit_now)
            return;
        if(!scan_util_is_running())
            break;

        port_def = scan_port_list[port_index];
        if(result->response == SCAN_HSTATE_LIVE && port_def.required == 0 &&
            !scan.opt_scan_all)
            continue;
        
        if(port_def.method == SCAN_TCP_CONNECT)
            ret = probe_connect_tcp(thread_id, result, &port_def, ip_addr);
        else if(port_def.method == SCAN_UDP_SENDRECV)
            ret = probe_sendrecv_udp(thread_id, result, &port_def, ip_addr);
        
        if(ret)
            break;
    }

    if(port_index >= 0 && result->response == SCAN_HSTATE_UNKNOWN){
        log_trace("%s host dead, ", thread_id);
        result->response = SCAN_HSTATE_DEAD;
    }else if(result->response == SCAN_HSTATE_LIVE){
        if(!scan.opt_skip_resolve && scan_resolve_hostname(ip_str, hostname_buffer, sizeof(hostname_buffer)))
            result->hostname = strdup(hostname_buffer);
    }
    g_async_queue_push(results_queue, result);

    log_trace("%s End scan thread [time: %lu ms]!", thread_id, nm_time_ms_diff(thread_start));
}


bool scan_discover_subnet(int connect, int listen) {
    log_trace("scan_discover_subnet_hosts starting, connect: %i, listen: %i",
                connect, listen);
    
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
    log_trace("scan_discover_subnet_hosts: start waiting for connect");
    if(connect)
        g_thread_join(conn_thread);

    log_trace("scan_discover_subnet_hosts: start waiting for listen");
    if(listen)
        g_thread_join(list_thread);

    log_trace("scan_discover_subnet_hosts ending");
    return true;

}


int scan_list_arp_hosts(){
    log_trace("scan_list_arp_hosts: called");
    
    FILE *arp_fd;
    nm_host *entry;

    char line[NM_GEN_BUFFSIZE], ip_buffer[NM_MAX_BUFF_IP], host_buffer[NM_MAX_BUFF_HOST];
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
    char line[NM_GEN_BUFFSIZE], ip_buffer[NM_MAX_BUFF_IP], host_buffer[NM_MAX_BUFF_HOST];
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

            //update ip and hostname, where hostname is host or ip, whichever we have
            if(!scan.opt_skip_resolve && scan_resolve_hostname(ip_buffer, host_buff, sizeof(host_buff)))
                nm_host_set_attributes(scan.localhost, ip_buffer, NULL, NULL, NULL, host_buff);
            else
                nm_host_set_attributes(scan.localhost, ip_buffer, NULL, NULL, NULL, NULL);
            
            if(ifa->ifa_netmask != NULL){
                struct sockaddr_in *nmv = (struct sockaddr_in*)ifa->ifa_netmask;
                nm_host_set_attributes(scan.localhost, NULL, NULL, inet_ntoa(nmv->sin_addr), NULL, NULL);
            }

        } else if (family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr, ip6_buffer, sizeof(ip6_buffer));
            nm_host_set_attributes(scan.localhost, NULL, ip6_buffer, NULL, NULL, NULL);
        } else if (family == AF_PACKET) {
            nm_format_hw_address(hwaddr_buffer, sizeof(hwaddr_buffer), (struct sockaddr_ll *) ifa->ifa_addr);
            if(!scan.opt_skip_resolve)
                nm_update_hw_vendor(hwaddr_buffer, sizeof(hwaddr_buffer));
            nm_host_set_attributes(scan.localhost, NULL, NULL, NULL, hwaddr_buffer, NULL);
        }
    }
    freeifaddrs(if_addr);
    
    scan.hosts = nm_host_merge_in_list(scan.hosts, scan.localhost);
    
    return true;

}


void scan_start() {
    log_trace("scan_start: called");
    assert(scan.init == 1);

    if(scan_util_is_running()){
        puts("scan_start: already running");
        return;
    }
    scan.running = 1;
    unsigned long starttime = nm_time_ms();

    if(!scan_list_localhost())
        log_warn("Could not resolve localhost address details");
    //nm_host_print(scan.localhost);
    
    if(!scan.opt_scan_only){
        int routers_found = scan_list_gateways();
        log_info("Router entries found: %d", routers_found);
        int arps_found = scan_list_arp_hosts();
        log_info("ARP entries found: %d", arps_found);
    
    }
    if(scan.opt_known_first || scan.opt_known_only){
        puts("- Known Lists: -->");
        scan_print_mates(scan.hosts, true);
        if(scan.opt_known_only)
            return;
    }
    
    if(!scan.opt_known_only){
        printf("- Starting scan...\n");
        scan_discover_subnet(scan.opt_connect_threads > 0, scan.opt_listen_threads > 0);
        puts("- Results: -->");
        scan_print_mates(scan.hosts, false);
    }
    
    scan.running = 0;
    printf("- Scan done in %.1fs with %i hosts found\n", 
           nm_time_ms_diff(starttime) / 1000.0f, nm_list_len(scan.hosts));

    log_trace("scan_start: end");

}


void scan_stop(){
    if(scan.running)
        scan.quit_now = 1;
}

void scan_init(){

    if(scan.init)
        return;

    vendor_db_init();
    scan.quit_now = 0;
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

scan_state * scan_getstate() {
    return &scan;
}
