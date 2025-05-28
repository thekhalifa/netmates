#include "nm-probe.h"

static probe_port probe_port_connect_list[] = {
    //rfc 2616
    {   .method = PROBE_TCP_CONNECT, .port = 80,    .service = "http", .required = 1, .host_type = HOST_TYPE_PC },
    {   .method = PROBE_TCP_CONNECT, .port = 5357,  .service = "wsd", .required = 1, .host_type = HOST_TYPE_PC_WIN},
    {
        .method = PROBE_UDP_SENDRECV, .port = 137,  .service = "netbios-ns", .required = 1, .host_type = HOST_TYPE_PC,
        .query_payload = { .length = sizeof(PROTO_NBS_QUERY), .message = PROTO_NBS_QUERY }
    },
    {
        .method = PROBE_UDP_SENDRECV, .port = 53,   .service = "dns", .required = 1, .host_type = HOST_TYPE_ROUTER,
        .query_cb = proto_generate_query_dns_targetptr, .protocol = &proto_dns_definition
    },
    {   .method = PROBE_TCP_CONNECT, .port = 22,    .service = "ssh", .required = 1, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 443,   .service = "https", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 139,   .service = "netbios-ssn", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 445,   .service = "smb-ds", .required = 0, .host_type = HOST_TYPE_PC},
    //iphone, usually no ACK
    {   .method = PROBE_TCP_CONNECT, .port = 62078, .service = "itunes", .required = 1, .host_type = HOST_TYPE_PHONE},
    /* Additional services */
    {   .method = PROBE_TCP_CONNECT, .port = 631,   .service = "ipp", .required = 1, .host_type = HOST_TYPE_PRINTER},
    {   .method = PROBE_TCP_CONNECT, .port = 9100,  .service = "hp-print", .required = 0, .host_type = HOST_TYPE_PRINTER},
    {   .method = PROBE_TCP_CONNECT, .port = 4070,  .service = "alexa-spotify", .required = 0, .host_type = HOST_TYPE_DEVICE},
    {   .method = PROBE_TCP_CONNECT, .port = 3306,  .service = "mysql", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 21,    .service = "ftp", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 6668,  .service = "tuya", .required = 0, .host_type = HOST_TYPE_DEVICE},
    {   .method = PROBE_TCP_CONNECT, .port = 1883,  .service = "mqtt", .required = 0, .host_type = HOST_TYPE_DEVICE},
    /* Obscure services and non-standard ports */
    {   .method = PROBE_UDP_SENDRECV, .port = 5351, .service = "nat-pmp", .required = 1, .host_type = HOST_TYPE_ROUTER,
        .query_payload = { .length = 2, .message = "\0\0" }
    },
    {   .method = PROBE_TCP_CONNECT, .port = 5900,  .service = "vnc", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 25,    .service = "smtp", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 88,    .service = "kerberos", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 110,   .service = "pop3", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 995,   .service = "pop3s", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 123,   .service = "ntp", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 143,   .service = "imap", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 993,   .service = "imaps", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 389,   .service = "ldap", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 636,   .service = "ldaps", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 70,    .service = "gopher", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 79,    .service = "finger", .required = 0, .host_type = HOST_TYPE_PC},
    /* http alternatives */
    {   .method = PROBE_TCP_CONNECT, .port = 1080,  .service = "http", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 8000,  .service = "http", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 8008,  .service = "http", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 8080,  .service = "http", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 8443,  .service = "https", .required = 0, .host_type = HOST_TYPE_PC},
    {   .method = PROBE_TCP_CONNECT, .port = 8888,  .service = "http", .required = 0, .host_type = HOST_TYPE_PC},
    /* amazon echo - maybe even alexa-40317 */
    {   .method = PROBE_TCP_CONNECT, .port = 55442, .service = "alexa", .required = 0, .host_type = HOST_TYPE_DEVICE},
    {   .method = PROBE_TCP_CONNECT, .port = 55443, .service = "alexa", .required = 0, .host_type = HOST_TYPE_DEVICE},
    /* apple ports */
    {   .method = PROBE_TCP_CONNECT, .port = 548,   .service = "afp", .required = 0, .host_type = HOST_TYPE_PC_MAC},
    {   .method = PROBE_TCP_CONNECT, .port = 2195,  .service = "apns", .required = 0, .host_type = HOST_TYPE_PC_MAC},
    {   .method = PROBE_TCP_CONNECT, .port = 2196,  .service = "apns", .required = 0, .host_type = HOST_TYPE_PC_MAC},
    {   .method = PROBE_TCP_CONNECT, .port = 2197,  .service = "apns", .required = 0, .host_type = HOST_TYPE_PC_MAC},
    {}
};


static probe_port probe_port_listen_list[] = {
    {
        .method = PROBE_UDP_SENDRECV, .port = 1900, .service = "ssdp", .required = 1,
        .bind_port = 0, .mc_join = 1, .mc_ip = "239.255.255.250", .send_ip = "239.255.255.250",
        .min_time = 100, .max_time = 60000,
        .query_cb = probe_generate_query_string, .response_cb = probe_response_ssdp,
        .protocol = &proto_ssdp_definition,
    },
    {
        .method = PROBE_UDP_RECV, .port = 1900, .service = "ssdp", .required = 1,
        .bind_port = 1900, .mc_join = 0, .mc_ip = "239.255.255.250", .bind_fail_confirms = 1,
        .min_time = 100, .max_time = 60000,
        .query_cb = NULL, .response_cb = probe_response_ssdp,
        .protocol = &proto_ssdp_definition,
    },
    {
        .method = PROBE_UDP_SENDRECV, .port = 5353, .service = "mdns", .required = 1, .family = PROBE_FAMILY_INET6,
        //.bind_port = 5353, .mc_join = 1, .mc_ip = "ff02::fb", .send_ip = "ff02::fb",
        .bind_port = 5353, .mc_join = 1, .mc_ip = "ff02::fb", .send_ip = "ff02::fb",
        .min_time = 100, .max_time = 60000,
        .query_cb = proto_generate_query_mdns, .response_cb = probe_response_mdns,
        .protocol = &proto_mdns_definition,
    },
    {
        .method = PROBE_UDP_SENDRECV, .port = 5353, .service = "mdns", .required = 1,
        .bind_port = 0, .mc_join = 1, .mc_ip = "224.0.0.251", .send_ip = "224.0.0.251",
        .min_time = 100, .max_time = 60000,
        .query_cb = proto_generate_query_mdns, .response_cb = probe_response_mdns,
        .protocol = &proto_mdns_definition,
    },
    {
        .method = PROBE_UDP_RECV, .port = 5353, .service = "mdns", .required = 1,
        .bind_port = 5353, .mc_join = 0, .mc_ip = "224.0.0.251", .bind_fail_confirms = 1,
        .min_time = 100, .max_time = 60000,
        .query_cb = NULL, .response_cb = probe_response_mdns,
        .protocol = &proto_mdns_definition,
    },
    {
        .method = PROBE_UDP_RECV, .port = 6771, .service = "bt-lsd", .required = 1,
        .bind_port = 6771, .mc_join = 1, .mc_ip = "239.192.152.143", .bind_fail_confirms = 1,
        .min_time = 200, .max_time = 60000,
        .query_cb = NULL, .response_cb = probe_response_ack,
    },
    {
        .method = PROBE_UDP_RECV, .port = 6666, .service = "tuya", .required = 1, .host_type = HOST_TYPE_DEVICE,
        .bind_port = 6666, .mc_join = 0,
        .min_time = 200, .max_time = 10000,
        .query_cb = NULL, .response_cb = probe_response_ack,
    },
    {
        .method = PROBE_UDP_RECV, .port = 6667, .service = "tuya", .required = 1, .host_type = HOST_TYPE_DEVICE,
        .bind_port = 6667, .mc_join = 0,
        .min_time = 200, .max_time = 10000,
        .query_cb = NULL, .response_cb = probe_response_ack,
    },
    {
        .method = PROBE_UDP_RECV, .port = 138, .service = "netbios-ds", .required = 1, .host_type = HOST_TYPE_DEVICE,
        .bind_port = 138, .mc_join = 0,
        .min_time = 200, .max_time = 30000,
        .query_cb = NULL, .response_cb = probe_response_ack,
    },
    {}
};


void probe_result_destroy(probe_result *result)
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

probe_port *probe_get_connect_ports()
{
    return probe_port_connect_list;
}

probe_port *probe_get_listen_ports()
{
    return probe_port_listen_list;
}

int probe_count_connect_ports()
{
    int count = 0;
    const probe_port *ports = probe_port_connect_list;
    while ( (ports++)->method ) {
        count++;
    }
    
    return count;
}

int probe_count_listen_ports()
{
    int count = 0;
    const probe_port *ports = probe_port_listen_list;
    while ( (ports++)->method ) {
        count++;
    }
    
    return count;
}

bool probe_response_ack(probe_result *result, const uint8_t *in_buffer, ssize_t in_size)
{
    result->response = PROBE_HSTATE_LIVE;
    if (result->port_def) {
        result->services = nm_list_add(result->services, strdup(result->port_def->service));
    }
    return true;
}

bool probe_response_log(probe_result *result, const uint8_t *in_buffer, ssize_t in_size)
{
    result->response = PROBE_HSTATE_LIVE;
    nm_log_trace_bytes("scan_log_response", in_buffer, in_size);
    return true;
}

bool probe_send_proto_query(int sd, probe_port *sp, const char *logsign)
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

    ssize_t saddrsize = probe_sock_addr_from_ip((struct sockaddr *)&saddr, sp->family, sp->send_ip, sp->port);
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
        }
        log_trace("%s Sent query with %li bytes", logsign, bytes_sent);
        query = query + 1;
        queries_sent++;
    }

    log_debug("%s probe_send_proto_query: sent %i queries", logsign, queries_sent);
    return true;
}


int probe_connect_tcp(const char *thread_id, probe_result *result,
                      probe_port *port_def, struct in_addr *inaddr, int timeoutms)
{
    int sd, cnct_ret, poll_ret, so_error;
    struct sockaddr_in6 saddr6;
    ssize_t saddrsize = 0;
    struct pollfd poll_arg;


    sd = socket(PROBE_FAMILY_TO_AF(port_def->family), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_IP);
    if (sd < 0) {
        log_debug("%s\t socket errno: %i, errdesc: %s", thread_id, errno, strerror(errno));
        result->response = PROBE_HSTATE_ERROR;
        return -EIO;
    }

    saddrsize = probe_sock_set_saddr((struct sockaddr *)&saddr6, port_def->family, inaddr, port_def->port);

    //log_debug("%s connecting to port %hu", thread_id, port_def->port);
    cnct_ret = connect(sd, (struct sockaddr *)&saddr6, saddrsize);
    if (cnct_ret != -1 || errno != EINPROGRESS) {
        log_debug("%s\t connect unexpected error on port %i, errno: %i, errdesc: %s\n", thread_id, port_def->port,
                  errno, strerror(errno));
        result->response = PROBE_HSTATE_ERROR;
        close(sd);
        return -EIO;
    }

    poll_arg.fd = sd;
    /* include err event as open connect_ports can be too quick */
    poll_arg.events = POLL_IN | POLL_OUT | POLL_ERR;
    poll_ret = poll(&poll_arg, 1, timeoutms);
    //log_trace("%s poll on port %hu returned %i", thread_id, port_def->port, poll_ret);
    so_error = probe_sock_get_error(sd);

    /* check poll result and socket state */
    if (poll_ret > 0) {
        //poll has connect() success or error is connection refused, both mean host is live
        if (so_error == 0 || so_error == ECONNREFUSED) {
            result->response = PROBE_HSTATE_LIVE;
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


int probe_sendrecv_udp(const char *thread_id, probe_result *result,
                       probe_port *port_def, struct in_addr *inaddr, int timeoutms)
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


    sd = socket(PROBE_FAMILY_TO_AF(port_def->family), SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_IP);
    if (sd < 0) {
        log_debug("%s\t socket errno: %i, errdesc: %s", thread_id, errno, strerror(errno));
        result->response = PROBE_HSTATE_ERROR;
        return -EIO;
    }

    addr_size = probe_sock_set_saddr((struct sockaddr *)&target_addr, port_def->family, inaddr, port_def->port);

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
        result->response = PROBE_HSTATE_ERROR;
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
        result->response = PROBE_HSTATE_ERROR;
        close(sd);
        return -EIO;
    }

    // wait for response
    poll_arg.fd = sd;
    poll_arg.events = POLL_IN;
    poll_ret = poll(&poll_arg, 1, timeoutms);

    /* check poll result and socket state */
    if (poll_ret > 0 && poll_arg.revents & POLL_IN) {
        //poll has data from recvfrom
        result->response = PROBE_HSTATE_LIVE;
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


ssize_t probe_sock_addr_from_ip(struct sockaddr *saddr, enum probe_family family, const char *ip, uint16_t port)
{
    saddr->sa_family = PROBE_FAMILY_TO_AF(family);

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

ssize_t probe_sock_set_saddr(struct sockaddr *saddr, enum probe_family family, struct in_addr *inaddr, uint16_t port)
{
    saddr->sa_family = PROBE_FAMILY_TO_AF(family);

    if (family == PROBE_FAMILY_INET6) {
        struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)saddr;
        memcpy(&saddr6->sin6_addr, ((struct in6_addr *)inaddr), sizeof(struct in6_addr));
        saddr6->sin6_port = htons(port);
        return sizeof(struct sockaddr_in6);
    }

    struct sockaddr_in *saddr4 = (struct sockaddr_in *)saddr;
    memcpy(&saddr4->sin_addr, inaddr, sizeof(struct in_addr));
    saddr4->sin_port = htons(port);
    return sizeof(struct sockaddr_in);
}

int probe_sock_get_error(int sd)
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
