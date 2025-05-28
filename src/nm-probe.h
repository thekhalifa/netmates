/**
 * @file nm-probe.h
 * Probe states.
 *
 * SPDX-License-Identifier: GPL-3.0
 */
#ifndef NM_PROBE_H_INCLUDED
#define NM_PROBE_H_INCLUDED

#include <poll.h>

#include "nm-common.h"
#include "nm-host.h"
#include "nm-protocol.h"

enum probe_family {
    PROBE_FAMILY_INET4 = 0,
    PROBE_FAMILY_INET6
};
//this allows the ports to be set to 0 and reduces having to define family
#define PROBE_FAMILY_TO_AF(x) x == PROBE_FAMILY_INET6 ? AF_INET6 : AF_INET

/* first element in the probe list, so should start at 1 */
enum probe_method {
    PROBE_TCP_CONNECT = 1,
    PROBE_TCP_QUERY,
    PROBE_TCP_LISTEN,
    PROBE_UDP_SENDRECV,
    PROBE_UDP_RECV,
    PROBE_METHOD_LENGTH,
};

static char *probe_method_label[] = {
    "", //skip 0
    "tc",
    "tq",
    "tl",
    "uq",
    "ul",
    ""
};


enum probe_host_state {
    PROBE_HSTATE_UNKNOWN,
    PROBE_HSTATE_LIVE,
    PROBE_HSTATE_DEAD,
    PROBE_HSTATE_ERROR
};

typedef struct probe_port probe_port;

typedef struct probe_result {
    enum probe_host_state response;
    enum nm_host_type host_type;
    enum probe_method method;
    enum probe_family family;
    probe_port *port_def;
    nmlist *services;
    char *hostname;
    bool port_open;
    uint16_t port;
    union {
        struct in_addr inaddr;
        struct in6_addr inaddr6;
    } target;
} probe_result;


typedef int (*scan_query_callback)(char *buffer, size_t buffsize, char *data, struct sockaddr *targetaddr);
typedef bool(*scan_response_callback)(probe_result *result, const uint8_t *in_buffer, ssize_t in_size);

struct probe_port {
    enum probe_method method;
    enum probe_family family;
    int port;
    int required;
    int min_time;
    int max_time;
    int bind_port;
    int bind_fail_confirms;
    int mc_join;
    char *service;
    char *send_ip;
    char *mc_ip;
    proto_payload query_payload;
    scan_query_callback query_cb;
    scan_response_callback response_cb;
    enum nm_host_type host_type;
    proto_def *protocol;
};


void        probe_result_destroy(probe_result *result);

probe_port *probe_get_connect_ports();
probe_port *probe_get_listen_ports();
int         probe_count_connect_ports();
int         probe_count_listen_ports();

bool        probe_response_ack(probe_result *result, const uint8_t *in_buffer, ssize_t in_size);
bool        probe_response_log(probe_result *result, const uint8_t *in_buffer, ssize_t in_size);

bool        probe_send_proto_query(int sd, probe_port *sp, const char *logsign);
int         probe_connect_tcp(const char *thread_id, probe_result *result,
                              probe_port *port_def, struct in_addr *inaddr, int timeoutms);
int         probe_sendrecv_udp(const char *thread_id, probe_result *result,
                               probe_port *port_def, struct in_addr *inaddr, int timeoutms);

ssize_t     probe_sock_addr_from_ip(struct sockaddr *saddr, enum probe_family family, const char *ip, uint16_t port);
ssize_t     probe_sock_set_saddr(struct sockaddr *saddr, enum probe_family family, struct in_addr *inaddr, uint16_t port);
int         probe_sock_get_error(int sd);
ssize_t     probe_sock_addr_from_ip(struct sockaddr *saddr, enum probe_family family, const char *ip, uint16_t port);


#endif // NM_PROBE_H_INCLUDED
