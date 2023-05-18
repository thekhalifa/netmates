#ifndef NETWORK_MATES_NM_SCAN_H
#define NETWORK_MATES_NM_SCAN_H

#include <arpa/inet.h>
#include <asm-generic/errno.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>

#include "nm-common.h"
#include "nm-host.h"
#include "nm-protocol.h"


enum scan_protocol{
    SCAN_PROTO_TCP,
    SCAN_PROTO_UDP
};

enum scan_method{
    SCAN_NONE = 0,
    SCAN_TCP_CONNECT,
    SCAN_TCP_QUERY,
    SCAN_TCP_LISTEN,
    SCAN_UDP_SENDRECV,
    SCAN_UDP_RECV,
    SCAN_METHOD_LENGTH,
};

#define SCAN_PORT_METHOD_BUFFER_LEN 36

static char *scan_method_label[] = {
    "?",
    "tc",
    "tq",
    "tl",
    "uq",
    "ul",
    ""
};

enum scan_host_state{
    SCAN_HSTATE_UNKNOWN,
    SCAN_HSTATE_LIVE,
    SCAN_HSTATE_DEAD,
    SCAN_HSTATE_ERROR
};

typedef struct{
    int init;
    int running;
    int quit_now;
    int opt_print;
    int opt_known_first;
    int opt_known_only;
    int opt_scan_only;
    int opt_scan_all;
    int opt_skip_resolve;
    int opt_connect_threads;
    int opt_connect_timeout_ms;
    int opt_listen_threads;
    int opt_scan_timeout_ms;
    int opt_poll_thread_work_ms;
    int opt_max_hosts;
    int opt_subnet_offset;
    int stat_conn_hosts;
    int stat_list_ports;
    nmlist *hosts;
    nm_host *localhost;
} scan_state;


typedef struct {
    int length;
    uint32_t start_num;
    uint32_t stop_num;
    struct in_addr start_addr;
    struct in_addr stop_addr;
} scan_range;



typedef struct scan_port scan_port;

typedef struct scan_result{
    enum scan_host_state response;
    enum nm_host_type host_type;
    char *hostname;
    uint16_t port;
    bool port_open;
    struct in_addr target_addr;
    scan_port *port_def;
    nmlist *services;
    enum scan_method method;
}scan_result;


typedef int (*scan_query_callback)(char *buffer, size_t buffsize, char* data, struct in_addr);
typedef bool(*scan_response_callback)(scan_result *result, const uint8_t *in_buffer, ssize_t in_size);

struct scan_port {
    enum scan_method method;
    int port;
    int required;
    int min_time;
    int max_time;
    int bind_port;
    int bind_fail_confirms;
    int mc_join;
    char *service;
    char *mc_ip;
    proto_payload query_payload;
    scan_query_callback query_cb;
    scan_response_callback response_cb;
    enum nm_host_type host_type;
    proto_def *protocol;
};


/* Utils */
bool            scan_util_is_running();
bool            scan_util_calc_subnet_range(const char *ip, const char *netmask, scan_range *range);
void            scan_result_destroy(scan_result *result);

/* local info gathering */
int             scan_list_arp_hosts();
int             scan_list_gateways();
bool            scan_list_localhost();
int             scan_resolve_hostname(char *ip, char *hostname_buffer, size_t buffer_size);
//TODO: merge with ipv4 version
int             scan_resolve_hostname6(char *ip, char *hostname_buffer, size_t buffer_size);

/* application & scan functions */
void            scan_print_mates(nmlist *hosts, bool showtotal);
void            scan_process_result(scan_result *result, int *live_counter);

bool            scan_response_ack(scan_result *result, const uint8_t *in_buffer, ssize_t in_size);
bool            scan_response_log(scan_result *result, const uint8_t *in_buffer, ssize_t in_size);

gpointer        scan_main_listen_thread(gpointer data);
void            scan_listen_thread(gpointer target_data, gpointer results_data);
gpointer        scan_main_connect_thread(gpointer data);
void            scan_connect_thread(gpointer target_data, gpointer results_data);

bool            scan_discover_subnet(int connect, int listen);

void            scan_init();
void            scan_destroy();
scan_state     *scan_getstate();
void            scan_start();
void            scan_stop();


#endif //NETWORK_MATES_NM_SCAN_H
