#ifndef NETWORK_MATES_NM_SCAN_H
#define NETWORK_MATES_NM_SCAN_H

#include <arpa/inet.h>
#include <asm-generic/errno.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>

#include "nm-common.h"
#include "nm-host.h"
#include "nm-protocol.h"


enum scan_family{
    SCAN_FAMILY_INET4 = 0,
    SCAN_FAMILY_INET6
};
//this allows the ports to be set to 0 and reduces having to define family
#define SCAN_FAMILY_TO_AF(x) x == SCAN_FAMILY_INET6 ? AF_INET6 : AF_INET

enum scan_method{
    SCAN_NONE = 0,
    SCAN_TCP_CONNECT,
    SCAN_TCP_QUERY,
    SCAN_TCP_LISTEN,
    SCAN_UDP_SENDRECV,
    SCAN_UDP_RECV,
    SCAN_METHOD_LENGTH,
};

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
    bool init;
    bool running;
    bool opt_print;
    bool opt_print_list;
    bool opt_known_first;
    bool opt_known_only;
    bool opt_scan_only;
    bool opt_scan_all;
    bool opt_skip_resolve;
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
    //struct in_addr target_addr;
    union {
        struct in_addr inaddr;
        struct in6_addr inaddr6;
    } target;
    scan_port *port_def;
    nmlist *services;
    enum scan_method method;
    enum scan_family family;
}scan_result;


typedef int (*scan_query_callback)(char *buffer, size_t buffsize, char* data, struct sockaddr *targetaddr);
typedef bool(*scan_response_callback)(scan_result *result, const uint8_t *in_buffer, ssize_t in_size);

struct scan_port {
    enum scan_family family;
    enum scan_method method;
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


/* Utils */
bool            scan_util_is_running();
bool            scan_util_calc_subnet_range(const char *ip, const char *netmask, scan_range *range);
void            scan_result_destroy(scan_result *result);

/* local info gathering */
int             scan_list_arp_hosts();
int             scan_list_gateways();
bool            scan_list_localhost();
int             scan_resolve_hostname_new(enum scan_family family, char *ip, char *hostname_buffer, size_t buffer_size);
//TODO: merge with ipv4 version
//int             scan_resolve_hostname(char *ip, char *hostname_buffer, size_t buffer_size);
//int             scan_resolve_hostname6(char *ip, char *hostname_buffer, size_t buffer_size);
ssize_t         scan_socket_set_saddr(struct sockaddr *saddr, enum scan_family family, 
                                      struct in_addr *inaddr, uint16_t port);
ssize_t         scan_socket_addr_from_ip(struct sockaddr *saddr, enum scan_family family,
                                         const char *ip, uint16_t port);

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
