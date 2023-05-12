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



/* TODO: switch to probes? 
typedef void    (*run_probe)(int type);

typedef struct{
    char name[64];
    run_probe probe_cb;
    int enabled;
} scan_probe;


static scan_probe probe_list[] = {
    {"basic", NULL, 0},
    {"extensive probe", NULL, 0},
    {0},
};

*/



enum scan_event {
    SCAN_EVENT_START,
    SCAN_EVENT_END,
    SCAN_EVENT_UPDATE
};

enum scan_direction{
    SCAN_DIR_CONNECT,
    SCAN_DIR_LISTEN
};

enum scan_protocol{
    SCAN_PROTO_TCP,
    SCAN_PROTO_UDP
};

enum scan_host_state{
    SCAN_HSTATE_UNKNOWN,
    SCAN_HSTATE_LIVE,
    SCAN_HSTATE_DEAD,
    SCAN_HSTATE_ERROR
};


//typedef void    (*scanner_callback)(int type, void* data);


typedef struct{
    int init;
    int running;
    int quit_now;
    int opt_print;
    int opt_print_known_first;
    int opt_scan_known_only;
    int opt_skip_resolve;
    int opt_connect_threads;
    int opt_connect_timeout_ms;
    int opt_listen_threads;
    int opt_subnet_timeout_ms;
    int opt_poll_thread_work_us;
    int opt_max_hosts;
    int opt_subnet_offset;
    //scanner_callback event_cb;
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

typedef struct {
    uint length;
    const char * buffer;
} scan_payload;

typedef struct {
    int port;
    char *service;
    int required;
    enum scan_protocol protocol;
    enum nm_host_type device_type;
    const char *query_buffer;
    scan_payload query_payload;
} scan_port;


typedef struct {
    enum scan_direction direction;
    enum scan_host_state response;
    enum nm_host_type host_type;
    char *hostname;
    uint16_t port;
    struct in_addr target_addr;
    nmlist *services;
} scan_result;


typedef bool(*scan_query_callback)(int type, void* data);
typedef bool(*scan_response_callback)(scan_result *result, char *in_buffer, ssize_t in_size);

typedef struct {
    scan_port port;
    int min_time;
    int max_time;
    int bind_port;
    int mc_join;
    char *mc_ip;
    //scan_query_callback *query_cb;
    bool(*query_cb)(int, void*);
    scan_response_callback response_cb;
} scan_listen_port;


/* Utils */
bool            scan_util_is_running();
int             scan_util_get_sock_error(int sd);
int             scan_util_get_sock_info(int sd);
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
void            scan_print_mates(nmlist *hosts);
void            scan_process_result(scan_result *result, int *live_counter);

gpointer        scan_main_listen_thread(gpointer data);
void            scan_listen_thread(gpointer target_data, gpointer results_data);
gpointer        scan_main_connect_thread(gpointer data);
void            scan_connect_thread(gpointer target_data, gpointer results_data);

bool            scan_discover_subnet(int connect, int listen);

void            scan_start();
void            scan_stop();
void            scan_init(int print_known_first, int print_known_only, int skip_resolve,
                          int conn_threads, int conn_timeout, int max_hosts, 
                          int list_threads, int subnet_timeout, int subnet_offset);
void            scan_destroy();



typedef struct {
    char *signature;
    char *service_name;
    enum nm_host_type host_type;
} service_record;


bool    probe_ssdp_query(int sd, void *lp);
bool    probe_ssdp_response(scan_result *result, char *in_buffer, ssize_t in_size);

// bool    scan_proto_mdns_query(int sd, void *lp);
// bool    scan_proto_mdns_response(scan_result *result, char *in_buffer, ssize_t in_size);
// bool scan_proto_mdns_query(int sd, void *lp){
//     return true;
// 
// }
// 
// bool scan_proto_mdns_response(scan_result *result, char *in_buffer, ssize_t in_size){
//     log_debug("scan_proto_mdns_response - Port<TODO> received buffer len %zu", strnlen(in_buffer, in_size));
// 
//     return true;
// }



#endif //NETWORK_MATES_NM_SCAN_H
