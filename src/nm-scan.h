/**
 * @file nm-scan.h
 * Network scanning operations and thread pools.
 *
 * SPDX-License-Identifier: GPL-3.0
 */
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
#include <sys/socket.h>

#include "nm-common.h"
#include "nm-host.h"
#include "nm-protocol.h"
#include "nm-probe.h"


typedef struct {
    bool init;
    bool running;
    bool opt_print;
    bool opt_print_list;
    bool opt_print_brief;
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



/* Utils */
bool            scan_util_is_running();
bool            scan_util_calc_subnet_range(const char *ip, const char *netmask, scan_range *range);
void            scan_result_destroy(probe_result *result);

/* local info gathering */
int             scan_list_arp_hosts();
int             scan_list_gateways();
bool            scan_list_localhost();
int             scan_resolve_hostname_new(enum probe_family family, char *ip, char *hostname_buffer, size_t buffer_size);

/* application & scan functions */
void            scan_print_mates(nmlist *hosts, bool showtotal);
void            scan_process_result(probe_result *result, int *live_counter);

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
