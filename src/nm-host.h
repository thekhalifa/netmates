/**
 * @file nm-host.h
 * Host object
 *
 * SPDX-License-Identifier: GPL-3.0
 */
#ifndef NETWORK_MATES_NM_HOST_H
#define NETWORK_MATES_NM_HOST_H

#include "nm-common.h"

/* order of priority is lower number overrides the highs when a merge of
 * two hosts happens - except localhost  */
enum nm_host_type {
    HOST_TYPE_UNKNOWN = 0,
    HOST_TYPE_LOCALHOST,
    HOST_TYPE_ROUTER,
    HOST_TYPE_PHONE,
    HOST_TYPE_PRINTER,
    HOST_TYPE_DEVICE,
    HOST_TYPE_TV,
    HOST_TYPE_PC_MAC,
    HOST_TYPE_PC_WIN,
    HOST_TYPE_PC,
    HOST_TYPE_ANY,
    HOST_TYPE_KNOWN,
    HOST_TYPE_LENGTH
};

/** MAC address & vendor if queried. */
struct hw_details {
    char *addr;
    char *vendor;
};
typedef struct hw_details hw_details;


static hw_details HW_IFACE_NULL;

static char *nm_host_type_labels[] = {
    "?",
    "local",
    "router",
    "phone",
    "printer",
    "device",
    "tv",
    "mac pc",
    "win pc",
    "pc",
    "anything",
    "known",
    NULL
};

typedef struct {
    int type;
    //in_addr_t ip_addr;
    char *ip;
    char *ip6;
    char *netmask;
    char *hostname;
    hw_details hw_if;
    nmlist *list_ip;
    nmlist *list_ip6;
    nmlist *list_services;
    nmlist *list_ports;
    nmlist *list_hw_if;
} nm_host;


/* lifecycle functions */
nm_host    *nm_host_init(enum nm_host_type type);
void        nm_host_destroy(nm_host *host);
void        nm_host_set_type(nm_host *host, enum nm_host_type type);
void        nm_host_set_attributes(nm_host *host, char *ip, char *ip6, char *netmask,
                                   hw_details hw_if, char *hostname);
void        nm_host_add_service(nm_host *host, char *service);
void        nm_host_add_services(nm_host *host, nmlist *services);
void        nm_host_add_ports(nm_host *host, nmlist *ports);
void        nm_host_add_port(nm_host *host, uint16_t port, char *method);
void        nm_host_print_brief(nm_host *host);
void        nm_host_print_long(nm_host *host);
void        nm_host_print_wide(nm_host *host);
const char *nm_host_label(nm_host *host);
const char *nm_host_type(nm_host *host);
/* entry merge functions */

nmlist     *nm_host_merge_in_list(nmlist *list, nm_host *newhost);
void        nm_host_merge(nm_host *dst, nm_host *src);

nmlist     *nm_host_merge_field(char **dest_field, char *src_field,
                                nmlist *dest_list_field, nmlist *src_list_field);

nmlist     *nm_host_sort_list(nmlist *list);

#endif //NETWORK_MATES_NM_HOST_H
