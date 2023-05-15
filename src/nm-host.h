#ifndef NETWORK_MATES_NM_HOST_H
#define NETWORK_MATES_NM_HOST_H

#include "nm-common.h"

//typedef nmarray      HostArray;      /* type for host* array */
//typedef nmlist       HothList;       /* type for other field linked lists */


/* order of priority is lower number overrides the highs when a merge of
 * two hosts happens - except localhost  */
enum nm_host_type{
    HOST_TYPE_UNKNOWN = 0,
    HOST_TYPE_LOCALHOST,
    HOST_TYPE_ROUTER,
    HOST_TYPE_PHONE,
    HOST_TYPE_PRINTER,
    HOST_TYPE_SMART_DEVICE,
    HOST_TYPE_SMART_TV,
    HOST_TYPE_PC_WIN,
    HOST_TYPE_PC,
    HOST_TYPE_ANY,
    HOST_TYPE_LENGTH
};

static char *nm_host_type_labels[] = {
        "?",
        "local",
        "router",
        "phone",
        "printer",
        "smart device",
        "TV",
        "Windows PC",
        "PC",
        "anything",
        NULL
};


typedef struct {
    int type;
    in_addr_t ip_addr;
    char *ip;
    char *ip6;
    char *netmask;
    char *hostname;
    char *hw_addr;
    nmlist *list_ip;
    nmlist *list_ip6;
    nmlist *list_hw_addr;
    nmlist *list_services;
} nm_host;


/* lifecycle functions */
nm_host    *nm_host_init(enum nm_host_type type);
void        nm_host_destroy(nm_host *host);
void        nm_host_set_type(nm_host *host, enum nm_host_type type);
void        nm_host_set_attributes(nm_host *host, char *ip, char *ip6, char *netmask, 
                                   char *hw_addr, char *hostname);
void        nm_host_add_services(nm_host *host, nmlist *services);
void        nm_host_print(nm_host *host);
void        nm_host_print_wide(nm_host *host);
const char *nm_host_label(nm_host *host);

/* entry merge functions */

nmlist     *nm_host_merge_in_list(nmlist *list, nm_host *newhost);
void        nm_host_merge(nm_host *dst, nm_host *src);

/*
nm_host    *nm_host_merge_into_array(nm_host *src_host, HostArray *array);
*/
static nmlist *nm_host_merge_field(char **dest_field, char *src_field, 
                                     nmlist *dest_list_field, nmlist *src_list_field);


#endif //NETWORK_MATES_NM_HOST_H
