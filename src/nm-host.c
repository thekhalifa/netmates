#include "nm-host.h"


nm_host *nm_host_init(enum nm_host_type type) {
    nm_host *entry = malloc(sizeof(nm_host));
    memset(entry, 0, sizeof(nm_host));
    entry->type = type;
    return entry;
}

void nm_host_destroy(nm_host *host) {
    
    if(!host)
        return;
    
    free(host->ip);
    free(host->ip6);
    free(host->netmask);
    free(host->hostname);
    free(host->hw_if.addr);
    free(host->hw_if.vendor);

    nm_list_free(host->list_ip, true);
    nm_list_free(host->list_ip6, true);
    nm_list_free(host->list_services, true);

    free(host);

}

void nm_host_set_type(nm_host *host, enum nm_host_type type) {
    //type - by declaration priority, except localhost
    if(type > HOST_TYPE_UNKNOWN && (type < host->type || host->type == HOST_TYPE_UNKNOWN))
        host->type = type;
}

void nm_host_set_attributes(nm_host *host, char *ip, char *ip6, char *netmask, 
                            hw_details hw_if, char *hostname){
    assert(host != NULL);

    if(nm_string_len(ip))
        host->list_ip = nm_host_merge_field(&host->ip, ip,
                                    host->list_ip, NULL);
    if(nm_string_len(ip6))
        host->list_ip6 = nm_host_merge_field(&host->ip6, ip6, host->list_ip6, NULL);

    if(nm_string_len(hostname)){
        if(host->hostname == NULL)
            host->hostname = strdup(hostname);
        else if(strcmp(host->hostname, hostname))
            log_warn("nm_host_set_attributes: found conflicting hostnames: %s, %s", host->hostname, hostname);
    }
    
    if(nm_string_len(hw_if.addr) && host->hw_if.addr == NULL){
        host->hw_if.addr = strdup(hw_if.addr);
        host->hw_if.vendor = strdup(hw_if.vendor);
    }else if(nm_string_len(hw_if.addr)){
        //replace addr with a longer string
        char addr[NM_MID_BUFFSIZE];
        char vendor[NM_MID_BUFFSIZE];
        snprintf(addr, NM_MID_BUFFSIZE, "%s, %s", host->hw_if.addr, hw_if.addr);
        snprintf(vendor, NM_MID_BUFFSIZE, "%s, %s", 
                 host->hw_if.vendor ? host->hw_if.vendor : "", 
                 hw_if.vendor ? hw_if.vendor : "");
        free(host->hw_if.addr);
        free(host->hw_if.vendor);
        host->hw_if.addr = strdup(addr);
        host->hw_if.vendor = strdup(vendor);
    }
    
    if(nm_string_len(netmask)){
        if(host->netmask == NULL)
            host->netmask = strdup(netmask);
        else if(strcmp(host->netmask, netmask))
            log_warn("nm_host_set_attributes: found conflicting netmask: %s, %s", host->netmask, netmask);
    }
}

nmlist *nm_host_merge_in_list(nmlist *list, nm_host *newhost) {
    // match against the list
    nm_host *host, *foundhost = NULL;
    nm_list_foreach(node, list) {
        host = node->data;
        
        if (newhost->ip && host->ip && 
            (!strcmp(newhost->ip, host->ip) || nm_list_find_string(host->list_ip, newhost->ip))) {
            foundhost = host;
            break;
        }
        if (newhost->ip6 && host->ip6 && 
            (!strcmp(newhost->ip6, host->ip6) || nm_list_find_string(host->list_ip6, newhost->ip6))) {
            foundhost = host;
            break;
        }
        if (newhost->hw_if.addr && host->hw_if.addr && (!strcmp(newhost->hw_if.addr, host->hw_if.addr))) {
            foundhost = host;
            break;
        }
    }
    
    if(foundhost){
        nm_host_merge(foundhost, newhost);
        nm_host_destroy(newhost);
        return list;
    }
    // no match, add in list
    return nm_list_add(list, newhost);
}


void nm_host_add_service(nm_host *host, char *service) {
    assert(host != NULL);
    assert(service != NULL);

    if(!nm_list_find_string(host->list_services, service))
        host->list_services = nm_list_add(host->list_services, strdup(service));
}


void nm_host_add_services(nm_host *host, nmlist *services) {
    assert(host != NULL);
    assert(services != NULL);

    host->list_services = nm_host_merge_field(NULL, NULL, host->list_services, services);
}

void nm_host_add_port(nm_host *host, uint16_t port, char *method) {
    assert(host != NULL);
    assert(port != 0);
    assert(method != 0);
    
    char buffer[NM_GEN_BUFFSIZE];
    sprintf(buffer, "%hu/%s", port, method);
    if(!nm_list_find_string(host->list_ports, buffer))
        host->list_ports = nm_list_add(host->list_ports, strdup(buffer));

}

void nm_host_add_ports(nm_host *host, nmlist *ports) {
    assert(host != NULL);
    assert(ports != NULL);

    host->list_ports = nm_host_merge_field(NULL, NULL, host->list_ports, ports);
}


void nm_host_print(nm_host *host) {
    assert(host != NULL);
    assert(host->ip != NULL || host->ip6 != NULL);

    const char *type = nm_host_type_labels[host->type];
    if(host->hostname)
        printf("+ [%s] %s\n", type, host->hostname);
    else
        printf("+ [%s]\n", type);

    if(host->ip)
        printf("   IPv4:  %s\n", host->ip);
    nm_list_foreach(node, host->list_ip)
        printf("   IPv4:  %s\n", (char *)node->data);

    if(host->ip6)
        printf("   IPv6:  %s\n", host->ip6);
    nm_list_foreach(node, host->list_ip6)
        printf("   IPv6:  %s\n", (char *)node->data);

    if(host->hw_if.addr){
        if(host->hw_if.vendor)
            printf("   MAC:   %s %s\n", host->hw_if.addr, host->hw_if.vendor);
        else
            printf("   MAC:   %s\n", host->hw_if.addr);
    }

    if(host->list_services == NULL)
        return;
    printf("   Srvc:  ");
    nm_list_foreach(node, host->list_services)
        printf("%s ", (char *)node->data);
    printf("\n");
}


void nm_host_print_wide(nm_host *host) {
    assert(host != NULL);
    assert(host->ip != NULL || host->ip6 != NULL);

    const char *type = nm_host_type_labels[host->type];
    char *hostname = host->hostname ? host->hostname : "";
    char *ip = host->ip ? host->ip : "";
    char *ip6 = host->ip6 ? host->ip6 : "";
    char *hwaddr = host->hw_if.addr ? host->hw_if.addr : "";
    char *hwvendor = host->hw_if.vendor ? host->hw_if.vendor : "";
    
    printf("+ %-8s-> %-15s\t%-22s\t%-12s\t%17s\t%s\n",
           type, ip, ip6, hostname, hwaddr, hwvendor);
    
    nmlist *ipnode = host->list_ip;
    nmlist *ip6node = host->list_ip6;
    while(ipnode || ip6node) {
        ip = ipnode ? ipnode->data : "";
        ip6 = ip6node ? ip6node->data : "";
        
        printf("             %-15s\t%s-22\n", ip, ip6);
        ipnode = ipnode ? ipnode->next : NULL;
        ip6node = ip6node ? ip6node->next : NULL;
    }

    if(host->list_services) {
        printf("             [");
        nm_list_foreach(node, host->list_services)
            printf("%s%s", (char *)node->data, node->next ? ", " : "");
        printf("]\n");
    }

    if(host->list_ports) {
        printf("             [");
        nm_list_foreach(node, host->list_ports)
            printf("%s%s", (char *)node->data, node->next ? ", " : "");
        printf("]\n");
    }
}


void nm_host_print2(nm_host *host) {
    assert(host != NULL);
    assert(host->ip != NULL || host->ip6 != NULL);

    const char *type = nm_host_type_labels[host->type];
    if(host->ip != NULL)
        printf("+ Type: %-10s IPv4: [%s] \thostname: [%s]", type, host->ip, host->hostname);
    else
        printf("+ Type: %-10s IPv6: [%s] \thostname: [%s]", type, host->ip6, host->hostname);

    if(host->type == HOST_TYPE_LOCALHOST)
        printf(", Netmask: %s", host->netmask);
    if(host->ip != NULL && host->ip6 != NULL)
        printf(", IPv6: %s", host->ip6);
    printf("\n");

    char *other_label[] = {"Other IP", "Other IPv6", "Services"};
    nmlist *other_list[] = {host->list_ip, host->list_ip6, host->list_services};
    
    int items = sizeof(other_label) / sizeof(other_label[0]);
    for(int j=0; j<items; j++){
        if(other_list[j] == NULL || other_list[j]->data == NULL)
            continue;
        
        printf("\t\t--%s: \t", other_label[j]);
        nm_list_foreach(node, other_list[j]) {
            printf("%s%s", (char *)node->data, node->next ? ", ": "\n");
        }
    }
}

void nm_host_print3(nm_host *host) {
    assert(host != NULL);
    assert(host->ip != NULL || host->ip6 != NULL);

    const char *type = nm_host_type_labels[host->type];
    if(host->hostname)
        printf("+ [%s] %s\n", type, host->hostname);
    else
        printf("+ [%s]\n", type);
    
    if(host->type == HOST_TYPE_LOCALHOST)
        printf("   Mask: %s\n", host->netmask);

    if(host->ip)
        printf("   ip4:  %s\n", host->ip);
    nm_list_foreach(node, host->list_ip)
        printf("   ip4:  %s\n", (char *)node->data);

    if(host->ip6)
        printf("   ip6:  %s\n", host->ip6);
    nm_list_foreach(node, host->list_ip6)
        printf("   ip6:  %s\n", (char *)node->data);

    nm_list_foreach(node, host->list_services)
        printf("   Service:  %s\n", (char *)node->data);

}


const char *nm_host_label(nm_host *host) {
    assert(host != NULL);

    if(host->hostname)
        return host->hostname;
    if(host->ip)
        return host->ip;
    if(host->ip6)
        return host->ip6;
    if(host->hw_if.addr)
        return host->hw_if.addr;
    
    return NULL;
}

const char *nm_host_type(nm_host *host) {
    assert(host != NULL);
    assert(host->type >= HOST_TYPE_UNKNOWN);
    assert(host->type < HOST_TYPE_LENGTH);

    return nm_host_type_labels[host->type];
}


nmlist *nm_host_merge_field(char **dest_field, char *src_field, 
                                   nmlist *dest_list_field, nmlist *src_list_field) {

    nmlist* node;
    if (dest_field && *dest_field == NULL && nm_string_len(src_field) > 0) {
        *dest_field = strdup(src_field);
    } else if (dest_field && *dest_field != NULL && 
        nm_string_len(src_field) > 0 && strcmp(*dest_field, src_field) != 0) {
        if(!nm_list_find_string(dest_list_field, src_field)) {
            node = nm_list_add(dest_list_field, strdup(src_field));
            if(!dest_list_field )
                dest_list_field = node;
        }
    }

    const char *other_item;
    nm_list_foreach(srcnode, src_list_field) {
        other_item = srcnode->data;
        if(nm_string_len(other_item) && !nm_list_find_string(dest_list_field, other_item)) {
            node = nm_list_add(dest_list_field, strdup(srcnode->data));
            if(!dest_list_field )
                dest_list_field = node;
        }
    }

    return dest_list_field;
}

void nm_host_merge(nm_host *dst, nm_host *src){
    assert(dst != NULL);
    assert(src != NULL);

    //type by priority
    nm_host_set_type(dst, src->type);
    
    //hostname
    if(dst->hostname == NULL && nm_string_len(src->hostname) > 0){
        dst->hostname = strdup(src->hostname);
    }else if(nm_string_len(dst->hostname) && nm_string_len(src->hostname) && 
                strcmp(dst->hostname, src->hostname)){
        log_trace("nm_host_merge: found conflicting hostnames: %s, %s",
                  dst->hostname, src->hostname);
    }

    //hw addr
    if(dst->hw_if.addr == NULL && nm_string_len(src->hw_if.addr) > 0){
        dst->hw_if.addr = strdup(src->hw_if.addr);
    }else if(nm_string_len(dst->hw_if.addr) && nm_string_len(src->hw_if.addr) && 
                strcmp(dst->hw_if.addr, src->hw_if.addr)){
        //replace addr with a longer string
        char addr[NM_HWADDR_STRLEN];
        char vendor[NM_HWADDR_STRLEN];
        snprintf(addr, NM_HWADDR_STRLEN, "%s, %s", dst->hw_if.addr, src->hw_if.addr);
        snprintf(vendor, NM_HWADDR_STRLEN, "%s, %s", dst->hw_if.vendor, src->hw_if.vendor);
        snprintf(vendor, NM_HWADDR_STRLEN, "%s, %s", 
                 dst->hw_if.vendor ? dst->hw_if.vendor : "",
                 src->hw_if.vendor ? src->hw_if.vendor : "");
        free(dst->hw_if.addr);
        free(dst->hw_if.vendor);
        dst->hw_if.addr = strdup(addr);
        dst->hw_if.vendor = strdup(vendor);
    }

    //ip
    dst->list_ip = nm_host_merge_field(&dst->ip, src->ip, dst->list_ip, src->list_ip);
    //ip6
    dst->list_ip6 = nm_host_merge_field(&dst->ip6, src->ip6, dst->list_ip6, src->list_ip6);
    //services
    dst->list_services = nm_host_merge_field(NULL, NULL, dst->list_services, src->list_services);
    //ports
    dst->list_ports = nm_host_merge_field(NULL, NULL, dst->list_ports, src->list_ports);
    
}

static int nm_host_sort_compare(const void *data1, const void *data2){
    
    const nm_host *left = data1;
    const nm_host *right = data2;
    
    
    if(left->type == HOST_TYPE_LOCALHOST)
        return -1;
    else if(right->type == HOST_TYPE_LOCALHOST)
        return 1;
    else if(left->type == HOST_TYPE_ROUTER)
        return -1;
    else if(right->type == HOST_TYPE_ROUTER)
        return 1;

    if(left->ip && right->ip)
        return strcmp(left->ip, right->ip);
    
    if(left->ip6 && right->ip6)
        return strcmp(left->ip6, right->ip6);
    
    if(left->ip && !right->ip)
        return -1;

    
    return 1;
}

nmlist *nm_host_sort_list(nmlist *list) {
    assert(list != NULL);
    
    nmlist *sorted = g_list_sort(list, nm_host_sort_compare);
    return sorted;
    
}
