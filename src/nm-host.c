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
    free(host->hw_addr);

//     if(host->ip)
//         free(host->ip);
//     if(host->ip6)
//         free(host->ip6);
//     if(host->netmask)
//         free(host->netmask);
//     if(host->hostname)
//         free(host->hostname);
//     if(host->hw_addr)
//         free(host->hw_addr);

    nm_list_free(host->list_ip, true);
    nm_list_free(host->list_ip6, true);
    nm_list_free(host->list_hw_addr, true);
    nm_list_free(host->list_services, true);

    free(host);

}

void nm_host_set_type(nm_host *host, enum nm_host_type type) {
    //type - by declaration priority, except localhost
    if(type < host->type)
        host->type = type;
}

void nm_host_set_attributes(nm_host *host, char *ip, char *ip6, char *netmask, char *hw_addr, char *hostname){
    assert(host != NULL);

    if(nm_string_len(ip))
        host->list_ip = nm_host_merge_field(&host->ip, ip,
                                    host->list_ip, NULL);
    if(nm_string_len(ip6))
        host->list_ip6 = nm_host_merge_field(&host->ip6, ip6, host->list_ip6, NULL);
    if(nm_string_len(hw_addr))
        host->list_hw_addr = nm_host_merge_field(&host->hw_addr, hw_addr, host->list_hw_addr, NULL);

    if(nm_string_len(hostname)){
        if(host->hostname == NULL)
            host->hostname = strdup(hostname);
        else if(strcmp(host->hostname, hostname))
            log_warn("nm_host_set_attributes: found conflicting hostnames: %s, %s", host->hostname, hostname);
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
        
    }
    
    if(foundhost){
        log_debug("nm_host_merge_in_list: found matching host, merging %s with %s",
                    nm_host_label(newhost), nm_host_label(foundhost));
        nm_host_merge(foundhost, newhost);
        return list;
    }
    
    // no match, add in list
    return nm_list_add(list, newhost);
}

void nm_host_add_services(nm_host *host, nmlist *services) {
    assert(host != NULL);
    assert(services != NULL);

    host->list_services = nm_host_merge_field(NULL, NULL, host->list_services, services);
}

void nm_host_print2(nm_host *host) {
    assert(host != NULL);
    assert(host->ip != NULL || host->ip6 != NULL);

    const char *type = nm_host_type_labels[host->type];

    if(host->ip != NULL)
        printf("+ Type: %-10s IPv4: [%s] \thostname: [%s]", type, host->ip, host->hostname);
    else
        printf("+ Type: %-10s IPv6: [%s] \thostname: [%s]", type, host->ip6, host->hostname);

    if(host->hw_addr != NULL)
        printf(" \t-- HW: %s", host->hw_addr);
    if(host->type == HOST_TYPE_LOCALHOST)
        printf(", Netmask: %s", host->netmask);
    if(host->ip != NULL && host->ip6 != NULL)
        printf(", IPv6: %s", host->ip6);
    printf("\n");

    char *other_label[] = {"Other IP", "Other IPv6", "Other HW", "Services"};
    nmlist *other_list[] = {host->list_ip, host->list_ip6, host->list_hw_addr, host->list_services};
    
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


void nm_host_print(nm_host *host) {
    assert(host != NULL);
    assert(host->ip != NULL || host->ip6 != NULL);

    const char *type = nm_host_type_labels[host->type];
    if(host->hostname)
        printf("+ [%s] %s\n", type, host->hostname);
    else
        printf("+ [%s]\n", type);
    
    if(host->type == HOST_TYPE_LOCALHOST)
        printf("   Mask: %s\n", host->netmask);

    if(host->hw_addr)
        printf("   HW:   %s\n", host->hw_addr);
    nm_list_foreach(node, host->list_hw_addr)
        printf("   HW:   %s\n", (char *)node->data);
    
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
    if(host->hw_addr)
        return host->hw_addr;
    
    return NULL;

}


static nmlist *nm_host_merge_field(char **dest_field, char *src_field, 
                                   nmlist *dest_list_field, nmlist *src_list_field) {

    //assert(dest_field != NULL);

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
        log_warn("nm_host_merge: found conflicting hostnames: %s, %s", dst->hostname, src->hostname);
    }

    //ip
    dst->list_ip = nm_host_merge_field(&dst->ip, src->ip,
                                        dst->list_ip, src->list_ip);
    //hw address
    dst->list_hw_addr = nm_host_merge_field(&dst->hw_addr, src->hw_addr,
                                             dst->list_hw_addr, src->list_hw_addr);
    //ip6
    dst->list_ip6 = nm_host_merge_field(&dst->ip6, src->ip6,
                                         dst->list_ip6, src->list_ip6);

    //services
    dst->list_services = nm_host_merge_field(NULL, NULL,
                                         dst->list_services, src->list_services);

}

/*

nm_host *nm_host_merge_into_array(nm_host *host, HostArray *array){
    assert(array != NULL);
    assert(host != NULL);
    assert(host->ip != NULL || host->ip6 != NULL);    //find by ip only, assert otherwise

    //empty array, append entry into it
    if(array->len == 0){
        nm_host_array_append(array, host);
        return host;
    }

    //merge
    nm_host *find_entry;
    for (int i=0; i < array->len; i++){
        find_entry = nm_host_array_index(array, i);
        if((find_entry->ip != NULL && host->ip != NULL && strcmp(find_entry->ip, host->ip) == 0) ||
                (find_entry->ip6 != NULL && host->ip6 != NULL && strcmp(find_entry->ip6, host->ip6) == 0)){
            nm_host_merge(find_entry, host);
            nm_host_destroy(host);
            return find_entry;
        }
    }
    //not found, append it
    nm_host_array_append(array, host);
    return host;
}


*/
