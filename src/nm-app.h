#ifndef NETWORK_MATES_NM_APP_H
#define NETWORK_MATES_NM_APP_H

#include "nm-common.h"


typedef struct {
    bool arg_known_only;
    bool arg_known_first;
    bool arg_skip_resolve;
    int arg_conn_threads;
    int arg_conn_timeout;
    int arg_list_threads;
    int arg_max_hosts;
    int arg_scan_timeout;
    int arg_subnet_offset;
} nm_application;


int init_application(int argc, char **argv);

#endif //NETWORK_MATES_NM_APP_H
