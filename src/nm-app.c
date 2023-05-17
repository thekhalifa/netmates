#include <signal.h>
#include "nm-common.h"
#include "nm-scan.h"


/* Application argument defaults */
struct {
    int log_level;
    bool arg_known_only;
    bool arg_known_first;
    bool arg_scan_only;
    bool arg_scan_all;
    bool arg_skip_resolve;
    int arg_conn_threads;
    int arg_conn_timeout;
    int arg_list_threads;
    int arg_max_hosts;
    int arg_scan_timeout;
    int arg_subnet_offset;
}  nm_app = {
    .log_level = LOG_DEBUG,
    .arg_known_only = false,
    .arg_known_first = false,
    .arg_skip_resolve = false,
    .arg_scan_only = false,
    .arg_scan_all = true,
    .arg_scan_timeout = 5000,
    .arg_max_hosts = -1,
    .arg_conn_timeout = 200,
    .arg_conn_threads = 3,
    .arg_list_threads = 0,
    .arg_subnet_offset = -1,
};

void print_version() {
    printf(""NM_APP_NAME" version "NM_APP_VERSION"\n");
}


void print_usage() {
    printf("Usage: \n"
    "\n"
    "    "NM_APP_NAME" [options]\n"
    "  \n"
    "Options: \n"
    "    -k, --known-only            print known hosts only, no scan\n"
    "    -K, --known-first           print known hosts first then scan\n"
    "    -s, --scan-only             print scan results only, no known hosts\n"
    "    -S, --scan-all              scan using all methods even if host is live\n"
    "    -n, --skip-resolve          skip resolving hosts and show numeric values\n"
    "\n"
    "    -t, --scan-timeout <N>      scan timeout in milliseconds\n"
    "    -T, --connect-timeout <N>   connect scan timeout in milliseconds\n"
    "    -c, --connect-threads <N>   number of connect threads. Set to 0 to skip connecting\n"
    "    -l, --listen-threads <N>    number of listen threads. Set to 0 to skip listening\n"
    "    -m, --max-hosts <N>         max number of host ipv4 to scan within the subnet\n"
    "    -o, --subnet-offset <N>     offset the first host scan ipv4\n"
    "\n"
    "    -g, --debug                 print debug messages\n"
    "    -G, --trace                 print trace messages\n"
    "    -v, --version               print version number and exit\n"
    "    -h, --help                  help message (this one)\n"
    "\n");
}

void exit_arg_error(char *option, char * argument) {
    printf("Invalid value: %s for argument: %s\n\n", argument, option);
    exit(1);
}

void process_args(int argc, char *argv[]) {
    int arg_index = 1;
    
    while(arg_index < argc){
        char *option   = argv[arg_index];
        char *argument = "";

        if(arg_index + 1 < argc){
            argument = argv[arg_index + 1];
        }

        if(!strcmp(option, "-h") || !strcmp(option, "--help")){
            print_usage();
            exit(0);
        }else if(!strcmp(option, "-v") || !strcmp(option, "--version")){
            print_version();
            exit(0);
        }else if(!strcmp(option, "-g") || !strcmp(option, "--debug")){
            log_set_level(LOG_DEBUG);
        }else if(!strcmp(option, "-G") || !strcmp(option, "--trace")){
            log_set_level(LOG_TRACE);
        }else if(!strcmp(option, "-k") || !strcmp(option, "--known-only")){
            nm_app.arg_known_only = true;
        }else if(!strcmp(option, "-K") || !strcmp(option, "--known-first")){
            nm_app.arg_known_first = true;
        }else if(!strcmp(option, "-s") || !strcmp(option, "--scan-only")){
            nm_app.arg_scan_only = true;
        }else if(!strcmp(option, "-S") || !strcmp(option, "--scan-all")){
            nm_app.arg_scan_all = true;
        }else if(!strcmp(option, "-n") || !strcmp(option, "--skip-resolve")){
            nm_app.arg_skip_resolve = true;
        }else if(!strcmp(option, "-c") || !strcmp(option, "--connect-threads")){
            if(strlen(argument) > 0 && isdigit(argument[0]))
                nm_app.arg_conn_threads = atoi(argument);
            else
                exit_arg_error(option, argument);
            arg_index++;
        }else if(!strcmp(option, "-l") || !strcmp(option, "--listen-threads")){
            if(strlen(argument) > 0)
                nm_app.arg_list_threads = atoi(argument);
            else
                exit_arg_error(option, argument);
            arg_index++;
        }else if(!strcmp(option, "-t") || !strcmp(option, "--scan-timeout")){
            if(strlen(argument) > 0)
                nm_app.arg_scan_timeout = atoi(argument);
            else
                exit_arg_error(option, argument);
            arg_index++;
        }else if(!strcmp(option, "-T") || !strcmp(option, "--connect-timeout")){
            if(strlen(argument) > 0)
                nm_app.arg_conn_timeout = atoi(argument);
            else 
                exit_arg_error(option, argument);
            arg_index++;
        }else if(!strcmp(option, "-m") || !strcmp(option, "--max-hosts")){
            if(strlen(argument) > 0)
                nm_app.arg_max_hosts = atoi(argument);
            else 
                exit_arg_error(option, argument);
            arg_index++;
        }else if(!strcmp(option, "-o") || !strcmp(option, "--subnet-offset")){
            if(strlen(argument) > 0)
                nm_app.arg_subnet_offset = atoi(argument);
            else 
                exit_arg_error(option, argument);
            arg_index++;
        }else{
            printf("Invalid argument: %s\n\n", option);
            exit(1);
        }
        arg_index++;
    }
}

void signal_handler(int signum){
    psignal(signum, "Signal received, stopping scan and quitting.");
    scan_stop();
}

static void signal_setup(){
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    return;
}

int init_application(int argc, char **argv){

    log_set_level(nm_app.log_level);

    log_debug("Startup");
    process_args(argc, argv);
    
    signal_setup();

    scan_state *state = scan_getstate();
    state->opt_print = true;
    state->opt_known_first = nm_app.arg_known_first;
    state->opt_known_only = nm_app.arg_known_only;
    state->opt_skip_resolve = nm_app.arg_skip_resolve;

    state->opt_scan_only = nm_app.arg_scan_only;
    state->opt_scan_all = nm_app.arg_scan_all;
    state->opt_scan_timeout_ms = nm_app.arg_scan_timeout;
    state->opt_max_hosts = nm_app.arg_max_hosts;
    state->opt_subnet_offset = nm_app.arg_subnet_offset;
    state->opt_connect_threads = nm_app.arg_conn_threads;
    state->opt_connect_timeout_ms = nm_app.arg_conn_timeout;
    state->opt_listen_threads = nm_app.arg_list_threads;
    
    scan_init();
    scan_start();
    scan_destroy();
    return 0;

}

int main (int argc, char **argv){
    return init_application(argc, argv);    
}
