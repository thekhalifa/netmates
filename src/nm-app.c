#include <signal.h>
#include "nm-common.h"
#include "nm-scan.h"


/* Application argument defaults */
struct {
    int log_level;
    bool arg_list_format;
    bool arg_brief_format;
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
    .log_level = LOG_WARN,          /* default: LOG_WARN */
    .arg_known_only = false,
    .arg_known_first = false,
    .arg_skip_resolve = false,
    .arg_scan_only = false,
    .arg_scan_all = false,
    .arg_scan_timeout = 5000,       /* default: 5000ms */
    .arg_conn_timeout = 200,        /* default: 300ms */
    .arg_conn_threads = 255,        /* default: 255 */
    .arg_list_threads = 12,         /* default: 12 */
    .arg_max_hosts = 0,
    .arg_subnet_offset = 0,
};


void print_version()
{
    printf(""NM_APP_NAME" version "NM_APP_VERSION"\n");
}

void print_usage()
{
    printf("Usage: \n"
           "\n"
           "    "NM_APP_NAME" [options]\n"
           "  \n"
           "Options: \n"
           "    -k, --known-only            show known hosts only, no scan\n"
           "    -K, --known-first           show known hosts first then scan\n"
           "    -s, --scan-only             show scan results only, no known hosts\n"
           "    -S, --scan-all              scan using all methods even if host is live\n"
           "    -n, --skip-resolve          skip resolving hosts and show numeric values\n"
           "\n"
           "    -t, --scan-timeout <N>      scan timeout in seconds\n"
           "    -T, --connect-timeout <N>   connect scan timeout in milliseconds\n"
           "    -c, --connect-threads <N>   number of connect threads. Set to 0 to skip connecting\n"
           "    -l, --listen-threads <N>    number of listen threads. Set to 0 to skip listening\n"
           "    -m, --max-hosts <N>         max number of host ipv4 to scan within the subnet\n"
           "    -o, --subnet-offset <N>     offset the first host scan ipv4\n"
           "\n"
           "    -L, --list-format           print results as a list\n"
           "    -B, --brief-format          print IPs, hostnames only\n"
           "    -g, --debug                 print debug messages\n"
           "    -G, --trace                 print trace messages\n"
           "    -v, --version               print version number and exit\n"
           "    -h, --help                  help message (this one)\n"
           "\n");
}

void exit_arg_error(char *arg, char *value)
{
    printf("Invalid value: %s for argument: %s\n\n", value, arg);
    exit(1);
}

void process_args(int argc, char *argv[])
{
    int argindex = 1;

    while (argindex < argc) {
        char *arg   = argv[argindex];
        char *argvalue = "";

        if (argindex + 1 < argc) {
            argvalue = argv[argindex + 1];
        }

        if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            print_usage();
            exit(0);
        } else if (!strcmp(arg, "-v") || !strcmp(arg, "--version")) {
            print_version();
            exit(0);
        } else if (!strcmp(arg, "-g") || !strcmp(arg, "--debug")) {
            log_set_level(LOG_DEBUG);
        } else if (!strcmp(arg, "-G") || !strcmp(arg, "--trace")) {
            log_set_level(LOG_TRACE);
        } else if (!strcmp(arg, "-L") || !strcmp(arg, "--list-format")) {
            nm_app.arg_list_format = true;
        } else if (!strcmp(arg, "-B") || !strcmp(arg, "--brief-format")) {
            nm_app.arg_brief_format = true;
        } else if (!strcmp(arg, "-k") || !strcmp(arg, "--known-only")) {
            nm_app.arg_known_only = true;
        } else if (!strcmp(arg, "-K") || !strcmp(arg, "--known-first")) {
            nm_app.arg_known_first = true;
        } else if (!strcmp(arg, "-s") || !strcmp(arg, "--scan-only")) {
            nm_app.arg_scan_only = true;
        } else if (!strcmp(arg, "-S") || !strcmp(arg, "--scan-all")) {
            nm_app.arg_scan_all = true;
        } else if (!strcmp(arg, "-n") || !strcmp(arg, "--skip-resolve")) {
            nm_app.arg_skip_resolve = true;
        } else if (!strcmp(arg, "-c") || !strcmp(arg, "--connect-threads")) {
            if (strlen(argvalue) > 0 && isdigit(argvalue[0]))
                nm_app.arg_conn_threads = atoi(argvalue);
            else
                exit_arg_error(arg, argvalue);
            argindex++;
        } else if (!strcmp(arg, "-l") || !strcmp(arg, "--listen-threads")) {
            if (strlen(argvalue) > 0)
                nm_app.arg_list_threads = atoi(argvalue);
            else
                exit_arg_error(arg, argvalue);
            argindex++;
        } else if (!strcmp(arg, "-t") || !strcmp(arg, "--scan-timeout")) {
            if (strlen(argvalue) > 0)
                nm_app.arg_scan_timeout = atoi(argvalue) * 1000;
            else
                exit_arg_error(arg, argvalue);
            argindex++;
        } else if (!strcmp(arg, "-T") || !strcmp(arg, "--connect-timeout")) {
            if (strlen(argvalue) > 0)
                nm_app.arg_conn_timeout = atoi(argvalue);
            else
                exit_arg_error(arg, argvalue);
            argindex++;
        } else if (!strcmp(arg, "-m") || !strcmp(arg, "--max-hosts")) {
            if (strlen(argvalue) > 0)
                nm_app.arg_max_hosts = atoi(argvalue);
            else
                exit_arg_error(arg, argvalue);
            argindex++;
        } else if (!strcmp(arg, "-o") || !strcmp(arg, "--subnet-offset")) {
            if (strlen(argvalue) > 0)
                nm_app.arg_subnet_offset = atoi(argvalue);
            else
                exit_arg_error(arg, argvalue);
            argindex++;
        } else {
            printf("Invalid argument: %s\n\n", arg);
            exit(1);
        }
        argindex++;
    }
}

void signal_handler(int signum)
{
    psignal(signum, "Signal received, stopping scan and quitting.");
    scan_stop();
}

static void signal_setup()
{
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    return;
}

int init_application(int argc, char **argv)
{
    log_set_level(nm_app.log_level);
    log_set_lock(nm_log_set_lock, NULL);
    if (isatty(STDERR_FILENO))
        log_set_colour(true);
    if (isatty(STDOUT_FILENO))
        nm_enable_colour();


    log_debug("Startup");
    process_args(argc, argv);

    signal_setup();

    scan_state *state = scan_getstate();
    state->opt_print = true;
    state->opt_print_list = nm_app.arg_list_format;
    state->opt_print_brief = nm_app.arg_brief_format;
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

int main(int argc, char **argv)
{
    return init_application(argc, argv);
}
