#include "nm-app.h"
#include "nm-scan.h"

/* Application argument defaults */
static nm_application nm_app = {
        .arg_known_only = false,
        .arg_known_first = false,
        .arg_skip_resolve = false,
        .arg_conn_timeout = -1,
        .arg_conn_threads = 255,
        .arg_list_threads = 0,
        .arg_max_hosts = 5,
        .arg_scan_timeout = -1,
        .arg_subnet_offset = 117,
//         .arg_scan_to = -1,
//         .arg_conn_th = -1,
//         .arg_conn_to = -1,
//         .arg_list_th = -1,
};

void print_usage() {
    printf("Usage: \n"
    "    nmlite [options]\n"
    "    \n"
    "    Options: \n"
    "       -g     print debug messages\n"
    "       -h     help message (this one)\n"
    "\n");
}

/*
 * 
    const GOptionEntry cmd_options[] = {
            {"cli", 'i', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &nm_app.arg_cli,
                                "Run CLI only, no GUI. This is the default option when running as '" NM_APP_CLI_NAME "'.", NULL},
            {"gui", 'g', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &nm_app.arg_gui,
                                "Run the GUI. This is the default when command name is not '" NM_APP_CLI_NAME "'", NULL},
            {"scan-timeout", 'T', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &nm_app.arg_scan_to,
                    "Maximum time to spend scanning, either connecting or listening, in seconds.", NULL},
            {"max-hosts", 'm', G_OPTION_FLAG_NONE, G_OPTION_ARG_INT, &nm_app.arg_max_hosts,
                        "IPv4 maximum number of subnet hosts to scan. Defaults to the full subnet up to 254 (/24).", NULL},
            {"known-only", 'k', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &nm_app.arg_known_only,
                                "Show and resolve Known Hosts only based on kernel data.", NULL},
            {"known-first", 'f', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &nm_app.arg_known_first,
                                "Show details of Known Hosts first based on kernel data as that is "
                                "quick then proceed to scan the network.", NULL},
            {"numeric", 'n', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &nm_app.arg_skip_resolve,
                    "Skip resolving hostnames and hw vendors.", NULL},
            {"connect-threads", 'c', G_OPTION_FLAG_NONE, G_OPTION_ARG_INT, &nm_app.arg_conn_th,
                    "Maximum number of connection threads to use when scanning.", NULL},
            {"connect-timeout", 't', G_OPTION_FLAG_NONE, G_OPTION_ARG_INT, &nm_app.arg_conn_to,
                    "Maximum time to wait for a response from a specific port in milliseconds.", NULL},
            {"listen-threads", 'l', G_OPTION_FLAG_NONE, G_OPTION_ARG_INT, &nm_app.arg_list_th,
                    "Maximum number of listening threads to use when scanning.", NULL},
    };
*/


int process_args(int argc, char *argv[]) {
    int arg_index = 1;
    int shouldRun = 0;
    
    while(arg_index < argc){
        char *option   = argv[arg_index];
        char *argument = "";

        if(arg_index + 1 < argc){
            argument = argv[arg_index + 1];
        }

        if(!strcmp(option, "-h")){
            print_usage();
            exit(0);
        }else if(!strcmp(option, "-g")){
            log_set_level(LOG_WARN);
        }else if(!strcmp(option, "-g1")){
            log_set_level(LOG_DEBUG);
        }else if(!strcmp(option, "-g2")){
            log_set_level(LOG_TRACE);
//         }else if(!strcmp(option, "-dpi")){
//             if(strlen(argument) > 0)
//                 cli_requested_dpi = atoi(argument) - 1;
//             run_action = RUN_ACTION_SET;
//             arg_index++;
//         }else if(!strcmp(option, "-led")){
//             if(strlen(argument) > 0)
//                 cli_requested_led = atoi(argument) - 1;
//             run_action = RUN_ACTION_SET;
//             arg_index++;
//         }else if(!strcmp(option, "-speed")){
//             if(strlen(argument) > 0)
//                 cli_requested_speed = atoi(argument) - 1;
//             run_action = RUN_ACTION_SET;
//             arg_index++;
        }else{
            printf("Invalid argument: %s\n\n", option);
            print_usage();
            exit(1);
        }
        arg_index++;
    }
    
    
    return shouldRun;
}

/* Keeps the main loop running as the only source while the scan happens in a separate thread */
/*
static gboolean check_cli_running(gpointer data){
    g_assert(nm_app.scan_thread != NULL);

    if(!scan_util_is_running()){
        g_thread_unref(nm_app.scan_thread);
        return G_SOURCE_REMOVE;
    }
    usleep(500000);
    return G_SOURCE_CONTINUE;
}
*/


/*
static gboolean on_signal_received (gpointer data){

    void(*stop_scan)(void) = data;
    g_message("Signal received, quitting!\n");
    stop_scan();
    g_application_quit(G_APPLICATION(nm_app.gtk_app));
    return G_SOURCE_REMOVE;
}
*/

static void setup_signals(){
    //g_unix_signal_add(SIGTERM, on_signal_received, (gpointer)scan_stop_threads);
    //g_unix_signal_add(SIGINT, on_signal_received, (gpointer)scan_stop_threads);
    return;
}



int init_application(int argc, char **argv){
    
    
    log_set_level(LOG_TRACE);
    log_debug("Startup");

    process_args(argc, argv);
    
    setup_signals();
    scan_init(nm_app.arg_known_first,
              nm_app.arg_known_only,
              nm_app.arg_skip_resolve,
              nm_app.arg_conn_threads,
              nm_app.arg_conn_timeout,
              nm_app.arg_max_hosts,
              nm_app.arg_list_threads,
              nm_app.arg_scan_timeout,
              nm_app.arg_subnet_offset);
    
    //scan_start_cli_thread(NULL);
    scan_start();
    scan_destroy();
    return 0;
    
    //nm_app.scan_thread = g_thread_try_new("ScanThread", scan_start_cli_thread, NULL, &error);
    /*
    if(error != NULL){
        puts("Error starting the scan thread, quitting");
        return 1;
    }

    g_idle_add(check_cli_running, NULL);
    */
    //build_window(gtkapp);


}

