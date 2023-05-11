#include "nm-common.h"
#include "nm-window.h"

void window_basic_on_activate(GtkApplication *gtkapp, gpointer user_data){
    build_window(gtkapp);

    nm_host *host;
    GList *services;

    host = nm_host_init(HOST_TYPE_LOCALHOST);
    host->hostname = "locahost1";
    host->ip = "127.0.1.1";
    host->ip6 = "::1";
    host->hw_addr = "00:FF:EE:DD:12:34 [Big Manufacturing Inc]";
    list_add_item(host);

    host = nm_host_init(HOST_TYPE_ROUTER);
    host->hostname = "big-fancy-router";
    host->ip = "192.168.1.1";
    host->ip6 = "fe80:abcd::0001:0002:0003:0004";
    host->hw_addr = "12:23:34:55:66:23";
    list_add_item(host);

    host = nm_host_init(HOST_TYPE_ANY);
    host->hostname = "Any_Host";
    host->ip = "192.168.1.2";
    services = g_list_append(NULL, "Service1");
    nm_host_add_services(host, services);
    list_add_item(host);

    host = nm_host_init(HOST_TYPE_SMART_DEVICE);
    host->hostname = "Smart_Light_2000";
    host->ip = "10.168.228.192";
    services = g_list_append(NULL, "UPNP");
    services = g_list_append(services, "upnp");
    services = g_list_append(services, "mdns");
    services = g_list_append(services, "Netflix");
    nm_host_add_services(host, services);
    list_add_item(host);

    host = nm_host_init(HOST_TYPE_SMART_TV);
    host->hostname = "Smart_Screen_TV";
    host->ip = "10.168.1.245";
    list_add_item(host);

    host = nm_host_init(HOST_TYPE_PHONE);
    host->hostname = "PhoneOne";
    host->ip = "10.168.1.173";
    list_add_item(host);

    host = nm_host_init(HOST_TYPE_COMPUTER);
    host->hostname = "laptop2092348453";
    host->ip = "10.168.1.79";
    list_add_item(host);

    host = nm_host_init(HOST_TYPE_PRINTER);
    host->hostname = "Printy_the_expensive";
    host->ip = "192.168.1.12";
    list_add_item(host);

    host = nm_host_init(HOST_TYPE_UNKNOWN);
    host->hostname = "192.168.1.123";
    host->ip = "192.168.1.123";
    list_add_item(host);

}

void window_update_on_activate(GtkApplication *gtkapp, gpointer user_data){
    build_window(gtkapp);

    nm_host *host;
    GList *services;

    host = nm_host_init(HOST_TYPE_LOCALHOST);
    host->hostname = "locahost1";
    host->ip = "127.0.1.1";
    host->ip6 = "::1";
    host->hw_addr = "00:FF:EE:DD:12:34 [Big Manufacturing Inc]";
    services = g_list_append(NULL, "UPNP");
    services = g_list_append(services, "upnp");
    services = g_list_append(services, "mdns");
    services = g_list_append(services, "Netflix");
    nm_host_add_services(host, services);
    list_add_item(host);

    host->type = HOST_TYPE_PHONE;
    host->hw_addr = "00:FF:EE:DD:00:00";
    list_update_item(host);

    host = nm_host_init(HOST_TYPE_ROUTER);
    host->hostname = "big-fancy-router";
    host->ip = "192.168.1.1";
    host->ip6 = NULL;
    host->hw_addr = "12:23:34:55:66:23";
    services = g_list_append(NULL, "Service1");
    nm_host_add_services(host, services);
    list_add_item(host);

    host->ip6 = "fe80:abcd::0001:0002:0003:0004";
    list_update_item(host);


}

void test_window_basic(void) {
    GtkApplication *app = gtk_application_new ("ak.Network_List", G_APPLICATION_FLAGS_NONE);
    g_signal_connect (app, "activate", G_CALLBACK (window_basic_on_activate), NULL);
    g_assert_false(g_application_run(G_APPLICATION(app), 0, NULL));
    g_object_unref (app);
}


void test_window_update(void) {
    GtkApplication *app = gtk_application_new ("ak.Network_List", G_APPLICATION_FLAGS_NONE);
    g_signal_connect (app, "activate", G_CALLBACK (window_update_on_activate), NULL);
    g_assert_false(g_application_run(G_APPLICATION(app), 0, NULL));
    g_object_unref (app);
}



int main (int argc, char **argv){

    g_test_init(&argc, &argv, NULL);
    if(!g_test_verbose())
        g_log_set_handler(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO, nm_log_dummy, NULL);

    g_test_add_func("/window/basic", test_window_basic);
    g_test_add_func("/window/update", test_window_update);

    return g_test_run();
}
