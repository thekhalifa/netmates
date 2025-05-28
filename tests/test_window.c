/**
 * @file test_window.c
 * nm-window tests
 *
 * SPDX-License-Identifier: GPL-3.0
 */
#include "nm-appwindow.h"


void nm_log_dummy(const char *log_domain, int log_level, const char *message, void *user_data)
{
    //do nothing.
}

void window_basic_on_activate(GtkApplication *gtkapp, gpointer user_data)
{

    on_app_activate(gtkapp, (void *)false);

    nm_host *host;

    host = nm_host_init(HOST_TYPE_LOCALHOST);
    host->hostname = "locahost1";
    host->ip = "127.0.1.1";
    host->ip6 = "::1";
    host->hw_if.addr = "00:FF:EE:DD:12:34";
    host->hw_if.vendor = "Big Manufacturing Inc";
    list_box_add_host(host);

    host = nm_host_init(HOST_TYPE_ROUTER);
    host->hostname = "big-fancy-router";
    host->ip = "192.168.1.1";
    host->ip6 = "fe80:abcd::0001:0002:0003:0004";
    //host->hw_addr = "12:23:34:55:66:23";
    list_box_add_host(host);

    host = nm_host_init(HOST_TYPE_ANY);
    host->hostname = "Any_Host";
    host->ip = "192.168.1.2";
    host->list_services = nm_list_add(host->list_services, "upnp");
    list_box_add_host(host);

    host = nm_host_init(HOST_TYPE_DEVICE);
    host->hostname = "Smart_Light_2000";
    host->ip = "10.168.228.192";
    host->list_services = nm_list_add(host->list_services, "UPNP");
    host->list_services = nm_list_add(host->list_services, "upnp");
    host->list_services = nm_list_add(host->list_services, "mdns");
    host->list_services = nm_list_add(host->list_services, "Netflix");
    list_box_add_host(host);

    host = nm_host_init(HOST_TYPE_TV);
    host->hostname = "Smart_Screen_TV";
    host->ip = "10.168.1.245";
    list_box_add_host(host);

    host = nm_host_init(HOST_TYPE_PHONE);
    host->hostname = "PhoneOne";
    host->ip = "10.168.1.173";
    list_box_add_host(host);

    host = nm_host_init(HOST_TYPE_PC);
    host->hostname = "laptop2092348453";
    host->ip = "10.168.1.79";
    list_box_add_host(host);

    host = nm_host_init(HOST_TYPE_PRINTER);
    host->hostname = "Printy_the_expensive";
    host->ip = "192.168.1.12";
    list_box_add_host(host);

    host = nm_host_init(HOST_TYPE_UNKNOWN);
    host->hostname = "192.168.1.123";
    host->ip = "192.168.1.123";
    list_box_add_host(host);

}

void test_window_basic(void)
{
    GtkApplication *app = gtk_application_new("uk.netmates", 0);
    g_signal_connect(app, "activate", G_CALLBACK(window_basic_on_activate), NULL);
    g_assert_false(g_application_run(G_APPLICATION(app), 0, NULL));
    g_object_unref(app);
}


int main(int argc, char **argv)
{

    g_test_init(&argc, &argv, NULL);
    if (!g_test_verbose())
        g_log_set_handler(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO, nm_log_dummy, NULL);

    g_test_add_func("/window/basic", test_window_basic);

    return g_test_run();
}
