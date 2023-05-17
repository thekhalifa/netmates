#ifndef NETWORK_MATES_NM_WINDOW_H
#define NETWORK_MATES_NM_WINDOW_H

#include <glib-2.0/glib.h>
//#include <glib.h>
//#include <gtk/gtk.h>
#include <gtk-3.0/gtk/gtk.h>

#include "nm-common.h"
#include "nm-host.h"
#include "nm-scan.h"

#define NM_APPLICATION_UI_FILE "gui/nm-window.ui"
#define NM_APPLICATION_CSS_FILE "gui/nm-style.css"
#define NM_RESOURCE_BASE "/ws/khalifa/network-mates/"

#define ICON_TYPE_PHONE "phone"
#define ICON_TYPE_COMPUTER "computer"
#define ICON_TYPE_ROUTER "network-wireless"
#define ICON_TYPE_PRINTER "printer"
#define ICON_TYPE_LOCALHOST "mark-location"
#define ICON_TYPE_SMART_TV "tv"
#define ICON_TYPE_SMART_DEVICE "cpu"
#define ICON_TYPE_OTHER "help-browser"


typedef struct {
    GtkApplication *gtk_app;
    GtkApplicationWindow *window;
    GtkWidget *window_widget;
    GtkBuilder *builder;
    GtkWidget *spinner;
    GtkWidget *refresh_button;
    GtkListBox *listbox;
    GListStore *list_store;
    char *host_icons[HOST_TYPE_LENGTH];
} nm_window;

typedef struct{
    GObject parent;
    gchar  *host_name;
    gint    host_type;
    gchar  *host_type_label;
    gchar  *host_ipv4;
    gchar  *host_ipv6;
    gchar  *host_hw_addr;
    gchar  *host_hw_vendor;
    GArray *host_other_ip4;
    GArray *host_other_ip6;
    GArray *host_services;
} HostItem;


void list_add_item(nm_host *entry);

void on_refresh_clicked(GtkWidget *widget, gpointer user_data);
void on_app_activate(GtkApplication *gtkapp, gpointer user_data);

int init_application(int argc, char **argv);

#endif //NETWORK_MATES_NM_WINDOW_H
