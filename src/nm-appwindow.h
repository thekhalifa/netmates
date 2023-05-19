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
#define NM_APPLICATION_ICON "network-wireless"

struct icon_def {
    char *icon;
    char *description;
} ;

typedef struct {
    GtkApplication *gtk_app;
    GtkApplicationWindow *window;
    GtkWidget *window_widget;
    GtkBuilder *builder;
    GtkWidget *spinner;
    GtkWidget *refresh_button;
    GtkSpinButton *scan_timeout;
    GtkSwitch *known_hosts;
    GtkSwitch *scan_all;
    //GtkMenuButton *main_menu;
    GtkListBox *listbox;
    char *host_icons[HOST_TYPE_LENGTH];
    struct icon_def icons[HOST_TYPE_LENGTH];
} nm_window;


void list_add_item(nm_host *entry);

void on_refresh_clicked(GtkWidget *widget, gpointer user_data);
void on_app_activate(GtkApplication *gtkapp, gpointer user_data);

int init_application(int argc, char **argv);

#endif //NETWORK_MATES_NM_WINDOW_H
