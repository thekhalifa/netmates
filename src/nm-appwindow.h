/**
 * @file nm-appwindow.h
 * GTK application and window
 *
 * SPDX-License-Identifier: GPL-3.0
 */
#ifndef NETWORK_MATES_NM_APPWINDOW_H
#define NETWORK_MATES_NM_APPWINDOW_H

#include <gtk-3.0/gtk/gtk.h>

#include "nm-common.h"
#include "nm-host.h"
#include "nm-scan.h"

#define NM_APPLICATION_UI_FILE "gui/nm-window.ui"
#define NM_APPLICATION_CSS_FILE "gui/nm-style.css"
#define NM_RESOURCE_BASE "/uk/netmates/"
#define NM_APPLICATION_ICON "network-wireless"
#define NM_GUI_APP_NAME "uk.netmates"

struct icon_def {
    char *icon;
    char *description;
};

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


void list_box_add_host(nm_host *host);
void list_box_clear();

void on_app_activate(GtkApplication *gtkapp, gpointer should_run);

int init_application(int argc, char **argv);

#endif //NETWORK_MATES_NM_APPWINDOW_H
