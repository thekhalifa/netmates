#include "nm-appwindow.h"

static nm_window window = {
        .icons[HOST_TYPE_UNKNOWN] = {"help-browser","Unknown device type"},
        .icons[HOST_TYPE_LOCALHOST] = {"mark-location","localhost"},
        .icons[HOST_TYPE_ROUTER] = {"modem","router or gateway device"},
        .icons[HOST_TYPE_PHONE] = {"phone","smart phone"},
        .icons[HOST_TYPE_PRINTER] = {"printer","printer or print sharing device"},
        .icons[HOST_TYPE_DEVICE] = {"cpu","smart device"},
        .icons[HOST_TYPE_TV] = {"tv","smart TV or streaming device"},
        .icons[HOST_TYPE_PC] = {"computer","PC or server"},
        .icons[HOST_TYPE_PC_MAC] = {"computer","Mac computer"},
        .icons[HOST_TYPE_PC_WIN] = {"computer","Windows computer"},
        .icons[HOST_TYPE_ANY] = {"computer","Other device"},
        .icons[HOST_TYPE_KNOWN] = {"network-wired","Previously seen device, but not scanned"},
};


static char *
create_title_label(nm_host *host){
    static const char *title_format = "<span foreground=\"#338E5E\" size=\"larger\"><b>%s</b></span>";
    static const char *ipv4_format =        "\n<tt><small>inet:   %s</small></tt>";
    static const char *ipv6_format =        "\n<tt><small>inet6:  %s</small></tt>";
    static const char *hw_format =          "\n<tt><small>link:   %s</small></tt>";
    static const char *hwv_format =         "\n<tt><small>vendor: %s</small></tt>";
    char buffer[1024];
    int position = 0;

    
    //Title
    position += sprintf(buffer, title_format, nm_host_label(host));

    //Details
    if(host->ip)
        position += sprintf(buffer + position, ipv4_format, host->ip);
    nm_list_foreach(n, host->list_ip)
        position += sprintf(buffer + position, ipv4_format, n->data);
    
    //Details
    if(host->ip6)
        position += sprintf(buffer + position, ipv6_format, host->ip6);
    nm_list_foreach(n, host->list_ip6)
        position += sprintf(buffer + position, ipv6_format, n->data);

    if(host->hw_if.addr)
        position += sprintf(buffer + position, hw_format, host->hw_if.addr);
    if(host->hw_if.vendor)
        position += sprintf(buffer + position, hwv_format, host->hw_if.vendor);

    return g_strdup(buffer);
}

static char *
create_tooltip(nm_host *host){
    static const char *hostname_format = "Hostname: %s";
    static const char *detail_start_format = "<tt><small>";
    static const char *ipv4_format =        "\nipv4:     %s";
    static const char *ipv6_format =        "\nipv6:     %s";
    static const char *hw_format =          "\nmac:      %s";
    static const char *hwv_format =         "\nvendor:   %s";
    static const char *services_heading =   "\nservices: ";
    static const char *ports_heading =      "\nports:    ";
    static const char *detail_end_format = "</small></tt>";

    char buffer[1024];
    char servicebuffer[NM_GEN_BUFFSIZE];
    char portbuffer[NM_GEN_BUFFSIZE];
    char *pointer = buffer;

    pointer = stpcpy(buffer, detail_start_format);
    if(host->hostname)
        pointer += sprintf(pointer, hostname_format, host->hostname);

    if(host->ip)
        pointer += sprintf(pointer, ipv4_format, host->ip);
    nm_list_foreach(n, host->list_ip)
        pointer += sprintf(pointer, ipv4_format, n->data);

    if(host->ip6)
        pointer += sprintf(pointer, ipv6_format, host->ip6);
    nm_list_foreach(n, host->list_ip6)
        pointer += sprintf(pointer, ipv6_format, n->data);

    if(host->hw_if.addr)
        pointer += sprintf(pointer, hw_format, host->hw_if.addr);
    if(host->hw_if.vendor)
        pointer += sprintf(pointer, hwv_format, host->hw_if.vendor);

    if(host->list_services)
        pointer = stpcpy(pointer, services_heading);
    nm_list_foreach(n, host->list_services) {
        pointer += sprintf(pointer, "%s", (char*)n->data);
        if(n->next)
            pointer += sprintf(pointer, ", ");
    }
        
    if(host->list_ports)
        pointer = stpcpy(pointer, ports_heading);
    nm_list_foreach(n, host->list_ports) {
        pointer += sprintf(pointer, "%s", (char*)n->data);
        if(n->next)
            pointer += sprintf(pointer, ", ");
    }

    stpcpy(pointer, detail_end_format);

    return g_strdup(buffer);
}


void
create_services_tags(GtkWidget *flow_box, nm_host *host) {
    g_assert(flow_box != NULL && host != NULL);
    
    static const char *tag_format = "<span font_weight='light' size='smaller'>%s</span>";
    char tagbuff[128];
    GtkWidget *flow_child;
    GtkWidget *label;
    
    nm_list_foreach(n, host->list_services) {
        
        sprintf(tagbuff, tag_format, n->data);
        label = gtk_label_new(tagbuff);
        gtk_label_set_use_markup(GTK_LABEL(label), TRUE);
        gtk_widget_set_tooltip_text(label, n->data);
        
        flow_child = gtk_flow_box_child_new();
        GtkStyleContext *sc = gtk_widget_get_style_context(flow_child);
        gtk_style_context_add_class(sc, "nm-tag-container"); //"rubberband"
        //gtk_widget_set_opacity(flow_child, 0.8);
        
        gtk_container_add(GTK_CONTAINER(flow_child), label);
        gtk_container_add(GTK_CONTAINER(flow_box), flow_child);
    }
    
}


static GtkWidget *list_create_list_row(nm_host *host){

    
    //left side image
    //char *icon_name = window.host_icons[entry_item->host_type];
    char *icon = window.icons[host->type].icon;
    char *icon_tip = window.icons[host->type].description;
    GtkWidget *row_image = gtk_image_new_from_icon_name(icon, GTK_ICON_SIZE_LARGE_TOOLBAR);
    GtkWidget *button = gtk_button_new();
    gtk_button_set_image(GTK_BUTTON(button), row_image);
    //gtk_widget_set_tooltip_text(button, entry_item->host_type_label);
    gtk_widget_set_tooltip_text(button, icon_tip);
    //gtk_button_set_relief(GTK_BUTTON(button), GTK_RELIEF_NONE);
    gtk_widget_set_size_request(button, 40, 40);
    gtk_widget_set_valign(button, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(button, GTK_ALIGN_START);
    //g_signal_connect(button, "clicked", G_CALLBACK(on_more_info_clicked), entry_item);

    //main label
    char *title_text = create_title_label(host);
    GtkWidget *host_label = gtk_label_new(title_text);
    g_free(title_text);
    gtk_label_set_use_markup(GTK_LABEL(host_label), TRUE);
    gtk_label_set_selectable(GTK_LABEL(host_label), TRUE);
    gtk_label_set_ellipsize(GTK_LABEL(host_label), PANGO_ELLIPSIZE_END);
    gtk_label_set_justify(GTK_LABEL(host_label), GTK_JUSTIFY_LEFT);
    gtk_widget_set_halign(GTK_WIDGET(host_label), GTK_ALIGN_START);
    gtk_widget_set_valign(GTK_WIDGET(host_label), GTK_ALIGN_START);
    //char *host_tooltip = create_label_tooltip_text_for_host(entry_item);
    char *host_tooltip = create_tooltip(host);
    //gtk_widget_set_tooltip_text(host_label, host_tooltip);
    gtk_widget_set_tooltip_markup(host_label, host_tooltip);
    g_free(host_tooltip);

    //services flow
    GtkWidget *flow_box = gtk_flow_box_new();
    gtk_widget_set_size_request(flow_box, 40, 40);
    gtk_widget_set_halign(flow_box, GTK_ALIGN_END);
    gtk_widget_set_valign(flow_box, GTK_ALIGN_START);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(flow_box), 2);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow_box), 3);
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow_box), GTK_SELECTION_NONE);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(flow_box), 2);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(flow_box), 2);
    gtk_flow_box_set_homogeneous(GTK_FLOW_BOX(flow_box), TRUE);
    gtk_orientable_set_orientation(GTK_ORIENTABLE(flow_box), GTK_ORIENTATION_VERTICAL);

    create_services_tags(flow_box, host);

    GtkWidget* mid_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_pack_start(GTK_BOX(mid_box), host_label, TRUE, TRUE, 0);
    gtk_box_pack_end(GTK_BOX(mid_box), flow_box, FALSE, TRUE, 0);


    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_pack_start(GTK_BOX(box), button, FALSE, TRUE, 5);
    gtk_box_pack_start(GTK_BOX(box), mid_box, TRUE, TRUE, 5);
    //gtk_widget_set_size_request(box, -1, 80);
    
    GtkWidget *listboxrow = gtk_list_box_row_new();
    gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(listboxrow), false);
    gtk_container_add(GTK_CONTAINER(listboxrow), box);
    gtk_widget_show_all(listboxrow);
    return listboxrow;
}

void list_box_add_host(nm_host *host) {
    assert(window.listbox != NULL);
    gtk_container_add(GTK_CONTAINER(window.listbox), list_create_list_row(host));
}

void list_box_clear() {
    assert(window.listbox != NULL);
    GList *n = gtk_container_get_children(GTK_CONTAINER(window.listbox));
    for(; n; n = n->next){
        gtk_widget_destroy(GTK_WIDGET(n->data));
    }
}

void set_options_from_scan() {
    scan_state *state = scan_getstate();
    gtk_switch_set_state (window.known_hosts, state->opt_known_only);
    gtk_switch_set_state (window.scan_all, state->opt_scan_all);
    gtk_spin_button_set_value (window.scan_timeout, (float)state->opt_scan_timeout_ms / 1000);       
}

void set_scan_from_options() {
    scan_state *state = scan_getstate();
    state->opt_known_only = gtk_switch_get_state (window.known_hosts);
    state->opt_scan_all = gtk_switch_get_state (window.scan_all);
    state->opt_scan_timeout_ms = (int)gtk_spin_button_get_value (window.scan_timeout) * 1000;
}

void show_scan_started() {

    gtk_spinner_start(GTK_SPINNER(window.spinner));
    gtk_widget_show(window.spinner);
    gtk_widget_hide(window.refresh_button);

    
}

void show_scan_ended() {

    gtk_spinner_stop(GTK_SPINNER(window.spinner));
    gtk_widget_hide(window.spinner);
    gtk_widget_show(window.refresh_button);

    
}

gboolean refresh_results(gpointer data) {
    //puts("Refreshing results");
    
    //g_list_store_remove_all(window.list_store);
//     GList *n = gtk_container_get_children(GTK_CONTAINER(window.listbox));
//     for(; n; n = n->next){
//         gtk_widget_destroy(GTK_WIDGET(n->data));
//     }
   
    list_box_clear();
    
    scan_state *state = scan_getstate();
    nm_list_foreach(h, state->hosts) {
        //list_add_item(h->data);
        //gtk_container_add(GTK_CONTAINER(window.listbox), list_create_list_row(h->data));
        list_box_add_host(h->data);
    }

    show_scan_ended();
    
    return FALSE;

}

gpointer refresh_thread(gpointer data) {
    //puts("Refreshing hosts...");

    scan_start();
    scan_stop();
    g_idle_add (refresh_results, NULL);
    
    return NULL;
}



void refresh_hosts() {
    
    show_scan_started();
    set_scan_from_options();

    GThread *thread;
    GError *error;
    thread = g_thread_try_new("ScanThread", refresh_thread, 0, &error);
    if(error == NULL){
        puts("Error starting the scan thread");
        return;
    }
    g_thread_unref(thread);
}


void refresh_hosts_initial() {
    

    scan_state *state = scan_getstate();
    bool prev_known = state->opt_known_only;
    state->opt_known_only = true;

    //show_scan_started();

    scan_start();
    scan_stop();
    
    //g_list_store_remove_all(window.list_store);
    nm_list_foreach(h, state->hosts) {
        //list_add_item(h->data);
        //gtk_container_add(GTK_CONTAINER(window.listbox), list_create_list_row(h->data));
        list_box_add_host(h->data);
    }

    show_scan_ended();
    state->opt_known_only = prev_known;
    
//     if(!state->opt_known_only)
//         refresh_hosts();
    
}


gboolean on_option_known_hosts_clicked(GtkSwitch *button, gboolean state, gpointer user_data){

    printf("on_option_known_hosts_clicked: new state: %i\n", state);
    return false;
}

gboolean on_option_scan_timeout_changed(GtkSpinButton *button, gpointer user_data){
    
    printf("on_option_scan_timeout_changed: new value: %i\n", (int)gtk_spin_button_get_value(button));
    return false;
}

void on_refresh_clicked(GtkWidget *widget, gpointer user_data){
    refresh_hosts();
}


void on_window_destroyed(GtkWidget *widget, gpointer user_data){
    scan_stop();
}

void on_app_activate(GtkApplication *gtkapp, gpointer should_run){
    window.gtk_app = gtkapp;

    //window.builder = gtk_builder_new_from_file(UI_FILE_BASE NM_APPLICATION_UI_FILE);
    window.builder = gtk_builder_new_from_resource(NM_RESOURCE_BASE NM_APPLICATION_UI_FILE);

    window.window_widget = GTK_WIDGET(gtk_builder_get_object(window.builder, "main_window"));
    window.window = GTK_APPLICATION_WINDOW(window.window_widget);
    g_signal_connect(window.window, "destroy", G_CALLBACK(on_window_destroyed), NULL);

    gtk_window_set_icon_name(GTK_WINDOW(window.window), NM_APPLICATION_ICON);
    window.spinner = GTK_WIDGET(gtk_builder_get_object(window.builder, "refresh_spinner"));
    window.refresh_button = GTK_WIDGET(gtk_builder_get_object(window.builder, "refresh_button"));
    gtk_widget_set_size_request(window.spinner, 20, -1);
    gtk_widget_set_size_request(window.refresh_button, 30, -1);
    g_signal_connect(window.refresh_button, "clicked", G_CALLBACK(on_refresh_clicked), NULL);

    //window.main_menu = GTK_MENU_BUTTON(gtk_builder_get_object(window.builder, "main_menu"));
    window.known_hosts = GTK_SWITCH(gtk_builder_get_object(window.builder, "switch_known_hosts"));
    window.scan_all = GTK_SWITCH(gtk_builder_get_object(window.builder, "switch_scan_all"));
    window.scan_timeout = GTK_SPIN_BUTTON(gtk_builder_get_object(window.builder, "field_scan_timeout"));
//     //defaults
//     gtk_switch_set_state (GTK_SWITCH(known_hosts), false);
//     gtk_spin_button_set_value (GTK_SPIN_BUTTON(scan_timeout), 5.0f);
//     //signals
//     g_signal_connect(known_hosts, "state-set", on_option_known_hosts_clicked, NULL);
//     g_signal_connect(scan_timeout, "value-changed", on_option_scan_timeout_changed, NULL);
    
    
    
    //create popover

    window.listbox = GTK_LIST_BOX(gtk_builder_get_object(window.builder, "main_listbox"));
    gtk_list_box_set_activate_on_single_click(window.listbox, FALSE);
    gtk_list_box_set_selection_mode(window.listbox, GTK_SELECTION_NONE);
    //gtk_widget_set_size_request(GTK_WIDGET(window.listbox), 390, 400);

    //init list store and stuff
    //window.list_store = g_list_store_new(host_item_get_type());
    //gtk_list_box_bind_model(GTK_LIST_BOX(window.listbox), G_LIST_MODEL(window.list_store),
    //                        list_create_row, NULL, NULL);

    //Add CSS resource for tags
    GtkCssProvider *provider = gtk_css_provider_new();
    gtk_css_provider_load_from_resource(provider, NM_RESOURCE_BASE NM_APPLICATION_CSS_FILE);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(provider),
                                              GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    //gtk_widget_set_size_request(GTK_WIDGET(window.window), 200, 400);
    //gtk_window_set_default_size(window.window, 200, 500);
    gtk_application_add_window(window.gtk_app, GTK_WINDOW(window.window));
    gtk_widget_show_all (GTK_WIDGET(window.window_widget));
    gtk_widget_hide(window.spinner);
    
    if(should_run) {
        set_options_from_scan();
        refresh_hosts_initial();
    }
}

int init_application(int argc, char **argv){
    gint status;
    
    log_set_level(LOG_ERROR);
    
    scan_state *state = scan_getstate();
    state->opt_print = false;
    state->opt_known_only = false;
    state->opt_skip_resolve = false;
    state->opt_scan_only = false;
    state->opt_scan_all = 0;
    state->opt_scan_timeout_ms = 15000;
    state->opt_max_hosts = 0;
    state->opt_subnet_offset = 0;
    state->opt_connect_threads = 255;
    state->opt_connect_timeout_ms = 300;
    state->opt_listen_threads = 10;

    scan_init();

    GtkApplication *gtk_app = gtk_application_new ("ak.Network_List", G_APPLICATION_FLAGS_NONE);

    g_signal_connect (gtk_app, "activate", G_CALLBACK (on_app_activate), (void*)true);
    status = g_application_run (G_APPLICATION (gtk_app), argc, argv);
    
    scan_destroy();
    g_object_unref (gtk_app);
    return status;
}

//G_DEBUG=fatal-warnings
