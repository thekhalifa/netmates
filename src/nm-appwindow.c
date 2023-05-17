#include "nm-appwindow.h"

nm_window window = {
        .host_icons[HOST_TYPE_UNKNOWN] = ICON_TYPE_OTHER,
        .host_icons[HOST_TYPE_LOCALHOST] = ICON_TYPE_LOCALHOST,
        .host_icons[HOST_TYPE_ROUTER] = ICON_TYPE_ROUTER,
        .host_icons[HOST_TYPE_PHONE] = ICON_TYPE_PHONE,
        .host_icons[HOST_TYPE_PRINTER] = ICON_TYPE_PRINTER,
        .host_icons[HOST_TYPE_SMART_DEVICE] = ICON_TYPE_SMART_DEVICE,
        .host_icons[HOST_TYPE_SMART_TV] = ICON_TYPE_SMART_TV,
        .host_icons[HOST_TYPE_PC] = ICON_TYPE_COMPUTER,
        .host_icons[HOST_TYPE_PC_WIN] = ICON_TYPE_COMPUTER,
        .host_icons[HOST_TYPE_ANY] = ICON_TYPE_COMPUTER,
};


enum{
    PROP_HOST_NAME = 1,
    PROP_HOST_TYPE,
    PROP_HOST_TYPE_LABEL,
    PROP_HOST_IPV4,
    PROP_HOST_IPV6,
    PROP_HOST_HW_ADDR,
    PROP_HOST_HW_VENDOR,
    PROP_HOST_OTHER_IPV4,
    PROP_HOST_OTHER_IPV6,
    PROP_HOST_SERVICES,
    LAST_PROPERTY
};

static GParamSpec *host_item_props[LAST_PROPERTY] = { NULL, };

typedef struct{
    GObjectClass parent_class;
} HostItemClass;

G_DEFINE_TYPE(HostItem, host_item, G_TYPE_OBJECT)

static void host_item_init(HostItem *obj){
    obj->host_name = NULL;
    obj->host_type = HOST_TYPE_UNKNOWN;
    obj->host_type_label = NULL;
    obj->host_ipv4 = NULL;
    obj->host_ipv6 = NULL;
    obj->host_hw_addr = NULL;
    obj->host_hw_vendor = NULL;
    obj->host_other_ip4 = NULL;
    obj->host_other_ip6 = NULL;
    obj->host_services = NULL;
}

static void host_item_get_property(GObject *obj, guint prop_id, GValue *value, GParamSpec *param_spec){
    HostItem *item = (HostItem *)obj;
    switch(prop_id){
        case PROP_HOST_NAME:
            g_value_set_string(value, item->host_name);
            break;
        case PROP_HOST_TYPE:
            g_value_set_int(value, item->host_type);
            break;
        case PROP_HOST_TYPE_LABEL:
            g_value_set_string(value, item->host_type_label);
            break;
        case PROP_HOST_IPV4:
            g_value_set_string(value, item->host_ipv4);
            break;
        case PROP_HOST_IPV6:
            g_value_set_string(value, item->host_ipv6);
            break;
        case PROP_HOST_HW_ADDR:
            g_value_set_string(value, item->host_hw_addr);
            break;
        case PROP_HOST_HW_VENDOR:
            g_value_set_string(value, item->host_hw_vendor);
            break;
        case PROP_HOST_OTHER_IPV4:
            g_value_set_boxed(value, item->host_other_ip4);
            break;
        case PROP_HOST_OTHER_IPV6:
            g_value_set_boxed(value, item->host_other_ip6);
            break;
        case PROP_HOST_SERVICES:
            g_value_set_boxed(value, item->host_services);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID(obj, prop_id, param_spec);
            break;
    }
}

static void host_item_set_property(GObject *obj, guint prop_id, const GValue *value, GParamSpec *param_spec){
    HostItem *item = (HostItem *)obj;
    switch(prop_id){
        case PROP_HOST_NAME:
            g_free(item->host_name);
            item->host_name = g_value_dup_string(value);
            break;
        case PROP_HOST_TYPE:
            item->host_type = g_value_get_int(value);
            break;
        case PROP_HOST_TYPE_LABEL:
            g_free(item->host_type_label);
            item->host_type_label = g_value_dup_string(value);
            break;
        case PROP_HOST_IPV4:
            g_free(item->host_ipv4);
            item->host_ipv4 = g_value_dup_string(value);
            break;
        case PROP_HOST_IPV6:
            g_free(item->host_ipv6);
            item->host_ipv6 = g_value_dup_string(value);
            break;
        case PROP_HOST_HW_ADDR:
            g_free(item->host_hw_addr);
            item->host_hw_addr = g_value_dup_string(value);
            break;
        case PROP_HOST_HW_VENDOR:
            g_free(item->host_hw_vendor);
            item->host_hw_vendor = g_value_dup_string(value);
            break;
        case PROP_HOST_OTHER_IPV4:
            if(item->host_other_ip4)
                g_array_free(item->host_other_ip4, TRUE);
            item->host_other_ip4 = g_value_get_boxed(value);
            break;
        case PROP_HOST_OTHER_IPV6:
            if(item->host_other_ip6)
                g_array_free(item->host_other_ip6, TRUE);
            item->host_other_ip6 = g_value_get_boxed(value);
            break;
        case PROP_HOST_SERVICES:
            if(item->host_services)
                g_array_free(item->host_services, TRUE);
            item->host_services = g_value_get_boxed(value);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID(obj, prop_id, param_spec);
            break;
    }
}

static void host_item_finalize(GObject *obj){
    HostItem *item = (HostItem *)obj;
    g_free(item->host_name);
    g_free(item->host_type_label);
    g_free(item->host_ipv4);
    g_free(item->host_ipv6);
    g_free(item->host_hw_addr);
    g_free(item->host_hw_vendor);
    g_array_free(item->host_other_ip4, TRUE);
    g_array_free(item->host_other_ip6, TRUE);
    g_array_free(item->host_services, TRUE);
    G_OBJECT_CLASS(host_item_parent_class)->finalize(obj);
}


static void host_item_class_init(HostItemClass *class){
    GObjectClass *obj_cls = G_OBJECT_CLASS(class);

    obj_cls->get_property = host_item_get_property;
    obj_cls->set_property = host_item_set_property;
    obj_cls->finalize = host_item_finalize;

    host_item_props[PROP_HOST_NAME] = g_param_spec_string("host_name", "host_name", "host_name",
                                                           NULL, G_PARAM_READWRITE);
    host_item_props[PROP_HOST_TYPE] = g_param_spec_int("host_type", "host_type", "host_type",
                                    HOST_TYPE_UNKNOWN, HOST_TYPE_LENGTH, HOST_TYPE_UNKNOWN, G_PARAM_READWRITE);
    host_item_props[PROP_HOST_TYPE_LABEL] = g_param_spec_string("host_type_label", "host_type_label", "host_type_label",
                                                         NULL, G_PARAM_READWRITE);
    host_item_props[PROP_HOST_IPV4] = g_param_spec_string("host_ipv4", "host_ipv4", "host_ipv4",
                                                         NULL, G_PARAM_READWRITE);
    host_item_props[PROP_HOST_IPV6] = g_param_spec_string("host_ipv6", "host_ipv6", "host_ipv6",
                                                          NULL, G_PARAM_READWRITE);
    host_item_props[PROP_HOST_HW_ADDR] = g_param_spec_string("host_hw_addr", "host_hw_addr", "host_hw_addr",
                                                           NULL, G_PARAM_READWRITE);
    host_item_props[PROP_HOST_HW_VENDOR] = g_param_spec_string("host_hw_vendor", "host_hw_vendor", "host_hw_vendor",
                                                           NULL, G_PARAM_READWRITE);
    host_item_props[PROP_HOST_OTHER_IPV4] = g_param_spec_boxed("host_other_ip4", "host_other_ip4", "host_other_ip4",
                                                             G_TYPE_ARRAY, G_PARAM_READWRITE);
    host_item_props[PROP_HOST_OTHER_IPV6] = g_param_spec_boxed("host_other_ip6", "host_other_ip6", "host_other_ip6",
                                                             G_TYPE_ARRAY, G_PARAM_READWRITE);
    host_item_props[PROP_HOST_SERVICES] = g_param_spec_boxed("host_services", "host_services", "host_services",
                                                             G_TYPE_ARRAY, G_PARAM_READWRITE);

    g_object_class_install_properties(obj_cls, LAST_PROPERTY, host_item_props);
}


GArray *
copy_string_list_as_array(GList *src_list){
    char *curr_text;
    guint list_len = g_list_length(src_list);
    GList *curr_list = src_list;

    GArray *dst_array = g_array_sized_new(FALSE, FALSE, sizeof(char *), list_len);
    for(int i=0; i < list_len; i++){
        curr_text = strdup((char *)curr_list->data);
        g_array_append_val(dst_array, curr_text);
        curr_list = curr_list->next;
    }

    return dst_array;
}


static char *
create_label_text_for_host(HostItem *host_item){
    static const char *title_format = "<span foreground=\"#338E5E\" size=\"larger\"><b>%s</b></span>";
    static const char *ipv4_format =        "\n<tt><small>inet:   %s</small></tt>";
    static const char *ipv6_format =        "\n<tt><small>inet6:  %s</small></tt>";
    static const char *hw_format =          "\n<tt><small>link:   %s</small></tt>";
    static const char *hwv_format =         "\n<tt><small>vendor: %s</small></tt>";
    char buffer[1024];
    int position = 0;

    
    //Title
    position += sprintf(buffer, title_format, host_item->host_name);

    //Details
    if(host_item->host_ipv4)
        position += sprintf(buffer + position, ipv4_format, host_item->host_ipv4);
    if(host_item->host_other_ip4 && host_item->host_other_ip4->len > 0){
        for (int i = 0; i < host_item->host_other_ip4->len; i++){
            position += sprintf(buffer + position, ipv4_format, g_array_index(host_item->host_other_ip4, char *, i));
        }
    }
    
    if(host_item->host_ipv6)
        position += sprintf(buffer + position, ipv6_format, host_item->host_ipv6);
    if(host_item->host_other_ip6 && host_item->host_other_ip6->len > 0){
        for (int i = 0; i < host_item->host_other_ip6->len; i++){
            position += sprintf(buffer + position, ipv6_format, g_array_index(host_item->host_other_ip6, char *, i));
        }
    }
    if(host_item->host_hw_addr)
        position += sprintf(buffer + position, hw_format, host_item->host_hw_addr);
    if(host_item->host_hw_vendor)
        sprintf(buffer + position, hwv_format, host_item->host_hw_vendor);

    return g_strdup(buffer);
}

static char *
create_label_tooltip_text_for_host(HostItem *host_item){
    static const char *hostname_format = "Hostname: %s";
    static const char *detail_start_format = "<tt><small>";
    static const char *ipv4_format =     "\nIPv4:     %s";
    static const char *ipv6_format =     "\nIPv6:     %s";
    static const char *hw_format =       "\nMAC:      %s";
    static const char *hwv_format =      "\nVendor:   %s";
    static const char *services_format = "\nServices: ";
    static const char *detail_end_format = "</small></tt>";

    char buffer[1024];
    char *pointer = buffer;

    pointer = stpcpy(buffer, detail_start_format);
    if(host_item->host_name)
        pointer += sprintf(pointer, hostname_format, host_item->host_name);

    if(host_item->host_ipv4)
        pointer += sprintf(pointer, ipv4_format, host_item->host_ipv4);
    if(host_item->host_other_ip4 && host_item->host_other_ip4->len > 0){
        for (int i = 0; i < host_item->host_other_ip4->len; i++){
            pointer += sprintf(pointer, ipv4_format, g_array_index(host_item->host_other_ip4, char *, i));
        }
    }

    
    if(host_item->host_ipv6 && strlen(host_item->host_ipv6) > 0)
        pointer += sprintf(pointer, ipv6_format, host_item->host_ipv6);
    if(host_item->host_other_ip6 && host_item->host_other_ip6->len > 0){
        for (int i = 0; i < host_item->host_other_ip6->len; i++){
            pointer += sprintf(pointer, ipv6_format, g_array_index(host_item->host_other_ip6, char *, i));
        }
    }
    if(host_item->host_hw_addr && strlen(host_item->host_hw_addr) > 0)
        pointer += sprintf(pointer, hw_format, host_item->host_hw_addr);
    if(host_item->host_hw_vendor && strlen(host_item->host_hw_vendor) > 0)
        pointer += sprintf(pointer, hwv_format, host_item->host_hw_vendor);

    if(host_item->host_services && host_item->host_services->len > 0){
        char *curr_service;
        pointer = stpcpy(pointer, services_format);
        for (int i = 0; i < host_item->host_services->len; i++){
            curr_service = g_array_index(host_item->host_services, char *, i);
            pointer += sprintf(pointer, "%s", curr_service);
            if(i < (host_item->host_services->len - 1))
                pointer += sprintf(pointer, ", ");
        }
    }
    stpcpy(pointer, detail_end_format);

    return g_strdup(buffer);
}

static GtkWidget *
create_flow_box_child(const char *label, const char *image_name, const char *tooltip_text) {
    g_assert(!(label != NULL && image_name != NULL));
    g_assert(!(label == NULL && image_name == NULL));

    GtkWidget *child;
    GtkWidget *child_content;
    if(label != NULL) {
        char *formatted_label = g_strdup_printf("<span font_weight='light' size='smaller'>%s</span>", label);
        child_content = gtk_label_new(formatted_label);
        gtk_label_set_use_markup(GTK_LABEL(child_content), TRUE);
        g_free(formatted_label);
    }else {
        child_content = gtk_image_new_from_icon_name(image_name, GTK_ICON_SIZE_BUTTON);
    }

    if(tooltip_text)
        gtk_widget_set_tooltip_text(child_content, tooltip_text);

    child = gtk_flow_box_child_new();
    GtkStyleContext *sc = gtk_widget_get_style_context(child);
    gtk_style_context_add_class(sc, "nm-tag-container"); //"rubberband"
    gtk_widget_set_opacity(child, 0.8);
    gtk_container_add(GTK_CONTAINER(child), child_content);

    return child;
}

void
create_services_labels(GtkWidget *flow_box, HostItem *host_item) {
    g_assert(flow_box != NULL && host_item != NULL);

    char *curr_service;
    GtkWidget *flow_child;
    for (int i = 0; i < host_item->host_services->len; i++){
        curr_service = g_array_index(host_item->host_services, char *, i);
        flow_child = create_flow_box_child(curr_service, NULL, curr_service);
        gtk_container_add(GTK_CONTAINER(flow_box), flow_child);
    }
}


static GtkWidget *list_create_row(gpointer item, gpointer user_data){
    HostItem *entry_item = item;

    //left side image
    char *icon_name = window.host_icons[entry_item->host_type];
    GtkWidget *row_image = gtk_image_new_from_icon_name(icon_name, GTK_ICON_SIZE_LARGE_TOOLBAR);
    GtkWidget *button = gtk_button_new();
    gtk_button_set_image(GTK_BUTTON(button), row_image);
    gtk_widget_set_tooltip_text(button, entry_item->host_type_label);
    //gtk_button_set_relief(GTK_BUTTON(button), GTK_RELIEF_NONE);
    gtk_widget_set_size_request(button, 40, 40);
    gtk_widget_set_valign(button, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(button, GTK_ALIGN_START);
    //g_signal_connect(button, "clicked", G_CALLBACK(on_more_info_clicked), entry_item);

    //main label
    char *host_text = create_label_text_for_host(entry_item);
    GtkWidget *host_label = gtk_label_new(host_text);
    g_free(host_text);
    gtk_label_set_use_markup(GTK_LABEL(host_label), TRUE);
    gtk_label_set_selectable(GTK_LABEL(host_label), TRUE);
    gtk_label_set_ellipsize(GTK_LABEL(host_label), PANGO_ELLIPSIZE_END);
    gtk_label_set_justify(GTK_LABEL(host_label), GTK_JUSTIFY_LEFT);
    gtk_widget_set_halign(GTK_WIDGET(host_label), GTK_ALIGN_START);
    gtk_widget_set_valign(GTK_WIDGET(host_label), GTK_ALIGN_START);
    char *host_tooltip = create_label_tooltip_text_for_host(entry_item);
    //gtk_widget_set_tooltip_text(host_label, host_tooltip);
    gtk_widget_set_tooltip_markup(host_label, host_tooltip);
    g_free(host_tooltip);

    //services flow
    //GtkWidget *flow_box = gtk_label_new("Flow...\nFlow...");
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

    create_services_labels(flow_box, entry_item);
//    GtkWidget *flow_child1 = create_flow_box_child("Test", NULL, "Help Text for Test");
//    gtk_container_add(GTK_CONTAINER(flow_box), flow_child1);
//    GtkWidget *flow_child2 = create_flow_box_child(NULL, "network-wired-symbolic", "Help Text for Network");
//    gtk_container_add(GTK_CONTAINER(flow_box), flow_child2);

    GtkWidget* mid_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_pack_start(GTK_BOX(mid_box), host_label, TRUE, TRUE, 0);
    gtk_box_pack_end(GTK_BOX(mid_box), flow_box, FALSE, TRUE, 0);


    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_pack_start(GTK_BOX(box), button, FALSE, TRUE, 5);
    gtk_box_pack_start(GTK_BOX(box), mid_box, TRUE, TRUE, 5);
    //gtk_widget_set_size_request(box, -1, 80);
    gtk_widget_show_all(box);
    return box;
}


static gint list_compare_items_func(gconstpointer a, gconstpointer b, gpointer user_data){
    HostItem *entry_a = (HostItem *)a;
    HostItem *entry_b = (HostItem *)b;
    enum nm_host_type a_type, b_type;
    g_object_get(entry_a, "host_type", &a_type, NULL);
    g_object_get(entry_b, "host_type", &b_type, NULL);

    if(a_type == HOST_TYPE_LOCALHOST)
        return -1;
    else if(b_type == HOST_TYPE_LOCALHOST)
        return 1;
    else if(a_type == HOST_TYPE_ROUTER)
        return -1;
    else if(b_type == HOST_TYPE_ROUTER)
        return 1;

    return 1;

//     if(a_type == HOST_TYPE_LOCALHOST || b_type == HOST_TYPE_LOCALHOST ||
//             a_type == HOST_TYPE_ROUTER || b_type == HOST_TYPE_ROUTER){
//         return (gint)(a_type - b_type);
//     }
// 
//     return 1;
//     char *a_name, *b_name;
//     g_object_get(entry_a, "host_name", &a_name, NULL);
//     g_object_get(entry_b, "host_name", &b_name, NULL);
//     int result = strcasecmp(a_name, b_name);
// 
//     g_free(a_name);
//     g_free(b_name);
//     return result;
}

// void list_update_item(nm_host *host){
//     g_assert(host != NULL);
// 
//     HostItem *host_item;
//     guint list_len = g_list_model_get_n_items(G_LIST_MODEL(window.list_store));
//     for(int i=0; i<list_len; i++){
//         host_item = g_list_model_get_item(G_LIST_MODEL(window.list_store), i);
//         if(host->ip && host_item->host_ipv4 && strcmp(host_item->host_ipv4, host->ip) == 0){
//             // update the item
//             host_item_update_from_host(host_item, host);
//             g_list_store_remove(window.list_store, i);
//             g_list_store_insert_sorted(window.list_store, host_item, list_compare_items_func, NULL);
//             return;
//         //TODO: Add IPv6 Comparison
// //        }else if(host->ip == NULL && host->ip6 != NULL && host_item->host_ipv6 && strcmp(host_item->host_ipv6, host->ip6) == 0){
// //            //update the item
// //            return;
//         }
//     }
//     //not found, add it.
//     list_add_item(host);
// }


void list_add_item(nm_host *host){
    g_assert(host != NULL);

    // array will hold string copies and goes into entry_item object
    GArray *other_ip4_array = copy_string_list_as_array(host->list_ip);
    GArray *other_ip6_array = copy_string_list_as_array(host->list_ip6);
    GArray *services_array = copy_string_list_as_array(host->list_services);//nm_copy_string_list_as_array(host->services);

    HostItem *obj = g_object_new(host_item_get_type(),
                                 "host_name", nm_host_label(host),
                                 "host_type", host->type,
                                 "host_type_label", nm_host_type(host),
                                 "host_ipv4", host->ip,
                                 "host_ipv6", host->ip6,
                                 "host_hw_addr", host->hw_if.addr,
                                 "host_hw_vendor", host->hw_if.vendor,
                                 "host_other_ip4", other_ip4_array,
                                 "host_other_ip6", other_ip6_array,
                                 "host_services", services_array,
                                 NULL);
    g_list_store_insert_sorted(window.list_store, obj, list_compare_items_func, NULL);
    g_object_unref(obj);
}



gboolean refresh_results(gpointer data) {
    puts("Refreshing results");
    
    g_list_store_remove_all(window.list_store);
    scan_state *state = scan_getstate();
    nm_list_foreach(h, state->hosts) {
        list_add_item(h->data);
    }

    gtk_widget_hide(window.spinner);
    gtk_widget_show(window.refresh_button);
    
    return FALSE;

}

gpointer refresh_thread(gpointer data) {
    puts("Refreshing hosts...");

    scan_start();
    scan_stop();
    g_idle_add (refresh_results, NULL);
    
    return NULL;
}



void refresh_hosts() {
    
    gtk_spinner_start(GTK_SPINNER(window.spinner));
    gtk_widget_show(window.spinner);
    gtk_widget_hide(window.refresh_button);

    GThread *thread;
    GError *error;
    thread = g_thread_try_new("ScanThread", refresh_thread, 0, &error);
    if(error == NULL){
        puts("Error starting the scan thread");
        return;
    }
    g_thread_unref(thread);
}


void refresh_hosts_known() {
    
    gtk_spinner_start(GTK_SPINNER(window.spinner));
    gtk_widget_show(window.spinner);
    gtk_widget_hide(window.refresh_button);

    scan_state *state = scan_getstate();
    bool prev_known = state->opt_known_only;
    state->opt_known_only = true;

    scan_start();
    scan_stop();
    
    g_list_store_remove_all(window.list_store);
    nm_list_foreach(h, state->hosts) {
        list_add_item(h->data);
    }

    gtk_widget_hide(window.spinner);
    gtk_widget_show(window.refresh_button);
    state->opt_known_only = prev_known;
    
    if(!state->opt_known_only)
        refresh_hosts();
    
}


void on_more_info_clicked(GtkWidget *widget, gpointer user_data){
//     printf("on_more_info_clicked\n");
//     HostItem *host_item = (HostItem *)user_data;
}


void on_refresh_clicked(GtkWidget *widget, gpointer user_data){
    refresh_hosts();
}


void on_window_destroyed(GtkWidget *widget, gpointer user_data){
    scan_stop();
}

void on_app_activate(GtkApplication *gtkapp, gpointer user_data){
    window.gtk_app = gtkapp;

    //window.builder = gtk_builder_new_from_file(UI_FILE_BASE NM_APPLICATION_UI_FILE);
    window.builder = gtk_builder_new_from_resource(NM_RESOURCE_BASE NM_APPLICATION_UI_FILE);

    window.window_widget = GTK_WIDGET(gtk_builder_get_object(window.builder, "main_window"));
    window.window = GTK_APPLICATION_WINDOW(window.window_widget);
    g_signal_connect(window.window, "destroy", G_CALLBACK(on_window_destroyed), NULL);

    window.spinner = GTK_WIDGET(gtk_builder_get_object(window.builder, "refresh_spinner"));
    window.refresh_button = GTK_WIDGET(gtk_builder_get_object(window.builder, "refresh_button"));
    gtk_widget_set_size_request(window.spinner, 20, -1);
    gtk_widget_set_size_request(window.refresh_button, 30, -1);
    g_signal_connect(window.refresh_button, "clicked", G_CALLBACK(on_refresh_clicked), NULL);

    window.listbox = GTK_LIST_BOX(gtk_builder_get_object(window.builder, "main_listbox"));
    gtk_list_box_set_activate_on_single_click(window.listbox, FALSE);
    gtk_list_box_set_selection_mode(window.listbox, GTK_SELECTION_NONE);
    //gtk_widget_set_size_request(GTK_WIDGET(window.listbox), 390, 400);

    //init list store and stuff
    window.list_store = g_list_store_new(host_item_get_type());
    gtk_list_box_bind_model(GTK_LIST_BOX(window.listbox), G_LIST_MODEL(window.list_store),
                            list_create_row, NULL, NULL);

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
    
    refresh_hosts_known();
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
    state->opt_max_hosts = -1;
    state->opt_subnet_offset = 0;
    state->opt_connect_threads = 255;
    state->opt_connect_timeout_ms = 300;
    state->opt_listen_threads = 10;

    scan_init();

    GtkApplication *gtk_app = gtk_application_new ("ak.Network_List", G_APPLICATION_FLAGS_NONE);

    g_signal_connect (gtk_app, "activate", G_CALLBACK (on_app_activate), NULL);
    status = g_application_run (G_APPLICATION (gtk_app), argc, argv);
    
    scan_destroy();
    g_object_unref (gtk_app);
    return status;
}

//G_DEBUG=fatal-warnings
