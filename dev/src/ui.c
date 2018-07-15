#include <stdio.h>
#include <stdlib.h>

#include <gtk/gtk.h>

#include "ui.h"

struct ui_port_filter_s ui_port_filter;
struct ui_proto_filter_s ui_proto_filter;
struct ui_app_filter_s ui_app_filter;

GtkEntry *gtk_entry_src_port = NULL;
GtkEntry *gtk_entry_dst_port = NULL;

GObject *gtk_check_btn_1 = NULL;
GObject *gtk_check_btn_2 = NULL;
GObject *gtk_check_btn_3 = NULL;
GObject *gtk_check_btn_4 = NULL;

static void tg_btn_port_filter(GtkToggleButton *source, gpointer data)
{
    ui_port_filter.enabled = !ui_port_filter.enabled;

    if (gtk_toggle_button_get_active(source)) {
	const gchar *src_port = gtk_entry_get_text(gtk_entry_src_port);
	const gchar *dst_port = gtk_entry_get_text(gtk_entry_dst_port);
	ui_port_filter.src_port = atoi(src_port);
	ui_port_filter.dst_port = atoi(dst_port);
        g_print("is_enabled=%d, src_port=%d, dst_port=%d\n",
		ui_port_filter.enabled, ui_port_filter.src_port, ui_port_filter.dst_port);
    }
}

static void tg_btn_proto_filter(GtkToggleButton *source, gpointer data)
{
    ui_proto_filter.enabled = !ui_proto_filter.enabled;

    if (gtk_toggle_button_get_active(source)) {
        g_print("is_enabled=%d, protocol=%d", ui_proto_filter.enabled, ui_proto_filter.protocol);
    }
}

static void tg_btn_app_filter(GtkToggleButton *source, gpointer data)
{
    ui_app_filter.enabled = !ui_app_filter.enabled;

    if (gtk_toggle_button_get_active(source)) {
        g_print("is_enabled=%d\n", ui_app_filter.enabled);
#if 0
        ui_app_filter.id = 0;
        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_check_btn_1))) {
            g_print("check btn 1 ok\n");
	    ui_app_filter.id |= 0x01;
        }

        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_check_btn_2))) {
            g_print("check btn 2 ok\n");
            ui_app_filter.id |= 0x02;
        }

        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_check_btn_3))) {
            g_print("check btn 3 ok\n");
            ui_app_filter.id |= 0x04;
        }

        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_check_btn_4))) {
            g_print("check btn 4 ok\n");
            ui_app_filter.id |= 0x08;
        }
        g_print("id=%x\n", ui_app_filter.id);
#endif
    }

}

static void radio_btn_proto_filter(GtkRadioButton *source, gpointer data)
{
    int i = 0;
    GSList *tmp_list = gtk_radio_button_get_group(source);
    GtkToggleButton *tmp_button = NULL;

    while (tmp_list) {
        tmp_button = GTK_TOGGLE_BUTTON(tmp_list->data);
        tmp_list = tmp_list->next;

        if (gtk_toggle_button_get_active(tmp_button)) {
            break;
        }
        tmp_button = NULL;
	i++;
    }
    ui_proto_filter.protocol = i;
}

static void quit_thread(GtkWidget *widget, gpointer data)
{
    gtk_main_quit();
    //exit(1);
}

void *gtk_ui_main(void *args)
{
    GtkBuilder *builder;
    GtkWidget  *window;
    GObject *button, *radio_button;
    GError *error = NULL;

    gtk_init(NULL, NULL);

    /* Construct a GtkBuilder instance and load our UI description */
    builder = gtk_builder_new();
    if (gtk_builder_add_from_file (builder, "builder.ui", &error) == 0) {
        g_printerr ("Error loading file: %s\n", error->message);
        g_clear_error (&error);

        return (void *)-1;
    }

    /* Connect signal handlers to the constructed widgets. */
    window = GTK_WIDGET(gtk_builder_get_object (builder, "window"));
    g_signal_connect(window, "destroy", G_CALLBACK(quit_thread), NULL);

    button = gtk_builder_get_object(builder, "togglebutton1");
    gtk_entry_src_port = GTK_ENTRY(gtk_builder_get_object(builder, "entry1"));
    gtk_entry_dst_port = GTK_ENTRY(gtk_builder_get_object(builder, "entry2"));
    g_signal_connect(button, "toggled", G_CALLBACK(tg_btn_port_filter), NULL);

    radio_button = gtk_builder_get_object(builder, "radiobutton1");
    g_signal_connect(radio_button, "toggled", G_CALLBACK(radio_btn_proto_filter), NULL);

    button = gtk_builder_get_object(builder, "togglebutton2");
    g_signal_connect(button, "toggled", G_CALLBACK(tg_btn_proto_filter), NULL);

    button = gtk_builder_get_object(builder, "togglebutton3");
    g_signal_connect(button, "toggled", G_CALLBACK(tg_btn_app_filter), NULL);

#if 0
    gtk_check_btn_1  = gtk_builder_get_object(builder, "checkbutton1");
    gtk_check_btn_2  = gtk_builder_get_object(builder, "checkbutton2");
    gtk_check_btn_3  = gtk_builder_get_object(builder, "checkbutton3");
    gtk_check_btn_4  = gtk_builder_get_object(builder, "checkbutton4");
#endif

    gtk_widget_show(window);
    gtk_main();

    return NULL;
}


int is_ui_port_filter_enabled(void)
{
    return ui_port_filter.enabled;
}

short get_ui_port_filter_src_port(void)
{
    return ui_port_filter.src_port;
}

short get_ui_port_filter_dst_port(void)
{
    return ui_port_filter.dst_port;
}

int is_ui_proto_filter_enabled(void)
{
    return ui_proto_filter.enabled;
}

int get_ui_proto_filter_protocol(void)
{
    return ui_proto_filter.protocol;
}

int is_ui_app_filter_enabled(void)
{
    return ui_app_filter.enabled;
}

int get_ui_app_filter_id(void)
{
    return ui_app_filter.id;
}

