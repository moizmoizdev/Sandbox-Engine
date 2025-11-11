#include <gtk/gtk.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include "sandbox.h"
#include "process_control.h"
#include "namespaces.h"

/* Application state structure */
typedef struct {
    GtkApplication *app;
    GtkWindow *window;
    GtkButton *select_file_btn;
    GtkButton *run_btn;
    GtkButton *stop_btn;
    GtkLabel *file_label;
    GtkLabel *status_label;
    /* Namespace configuration checkboxes */
    GtkCheckButton *ns_pid_check;
    GtkCheckButton *ns_mount_check;
    GtkCheckButton *ns_net_check;
    GtkCheckButton *ns_uts_check;
    /* Namespace detailed settings */
    GtkEntry *ns_uts_hostname_entry;
    GtkExpander *ns_pid_expander;
    GtkExpander *ns_mount_expander;
    GtkExpander *ns_net_expander;
    GtkExpander *ns_uts_expander;
    char *selected_file;
    pid_t sandboxed_pid;
    gboolean process_running;
} AppState;

/* Forward declarations */
static void on_activate(GtkApplication *app, gpointer user_data);
static void on_file_selected(GtkWidget *widget, gpointer user_data);
static void on_file_chooser_response(GtkNativeDialog *dialog, gint response_id, gpointer user_data);
static void on_run_clicked(GtkWidget *widget, gpointer user_data);
static void on_stop_clicked(GtkWidget *widget, gpointer user_data);
static void setup_ui(AppState *state);
static void cleanup_state(AppState *state);

/* File chooser response callback */
static void on_file_chooser_response(GtkNativeDialog *dialog, gint response_id, gpointer user_data) {
    AppState *state = (AppState *)user_data;
    
    if (response_id == GTK_RESPONSE_ACCEPT) {
        GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
        GFile *file = gtk_file_chooser_get_file(chooser);
        
        if (state->selected_file) {
            g_free(state->selected_file);
        }
        
        state->selected_file = g_file_get_path(file);
        gtk_label_set_text(state->file_label, 
                          state->selected_file ? state->selected_file : "No file selected");
        
        g_object_unref(file);
        
        /* Enable run button if file is selected */
        gtk_widget_set_sensitive(GTK_WIDGET(state->run_btn), TRUE);
    }
    
    gtk_native_dialog_destroy(dialog);
    g_object_unref(dialog);
}

/* File selection callback */
static void on_file_selected(GtkWidget *widget, gpointer user_data) {
    AppState *state = (AppState *)user_data;
    GtkFileChooserNative *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;

    dialog = gtk_file_chooser_native_new("Select File to Sandbox",
                                         GTK_WINDOW(state->window),
                                         action,
                                         "_Open",
                                         "_Cancel");

    g_signal_connect(dialog, "response", G_CALLBACK(on_file_chooser_response), state);
    gtk_native_dialog_show(GTK_NATIVE_DIALOG(dialog));
}

/* Run button callback */
static void on_run_clicked(GtkWidget *widget, gpointer user_data) {
    AppState *state = (AppState *)user_data;
    
    if (!state->selected_file) {
        gtk_label_set_text(state->status_label, "Error: No file selected");
        return;
    }
    
    if (state->process_running) {
        gtk_label_set_text(state->status_label, "Error: Process already running");
        return;
    }
    
    /* Get namespace configuration from checkboxes */
    int ns_flags = 0;
    const char *uts_hostname = NULL;
    
    if (gtk_check_button_get_active(state->ns_pid_check)) {
        ns_flags |= NS_PID;
    }
    if (gtk_check_button_get_active(state->ns_mount_check)) {
        ns_flags |= NS_MOUNT;
    }
    if (gtk_check_button_get_active(state->ns_net_check)) {
        ns_flags |= NS_NET;
    }
    if (gtk_check_button_get_active(state->ns_uts_check)) {
        ns_flags |= NS_UTS;
        /* Get custom hostname if provided */
        const char *hostname_text = gtk_editable_get_text(GTK_EDITABLE(state->ns_uts_hostname_entry));
        if (hostname_text && strlen(hostname_text) > 0) {
            uts_hostname = hostname_text;
        } else {
            uts_hostname = "sandbox"; /* Default hostname */
        }
    }
    
    /* Create sandboxed process with namespace configuration */
    pid_t pid = create_sandboxed_process(state->selected_file, ns_flags, uts_hostname);
    
    if (pid < 0) {
        gtk_label_set_text(state->status_label, "Error: Failed to create sandboxed process");
        return;
    }
    
    state->sandboxed_pid = pid;
    state->process_running = TRUE;
    
    char status_msg[128];
    snprintf(status_msg, sizeof(status_msg), "Process running (PID: %d)", pid);
    gtk_label_set_text(state->status_label, status_msg);
    
    /* Update UI state */
    gtk_widget_set_sensitive(GTK_WIDGET(state->select_file_btn), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(state->run_btn), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(state->stop_btn), TRUE);
}

/* Stop button callback */
static void on_stop_clicked(GtkWidget *widget, gpointer user_data) {
    AppState *state = (AppState *)user_data;
    
    if (!state->process_running || state->sandboxed_pid <= 0) {
        return;
    }
    
    /* Terminate the sandboxed process */
    if (terminate_process(state->sandboxed_pid) == 0) {
        state->process_running = FALSE;
        state->sandboxed_pid = 0;
        
        gtk_label_set_text(state->status_label, "Process stopped");
        
        /* Update UI state */
        gtk_widget_set_sensitive(GTK_WIDGET(state->select_file_btn), TRUE);
        gtk_widget_set_sensitive(GTK_WIDGET(state->run_btn), TRUE);
        gtk_widget_set_sensitive(GTK_WIDGET(state->stop_btn), FALSE);
    } else {
        gtk_label_set_text(state->status_label, "Error: Failed to stop process");
    }
}

/* Setup UI components */
static void setup_ui(AppState *state) {
    GtkWidget *box;
    GtkWidget *header;
    GtkWidget *content;
    GtkWidget *button_box;
    
    /* Create main window */
    state->window = GTK_WINDOW(gtk_application_window_new(state->app));
    gtk_window_set_title(state->window, "Sandboxing Engine");
    gtk_window_set_default_size(state->window, 800, 600);
    
    /* Create main container */
    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(box, 10);
    gtk_widget_set_margin_bottom(box, 10);
    gtk_widget_set_margin_start(box, 10);
    gtk_widget_set_margin_end(box, 10);
    gtk_window_set_child(state->window, box);
    
    /* Header section */
    header = gtk_label_new("Sandboxing Engine - Process Monitor");
    gtk_widget_add_css_class(header, "title");
    gtk_box_append(GTK_BOX(box), header);
    
    /* File selection section */
    content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_box_append(GTK_BOX(box), content);
    
    state->file_label = GTK_LABEL(gtk_label_new("No file selected"));
    gtk_label_set_selectable(state->file_label, TRUE);
    gtk_box_append(GTK_BOX(content), GTK_WIDGET(state->file_label));
    
    state->select_file_btn = GTK_BUTTON(gtk_button_new_with_label("Select File"));
    g_signal_connect(state->select_file_btn, "clicked", 
                     G_CALLBACK(on_file_selected), state);
    gtk_box_append(GTK_BOX(content), GTK_WIDGET(state->select_file_btn));
    
    /* Namespace configuration section */
    GtkWidget *ns_section = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *ns_label = gtk_label_new("Namespace Isolation Settings:");
    gtk_widget_set_margin_top(ns_label, 10);
    gtk_box_append(GTK_BOX(ns_section), ns_label);
    
    GtkWidget *ns_list = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    
    /* PID Namespace Expander */
    state->ns_pid_check = GTK_CHECK_BUTTON(gtk_check_button_new_with_label("PID Namespace"));
    gtk_check_button_set_active(state->ns_pid_check, TRUE);
    state->ns_pid_expander = GTK_EXPANDER(gtk_expander_new_with_mnemonic("_Details"));
    GtkWidget *pid_details = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *pid_desc = gtk_label_new("Isolates process IDs. Sandboxed process will see its own PID namespace.\n"
                                        "• Process will think it's PID 1 (init)\n"
                                        "• Cannot see host system processes\n"
                                        "• Process tree is isolated\n"
                                        "⚠ Requires root privileges or CAP_SYS_ADMIN");
    gtk_label_set_wrap(GTK_LABEL(pid_desc), TRUE);
    gtk_label_set_selectable(GTK_LABEL(pid_desc), TRUE);
    gtk_widget_set_margin_start(pid_desc, 20);
    gtk_box_append(GTK_BOX(pid_details), GTK_WIDGET(state->ns_pid_check));
    gtk_box_append(GTK_BOX(pid_details), pid_desc);
    gtk_expander_set_child(GTK_EXPANDER(state->ns_pid_expander), pid_details);
    gtk_box_append(GTK_BOX(ns_list), GTK_WIDGET(state->ns_pid_expander));
    
    /* Mount Namespace Expander */
    state->ns_mount_check = GTK_CHECK_BUTTON(gtk_check_button_new_with_label("Mount Namespace"));
    gtk_check_button_set_active(state->ns_mount_check, TRUE);
    state->ns_mount_expander = GTK_EXPANDER(gtk_expander_new_with_mnemonic("_Details"));
    GtkWidget *mount_details = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *mount_desc = gtk_label_new("Isolates filesystem mount points. Sandboxed process has separate filesystem view.\n"
                                          "• Cannot see host filesystem\n"
                                          "• Can mount its own filesystems\n"
                                          "• File system changes are isolated\n"
                                          "⚠ Requires root privileges or CAP_SYS_ADMIN");
    gtk_label_set_wrap(GTK_LABEL(mount_desc), TRUE);
    gtk_label_set_selectable(GTK_LABEL(mount_desc), TRUE);
    gtk_widget_set_margin_start(mount_desc, 20);
    gtk_box_append(GTK_BOX(mount_details), GTK_WIDGET(state->ns_mount_check));
    gtk_box_append(GTK_BOX(mount_details), mount_desc);
    gtk_expander_set_child(GTK_EXPANDER(state->ns_mount_expander), mount_details);
    gtk_box_append(GTK_BOX(ns_list), GTK_WIDGET(state->ns_mount_expander));
    
    /* Network Namespace Expander */
    state->ns_net_check = GTK_CHECK_BUTTON(gtk_check_button_new_with_label("Network Namespace"));
    gtk_check_button_set_active(state->ns_net_check, TRUE);
    state->ns_net_expander = GTK_EXPANDER(gtk_expander_new_with_mnemonic("_Details"));
    GtkWidget *net_details = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *net_desc = gtk_label_new("Isolates network stack. Sandboxed process has no network access.\n"
                                        "• No internet access\n"
                                        "• No local network access\n"
                                        "• Only loopback interface available\n"
                                        "• Cannot send/receive network data\n"
                                        "⚠ Requires root privileges or CAP_NET_ADMIN");
    gtk_label_set_wrap(GTK_LABEL(net_desc), TRUE);
    gtk_label_set_selectable(GTK_LABEL(net_desc), TRUE);
    gtk_widget_set_margin_start(net_desc, 20);
    gtk_box_append(GTK_BOX(net_details), GTK_WIDGET(state->ns_net_check));
    gtk_box_append(GTK_BOX(net_details), net_desc);
    gtk_expander_set_child(GTK_EXPANDER(state->ns_net_expander), net_details);
    gtk_box_append(GTK_BOX(ns_list), GTK_WIDGET(state->ns_net_expander));
    
    /* UTS Namespace Expander */
    state->ns_uts_check = GTK_CHECK_BUTTON(gtk_check_button_new_with_label("UTS Namespace"));
    gtk_check_button_set_active(state->ns_uts_check, TRUE);
    state->ns_uts_expander = GTK_EXPANDER(gtk_expander_new_with_mnemonic("_Details"));
    GtkWidget *uts_details = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *uts_desc = gtk_label_new("Isolates hostname and domain name. Sandboxed process sees custom hostname.\n"
                                        "• Process cannot identify host system\n"
                                        "• Custom hostname can be set\n"
                                        "• Appears as different machine");
    gtk_label_set_wrap(GTK_LABEL(uts_desc), TRUE);
    gtk_label_set_selectable(GTK_LABEL(uts_desc), TRUE);
    gtk_widget_set_margin_start(uts_desc, 20);
    
    GtkWidget *uts_config = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    GtkWidget *uts_hostname_label = gtk_label_new("Hostname:");
    state->ns_uts_hostname_entry = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_placeholder_text(state->ns_uts_hostname_entry, "sandbox (default)");
    gtk_editable_set_text(GTK_EDITABLE(state->ns_uts_hostname_entry), "sandbox");
    gtk_box_append(GTK_BOX(uts_config), uts_hostname_label);
    gtk_box_append(GTK_BOX(uts_config), GTK_WIDGET(state->ns_uts_hostname_entry));
    gtk_widget_set_margin_start(GTK_WIDGET(uts_config), 20);
    
    gtk_box_append(GTK_BOX(uts_details), GTK_WIDGET(state->ns_uts_check));
    gtk_box_append(GTK_BOX(uts_details), uts_desc);
    gtk_box_append(GTK_BOX(uts_details), uts_config);
    gtk_expander_set_child(GTK_EXPANDER(state->ns_uts_expander), uts_details);
    gtk_box_append(GTK_BOX(ns_list), GTK_WIDGET(state->ns_uts_expander));
    
    gtk_box_append(GTK_BOX(ns_section), ns_list);
    gtk_box_append(GTK_BOX(box), ns_section);
    
    /* Control buttons */
    button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_append(GTK_BOX(box), button_box);
    
    state->run_btn = GTK_BUTTON(gtk_button_new_with_label("Run in Sandbox"));
    g_signal_connect(state->run_btn, "clicked", 
                     G_CALLBACK(on_run_clicked), state);
    gtk_widget_set_sensitive(GTK_WIDGET(state->run_btn), FALSE);
    gtk_box_append(GTK_BOX(button_box), GTK_WIDGET(state->run_btn));
    
    state->stop_btn = GTK_BUTTON(gtk_button_new_with_label("Stop Process"));
    g_signal_connect(state->stop_btn, "clicked", 
                     G_CALLBACK(on_stop_clicked), state);
    gtk_widget_set_sensitive(GTK_WIDGET(state->stop_btn), FALSE);
    gtk_box_append(GTK_BOX(button_box), GTK_WIDGET(state->stop_btn));
    
    /* Status label */
    state->status_label = GTK_LABEL(gtk_label_new("Ready"));
    gtk_box_append(GTK_BOX(box), GTK_WIDGET(state->status_label));
}

/* Application activation */
static void on_activate(GtkApplication *app, gpointer user_data) {
    AppState *state = (AppState *)user_data;
    
    setup_ui(state);
    gtk_window_present(state->window);
}

/* Cleanup application state */
static void cleanup_state(AppState *state) {
    if (state->process_running && state->sandboxed_pid > 0) {
        terminate_process(state->sandboxed_pid);
    }
    
    if (state->selected_file) {
        g_free(state->selected_file);
    }
}

/* Main entry point */
int main(int argc, char *argv[]) {
    AppState state = {0};
    int status;
    
    /* Initialize GTK */
    state.app = gtk_application_new("com.sandbox.engine", G_APPLICATION_DEFAULT_FLAGS);
    
    g_signal_connect(state.app, "activate", G_CALLBACK(on_activate), &state);
    
    status = g_application_run(G_APPLICATION(state.app), argc, argv);
    
    cleanup_state(&state);
    g_object_unref(state.app);
    
    return status;
}

