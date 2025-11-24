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
#include "firewall.h"

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
    /* Firewall configuration */
    GtkCheckButton *firewall_enabled_check;
    GtkComboBoxText *firewall_policy_combo;
    GtkButton *firewall_load_policy_btn;
    GtkLabel *firewall_status_label;
    /* Log viewer */
    GtkTextView *log_view;
    GtkTextBuffer *log_buffer;
    char *selected_file;
    char *selected_policy_file;
    FirewallPolicy firewall_policy;
    pid_t sandboxed_pid;
    gboolean process_running;
} AppState;

/* Forward declarations */
static void on_activate(GtkApplication *app, gpointer user_data);
static void setup_ui(AppState *state);
static void on_file_selected(GtkWidget *widget, gpointer user_data);
static void on_run_clicked(GtkWidget *widget, gpointer user_data);
static void on_stop_clicked(GtkWidget *widget, gpointer user_data);
/* Firewall callbacks */
static void on_firewall_policy_changed(GtkWidget *widget, gpointer user_data);
static void on_load_firewall_policy(GtkWidget *widget, gpointer user_data);
/* Log functions */
static void append_log(AppState *state, const char *message);
static gboolean update_logs(gpointer user_data);
static void on_policy_chooser_response(GtkNativeDialog *dialog, gint response_id, gpointer user_data);
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
    
    /* Log the configuration */
    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "\n=== Starting Sandboxed Process ===\n");
    append_log(state, log_msg);
    snprintf(log_msg, sizeof(log_msg), "File: %s\n", state->selected_file);
    append_log(state, log_msg);
    snprintf(log_msg, sizeof(log_msg), "Namespaces: PID=%s, Mount=%s, Network=%s, UTS=%s\n",
             (ns_flags & NS_PID) ? "ON" : "OFF",
             (ns_flags & NS_MOUNT) ? "ON" : "OFF",
             (ns_flags & NS_NET) ? "ON" : "OFF",
             (ns_flags & NS_UTS) ? "ON" : "OFF");
    append_log(state, log_msg);
    
    const char *fw_policy_name[] = {"DISABLED", "NO_NETWORK", "STRICT", "MODERATE", "CUSTOM"};
    snprintf(log_msg, sizeof(log_msg), "Firewall Policy: %s\n", fw_policy_name[state->firewall_policy]);
    append_log(state, log_msg);
    
    /* Create sandboxed process with namespace and firewall configuration */
    pid_t pid = create_sandboxed_process(state->selected_file, ns_flags, uts_hostname,
                                         state->firewall_policy, state->selected_policy_file);
    
    if (pid < 0) {
        gtk_label_set_text(state->status_label, "Error: Failed to create sandboxed process");
        append_log(state, "ERROR: Failed to create sandboxed process\n");
        return;
    }
    
    state->sandboxed_pid = pid;
    state->process_running = TRUE;
    
    char status_msg[128];
    snprintf(status_msg, sizeof(status_msg), "Process running (PID: %d)", pid);
    gtk_label_set_text(state->status_label, status_msg);
    snprintf(log_msg, sizeof(log_msg), "Process started with PID: %d\n", pid);
    append_log(state, log_msg);
    
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
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Stopping process PID: %d\n", state->sandboxed_pid);
    append_log(state, log_msg);
    
    if (terminate_process(state->sandboxed_pid) == 0) {
        state->process_running = FALSE;
        state->sandboxed_pid = 0;
        
        gtk_label_set_text(state->status_label, "Process stopped");
        append_log(state, "Process stopped successfully\n");
        
        /* Update UI state */
        gtk_widget_set_sensitive(GTK_WIDGET(state->select_file_btn), TRUE);
        gtk_widget_set_sensitive(GTK_WIDGET(state->run_btn), TRUE);
        gtk_widget_set_sensitive(GTK_WIDGET(state->stop_btn), FALSE);
    } else {
        gtk_label_set_text(state->status_label, "Error: Failed to stop process");
        append_log(state, "ERROR: Failed to stop process\n");
    }
}

/* Firewall policy changed callback */
static void on_firewall_policy_changed(GtkWidget *widget, gpointer user_data) {
    AppState *state = (AppState *)user_data;
    
    const char *policy_text = gtk_combo_box_text_get_active_text(state->firewall_policy_combo);
    if (!policy_text) return;
    
    if (strcmp(policy_text, "Disabled") == 0) {
        state->firewall_policy = FIREWALL_DISABLED;
        gtk_label_set_text(state->firewall_status_label, "Firewall: Disabled");
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_load_policy_btn), FALSE);
    } else if (strcmp(policy_text, "No Network") == 0) {
        state->firewall_policy = FIREWALL_NO_NETWORK;
        gtk_label_set_text(state->firewall_status_label, "Firewall: Complete Network Isolation");
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_load_policy_btn), FALSE);
    } else if (strcmp(policy_text, "Strict") == 0) {
        state->firewall_policy = FIREWALL_STRICT;
        gtk_label_set_text(state->firewall_status_label, "Firewall: Strict (Whitelist Only)");
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_load_policy_btn), TRUE);
    } else if (strcmp(policy_text, "Moderate") == 0) {
        state->firewall_policy = FIREWALL_MODERATE;
        gtk_label_set_text(state->firewall_status_label, "Firewall: Moderate (Block Dangerous Ports)");
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_load_policy_btn), TRUE);
    } else if (strcmp(policy_text, "Custom") == 0) {
        state->firewall_policy = FIREWALL_CUSTOM;
        gtk_label_set_text(state->firewall_status_label, "Firewall: Custom Policy Required");
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_load_policy_btn), TRUE);
    }
    
    g_free((void*)policy_text);
}

/* Policy file chooser response callback */
static void on_policy_chooser_response(GtkNativeDialog *dialog, gint response_id, gpointer user_data) {
    AppState *state = (AppState *)user_data;
    
    if (response_id == GTK_RESPONSE_ACCEPT) {
        GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
        GFile *file = gtk_file_chooser_get_file(chooser);
        
        if (state->selected_policy_file) {
            g_free(state->selected_policy_file);
        }
        
        state->selected_policy_file = g_file_get_path(file);
        
        char status_msg[256];
        snprintf(status_msg, sizeof(status_msg), "Policy loaded: %s", state->selected_policy_file);
        gtk_label_set_text(state->firewall_status_label, status_msg);
        
        g_object_unref(file);
    }
    
    gtk_native_dialog_destroy(dialog);
    g_object_unref(dialog);
}

/* Load firewall policy button callback */
static void on_load_firewall_policy(GtkWidget *widget, gpointer user_data) {
    AppState *state = (AppState *)user_data;
    GtkFileChooserNative *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;

    dialog = gtk_file_chooser_native_new("Select Firewall Policy File",
                                         GTK_WINDOW(state->window),
                                         action,
                                         "_Open",
                                         "_Cancel");
    
    /* Add file filter for .policy files */
    GtkFileFilter *filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "Policy Files");
    gtk_file_filter_add_pattern(filter, "*.policy");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);

    g_signal_connect(dialog, "response", G_CALLBACK(on_policy_chooser_response), state);
    gtk_native_dialog_show(GTK_NATIVE_DIALOG(dialog));
}

/* Append log message to the log viewer */
static void append_log(AppState *state, const char *message) {
    if (!state->log_buffer) return;
    
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(state->log_buffer, &end);
    gtk_text_buffer_insert(state->log_buffer, &end, message, -1);
    
    /* Auto-scroll to bottom */
    GtkTextMark *mark = gtk_text_buffer_get_insert(state->log_buffer);
    gtk_text_view_scroll_to_mark(state->log_view, mark, 0.0, TRUE, 0.0, 1.0);
}

/* Update logs from firewall log file */
static gboolean update_logs(gpointer user_data) {
    AppState *state = (AppState *)user_data;
    static long last_position = 0;
    
    FILE *log_file = fopen("/tmp/sandbox_firewall.log", "r");
    if (!log_file) {
        return G_SOURCE_CONTINUE; /* Keep trying */
    }
    
    /* Seek to last read position */
    fseek(log_file, last_position, SEEK_SET);
    
    char line[512];
    while (fgets(line, sizeof(line), log_file)) {
        append_log(state, line);
    }
    
    /* Save current position */
    last_position = ftell(log_file);
    fclose(log_file);
    
    return G_SOURCE_CONTINUE; /* Keep the timer running */
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
    
    /* Firewall configuration section */
    GtkWidget *firewall_section = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *firewall_label = gtk_label_new("Firewall Configuration:");
    gtk_widget_set_margin_top(firewall_label, 10);
    gtk_box_append(GTK_BOX(firewall_section), firewall_label);
    
    GtkWidget *firewall_controls = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    
    /* Firewall policy selector */
    GtkWidget *policy_label = gtk_label_new("Policy:");
    gtk_box_append(GTK_BOX(firewall_controls), policy_label);
    
    state->firewall_policy_combo = GTK_COMBO_BOX_TEXT(gtk_combo_box_text_new());
    gtk_combo_box_text_append_text(state->firewall_policy_combo, "Disabled");
    gtk_combo_box_text_append_text(state->firewall_policy_combo, "No Network");
    gtk_combo_box_text_append_text(state->firewall_policy_combo, "Strict");
    gtk_combo_box_text_append_text(state->firewall_policy_combo, "Moderate");
    gtk_combo_box_text_append_text(state->firewall_policy_combo, "Custom");
    gtk_combo_box_set_active(GTK_COMBO_BOX(state->firewall_policy_combo), 3); /* Default to Moderate */
    g_signal_connect(state->firewall_policy_combo, "changed",
                     G_CALLBACK(on_firewall_policy_changed), state);
    gtk_box_append(GTK_BOX(firewall_controls), GTK_WIDGET(state->firewall_policy_combo));
    
    /* Load policy file button */
    state->firewall_load_policy_btn = GTK_BUTTON(gtk_button_new_with_label("Load Policy File"));
    g_signal_connect(state->firewall_load_policy_btn, "clicked",
                     G_CALLBACK(on_load_firewall_policy), state);
    gtk_box_append(GTK_BOX(firewall_controls), GTK_WIDGET(state->firewall_load_policy_btn));
    
    gtk_box_append(GTK_BOX(firewall_section), firewall_controls);
    
    /* Firewall status label */
    state->firewall_status_label = GTK_LABEL(gtk_label_new("Firewall: Moderate (Block Dangerous Ports)"));
    gtk_label_set_selectable(state->firewall_status_label, TRUE);
    gtk_widget_set_margin_start(GTK_WIDGET(state->firewall_status_label), 10);
    gtk_box_append(GTK_BOX(firewall_section), GTK_WIDGET(state->firewall_status_label));
    
    /* Firewall info */
    GtkWidget *firewall_info = gtk_label_new(
        "Firewall Modes:\n"
        "• Disabled: No firewall, full network access\n"
        "• No Network: Complete network isolation (all syscalls blocked)\n"
        "• Strict: Whitelist only (specify allowed connections)\n"
        "• Moderate: Block dangerous ports, allow common services\n"
        "• Custom: Load custom policy from file"
    );
    gtk_label_set_wrap(GTK_LABEL(firewall_info), TRUE);
    gtk_widget_set_margin_start(firewall_info, 10);
    gtk_widget_set_margin_top(firewall_info, 5);
    gtk_box_append(GTK_BOX(firewall_section), firewall_info);
    
    gtk_box_append(GTK_BOX(box), firewall_section);
    
    /* Initialize firewall policy */
    state->firewall_policy = FIREWALL_MODERATE;
    state->selected_policy_file = NULL;
    
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
    
    /* Log viewer section */
    GtkWidget *log_section = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_margin_top(log_section, 10);
    GtkWidget *log_label = gtk_label_new("Firewall & Process Logs:");
    gtk_widget_set_halign(log_label, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(log_section), log_label);
    
    /* Scrolled window for log viewer */
    GtkWidget *scrolled = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(scrolled, TRUE);
    gtk_widget_set_size_request(scrolled, -1, 200);
    
    /* Text view for logs */
    state->log_view = GTK_TEXT_VIEW(gtk_text_view_new());
    gtk_text_view_set_editable(state->log_view, FALSE);
    gtk_text_view_set_wrap_mode(state->log_view, GTK_WRAP_WORD);
    gtk_text_view_set_monospace(state->log_view, TRUE);
    state->log_buffer = gtk_text_view_get_buffer(state->log_view);
    
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), GTK_WIDGET(state->log_view));
    gtk_box_append(GTK_BOX(log_section), scrolled);
    gtk_box_append(GTK_BOX(box), log_section);
    
    /* Start log update timer (check every 500ms) */
    g_timeout_add(500, update_logs, state);
    
    /* Initial log message */
    append_log(state, "Sandbox Engine initialized. Ready to run programs.\n");
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
    
    if (state->selected_policy_file) {
        g_free(state->selected_policy_file);
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

