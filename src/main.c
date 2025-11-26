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
#include <arpa/inet.h>
#include <netinet/in.h>

#include "sandbox.h"
#include "process_control.h"
#include "namespaces.h"
#include "firewall.h"
#include "cgroups.h"
#include "monitor.h"
#include "syscall_tracker.h"

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
    GtkButton *firewall_save_policy_btn;
    GtkLabel *firewall_status_label;
    /* Firewall rule configuration */
    GtkTreeView *firewall_rules_tree;
    GtkListStore *firewall_rules_store;
    GtkEntry *fw_rule_name_entry;
    GtkComboBoxText *fw_rule_protocol_combo;
    GtkComboBoxText *fw_rule_direction_combo;
    GtkComboBoxText *fw_rule_action_combo;
    GtkEntry *fw_rule_ip_entry;
    GtkEntry *fw_rule_mask_entry;
    GtkSpinButton *fw_rule_port_start_spin;
    GtkSpinButton *fw_rule_port_end_spin;
    GtkButton *fw_rule_add_btn;
    GtkButton *fw_rule_remove_btn;
    FirewallConfig *firewall_config; /* Store custom rules */
    /* Cgroup configuration */
    GtkCheckButton *cg_enabled_check;
    GtkSpinButton *cg_cpu_spin;
    GtkSpinButton *cg_memory_spin;
    GtkSpinButton *cg_pids_spin;
    GtkSpinButton *cg_threads_spin;
    CgroupConfig cgroup_config;
    /* Monitoring labels */
    GtkLabel *mon_cpu_label;
    GtkLabel *mon_memory_label;
    GtkLabel *mon_threads_label;
    GtkLabel *mon_fds_label;
    GtkLabel *mon_status_label;
    guint monitoring_timeout_id;
    /* Syscall tracking */
    SyscallTracker syscall_tracker;
    GtkCheckButton *syscall_tracking_check;
    GtkTextView *syscall_log_view;
    GtkTextBuffer *syscall_log_buffer;
    GtkTreeView *syscall_stats_tree;
    GtkListStore *syscall_stats_store;
    guint syscall_tracking_timeout_id;
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
static void on_save_firewall_policy(GtkWidget *widget, gpointer user_data);
static void on_add_firewall_rule(GtkWidget *widget, gpointer user_data);
static void on_remove_firewall_rule(GtkWidget *widget, gpointer user_data);
static void refresh_firewall_rules_list(AppState *state);
static void on_policy_chooser_response(GtkNativeDialog *dialog, gint response_id, gpointer user_data);
static void on_save_policy_chooser_response(GtkNativeDialog *dialog, gint response_id, gpointer user_data);
/* Log functions */
static void append_log(AppState *state, const char *message);
static gboolean update_logs(gpointer user_data);
static void on_policy_chooser_response(GtkNativeDialog *dialog, gint response_id, gpointer user_data);
/* Monitoring functions */
static void start_monitoring(AppState *state);
static void stop_monitoring(AppState *state);
static gboolean update_monitoring(gpointer user_data);
/* Syscall tracking functions */
static void start_syscall_tracking(AppState *state);
static void stop_syscall_tracking(AppState *state);
static gboolean update_syscall_tracking(gpointer user_data);
static void refresh_syscall_logs(AppState *state);
static void refresh_syscall_stats(AppState *state);
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
    
    /* Get cgroup configuration */
    CgroupConfig cg_config = {0};
    const CgroupConfig *cg_config_ptr = NULL;
    if (gtk_check_button_get_active(state->cg_enabled_check)) {
        int cpu_limit = gtk_spin_button_get_value_as_int(state->cg_cpu_spin);
        int memory_mb = gtk_spin_button_get_value_as_int(state->cg_memory_spin);
        int pids_limit = gtk_spin_button_get_value_as_int(state->cg_pids_spin);
        int max_threads = gtk_spin_button_get_value_as_int(state->cg_threads_spin);
        
        if (init_cgroup_config(&cg_config, cpu_limit, memory_mb, pids_limit, max_threads) == 0) {
            cg_config_ptr = &cg_config;
            snprintf(log_msg, sizeof(log_msg), "Resource Limits: CPU=%d%%, Memory=%dMB, PIDs=%d, Threads=%d\n",
                     cpu_limit, memory_mb, pids_limit, max_threads);
            append_log(state, log_msg);
        }
    }
    
    /* Save custom firewall rules to temp file if configured */
    char *temp_policy_file = NULL;
    if (state->firewall_config && 
        (state->firewall_policy == FIREWALL_CUSTOM || 
         state->firewall_policy == FIREWALL_STRICT ||
         state->firewall_config->rule_count > 0)) {
        /* Save to temp file */
        temp_policy_file = g_strdup("/tmp/sandbox_firewall_policy.policy");
        if (firewall_save_policy(state->firewall_config, temp_policy_file) < 0) {
            g_free(temp_policy_file);
            temp_policy_file = NULL;
        }
    }
    
    /* Use temp policy file if we created one, otherwise use selected file */
    const char *policy_file_to_use = temp_policy_file ? temp_policy_file : state->selected_policy_file;
    
    /* Create sandboxed process with namespace, firewall, and cgroup configuration */
    pid_t pid = create_sandboxed_process(state->selected_file, ns_flags, uts_hostname,
                                         state->firewall_policy, policy_file_to_use,
                                         cg_config_ptr);
    
    /* Cleanup temp file */
    if (temp_policy_file) {
        g_free(temp_policy_file);
    }
    
    /* Cleanup cgroup config if process creation failed */
    if (pid < 0 && cg_config_ptr) {
        free_cgroup_config(&cg_config);
    } else if (pid > 0 && cg_config_ptr) {
        /* Deep copy cgroup_path for state */
        if (cg_config.cgroup_path) {
            state->cgroup_config = cg_config;
            state->cgroup_config.cgroup_path = g_strdup(cg_config.cgroup_path);
        }
    }
    
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
    
    /* Start monitoring */
    start_monitoring(state);
    
    /* Start syscall tracking if enabled */
    if (gtk_check_button_get_active(state->syscall_tracking_check)) {
        start_syscall_tracking(state);
    }
    
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
    
    /* Stop monitoring */
    stop_monitoring(state);
    
    /* Stop syscall tracking */
    stop_syscall_tracking(state);
    
    /* Terminate the sandboxed process */
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Stopping process PID: %d\n", state->sandboxed_pid);
    append_log(state, log_msg);
    
    if (terminate_process(state->sandboxed_pid) == 0) {
        state->process_running = FALSE;
        state->sandboxed_pid = 0;
        
        gtk_label_set_text(state->status_label, "Process stopped");
        append_log(state, "Process stopped successfully\n");
        
        /* Cleanup cgroup */
        if (state->cgroup_config.cgroup_path) {
            cleanup_cgroup(&state->cgroup_config);
            free_cgroup_config(&state->cgroup_config);
        }
        
        /* Clear monitoring stats */
        gtk_label_set_text(state->mon_cpu_label, "--");
        gtk_label_set_text(state->mon_memory_label, "--");
        gtk_label_set_text(state->mon_threads_label, "--");
        gtk_label_set_text(state->mon_fds_label, "--");
        gtk_label_set_text(state->mon_status_label, "Stopped");
        
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
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_save_policy_btn), FALSE);
        /* Cleanup config if exists */
        if (state->firewall_config) {
            firewall_cleanup(state->firewall_config);
            state->firewall_config = NULL;
            refresh_firewall_rules_list(state);
        }
    } else if (strcmp(policy_text, "No Network") == 0) {
        state->firewall_policy = FIREWALL_NO_NETWORK;
        gtk_label_set_text(state->firewall_status_label, "Firewall: Complete Network Isolation");
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_load_policy_btn), FALSE);
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_save_policy_btn), FALSE);
        /* Cleanup config if exists */
        if (state->firewall_config) {
            firewall_cleanup(state->firewall_config);
            state->firewall_config = NULL;
            refresh_firewall_rules_list(state);
        }
    } else if (strcmp(policy_text, "Strict") == 0) {
        state->firewall_policy = FIREWALL_STRICT;
        gtk_label_set_text(state->firewall_status_label, "Firewall: Strict (Whitelist Only)");
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_load_policy_btn), TRUE);
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_save_policy_btn), TRUE);
        /* Initialize config if not exists */
        if (!state->firewall_config) {
            state->firewall_config = firewall_init(FIREWALL_STRICT);
            refresh_firewall_rules_list(state);
        }
    } else if (strcmp(policy_text, "Moderate") == 0) {
        state->firewall_policy = FIREWALL_MODERATE;
        gtk_label_set_text(state->firewall_status_label, "Firewall: Moderate (Block Dangerous Ports)");
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_load_policy_btn), TRUE);
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_save_policy_btn), TRUE);
        /* Initialize config if not exists */
        if (!state->firewall_config) {
            state->firewall_config = firewall_init(FIREWALL_MODERATE);
            refresh_firewall_rules_list(state);
        }
    } else if (strcmp(policy_text, "Custom") == 0) {
        state->firewall_policy = FIREWALL_CUSTOM;
        gtk_label_set_text(state->firewall_status_label, "Firewall: Custom Policy Required");
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_load_policy_btn), TRUE);
        gtk_widget_set_sensitive(GTK_WIDGET(state->firewall_save_policy_btn), TRUE);
        /* Initialize config if not exists */
        if (!state->firewall_config) {
            state->firewall_config = firewall_init(FIREWALL_CUSTOM);
            refresh_firewall_rules_list(state);
        }
    }
    
    g_free((void*)policy_text);
}

/* Policy file chooser response callback */
static void on_policy_chooser_response(GtkNativeDialog *dialog, gint response_id, gpointer user_data) {
    AppState *state = (AppState *)user_data;
    
    if (response_id == GTK_RESPONSE_ACCEPT) {
        GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
        GFile *file = gtk_file_chooser_get_file(chooser);
        char *file_path = g_file_get_path(file);
        
        if (state->selected_policy_file) {
            g_free(state->selected_policy_file);
        }
        
        state->selected_policy_file = file_path;
        
        /* Load policy into firewall config */
        if (!state->firewall_config) {
            state->firewall_config = firewall_init(state->firewall_policy);
        }
        
        if (firewall_load_policy(state->firewall_config, file_path) == 0) {
            char status_msg[256];
            snprintf(status_msg, sizeof(status_msg), "Policy loaded: %s", file_path);
            gtk_label_set_text(state->firewall_status_label, status_msg);
            append_log(state, "Firewall policy loaded successfully\n");
            
            /* Refresh rules list */
            refresh_firewall_rules_list(state);
        } else {
            gtk_label_set_text(state->firewall_status_label, "Error: Failed to load policy");
            append_log(state, "ERROR: Failed to load firewall policy\n");
        }
        
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

/* Save firewall policy button callback */
static void on_save_firewall_policy(GtkWidget *widget, gpointer user_data) {
    AppState *state = (AppState *)user_data;
    GtkFileChooserNative *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_SAVE;

    dialog = gtk_file_chooser_native_new("Save Firewall Policy File",
                                         GTK_WINDOW(state->window),
                                         action,
                                         "_Save",
                                         "_Cancel");
    
    /* Add file filter for .policy files */
    GtkFileFilter *filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "Policy Files");
    gtk_file_filter_add_pattern(filter, "*.policy");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);

    g_signal_connect(dialog, "response", G_CALLBACK(on_save_policy_chooser_response), state);
    gtk_native_dialog_show(GTK_NATIVE_DIALOG(dialog));
}

/* Save policy file chooser response callback */
static void on_save_policy_chooser_response(GtkNativeDialog *dialog, gint response_id, gpointer user_data) {
    AppState *state = (AppState *)user_data;
    
    if (response_id == GTK_RESPONSE_ACCEPT) {
        GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
        GFile *file = gtk_file_chooser_get_file(chooser);
        char *file_path = g_file_get_path(file);
        
        if (state->firewall_config) {
            if (firewall_save_policy(state->firewall_config, file_path) == 0) {
                char status_msg[256];
                snprintf(status_msg, sizeof(status_msg), "Policy saved to: %s", file_path);
                gtk_label_set_text(state->firewall_status_label, status_msg);
                append_log(state, "Firewall policy saved successfully\n");
            } else {
                gtk_label_set_text(state->firewall_status_label, "Error: Failed to save policy");
                append_log(state, "ERROR: Failed to save firewall policy\n");
            }
        } else {
            /* Create a temporary config and save */
            FirewallConfig *temp_config = firewall_init(state->firewall_policy);
            if (temp_config) {
                /* Add rules from list store */
                GtkTreeIter iter;
                gboolean valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(state->firewall_rules_store), &iter);
                while (valid) {
                    char *name, *proto_str, *dir_str, *act_str, *ip_str;
                    int port_start, port_end;
                    
                    gtk_tree_model_get(GTK_TREE_MODEL(state->firewall_rules_store), &iter,
                        0, &name, 1, &proto_str, 2, &dir_str, 3, &act_str,
                        4, &ip_str, 5, &port_start, 6, &port_end, -1);
                    
                    NetworkProtocol protocol = PROTO_ALL;
                    if (strcmp(proto_str, "TCP") == 0) protocol = PROTO_TCP;
                    else if (strcmp(proto_str, "UDP") == 0) protocol = PROTO_UDP;
                    else if (strcmp(proto_str, "ICMP") == 0) protocol = PROTO_ICMP;
                    
                    TrafficDirection direction = DIR_BOTH;
                    if (strcmp(dir_str, "INBOUND") == 0) direction = DIR_INBOUND;
                    else if (strcmp(dir_str, "OUTBOUND") == 0) direction = DIR_OUTBOUND;
                    
                    RuleAction action = ACTION_ALLOW;
                    if (strcmp(act_str, "DENY") == 0) action = ACTION_DENY;
                    else if (strcmp(act_str, "LOG") == 0) action = ACTION_LOG;
                    
                    const char *ip_ptr = (ip_str && strlen(ip_str) > 0) ? ip_str : NULL;
                    FirewallRule rule = firewall_create_rule(name, protocol, direction, action,
                                                             ip_ptr, NULL, port_start, port_end);
                    firewall_add_rule(temp_config, &rule);
                    
                    g_free(name);
                    g_free(proto_str);
                    g_free(dir_str);
                    g_free(act_str);
                    g_free(ip_str);
                    
                    valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(state->firewall_rules_store), &iter);
                }
                
                if (firewall_save_policy(temp_config, file_path) == 0) {
                    char status_msg[256];
                    snprintf(status_msg, sizeof(status_msg), "Policy saved to: %s", file_path);
                    gtk_label_set_text(state->firewall_status_label, status_msg);
                    append_log(state, "Firewall policy saved successfully\n");
                }
                firewall_cleanup(temp_config);
            }
        }
        
        g_free(file_path);
        g_object_unref(file);
    }
    
    gtk_native_dialog_destroy(dialog);
    g_object_unref(dialog);
}

/* Add firewall rule callback */
static void on_add_firewall_rule(GtkWidget *widget, gpointer user_data) {
    AppState *state = (AppState *)user_data;
    
    const char *name = gtk_editable_get_text(GTK_EDITABLE(state->fw_rule_name_entry));
    if (!name || strlen(name) == 0) {
        gtk_label_set_text(state->firewall_status_label, "Error: Rule name required");
        return;
    }
    
    const char *proto_text = gtk_combo_box_text_get_active_text(state->fw_rule_protocol_combo);
    const char *dir_text = gtk_combo_box_text_get_active_text(state->fw_rule_direction_combo);
    const char *act_text = gtk_combo_box_text_get_active_text(state->fw_rule_action_combo);
    
    const char *ip_text = gtk_editable_get_text(GTK_EDITABLE(state->fw_rule_ip_entry));
    const char *mask_text = gtk_editable_get_text(GTK_EDITABLE(state->fw_rule_mask_entry));
    int port_start = gtk_spin_button_get_value_as_int(state->fw_rule_port_start_spin);
    int port_end = gtk_spin_button_get_value_as_int(state->fw_rule_port_end_spin);
    
    if (port_end == 0) port_end = port_start;
    
    /* Add to list store */
    GtkTreeIter iter;
    gtk_list_store_append(state->firewall_rules_store, &iter);
    gtk_list_store_set(state->firewall_rules_store, &iter,
        0, name,
        1, proto_text ? proto_text : "ALL",
        2, dir_text ? dir_text : "BOTH",
        3, act_text ? act_text : "ALLOW",
        4, ip_text && strlen(ip_text) > 0 ? ip_text : "-",
        5, port_start,
        6, port_end,
        -1);
    
    /* Clear form */
    gtk_editable_set_text(GTK_EDITABLE(state->fw_rule_name_entry), "");
    gtk_editable_set_text(GTK_EDITABLE(state->fw_rule_ip_entry), "");
    gtk_editable_set_text(GTK_EDITABLE(state->fw_rule_mask_entry), "");
    gtk_spin_button_set_value(state->fw_rule_port_start_spin, 0);
    gtk_spin_button_set_value(state->fw_rule_port_end_spin, 0);
    
    g_free((void*)proto_text);
    g_free((void*)dir_text);
    g_free((void*)act_text);
    
    /* Update firewall config */
    if (!state->firewall_config) {
        state->firewall_config = firewall_init(state->firewall_policy);
    }
    
    NetworkProtocol protocol = PROTO_ALL;
    if (proto_text && strcmp(proto_text, "TCP") == 0) protocol = PROTO_TCP;
    else if (proto_text && strcmp(proto_text, "UDP") == 0) protocol = PROTO_UDP;
    else if (proto_text && strcmp(proto_text, "ICMP") == 0) protocol = PROTO_ICMP;
    
    TrafficDirection direction = DIR_BOTH;
    if (dir_text && strcmp(dir_text, "INBOUND") == 0) direction = DIR_INBOUND;
    else if (dir_text && strcmp(dir_text, "OUTBOUND") == 0) direction = DIR_OUTBOUND;
    
    RuleAction action = ACTION_ALLOW;
    if (act_text && strcmp(act_text, "DENY") == 0) action = ACTION_DENY;
    else if (act_text && strcmp(act_text, "LOG") == 0) action = ACTION_LOG;
    
    const char *ip_ptr = (ip_text && strlen(ip_text) > 0) ? ip_text : NULL;
    const char *mask_ptr = (mask_text && strlen(mask_text) > 0) ? mask_text : NULL;
    
    FirewallRule rule = firewall_create_rule(name, protocol, direction, action,
                                             ip_ptr, mask_ptr, port_start, port_end);
    firewall_add_rule(state->firewall_config, &rule);
    
    gtk_label_set_text(state->firewall_status_label, "Rule added successfully");
}

/* Remove firewall rule callback */
static void on_remove_firewall_rule(GtkWidget *widget, gpointer user_data) {
    AppState *state = (AppState *)user_data;
    
    GtkTreeSelection *selection = gtk_tree_view_get_selection(state->firewall_rules_tree);
    GtkTreeModel *model;
    GtkTreeIter iter;
    
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        int index = 0;
        GtkTreePath *path = gtk_tree_model_get_path(model, &iter);
        int *indices = gtk_tree_path_get_indices(path);
        if (indices) {
            index = indices[0];
        }
        gtk_tree_path_free(path);
        
        /* Remove from list store */
        gtk_list_store_remove(state->firewall_rules_store, &iter);
        
        /* Remove from firewall config */
        if (state->firewall_config && index < state->firewall_config->rule_count) {
            firewall_remove_rule(state->firewall_config, index);
        }
        
        gtk_label_set_text(state->firewall_status_label, "Rule removed");
    } else {
        gtk_label_set_text(state->firewall_status_label, "No rule selected");
    }
}

/* Refresh firewall rules list */
static void refresh_firewall_rules_list(AppState *state) {
    gtk_list_store_clear(state->firewall_rules_store);
    
    if (state->firewall_config) {
        for (int i = 0; i < state->firewall_config->rule_count; i++) {
            FirewallRule *rule = &state->firewall_config->rules[i];
            if (!rule->enabled) continue;
            
            const char *proto = "ALL";
            if (rule->protocol == PROTO_TCP) proto = "TCP";
            else if (rule->protocol == PROTO_UDP) proto = "UDP";
            else if (rule->protocol == PROTO_ICMP) proto = "ICMP";
            
            const char *dir = "BOTH";
            if (rule->direction == DIR_INBOUND) dir = "INBOUND";
            else if (rule->direction == DIR_OUTBOUND) dir = "OUTBOUND";
            
            const char *action = "ALLOW";
            if (rule->action == ACTION_DENY) action = "DENY";
            else if (rule->action == ACTION_LOG) action = "LOG";
            
            char ip_str[32] = "-";
            if (rule->has_ip_filter) {
                inet_ntop(AF_INET, &rule->ip_addr, ip_str, sizeof(ip_str));
            }
            
            char port_str[32];
            if (rule->port_start == rule->port_end) {
                snprintf(port_str, sizeof(port_str), "%d", rule->port_start);
            } else {
                snprintf(port_str, sizeof(port_str), "%d-%d", rule->port_start, rule->port_end);
            }
            
            GtkTreeIter iter;
            gtk_list_store_append(state->firewall_rules_store, &iter);
            gtk_list_store_set(state->firewall_rules_store, &iter,
                0, rule->name,
                1, proto,
                2, dir,
                3, action,
                4, ip_str,
                5, rule->port_start,
                6, rule->port_end,
                -1);
        }
    }
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

/* Start monitoring process statistics */
static void start_monitoring(AppState *state) {
    if (state->sandboxed_pid <= 0) {
        return;
    }
    
    /* Initialize monitoring */
    init_monitoring(state->sandboxed_pid);
    
    /* Start update timer (update every 500ms) */
    state->monitoring_timeout_id = g_timeout_add(500, update_monitoring, state);
}

/* Stop monitoring */
static void stop_monitoring(AppState *state) {
    if (state->monitoring_timeout_id > 0) {
        g_source_remove(state->monitoring_timeout_id);
        state->monitoring_timeout_id = 0;
    }
}

/* Update monitoring display */
static gboolean update_monitoring(gpointer user_data) {
    AppState *state = (AppState *)user_data;
    
    if (!state->process_running || state->sandboxed_pid <= 0) {
        return G_SOURCE_CONTINUE;
    }
    
    ProcessStats stats;
    if (collect_process_stats(state->sandboxed_pid, &stats) == 0) {
        char buf[256];
        
        if (stats.is_running) {
            /* Update CPU */
            snprintf(buf, sizeof(buf), "%.2f%%", stats.cpu_percent);
            gtk_label_set_text(state->mon_cpu_label, buf);
            
            /* Update Memory */
            snprintf(buf, sizeof(buf), "%.2f MB", stats.memory_rss_kb / 1024.0);
            gtk_label_set_text(state->mon_memory_label, buf);
            
            /* Update Threads */
            snprintf(buf, sizeof(buf), "%d", stats.num_threads);
            gtk_label_set_text(state->mon_threads_label, buf);
            
            /* Update File Descriptors */
            snprintf(buf, sizeof(buf), "%d", stats.num_fds);
            gtk_label_set_text(state->mon_fds_label, buf);
            
            /* Update Status */
            gtk_label_set_text(state->mon_status_label, "Running");
        } else {
            /* Process stopped */
            gtk_label_set_text(state->mon_cpu_label, "--");
            gtk_label_set_text(state->mon_memory_label, "--");
            gtk_label_set_text(state->mon_threads_label, "--");
            gtk_label_set_text(state->mon_fds_label, "--");
            
            if (stats.signal_number > 0) {
                snprintf(buf, sizeof(buf), "Killed by signal %d (%s)", 
                         stats.signal_number, strsignal(stats.signal_number));
                gtk_label_set_text(state->mon_status_label, buf);
            } else if (stats.exit_status >= 0) {
                snprintf(buf, sizeof(buf), "Exited with status %d", stats.exit_status);
                gtk_label_set_text(state->mon_status_label, buf);
            } else {
                gtk_label_set_text(state->mon_status_label, "Stopped");
            }
            
            /* Stop monitoring */
            stop_monitoring(state);
            state->process_running = FALSE;
        }
    }
    
    return G_SOURCE_CONTINUE;
}

/* Start syscall tracking */
static void start_syscall_tracking(AppState *state) {
    if (state->sandboxed_pid <= 0) {
        return;
    }
    
    char log_file[256];
    snprintf(log_file, sizeof(log_file), "/tmp/sandbox_syscalls_%d.log", state->sandboxed_pid);
    
    if (syscall_tracker_init(&state->syscall_tracker, state->sandboxed_pid, log_file) == 0) {
        if (syscall_tracker_start(&state->syscall_tracker) == 0) {
            /* Start update timer (update every 100ms for real-time tracking) */
            state->syscall_tracking_timeout_id = g_timeout_add(100, update_syscall_tracking, state);
        } else {
            /* Failed to start - might need root */
            gtk_label_set_text(state->status_label, "Warning: Syscall tracking requires root privileges");
            syscall_tracker_cleanup(&state->syscall_tracker);
        }
    }
}

/* Stop syscall tracking */
static void stop_syscall_tracking(AppState *state) {
    if (state->syscall_tracking_timeout_id > 0) {
        g_source_remove(state->syscall_tracking_timeout_id);
        state->syscall_tracking_timeout_id = 0;
    }
    
    syscall_tracker_stop(&state->syscall_tracker);
    syscall_tracker_cleanup(&state->syscall_tracker);
}

/* Update syscall tracking display */
static gboolean update_syscall_tracking(gpointer user_data) {
    AppState *state = (AppState *)user_data;
    
    if (!state->process_running || state->sandboxed_pid <= 0) {
        return G_SOURCE_CONTINUE;
    }
    
    /* Process syscall events */
    syscall_tracker_process_event(&state->syscall_tracker);
    
    /* Refresh logs and stats periodically (every 10 updates = 1 second) */
    static int update_counter = 0;
    update_counter++;
    if (update_counter >= 10) {
        refresh_syscall_logs(state);
        refresh_syscall_stats(state);
        update_counter = 0;
    }
    
    return G_SOURCE_CONTINUE;
}

/* Refresh syscall logs */
static void refresh_syscall_logs(AppState *state) {
    if (!state->syscall_log_buffer) {
        return;
    }
    
    SyscallLogEntry entries[100];
    int count = syscall_tracker_get_logs(&state->syscall_tracker, entries, 100);
    
    if (count > 0) {
        /* Get current text length */
        GtkTextIter start, end;
        gtk_text_buffer_get_bounds(state->syscall_log_buffer, &start, &end);
        int current_length = gtk_text_iter_get_offset(&end);
        
        /* Only add new entries */
        static int last_log_count = 0;
        if (count > last_log_count) {
            for (int i = last_log_count; i < count; i++) {
                char log_line[512];
                syscall_format_entry(&entries[i], log_line, sizeof(log_line));
                
                GtkTextIter iter;
                gtk_text_buffer_get_end_iter(state->syscall_log_buffer, &iter);
                gtk_text_buffer_insert(state->syscall_log_buffer, &iter, log_line, -1);
                gtk_text_buffer_insert(state->syscall_log_buffer, &iter, "\n", -1);
            }
            
            /* Auto-scroll to bottom */
            GtkTextMark *mark = gtk_text_buffer_get_insert(state->syscall_log_buffer);
            gtk_text_view_scroll_to_mark(state->syscall_log_view, mark, 0.0, TRUE, 0.0, 1.0);
        }
        
        last_log_count = count;
    }
}

/* Refresh syscall statistics */
static void refresh_syscall_stats(AppState *state) {
    if (!state->syscall_stats_store) {
        return;
    }
    
    SyscallStats stats[500];
    int count = syscall_tracker_get_stats(&state->syscall_tracker, stats, 500);
    
    /* Clear existing stats */
    gtk_list_store_clear(state->syscall_stats_store);
    
    /* Add stats */
    for (int i = 0; i < count; i++) {
        char success_rate[32];
        if (stats[i].count > 0) {
            double success = ((double)(stats[i].count - stats[i].error_count) / stats[i].count) * 100.0;
            snprintf(success_rate, sizeof(success_rate), "%.1f%%", success);
        } else {
            strcpy(success_rate, "N/A");
        }
        
        GtkTreeIter iter;
        gtk_list_store_append(state->syscall_stats_store, &iter);
        gtk_list_store_set(state->syscall_stats_store, &iter,
            0, stats[i].syscall_name,
            1, (guint)stats[i].count,
            2, (guint)stats[i].error_count,
            3, success_rate,
            -1);
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
    gtk_window_set_default_size(state->window, 1000, 700);
    gtk_window_set_resizable(state->window, TRUE);
    
    /* Create scrolled window for entire content */
    GtkWidget *main_scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(main_scrolled), 
                                    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_window_set_child(state->window, main_scrolled);
    
    /* Create main container */
    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_margin_top(box, 5);
    gtk_widget_set_margin_bottom(box, 5);
    gtk_widget_set_margin_start(box, 5);
    gtk_widget_set_margin_end(box, 5);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(main_scrolled), box);
    
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
    GtkWidget *ns_section = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_set_margin_top(ns_section, 2);
    gtk_widget_set_margin_bottom(ns_section, 2);
    gtk_widget_set_margin_start(ns_section, 2);
    gtk_widget_set_margin_end(ns_section, 2);
    GtkWidget *ns_label = gtk_label_new("Namespace Isolation:");
    gtk_widget_set_margin_top(ns_label, 2);
    gtk_widget_set_margin_bottom(ns_label, 2);
    gtk_box_append(GTK_BOX(ns_section), ns_label);
    
    GtkWidget *ns_list = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
    
    /* PID Namespace */
    state->ns_pid_check = GTK_CHECK_BUTTON(gtk_check_button_new_with_label("PID Namespace"));
    gtk_check_button_set_active(state->ns_pid_check, TRUE);
    gtk_box_append(GTK_BOX(ns_list), GTK_WIDGET(state->ns_pid_check));
    
    /* Mount Namespace */
    state->ns_mount_check = GTK_CHECK_BUTTON(gtk_check_button_new_with_label("Mount Namespace"));
    gtk_check_button_set_active(state->ns_mount_check, TRUE);
    gtk_box_append(GTK_BOX(ns_list), GTK_WIDGET(state->ns_mount_check));
    
    /* Network Namespace */
    state->ns_net_check = GTK_CHECK_BUTTON(gtk_check_button_new_with_label("Network Namespace"));
    gtk_check_button_set_active(state->ns_net_check, TRUE);
    gtk_box_append(GTK_BOX(ns_list), GTK_WIDGET(state->ns_net_check));
    
    /* UTS Namespace */
    state->ns_uts_check = GTK_CHECK_BUTTON(gtk_check_button_new_with_label("UTS Namespace"));
    gtk_check_button_set_active(state->ns_uts_check, TRUE);
    gtk_box_append(GTK_BOX(ns_list), GTK_WIDGET(state->ns_uts_check));
    
    /* UTS Hostname configuration */
    GtkWidget *uts_config = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_widget_set_margin_start(uts_config, 20);
    gtk_widget_set_margin_top(uts_config, 2);
    GtkWidget *uts_hostname_label = gtk_label_new("Hostname:");
    state->ns_uts_hostname_entry = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_placeholder_text(state->ns_uts_hostname_entry, "sandbox (default)");
    gtk_editable_set_text(GTK_EDITABLE(state->ns_uts_hostname_entry), "sandbox");
    gtk_box_append(GTK_BOX(uts_config), uts_hostname_label);
    gtk_box_append(GTK_BOX(uts_config), GTK_WIDGET(state->ns_uts_hostname_entry));
    gtk_box_append(GTK_BOX(ns_list), uts_config);
    
    gtk_box_append(GTK_BOX(ns_section), ns_list);
    
    /* Create notebook (tabs) */
    GtkNotebook *notebook = GTK_NOTEBOOK(gtk_notebook_new());
    gtk_widget_set_vexpand(GTK_WIDGET(notebook), FALSE);
    
    /* Tab 1: Namespaces */
    gtk_notebook_append_page(notebook, ns_section, gtk_label_new("Namespaces"));
    
    /* Tab 2: Resource Limits (Cgroups) */
    GtkWidget *cg_tab = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_margin_top(cg_tab, 5);
    gtk_widget_set_margin_bottom(cg_tab, 5);
    gtk_widget_set_margin_start(cg_tab, 5);
    gtk_widget_set_margin_end(cg_tab, 5);
    
    GtkWidget *cg_label = gtk_label_new("Resource Limits (Cgroups):");
    gtk_box_append(GTK_BOX(cg_tab), cg_label);
    
    state->cg_enabled_check = GTK_CHECK_BUTTON(gtk_check_button_new_with_label("Enable Resource Limits"));
    gtk_box_append(GTK_BOX(cg_tab), GTK_WIDGET(state->cg_enabled_check));
    
    GtkWidget *cg_grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(cg_grid), 10);
    gtk_grid_set_row_spacing(GTK_GRID(cg_grid), 5);
    gtk_widget_set_margin_start(cg_grid, 10);
    gtk_widget_set_margin_top(cg_grid, 5);
    
    /* CPU limit */
    GtkWidget *cpu_label = gtk_label_new("CPU Limit (%):");
    gtk_grid_attach(GTK_GRID(cg_grid), cpu_label, 0, 0, 1, 1);
    state->cg_cpu_spin = GTK_SPIN_BUTTON(gtk_spin_button_new_with_range(0, 100, 1));
    gtk_spin_button_set_value(state->cg_cpu_spin, 0); /* 0 = unlimited */
    gtk_grid_attach(GTK_GRID(cg_grid), GTK_WIDGET(state->cg_cpu_spin), 1, 0, 1, 1);
    
    /* Memory limit */
    GtkWidget *mem_label = gtk_label_new("Memory Limit (MB):");
    gtk_grid_attach(GTK_GRID(cg_grid), mem_label, 0, 1, 1, 1);
    state->cg_memory_spin = GTK_SPIN_BUTTON(gtk_spin_button_new_with_range(0, 100000, 100));
    gtk_spin_button_set_value(state->cg_memory_spin, 0); /* 0 = unlimited */
    gtk_grid_attach(GTK_GRID(cg_grid), GTK_WIDGET(state->cg_memory_spin), 1, 1, 1, 1);
    
    /* PIDs limit */
    GtkWidget *pids_label = gtk_label_new("Max Processes:");
    gtk_grid_attach(GTK_GRID(cg_grid), pids_label, 0, 2, 1, 1);
    state->cg_pids_spin = GTK_SPIN_BUTTON(gtk_spin_button_new_with_range(0, 10000, 1));
    gtk_spin_button_set_value(state->cg_pids_spin, 0); /* 0 = unlimited */
    gtk_grid_attach(GTK_GRID(cg_grid), GTK_WIDGET(state->cg_pids_spin), 1, 2, 1, 1);
    
    /* Max threads/cores */
    GtkWidget *threads_label = gtk_label_new("Max CPU Cores/Threads:");
    gtk_grid_attach(GTK_GRID(cg_grid), threads_label, 0, 3, 1, 1);
    state->cg_threads_spin = GTK_SPIN_BUTTON(gtk_spin_button_new_with_range(0, 64, 1));
    gtk_spin_button_set_value(state->cg_threads_spin, 0); /* 0 = unlimited */
    gtk_grid_attach(GTK_GRID(cg_grid), GTK_WIDGET(state->cg_threads_spin), 1, 3, 1, 1);
    
    gtk_box_append(GTK_BOX(cg_tab), cg_grid);
    
    GtkWidget *cg_info = gtk_label_new(
        "Note: Set to 0 for unlimited.\n"
        "• CPU Limit: Percentage of CPU time (0-100)\n"
        "• Memory Limit: Maximum memory in MB\n"
        "• Max Processes: Maximum number of processes\n"
        "• Max CPU Cores: Maximum number of CPU cores/threads"
    );
    gtk_label_set_wrap(GTK_LABEL(cg_info), TRUE);
    gtk_widget_set_margin_start(cg_info, 20);
    gtk_widget_set_margin_top(cg_info, 10);
    gtk_box_append(GTK_BOX(cg_tab), cg_info);
    
    gtk_notebook_append_page(notebook, cg_tab, gtk_label_new("Resource Limits"));
    
    /* Tab 3: Monitoring */
    GtkWidget *mon_tab = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_margin_top(mon_tab, 5);
    gtk_widget_set_margin_bottom(mon_tab, 5);
    gtk_widget_set_margin_start(mon_tab, 5);
    gtk_widget_set_margin_end(mon_tab, 5);
    
    GtkWidget *mon_label = gtk_label_new("Process Statistics:");
    gtk_box_append(GTK_BOX(mon_tab), mon_label);
    
    GtkWidget *mon_grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(mon_grid), 10);
    gtk_grid_set_row_spacing(GTK_GRID(mon_grid), 5);
    gtk_widget_set_margin_top(mon_grid, 5);
    
    GtkWidget *cpu_mon_label = gtk_label_new("CPU Usage:");
    gtk_grid_attach(GTK_GRID(mon_grid), cpu_mon_label, 0, 0, 1, 1);
    state->mon_cpu_label = GTK_LABEL(gtk_label_new("--"));
    gtk_label_set_selectable(state->mon_cpu_label, TRUE);
    gtk_grid_attach(GTK_GRID(mon_grid), GTK_WIDGET(state->mon_cpu_label), 1, 0, 1, 1);
    
    GtkWidget *mem_mon_label = gtk_label_new("Memory (RSS):");
    gtk_grid_attach(GTK_GRID(mon_grid), mem_mon_label, 0, 1, 1, 1);
    state->mon_memory_label = GTK_LABEL(gtk_label_new("--"));
    gtk_label_set_selectable(state->mon_memory_label, TRUE);
    gtk_grid_attach(GTK_GRID(mon_grid), GTK_WIDGET(state->mon_memory_label), 1, 1, 1, 1);
    
    GtkWidget *threads_mon_label = gtk_label_new("Threads:");
    gtk_grid_attach(GTK_GRID(mon_grid), threads_mon_label, 0, 2, 1, 1);
    state->mon_threads_label = GTK_LABEL(gtk_label_new("--"));
    gtk_label_set_selectable(state->mon_threads_label, TRUE);
    gtk_grid_attach(GTK_GRID(mon_grid), GTK_WIDGET(state->mon_threads_label), 1, 2, 1, 1);
    
    GtkWidget *fds_mon_label = gtk_label_new("File Descriptors:");
    gtk_grid_attach(GTK_GRID(mon_grid), fds_mon_label, 0, 3, 1, 1);
    state->mon_fds_label = GTK_LABEL(gtk_label_new("--"));
    gtk_label_set_selectable(state->mon_fds_label, TRUE);
    gtk_grid_attach(GTK_GRID(mon_grid), GTK_WIDGET(state->mon_fds_label), 1, 3, 1, 1);
    
    GtkWidget *status_mon_label = gtk_label_new("Status:");
    gtk_grid_attach(GTK_GRID(mon_grid), status_mon_label, 0, 4, 1, 1);
    state->mon_status_label = GTK_LABEL(gtk_label_new("Not running"));
    gtk_label_set_selectable(state->mon_status_label, TRUE);
    gtk_grid_attach(GTK_GRID(mon_grid), GTK_WIDGET(state->mon_status_label), 1, 4, 1, 1);
    
    gtk_box_append(GTK_BOX(mon_tab), mon_grid);
    
    gtk_notebook_append_page(notebook, mon_tab, gtk_label_new("Monitoring"));
    
    /* Tab 4: Syscall Tracking */
    GtkWidget *syscall_tab = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_margin_top(syscall_tab, 5);
    gtk_widget_set_margin_bottom(syscall_tab, 5);
    gtk_widget_set_margin_start(syscall_tab, 5);
    gtk_widget_set_margin_end(syscall_tab, 5);
    
    /* Enable syscall tracking checkbox */
    state->syscall_tracking_check = GTK_CHECK_BUTTON(gtk_check_button_new_with_label("Enable Syscall Tracking"));
    gtk_check_button_set_active(state->syscall_tracking_check, FALSE);
    gtk_box_append(GTK_BOX(syscall_tab), GTK_WIDGET(state->syscall_tracking_check));
    
    GtkWidget *syscall_info = gtk_label_new(
        "Syscall tracking uses ptrace to intercept and log all system calls made by the sandboxed process.\n"
        "⚠ Requires root privileges or CAP_SYS_PTRACE capability.\n"
        "Note: Tracking may slow down the process significantly."
    );
    gtk_label_set_wrap(GTK_LABEL(syscall_info), TRUE);
    gtk_widget_set_margin_start(syscall_info, 20);
    gtk_widget_set_margin_top(syscall_info, 5);
    gtk_box_append(GTK_BOX(syscall_tab), syscall_info);
    
    /* Syscall log viewer */
    GtkWidget *syscall_log_label = gtk_label_new("Syscall Log:");
    gtk_widget_set_margin_top(syscall_log_label, 5);
    gtk_box_append(GTK_BOX(syscall_tab), syscall_log_label);
    
    GtkWidget *syscall_log_scrolled = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(syscall_log_scrolled, FALSE);
    gtk_widget_set_size_request(syscall_log_scrolled, -1, 120);
    
    state->syscall_log_view = GTK_TEXT_VIEW(gtk_text_view_new());
    gtk_text_view_set_editable(state->syscall_log_view, FALSE);
    gtk_text_view_set_wrap_mode(state->syscall_log_view, GTK_WRAP_WORD);
    gtk_text_view_set_monospace(state->syscall_log_view, TRUE);
    state->syscall_log_buffer = gtk_text_view_get_buffer(state->syscall_log_view);
    
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(syscall_log_scrolled), GTK_WIDGET(state->syscall_log_view));
    gtk_box_append(GTK_BOX(syscall_tab), syscall_log_scrolled);
    
    /* Syscall statistics */
    GtkWidget *syscall_stats_label = gtk_label_new("Syscall Statistics:");
    gtk_widget_set_margin_top(syscall_stats_label, 5);
    gtk_box_append(GTK_BOX(syscall_tab), syscall_stats_label);
    
    state->syscall_stats_store = gtk_list_store_new(4,
        G_TYPE_STRING,  /* Syscall name */
        G_TYPE_UINT,    /* Count */
        G_TYPE_UINT,    /* Error count */
        G_TYPE_STRING   /* Success rate */
    );
    
    state->syscall_stats_tree = GTK_TREE_VIEW(gtk_tree_view_new_with_model(GTK_TREE_MODEL(state->syscall_stats_store)));
    
    GtkCellRenderer *sc_renderer;
    GtkTreeViewColumn *sc_column;
    
    sc_renderer = gtk_cell_renderer_text_new();
    sc_column = gtk_tree_view_column_new_with_attributes("Syscall", sc_renderer, "text", 0, NULL);
    gtk_tree_view_column_set_sort_column_id(sc_column, 0);
    gtk_tree_view_append_column(state->syscall_stats_tree, sc_column);
    
    sc_renderer = gtk_cell_renderer_text_new();
    sc_column = gtk_tree_view_column_new_with_attributes("Count", sc_renderer, "text", 1, NULL);
    gtk_tree_view_column_set_sort_column_id(sc_column, 1);
    gtk_tree_view_append_column(state->syscall_stats_tree, sc_column);
    
    sc_renderer = gtk_cell_renderer_text_new();
    sc_column = gtk_tree_view_column_new_with_attributes("Errors", sc_renderer, "text", 2, NULL);
    gtk_tree_view_column_set_sort_column_id(sc_column, 2);
    gtk_tree_view_append_column(state->syscall_stats_tree, sc_column);
    
    sc_renderer = gtk_cell_renderer_text_new();
    sc_column = gtk_tree_view_column_new_with_attributes("Success Rate", sc_renderer, "text", 3, NULL);
    gtk_tree_view_append_column(state->syscall_stats_tree, sc_column);
    
    GtkWidget *syscall_stats_scrolled = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(syscall_stats_scrolled, FALSE);
    gtk_widget_set_size_request(syscall_stats_scrolled, -1, 100);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(syscall_stats_scrolled), GTK_WIDGET(state->syscall_stats_tree));
    gtk_box_append(GTK_BOX(syscall_tab), syscall_stats_scrolled);
    
    gtk_notebook_append_page(notebook, syscall_tab, gtk_label_new("Syscalls"));
    
    gtk_box_append(GTK_BOX(box), GTK_WIDGET(notebook));
    
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
    
    /* Save policy file button */
    state->firewall_save_policy_btn = GTK_BUTTON(gtk_button_new_with_label("Save Policy File"));
    g_signal_connect(state->firewall_save_policy_btn, "clicked",
                     G_CALLBACK(on_save_firewall_policy), state);
    gtk_box_append(GTK_BOX(firewall_controls), GTK_WIDGET(state->firewall_save_policy_btn));
    
    gtk_box_append(GTK_BOX(firewall_section), firewall_controls);
    
    /* Firewall rules configuration (expandable section) */
    GtkExpander *fw_rules_expander = GTK_EXPANDER(gtk_expander_new_with_mnemonic("_Configure Custom Rules"));
    GtkWidget *fw_rules_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_start(fw_rules_box, 20);
    gtk_widget_set_margin_top(fw_rules_box, 10);
    
    /* Rules list */
    GtkWidget *rules_label = gtk_label_new("Firewall Rules:");
    gtk_box_append(GTK_BOX(fw_rules_box), rules_label);
    
    /* Create list store for rules */
    state->firewall_rules_store = gtk_list_store_new(7, 
        G_TYPE_STRING,  /* Name */
        G_TYPE_STRING,  /* Protocol */
        G_TYPE_STRING,  /* Direction */
        G_TYPE_STRING,  /* Action */
        G_TYPE_STRING,  /* IP */
        G_TYPE_INT,     /* Port Start */
        G_TYPE_INT      /* Port End */
    );
    
    /* Create tree view */
    state->firewall_rules_tree = GTK_TREE_VIEW(gtk_tree_view_new_with_model(GTK_TREE_MODEL(state->firewall_rules_store)));
    
    /* Add columns */
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;
    
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Name", renderer, "text", 0, NULL);
    gtk_tree_view_append_column(state->firewall_rules_tree, column);
    
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Protocol", renderer, "text", 1, NULL);
    gtk_tree_view_append_column(state->firewall_rules_tree, column);
    
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Direction", renderer, "text", 2, NULL);
    gtk_tree_view_append_column(state->firewall_rules_tree, column);
    
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Action", renderer, "text", 3, NULL);
    gtk_tree_view_append_column(state->firewall_rules_tree, column);
    
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("IP", renderer, "text", 4, NULL);
    gtk_tree_view_append_column(state->firewall_rules_tree, column);
    
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Ports", renderer, "text", 5, NULL);
    gtk_tree_view_append_column(state->firewall_rules_tree, column);
    
    /* Scrolled window for rules list */
    GtkWidget *rules_scrolled = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(rules_scrolled, FALSE);
    gtk_widget_set_size_request(rules_scrolled, -1, 100);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(rules_scrolled), GTK_WIDGET(state->firewall_rules_tree));
    gtk_box_append(GTK_BOX(fw_rules_box), rules_scrolled);
    
    /* Rule input form */
    GtkWidget *rule_form = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(rule_form), 10);
    gtk_grid_set_row_spacing(GTK_GRID(rule_form), 5);
    
    /* Rule name */
    GtkWidget *name_label = gtk_label_new("Rule Name:");
    gtk_grid_attach(GTK_GRID(rule_form), name_label, 0, 0, 1, 1);
    state->fw_rule_name_entry = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_placeholder_text(state->fw_rule_name_entry, "e.g., Allow HTTP");
    gtk_grid_attach(GTK_GRID(rule_form), GTK_WIDGET(state->fw_rule_name_entry), 1, 0, 1, 1);
    
    /* Protocol */
    GtkWidget *proto_label = gtk_label_new("Protocol:");
    gtk_grid_attach(GTK_GRID(rule_form), proto_label, 0, 1, 1, 1);
    state->fw_rule_protocol_combo = GTK_COMBO_BOX_TEXT(gtk_combo_box_text_new());
    gtk_combo_box_text_append_text(state->fw_rule_protocol_combo, "ALL");
    gtk_combo_box_text_append_text(state->fw_rule_protocol_combo, "TCP");
    gtk_combo_box_text_append_text(state->fw_rule_protocol_combo, "UDP");
    gtk_combo_box_text_append_text(state->fw_rule_protocol_combo, "ICMP");
    gtk_combo_box_set_active(GTK_COMBO_BOX(state->fw_rule_protocol_combo), 1); /* Default TCP */
    gtk_grid_attach(GTK_GRID(rule_form), GTK_WIDGET(state->fw_rule_protocol_combo), 1, 1, 1, 1);
    
    /* Direction */
    GtkWidget *dir_label = gtk_label_new("Direction:");
    gtk_grid_attach(GTK_GRID(rule_form), dir_label, 2, 1, 1, 1);
    state->fw_rule_direction_combo = GTK_COMBO_BOX_TEXT(gtk_combo_box_text_new());
    gtk_combo_box_text_append_text(state->fw_rule_direction_combo, "BOTH");
    gtk_combo_box_text_append_text(state->fw_rule_direction_combo, "INBOUND");
    gtk_combo_box_text_append_text(state->fw_rule_direction_combo, "OUTBOUND");
    gtk_combo_box_set_active(GTK_COMBO_BOX(state->fw_rule_direction_combo), 0); /* Default BOTH */
    gtk_grid_attach(GTK_GRID(rule_form), GTK_WIDGET(state->fw_rule_direction_combo), 3, 1, 1, 1);
    
    /* Action */
    GtkWidget *action_label = gtk_label_new("Action:");
    gtk_grid_attach(GTK_GRID(rule_form), action_label, 0, 2, 1, 1);
    state->fw_rule_action_combo = GTK_COMBO_BOX_TEXT(gtk_combo_box_text_new());
    gtk_combo_box_text_append_text(state->fw_rule_action_combo, "ALLOW");
    gtk_combo_box_text_append_text(state->fw_rule_action_combo, "DENY");
    gtk_combo_box_text_append_text(state->fw_rule_action_combo, "LOG");
    gtk_combo_box_set_active(GTK_COMBO_BOX(state->fw_rule_action_combo), 0); /* Default ALLOW */
    gtk_grid_attach(GTK_GRID(rule_form), GTK_WIDGET(state->fw_rule_action_combo), 1, 2, 1, 1);
    
    /* IP Address */
    GtkWidget *ip_label = gtk_label_new("IP Address:");
    gtk_grid_attach(GTK_GRID(rule_form), ip_label, 2, 2, 1, 1);
    state->fw_rule_ip_entry = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_placeholder_text(state->fw_rule_ip_entry, "0.0.0.0 (any)");
    gtk_grid_attach(GTK_GRID(rule_form), GTK_WIDGET(state->fw_rule_ip_entry), 3, 2, 1, 1);
    
    /* Netmask */
    GtkWidget *mask_label = gtk_label_new("Netmask:");
    gtk_grid_attach(GTK_GRID(rule_form), mask_label, 0, 3, 1, 1);
    state->fw_rule_mask_entry = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_placeholder_text(state->fw_rule_mask_entry, "255.255.255.255");
    gtk_grid_attach(GTK_GRID(rule_form), GTK_WIDGET(state->fw_rule_mask_entry), 1, 3, 1, 1);
    
    /* Port Start */
    GtkWidget *port_start_label = gtk_label_new("Port Start:");
    gtk_grid_attach(GTK_GRID(rule_form), port_start_label, 2, 3, 1, 1);
    state->fw_rule_port_start_spin = GTK_SPIN_BUTTON(gtk_spin_button_new_with_range(0, 65535, 1));
    gtk_spin_button_set_value(state->fw_rule_port_start_spin, 0);
    gtk_grid_attach(GTK_GRID(rule_form), GTK_WIDGET(state->fw_rule_port_start_spin), 3, 3, 1, 1);
    
    /* Port End */
    GtkWidget *port_end_label = gtk_label_new("Port End:");
    gtk_grid_attach(GTK_GRID(rule_form), port_end_label, 0, 4, 1, 1);
    state->fw_rule_port_end_spin = GTK_SPIN_BUTTON(gtk_spin_button_new_with_range(0, 65535, 1));
    gtk_spin_button_set_value(state->fw_rule_port_end_spin, 0);
    gtk_grid_attach(GTK_GRID(rule_form), GTK_WIDGET(state->fw_rule_port_end_spin), 1, 4, 1, 1);
    
    gtk_box_append(GTK_BOX(fw_rules_box), rule_form);
    
    /* Add/Remove buttons */
    GtkWidget *rule_buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    state->fw_rule_add_btn = GTK_BUTTON(gtk_button_new_with_label("Add Rule"));
    g_signal_connect(state->fw_rule_add_btn, "clicked",
                     G_CALLBACK(on_add_firewall_rule), state);
    gtk_box_append(GTK_BOX(rule_buttons), GTK_WIDGET(state->fw_rule_add_btn));
    
    state->fw_rule_remove_btn = GTK_BUTTON(gtk_button_new_with_label("Remove Selected"));
    g_signal_connect(state->fw_rule_remove_btn, "clicked",
                     G_CALLBACK(on_remove_firewall_rule), state);
    gtk_box_append(GTK_BOX(rule_buttons), GTK_WIDGET(state->fw_rule_remove_btn));
    
    gtk_box_append(GTK_BOX(fw_rules_box), rule_buttons);
    
    gtk_expander_set_child(GTK_EXPANDER(fw_rules_expander), fw_rules_box);
    gtk_box_append(GTK_BOX(firewall_section), GTK_WIDGET(fw_rules_expander));
    
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
    state->firewall_config = NULL;
    
    /* Initialize syscall tracker */
    memset(&state->syscall_tracker, 0, sizeof(SyscallTracker));
    state->syscall_tracking_timeout_id = 0;
    
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
    gtk_widget_set_margin_top(log_section, 5);
    gtk_widget_set_vexpand(log_section, FALSE);
    GtkWidget *log_label = gtk_label_new("Firewall & Process Logs:");
    gtk_widget_set_halign(log_label, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(log_section), log_label);
    
    /* Scrolled window for log viewer */
    GtkWidget *scrolled = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(scrolled, FALSE);
    gtk_widget_set_size_request(scrolled, -1, 120);
    
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
    /* Stop monitoring */
    stop_monitoring(state);
    
    if (state->process_running && state->sandboxed_pid > 0) {
        terminate_process(state->sandboxed_pid);
    }
    
    /* Cleanup cgroup */
    if (state->cgroup_config.cgroup_path) {
        cleanup_cgroup(&state->cgroup_config);
        free_cgroup_config(&state->cgroup_config);
    }
    
    if (state->selected_file) {
        g_free(state->selected_file);
    }
    
    if (state->selected_policy_file) {
        g_free(state->selected_policy_file);
    }
    
    if (state->firewall_config) {
        firewall_cleanup(state->firewall_config);
        state->firewall_config = NULL;
    }
    
    /* Cleanup syscall tracker */
    stop_syscall_tracking(state);
}

/* Main entry point */
int main(int argc, char *argv[]) {
    AppState state = {0};
    /* Initialize cgroup config */
    memset(&state.cgroup_config, 0, sizeof(CgroupConfig));
    /* Initialize syscall tracker */
    memset(&state.syscall_tracker, 0, sizeof(SyscallTracker));
    state.monitoring_timeout_id = 0;
    state.syscall_tracking_timeout_id = 0;
    state.process_running = FALSE;
    state.sandboxed_pid = 0;
    int status;
    
    /* Initialize GTK */
    state.app = gtk_application_new("com.sandbox.engine", G_APPLICATION_DEFAULT_FLAGS);
    
    g_signal_connect(state.app, "activate", G_CALLBACK(on_activate), &state);
    
    status = g_application_run(G_APPLICATION(state.app), argc, argv);
    
    cleanup_state(&state);
    g_object_unref(state.app);
    
    return status;
}

