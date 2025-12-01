#define _GNU_SOURCE
#include "firewall.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stddef.h>

/* seccomp return values */
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif
#ifndef SECCOMP_RET_DATA
#define SECCOMP_RET_DATA 0x0000ffffU
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif

/* Default maximum rules */
#define DEFAULT_MAX_RULES 100
#define DEFAULT_LOG_FILE "/tmp/sandbox_firewall.log"

/* Syscall numbers for network operations */
#ifndef __NR_socket
#define __NR_socket 41
#endif
#ifndef __NR_connect
#define __NR_connect 42
#endif
#ifndef __NR_bind
#define __NR_bind 49
#endif
#ifndef __NR_sendto
#define __NR_sendto 44
#endif
#ifndef __NR_recvfrom
#define __NR_recvfrom 45
#endif
#ifndef __NR_sendmsg
#define __NR_sendmsg 46
#endif
#ifndef __NR_recvmsg
#define __NR_recvmsg 47
#endif
#ifndef __NR_seccomp
#define __NR_seccomp 317
#endif

/* Seccomp filter definitions */
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif

/* BPF instruction shortcuts */
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }

/* Logging helper */
static void log_firewall_event(FirewallConfig *config, const char *event) {
    if (!config || !config->log_enabled) return;
    
    FILE *log = fopen(config->log_file, "a");
    if (log) {
        time_t now = time(NULL);
        char timestamp[26];
        ctime_r(&now, timestamp);
        timestamp[24] = '\0'; /* Remove newline */
        fprintf(log, "[%s] %s\n", timestamp, event);
        fclose(log);
    }
}

/**
 * Initialize firewall with specified policy
 */
FirewallConfig* firewall_init(FirewallPolicy policy) {
    FirewallConfig *config = calloc(1, sizeof(FirewallConfig));
    if (!config) {
        perror("calloc");
        return NULL;
    }
    
    config->policy = policy;
    config->max_rules = DEFAULT_MAX_RULES;
    config->rules = calloc(config->max_rules, sizeof(FirewallRule));
    if (!config->rules) {
        free(config);
        return NULL;
    }
    
    config->rule_count = 0;
    config->log_enabled = 1;
    strncpy(config->log_file, DEFAULT_LOG_FILE, sizeof(config->log_file) - 1);
    
    /* Initialize statistics */
    config->packets_allowed = 0;
    config->packets_denied = 0;
    config->bytes_allowed = 0;
    config->bytes_denied = 0;
    
    /* Load default rules based on policy */
    switch (policy) {
        case FIREWALL_STRICT:
            /* In strict mode, deny everything by default */
            /* User must explicitly add allow rules */
            log_firewall_event(config, "Firewall initialized: STRICT mode (deny all by default)");
            break;
            
        case FIREWALL_MODERATE:
            /* Block commonly exploited ports */
            {
                /* Block Telnet */
                FirewallRule telnet = firewall_create_rule(
                    "Block Telnet", PROTO_TCP, DIR_BOTH, ACTION_DENY,
                    NULL, NULL, 23, 23
                );
                firewall_add_rule(config, &telnet);
                
                /* Block FTP */
                FirewallRule ftp = firewall_create_rule(
                    "Block FTP", PROTO_TCP, DIR_BOTH, ACTION_DENY,
                    NULL, NULL, 21, 21
                );
                firewall_add_rule(config, &ftp);
                
                /* Block SMB */
                FirewallRule smb = firewall_create_rule(
                    "Block SMB", PROTO_TCP, DIR_BOTH, ACTION_DENY,
                    NULL, NULL, 445, 445
                );
                firewall_add_rule(config, &smb);
                
                /* Allow HTTP/HTTPS */
                FirewallRule http = firewall_create_rule(
                    "Allow HTTP", PROTO_TCP, DIR_OUTBOUND, ACTION_ALLOW,
                    NULL, NULL, 80, 80
                );
                firewall_add_rule(config, &http);
                
                FirewallRule https = firewall_create_rule(
                    "Allow HTTPS", PROTO_TCP, DIR_OUTBOUND, ACTION_ALLOW,
                    NULL, NULL, 443, 443
                );
                firewall_add_rule(config, &https);
                
                /* Allow DNS */
                FirewallRule dns = firewall_create_rule(
                    "Allow DNS", PROTO_UDP, DIR_OUTBOUND, ACTION_ALLOW,
                    NULL, NULL, 53, 53
                );
                firewall_add_rule(config, &dns);
                
                log_firewall_event(config, "Firewall initialized: MODERATE mode");
            }
            break;
            
        case FIREWALL_NO_NETWORK:
            log_firewall_event(config, "Firewall initialized: NO_NETWORK mode (complete isolation)");
            break;
            
        case FIREWALL_CUSTOM:
            log_firewall_event(config, "Firewall initialized: CUSTOM mode");
            break;
            
        case FIREWALL_DISABLED:
        default:
            log_firewall_event(config, "Firewall initialized: DISABLED");
            break;
    }
    
    return config;
}

/**
 * Block network syscalls using seccomp
 */
int firewall_block_network_syscalls(void) {
    struct sock_filter filter[] = {
        /* Load syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        
        /* Block socket() */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        
        /* Block connect() */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        
        /* Block bind() */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        
        /* Block sendto() */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        
        /* Block recvfrom() */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvfrom, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        
        /* Block sendmsg() */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        
        /* Block recvmsg() */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        
        /* Allow all other syscalls */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter
    };
    
    /* Set NO_NEW_PRIVS to allow seccomp without root */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return -1;
    }
    
    /* Apply seccomp filter */
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
        perror("seccomp");
        return -1;
    }
    
    printf("Network syscalls blocked via seccomp\n");
    return 0;
}

/**
 * Apply seccomp filter for STRICT mode - block all network by default
 */
static int firewall_apply_strict_filter(void) {
    struct sock_filter filter[] = {
        /* Load syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        
        /* Block socket() - no network sockets allowed in strict mode */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        
        /* Block connect() */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        
        /* Block bind() */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        
        /* Allow all other syscalls */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter
    };
    
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return -1;
    }
    
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
        perror("seccomp");
        return -1;
    }
    
    printf("STRICT mode: All network syscalls blocked via seccomp\n");
    return 0;
}

/**
 * Apply seccomp filter for MODERATE/CUSTOM modes based on configured rules
 */
static int firewall_apply_moderate_filter(FirewallConfig *config) {
    int has_allow_rules = 0;
    int has_deny_rules = 0;
    
    /* Count rule types */
    for (int i = 0; i < config->rule_count; i++) {
        if (config->rules[i].enabled) {
            if (config->rules[i].action == ACTION_ALLOW) {
                has_allow_rules = 1;
            } else if (config->rules[i].action == ACTION_DENY) {
                has_deny_rules = 1;
            }
        }
    }
    
    /* Determine enforcement strategy based on policy and rules */
    int should_block_network = 0;
    
    if (config->policy == FIREWALL_MODERATE) {
        /* MODERATE: Always allow network, rely on Network Namespace */
        printf("✓ MODERATE mode: Allowing all network\n");
        printf("  → For isolation, enable Network Namespace\n");
        should_block_network = 0;
        
    } else if (config->policy == FIREWALL_CUSTOM) {
        /* CUSTOM: Behavior depends on rules */
        if (config->rule_count == 0) {
            /* No rules = allow all */
            printf("✓ CUSTOM mode: No rules configured, allowing all network\n");
            printf("  → Add rules or enable Network Namespace for protection\n");
            should_block_network = 0;
            
        } else if (has_allow_rules && !has_deny_rules) {
            /* Only ALLOW rules = deny-by-default (whitelist) */
            printf("✓ CUSTOM mode: ALLOW rules (deny-by-default)\n");
            printf("  → Blocking ALL network at kernel level\n");
            printf("  → Use Network Namespace to enable allowed connections\n");
            should_block_network = 1;
            
        } else if (has_deny_rules && !has_allow_rules) {
            /* Only DENY rules = allow-by-default (blacklist) */
            printf("✓ CUSTOM mode: DENY rules (allow-by-default)\n");
            printf("  → Allowing all network, use Network Namespace to block\n");
            should_block_network = 0;
            
        } else {
            /* Both ALLOW and DENY rules = ambiguous, default to block */
            printf("✓ CUSTOM mode: Mixed ALLOW/DENY rules\n");
            printf("  → Blocking ALL network (deny-by-default for safety)\n");
            printf("  → Use Network Namespace for granular control\n");
            should_block_network = 1;
        }
    }
    
    /* Apply seccomp filter if we should block */
    if (should_block_network) {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
        };
        
        struct sock_fprog prog = {
            .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
            .filter = filter
        };
        
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            perror("prctl(PR_SET_NO_NEW_PRIVS)");
            return -1;
        }
        
        if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
            perror("seccomp");
            return -1;
        }
        
        printf("  ✓ Seccomp filter installed\n");
    }
    
    return 0;
}

/**
 * Apply firewall rules to current process
 */
int firewall_apply(FirewallConfig *config) {
    if (!config) {
        return -1;
    }
    
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Applying firewall policy: %s", 
             firewall_policy_name(config->policy));
    log_firewall_event(config, log_msg);
    
    switch (config->policy) {
        case FIREWALL_NO_NETWORK:
            /* Block all network syscalls at kernel level */
            if (firewall_block_network_syscalls() < 0) {
                log_firewall_event(config, "ERROR: Failed to block network syscalls");
                return -1;
            }
            log_firewall_event(config, "Network access completely blocked via seccomp");
            printf("✓ NO_NETWORK: Complete network isolation active\n");
            break;
            
        case FIREWALL_STRICT:
            /* Strict mode: Block all network syscalls (similar to NO_NETWORK) */
            /* User must explicitly add allow rules (which require Network Namespace) */
            if (firewall_apply_strict_filter() < 0) {
                log_firewall_event(config, "ERROR: Failed to apply STRICT filter");
                return -1;
            }
            log_firewall_event(config, "STRICT mode: All network blocked, use with Network Namespace for selective access");
            printf("✓ STRICT: Network blocked at kernel level\n");
            printf("  To allow specific connections, enable Network Namespace and configure routing\n");
            break;
            
        case FIREWALL_MODERATE:
        case FIREWALL_CUSTOM:
            /* Moderate/Custom mode: Hybrid enforcement approach */
            if (firewall_apply_moderate_filter(config) < 0) {
                log_firewall_event(config, "WARNING: Failed to apply MODERATE filter");
            }
            
            snprintf(log_msg, sizeof(log_msg), 
                     "Firewall active with %d rules (best with Network Namespace)", 
                     config->rule_count);
            log_firewall_event(config, log_msg);
            
            /* Print active rules */
            if (config->rule_count > 0) {
                printf("\n");
                printf("═══ Configured Rules (%d) ═══\n", config->rule_count);
                for (int i = 0; i < config->rule_count; i++) {
                    if (config->rules[i].enabled) {
                        const char *action_str = config->rules[i].action == ACTION_ALLOW ? "ALLOW" : "DENY";
                        const char *proto_str = config->rules[i].protocol == PROTO_TCP ? "TCP" :
                                               config->rules[i].protocol == PROTO_UDP ? "UDP" : "ALL";
                        printf("  [%d] %s %s: %s", i, action_str, proto_str, config->rules[i].name);
                        if (config->rules[i].has_port_filter) {
                            printf(" (port %d", config->rules[i].port_start);
                            if (config->rules[i].port_end != config->rules[i].port_start) {
                                printf("-%d", config->rules[i].port_end);
                            }
                            printf(")");
                        }
                        printf("\n");
                    }
                }
                printf("═══════════════════════════════\n\n");
            }
            break;
            
        case FIREWALL_DISABLED:
        default:
            log_firewall_event(config, "Firewall disabled - full network access");
            printf("⚠ WARNING: Firewall disabled - unrestricted network access\n");
            break;
    }
    
    return 0;
}

/**
 * Add a firewall rule
 */
int firewall_add_rule(FirewallConfig *config, const FirewallRule *rule) {
    if (!config || !rule) {
        return -1;
    }
    
    if (config->rule_count >= config->max_rules) {
        fprintf(stderr, "Maximum number of firewall rules reached\n");
        return -1;
    }
    
    memcpy(&config->rules[config->rule_count], rule, sizeof(FirewallRule));
    config->rules[config->rule_count].enabled = 1;
    config->rule_count++;
    
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Rule added: %s", rule->name);
    log_firewall_event(config, log_msg);
    
    return 0;
}

/**
 * Remove a firewall rule by index
 */
int firewall_remove_rule(FirewallConfig *config, int index) {
    if (!config || index < 0 || index >= config->rule_count) {
        return -1;
    }
    
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Rule removed: %s", 
             config->rules[index].name);
    log_firewall_event(config, log_msg);
    
    /* Shift remaining rules */
    for (int i = index; i < config->rule_count - 1; i++) {
        memcpy(&config->rules[i], &config->rules[i + 1], sizeof(FirewallRule));
    }
    
    config->rule_count--;
    return 0;
}

/**
 * Get firewall statistics
 */
void firewall_get_stats(FirewallConfig *config, unsigned long *allowed, unsigned long *denied) {
    if (config) {
        if (allowed) *allowed = config->packets_allowed;
        if (denied) *denied = config->packets_denied;
    }
}

/**
 * Enable/disable firewall logging
 */
int firewall_set_logging(FirewallConfig *config, int enabled, const char *log_file) {
    if (!config) {
        return -1;
    }
    
    config->log_enabled = enabled;
    
    if (log_file) {
        strncpy(config->log_file, log_file, sizeof(config->log_file) - 1);
        config->log_file[sizeof(config->log_file) - 1] = '\0';
    }
    
    return 0;
}

/**
 * Cleanup firewall resources
 */
void firewall_cleanup(FirewallConfig *config) {
    if (config) {
        log_firewall_event(config, "Firewall shutting down");
        if (config->rules) {
            free(config->rules);
        }
        free(config);
    }
}

/**
 * Create a firewall rule (helper)
 */
FirewallRule firewall_create_rule(
    const char *name,
    NetworkProtocol protocol,
    TrafficDirection direction,
    RuleAction action,
    const char *ip_addr,
    const char *netmask,
    uint16_t port_start,
    uint16_t port_end
) {
    FirewallRule rule = {0};
    
    if (name) {
        strncpy(rule.name, name, sizeof(rule.name) - 1);
    }
    
    rule.protocol = protocol;
    rule.direction = direction;
    rule.action = action;
    
    /* IP filtering */
    if (ip_addr && netmask) {
        rule.has_ip_filter = 1;
        inet_pton(AF_INET, ip_addr, &rule.ip_addr);
        inet_pton(AF_INET, netmask, &rule.ip_mask);
    } else {
        rule.has_ip_filter = 0;
    }
    
    /* Port filtering */
    if (port_start > 0) {
        rule.has_port_filter = 1;
        rule.port_start = port_start;
        rule.port_end = (port_end > 0) ? port_end : port_start;
    } else {
        rule.has_port_filter = 0;
    }
    
    rule.enabled = 1;
    
    return rule;
}

/**
 * Load firewall policy from file
 */
int firewall_load_policy(FirewallConfig *config, const char *policy_file) {
    if (!config || !policy_file) {
        return -1;
    }
    
    FILE *fp = fopen(policy_file, "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }
    
    /* Clear existing rules - policy file replaces current config */
    while (config->rule_count > 0) {
        firewall_remove_rule(config, 0);
    }
    
    char line[512];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        /* Parse rule: name,protocol,direction,action,ip,mask,port_start,port_end */
        char name[64], proto[10], dir[10], act[10], ip[32], mask[32];
        int port_start, port_end;
        
        int parsed = sscanf(line, "%63[^,],%9[^,],%9[^,],%9[^,],%31[^,],%31[^,],%d,%d",
                           name, proto, dir, act, ip, mask, &port_start, &port_end);
        
        if (parsed >= 4) {
            NetworkProtocol protocol = PROTO_ALL;
            if (strcmp(proto, "TCP") == 0) protocol = PROTO_TCP;
            else if (strcmp(proto, "UDP") == 0) protocol = PROTO_UDP;
            else if (strcmp(proto, "ICMP") == 0) protocol = PROTO_ICMP;
            
            TrafficDirection direction = DIR_BOTH;
            if (strcmp(dir, "INBOUND") == 0) direction = DIR_INBOUND;
            else if (strcmp(dir, "OUTBOUND") == 0) direction = DIR_OUTBOUND;
            
            RuleAction action = ACTION_DENY;
            if (strcmp(act, "ALLOW") == 0) action = ACTION_ALLOW;
            else if (strcmp(act, "LOG") == 0) action = ACTION_LOG;
            
            const char *ip_ptr = (parsed >= 5 && strcmp(ip, "-") != 0) ? ip : NULL;
            const char *mask_ptr = (parsed >= 6 && strcmp(mask, "-") != 0) ? mask : NULL;
            uint16_t ps = (parsed >= 7) ? port_start : 0;
            uint16_t pe = (parsed >= 8) ? port_end : 0;
            
            FirewallRule rule = firewall_create_rule(name, protocol, direction, action,
                                                      ip_ptr, mask_ptr, ps, pe);
            firewall_add_rule(config, &rule);
        }
    }
    
    fclose(fp);
    
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Policy loaded from %s (%d rules)", 
             policy_file, config->rule_count);
    log_firewall_event(config, log_msg);
    
    return 0;
}

/**
 * Save firewall policy to file
 */
int firewall_save_policy(FirewallConfig *config, const char *policy_file) {
    if (!config || !policy_file) {
        return -1;
    }
    
    FILE *fp = fopen(policy_file, "w");
    if (!fp) {
        perror("fopen");
        return -1;
    }
    
    fprintf(fp, "# Firewall Policy File\n");
    fprintf(fp, "# Format: name,protocol,direction,action,ip,mask,port_start,port_end\n\n");
    
    for (int i = 0; i < config->rule_count; i++) {
        FirewallRule *rule = &config->rules[i];
        
        const char *proto = "ALL";
        if (rule->protocol == PROTO_TCP) proto = "TCP";
        else if (rule->protocol == PROTO_UDP) proto = "UDP";
        else if (rule->protocol == PROTO_ICMP) proto = "ICMP";
        
        const char *dir = "BOTH";
        if (rule->direction == DIR_INBOUND) dir = "INBOUND";
        else if (rule->direction == DIR_OUTBOUND) dir = "OUTBOUND";
        
        const char *action = "DENY";
        if (rule->action == ACTION_ALLOW) action = "ALLOW";
        else if (rule->action == ACTION_LOG) action = "LOG";
        
        char ip_str[32] = "-";
        char mask_str[32] = "-";
        
        if (rule->has_ip_filter) {
            inet_ntop(AF_INET, &rule->ip_addr, ip_str, sizeof(ip_str));
            inet_ntop(AF_INET, &rule->ip_mask, mask_str, sizeof(mask_str));
        }
        
        fprintf(fp, "%s,%s,%s,%s,%s,%s,%d,%d\n",
                rule->name, proto, dir, action, ip_str, mask_str,
                rule->port_start, rule->port_end);
    }
    
    fclose(fp);
    
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Policy saved to %s", policy_file);
    log_firewall_event(config, log_msg);
    
    return 0;
}

/**
 * Get policy name as string
 */
const char* firewall_policy_name(FirewallPolicy policy) {
    switch (policy) {
        case FIREWALL_DISABLED: return "DISABLED";
        case FIREWALL_NO_NETWORK: return "NO_NETWORK";
        case FIREWALL_STRICT: return "STRICT";
        case FIREWALL_MODERATE: return "MODERATE";
        case FIREWALL_CUSTOM: return "CUSTOM";
        default: return "UNKNOWN";
    }
}
