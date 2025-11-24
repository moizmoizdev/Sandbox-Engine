#ifndef FIREWALL_H
#define FIREWALL_H

#include <sys/types.h>
#include <netinet/in.h>

/* Firewall policy modes */
typedef enum {
    FIREWALL_DISABLED = 0,    /* No firewall, full network access */
    FIREWALL_NO_NETWORK,      /* Complete network isolation */
    FIREWALL_STRICT,          /* Whitelist only mode */
    FIREWALL_MODERATE,        /* Block dangerous ports, allow common services */
    FIREWALL_CUSTOM           /* User-defined rules */
} FirewallPolicy;

/* Network protocols */
typedef enum {
    PROTO_ALL = 0,
    PROTO_TCP = 6,
    PROTO_UDP = 17,
    PROTO_ICMP = 1
} NetworkProtocol;

/* Traffic direction */
typedef enum {
    DIR_INBOUND = 1,
    DIR_OUTBOUND = 2,
    DIR_BOTH = 3
} TrafficDirection;

/* Rule action */
typedef enum {
    ACTION_DENY = 0,
    ACTION_ALLOW = 1,
    ACTION_LOG = 2
} RuleAction;

/* Firewall rule structure */
typedef struct {
    char name[64];              /* Rule name/description */
    NetworkProtocol protocol;   /* Protocol to match */
    TrafficDirection direction; /* Traffic direction */
    RuleAction action;          /* Action to take */
    
    /* IP address filtering */
    int has_ip_filter;
    struct in_addr ip_addr;     /* IP address (IPv4) */
    struct in_addr ip_mask;     /* Network mask */
    
    /* Port filtering */
    int has_port_filter;
    uint16_t port_start;        /* Port range start */
    uint16_t port_end;          /* Port range end (0 = same as start) */
    
    int enabled;                /* Rule enabled flag */
} FirewallRule;

/* Firewall configuration */
typedef struct {
    FirewallPolicy policy;
    FirewallRule *rules;
    int rule_count;
    int max_rules;
    
    /* Statistics */
    unsigned long packets_allowed;
    unsigned long packets_denied;
    unsigned long bytes_allowed;
    unsigned long bytes_denied;
    
    /* Logging */
    int log_enabled;
    char log_file[256];
} FirewallConfig;

/**
 * Initialize firewall with specified policy
 * @param policy Firewall policy mode
 * @return Pointer to firewall config, NULL on error
 */
FirewallConfig* firewall_init(FirewallPolicy policy);

/**
 * Apply firewall rules to current process
 * This should be called after namespace setup and before executing sandboxed process
 * @param config Firewall configuration
 * @return 0 on success, -1 on error
 */
int firewall_apply(FirewallConfig *config);

/**
 * Add a firewall rule
 * @param config Firewall configuration
 * @param rule Rule to add
 * @return 0 on success, -1 on error
 */
int firewall_add_rule(FirewallConfig *config, const FirewallRule *rule);

/**
 * Remove a firewall rule by index
 * @param config Firewall configuration
 * @param index Rule index
 * @return 0 on success, -1 on error
 */
int firewall_remove_rule(FirewallConfig *config, int index);

/**
 * Load firewall policy from file
 * @param config Firewall configuration
 * @param policy_file Path to policy file
 * @return 0 on success, -1 on error
 */
int firewall_load_policy(FirewallConfig *config, const char *policy_file);

/**
 * Save firewall policy to file
 * @param config Firewall configuration
 * @param policy_file Path to policy file
 * @return 0 on success, -1 on error
 */
int firewall_save_policy(FirewallConfig *config, const char *policy_file);

/**
 * Get firewall statistics
 * @param config Firewall configuration
 * @param allowed Pointer to store allowed packet count
 * @param denied Pointer to store denied packet count
 */
void firewall_get_stats(FirewallConfig *config, unsigned long *allowed, unsigned long *denied);

/**
 * Enable/disable firewall logging
 * @param config Firewall configuration
 * @param enabled 1 to enable, 0 to disable
 * @param log_file Path to log file (NULL to use default)
 * @return 0 on success, -1 on error
 */
int firewall_set_logging(FirewallConfig *config, int enabled, const char *log_file);

/**
 * Cleanup and free firewall resources
 * @param config Firewall configuration
 */
void firewall_cleanup(FirewallConfig *config);

/**
 * Create a firewall rule
 * Helper function to easily create rules
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
);

/**
 * Apply seccomp filter to block network syscalls
 * Used for NO_NETWORK policy
 * @return 0 on success, -1 on error
 */
int firewall_block_network_syscalls(void);

/**
 * Get policy name as string
 * @param policy Firewall policy
 * @return Policy name
 */
const char* firewall_policy_name(FirewallPolicy policy);

#endif /* FIREWALL_H */
