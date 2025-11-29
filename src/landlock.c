/**
 * Landlock LSM Implementation
 * 
 * Provides fine-grained file access control using Linux Landlock LSM
 * to restrict sandboxed processes from accessing files outside allowed paths.
 */

#define _GNU_SOURCE
#include "landlock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/limits.h>
#include <stdint.h>

/* Include landlock.h if available - may not be present on older systems */
#include <linux/landlock.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif

#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif

#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

/* Landlock rule types */
#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 1
#endif

/* Structures should be defined in linux/landlock.h */

/* Default maximum rules */
#define DEFAULT_MAX_RULES 50
#define LANDLOCK_ABI_VERSION 3

/* Helper to check if path is absolute */
static int is_absolute_path(const char *path) {
    return path && path[0] == '/';
}

/**
 * Check if Landlock is available on this system
 */
int landlock_is_available(void) {
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE |
                             LANDLOCK_ACCESS_FS_WRITE_FILE |
                             LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_FILE |
                             LANDLOCK_ACCESS_FS_MAKE_CHAR |
                             LANDLOCK_ACCESS_FS_MAKE_DIR |
                             LANDLOCK_ACCESS_FS_MAKE_REG |
                             LANDLOCK_ACCESS_FS_MAKE_SOCK |
                             LANDLOCK_ACCESS_FS_MAKE_FIFO |
                             LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                             LANDLOCK_ACCESS_FS_MAKE_SYM |
                             LANDLOCK_ACCESS_FS_REFER |
                             LANDLOCK_ACCESS_FS_TRUNCATE,
    };
    
    int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        return 0; /* Landlock not available */
    }
    close(ruleset_fd);
    return 1;
}

/**
 * Initialize Landlock configuration with specified policy
 */
LandlockConfig* landlock_init(LandlockPolicy policy) {
    LandlockConfig *config = calloc(1, sizeof(LandlockConfig));
    if (!config) {
        return NULL;
    }
    
    config->policy = policy;
    config->max_rules = DEFAULT_MAX_RULES;
    config->rule_count = 0;
    config->enabled = (policy != LANDLOCK_DISABLED);
    config->rules = calloc(config->max_rules, sizeof(LandlockFileRule));
    
    if (!config->rules) {
        free(config);
        return NULL;
    }
    
    strncpy(config->log_file, "/tmp/sandbox_landlock.log", sizeof(config->log_file) - 1);
    
    /* Initialize preset rules if not custom */
    if (policy != LANDLOCK_DISABLED && policy != LANDLOCK_CUSTOM) {
        if (landlock_init_preset_rules(config) < 0) {
            fprintf(stderr, "Warning: Failed to initialize preset Landlock rules\n");
        }
    }
    
    return config;
}

/**
 * Add a file access rule
 */
int landlock_add_rule(LandlockConfig *config, const char *path, uint64_t access) {
    if (!config || !path) {
        return -1;
    }
    
    if (!is_absolute_path(path)) {
        fprintf(stderr, "Error: Landlock paths must be absolute: %s\n", path);
        return -1;
    }
    
    if (config->rule_count >= config->max_rules) {
        /* Expand rules array */
        int new_max = config->max_rules * 2;
        LandlockFileRule *new_rules = realloc(config->rules, new_max * sizeof(LandlockFileRule));
        if (!new_rules) {
            return -1;
        }
        config->rules = new_rules;
        config->max_rules = new_max;
        /* Clear new space */
        memset(&config->rules[config->rule_count], 0, 
               (new_max - config->rule_count) * sizeof(LandlockFileRule));
    }
    
    LandlockFileRule *rule = &config->rules[config->rule_count];
    strncpy(rule->path, path, sizeof(rule->path) - 1);
    rule->path[sizeof(rule->path) - 1] = '\0';
    rule->allowed_access = access;
    rule->enabled = 1;
    config->rule_count++;
    
    return 0;
}

/**
 * Initialize preset rules for STRICT policy
 */
static int init_strict_rules(LandlockConfig *config) {
    /* STRICT: Only allow execution of the program itself and reading libraries */
    /* Allow reading and executing from library directories (needed for dynamic linker) */
    if (landlock_add_rule(config, "/usr/lib", LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE) < 0) return -1;
    if (landlock_add_rule(config, "/lib", LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE) < 0) return -1;
    if (landlock_add_rule(config, "/lib64", LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE) < 0) return -1;
    if (landlock_add_rule(config, "/usr/lib64", LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE) < 0) return -1;
    
    /* Allow execution from system library directories (includes dynamic linker) */
    /* Note: The above /lib64 rule already covers ld-linux-x86-64.so.2 */
    if (landlock_add_rule(config, "/lib/x86_64-linux-gnu", 
                         LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE) < 0) {
        /* Might not exist on all systems, that's OK */
    }
    
    /* Note: The actual program directory is added by caller with EXECUTE permission */
    return 0;
}

/**
 * Initialize preset rules for MODERATE policy
 */
static int init_moderate_rules(LandlockConfig *config) {
    /* MODERATE: Allow read access to system dirs, block writes to /tmp */
    if (landlock_add_rule(config, "/usr", LANDLOCK_ACCESS_FS_READ) < 0) return -1;
    if (landlock_add_rule(config, "/lib", LANDLOCK_ACCESS_FS_READ) < 0) return -1;
    if (landlock_add_rule(config, "/lib64", LANDLOCK_ACCESS_FS_READ) < 0) return -1;
    if (landlock_add_rule(config, "/etc", LANDLOCK_ACCESS_FS_READ) < 0) return -1;
    if (landlock_add_rule(config, "/bin", LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_EXECUTE) < 0) return -1;
    if (landlock_add_rule(config, "/usr/bin", LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_EXECUTE) < 0) return -1;
    /* Explicitly deny /tmp writes by not adding it */
    return 0;
}

/**
 * Initialize preset rules for PERMISSIVE policy
 */
static int init_permissive_rules(LandlockConfig *config) {
    /* PERMISSIVE: Allow reads from most system paths, restrict writes */
    if (landlock_add_rule(config, "/usr", LANDLOCK_ACCESS_FS_READ) < 0) return -1;
    if (landlock_add_rule(config, "/lib", LANDLOCK_ACCESS_FS_READ) < 0) return -1;
    if (landlock_add_rule(config, "/lib64", LANDLOCK_ACCESS_FS_READ) < 0) return -1;
    if (landlock_add_rule(config, "/etc", LANDLOCK_ACCESS_FS_READ) < 0) return -1;
    if (landlock_add_rule(config, "/bin", LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_EXECUTE) < 0) return -1;
    if (landlock_add_rule(config, "/usr/bin", LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_EXECUTE) < 0) return -1;
    if (landlock_add_rule(config, "/opt", LANDLOCK_ACCESS_FS_READ) < 0) return -1;
    /* Allow limited write to a specific temp location if needed */
    /* Block general /tmp writes by not adding /tmp with write access */
    return 0;
}

/**
 * Initialize preset rules based on policy
 */
int landlock_init_preset_rules(LandlockConfig *config) {
    if (!config) {
        return -1;
    }
    
    switch (config->policy) {
        case LANDLOCK_STRICT:
            return init_strict_rules(config);
        case LANDLOCK_MODERATE:
            return init_moderate_rules(config);
        case LANDLOCK_PERMISSIVE:
            return init_permissive_rules(config);
        case LANDLOCK_DISABLED:
        case LANDLOCK_CUSTOM:
        default:
            return 0; /* No preset rules */
    }
}

/**
 * Apply Landlock ruleset to current process
 */
int landlock_apply(LandlockConfig *config) {
    if (!config || !config->enabled || config->policy == LANDLOCK_DISABLED) {
        return 0; /* Not an error - just disabled */
    }
    
    if (!landlock_is_available()) {
        fprintf(stderr, "Warning: Landlock is not available on this system (requires Linux 5.13+)\n");
        return -1;
    }
    
    if (config->rule_count == 0) {
        fprintf(stderr, "Warning: No Landlock rules defined\n");
        return -1;
    }
    
    /* Create ruleset */
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE |
                             LANDLOCK_ACCESS_FS_WRITE_FILE |
                             LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_FILE |
                             LANDLOCK_ACCESS_FS_MAKE_CHAR |
                             LANDLOCK_ACCESS_FS_MAKE_DIR |
                             LANDLOCK_ACCESS_FS_MAKE_REG |
                             LANDLOCK_ACCESS_FS_MAKE_SOCK |
                             LANDLOCK_ACCESS_FS_MAKE_FIFO |
                             LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                             LANDLOCK_ACCESS_FS_MAKE_SYM |
                             LANDLOCK_ACCESS_FS_REFER |
                             LANDLOCK_ACCESS_FS_TRUNCATE,
    };
    
    int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        perror("landlock_create_ruleset");
        return -1;
    }
    
    /* Add all rules */
    for (int i = 0; i < config->rule_count; i++) {
        if (!config->rules[i].enabled) {
            continue;
        }
        
        /* Open the path */
        int path_fd = open(config->rules[i].path, O_PATH | O_CLOEXEC);
        if (path_fd < 0) {
            fprintf(stderr, "Warning: Cannot open path for Landlock rule: %s (%s)\n",
                    config->rules[i].path, strerror(errno));
            continue; /* Skip this rule but continue */
        }
        
        /* Add rule */
        struct landlock_path_beneath_attr path_attr = {
            .allowed_access = config->rules[i].allowed_access,
            .parent_fd = path_fd,
        };
        
        int ret = syscall(__NR_landlock_add_rule, ruleset_fd,
                         LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);
        close(path_fd);
        
        if (ret < 0) {
            fprintf(stderr, "Warning: Failed to add Landlock rule for %s: %s\n",
                    config->rules[i].path, strerror(errno));
            close(ruleset_fd);
            return -1;
        }
    }
    
    /* Restrict this process */
    int ret = syscall(__NR_landlock_restrict_self, ruleset_fd, 0);
    close(ruleset_fd);
    
    if (ret < 0) {
        fprintf(stderr, "ERROR: landlock_restrict_self failed: %s\n", strerror(errno));
        perror("landlock_restrict_self");
        return -1;
    }
    
    printf("Landlock ruleset applied successfully (%d rules)\n", config->rule_count);
    printf("Landlock is now active - only explicitly allowed paths are accessible\n");
    return 0;
}

/**
 * Get policy name as string
 */
const char* landlock_policy_name(LandlockPolicy policy) {
    switch (policy) {
        case LANDLOCK_DISABLED:
            return "Disabled";
        case LANDLOCK_STRICT:
            return "Strict";
        case LANDLOCK_MODERATE:
            return "Moderate";
        case LANDLOCK_PERMISSIVE:
            return "Permissive";
        case LANDLOCK_CUSTOM:
            return "Custom";
        default:
            return "Unknown";
    }
}

/**
 * Cleanup and free Landlock resources
 */
void landlock_cleanup(LandlockConfig *config) {
    if (!config) {
        return;
    }
    
    if (config->rules) {
        free(config->rules);
        config->rules = NULL;
    }
    
    free(config);
}

