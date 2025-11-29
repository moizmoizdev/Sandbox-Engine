#ifndef LANDLOCK_H
#define LANDLOCK_H

#include <sys/types.h>
#include <stdint.h>

/* Landlock policy modes */
typedef enum {
    LANDLOCK_DISABLED = 0,   /* No Landlock restrictions */
    LANDLOCK_STRICT,         /* Minimal access - only execution */
    LANDLOCK_MODERATE,       /* Allow read access to system dirs, block /tmp writes */
    LANDLOCK_PERMISSIVE,     /* Allow most reads, restrict writes */
    LANDLOCK_CUSTOM          /* User-defined rules */
} LandlockPolicy;

/* File access operations (matches Landlock access flags) */
#define LANDLOCK_ACCESS_FS_EXECUTE      (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE   (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE    (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR     (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR   (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE  (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR    (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR     (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG     (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK    (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO    (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK   (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM     (1ULL << 12)
#define LANDLOCK_ACCESS_FS_REFER        (1ULL << 13)
#define LANDLOCK_ACCESS_FS_TRUNCATE     (1ULL << 14)

/* Convenience combinations */
#define LANDLOCK_ACCESS_FS_READ    (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)
#define LANDLOCK_ACCESS_FS_WRITE   (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
                                    LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR)
#define LANDLOCK_ACCESS_FS_RW      (LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_WRITE)

/* Landlock file rule structure */
typedef struct {
    char path[512];           /* Absolute path to file/directory */
    uint64_t allowed_access;  /* Bitmask of allowed operations */
    int enabled;              /* Rule enabled flag */
} LandlockFileRule;

/* Landlock configuration */
typedef struct {
    LandlockPolicy policy;
    LandlockFileRule *rules;
    int rule_count;
    int max_rules;
    int enabled;              /* Is Landlock enabled? */
    char log_file[256];       /* Log file path */
} LandlockConfig;

/**
 * Initialize Landlock configuration with specified policy
 * @param policy Landlock policy mode
 * @return Pointer to config, NULL on error
 */
LandlockConfig* landlock_init(LandlockPolicy policy);

/**
 * Apply Landlock ruleset to current process
 * This MUST be called before any file system access in the child process
 * @param config Landlock configuration
 * @return 0 on success, -1 on error
 */
int landlock_apply(LandlockConfig *config);

/**
 * Add a file access rule
 * @param config Landlock configuration
 * @param path Absolute path to file/directory
 * @param access Bitmask of allowed access operations
 * @return 0 on success, -1 on error
 */
int landlock_add_rule(LandlockConfig *config, const char *path, uint64_t access);

/**
 * Check if Landlock is available on this system
 * @return 1 if available, 0 if not
 */
int landlock_is_available(void);

/**
 * Get policy name as string
 * @param policy Landlock policy
 * @return Policy name
 */
const char* landlock_policy_name(LandlockPolicy policy);

/**
 * Cleanup and free Landlock resources
 * @param config Landlock configuration
 */
void landlock_cleanup(LandlockConfig *config);

/**
 * Initialize preset rules for a policy
 * @param config Landlock configuration
 * @return 0 on success, -1 on error
 */
int landlock_init_preset_rules(LandlockConfig *config);

#endif /* LANDLOCK_H */

