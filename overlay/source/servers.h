#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SLPCFG_MAX_SERVERS 10
#define SLPCFG_NAME_MAX 32
#define SLPCFG_HOST_MAX 128

typedef struct {
    char name[SLPCFG_NAME_MAX];
    char host[SLPCFG_HOST_MAX];
    unsigned short port;
} SlpServer;

/*
 * Load servers from `path`. Up to SLPCFG_MAX_SERVERS entries are read;
 * excess lines are ignored. Returns the number of servers loaded (0 on
 * open/parse failure). Any previous list is replaced.
 */
int slpServersLoad(const char *path);

/*
 * Parse servers from an in-memory buffer (used by the sysmodule, which must
 * not use stdio in a boot2 context). Up to SLPCFG_MAX_SERVERS entries are
 * read; returns the number loaded.
 */
int slpServersParse(const char *text, size_t len);

/* Number of servers in the last loaded list. */
int slpServersCount(void);

/* Pointer to the server at `index`, or NULL if out of range. */
const SlpServer *slpServersGet(int index);

/* Index of the first server whose name matches, or -1. */
int slpServersFindByName(const char *name);

#ifdef __cplusplus
}
#endif
