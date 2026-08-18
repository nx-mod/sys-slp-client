#include "servers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static SlpServer g_servers[SLPCFG_MAX_SERVERS];
static int g_count = 0;

static void trim(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' || s[len - 1] == ' ' || s[len - 1] == '\t'))
        s[--len] = '\0';
}

/* Parse one line into a server entry. Returns 1 on success, 0 to skip. */
static int parse_line(char *line, SlpServer *srv) {
    char *comment = strchr(line, '#');
    if (comment != NULL)
        *comment = '\0';
    trim(line);
    if (line[0] == '\0')
        return 0;

    char name[SLPCFG_NAME_MAX];
    char host[SLPCFG_HOST_MAX];
    char portstr[8];
    char user[SLPCFG_USER_MAX];
    char pass[SLPCFG_PASS_MAX];
    long port = 11451;

    user[0] = '\0';
    pass[0] = '\0';

    /* Accepted forms. Credentials are optional and only matter for relays that
     * require a login (they send an AUTH_ME 0x04 challenge and forward nothing
     * to peers that never answer it):
     *
     *   name host port user pass
     *   name host:port user pass
     *   name host port
     *   name host:port
     *
     * Try the longest form first so a 5-token line is not read as 3 tokens. */
    int nf = sscanf(line, "%31s %127s %7s %63s %63s",
                    name, host, portstr, user, pass);

    if (nf >= 3 && portstr[0] >= '0' && portstr[0] <= '9') {
        /* "name host port [user [pass]]" */
        port = strtol(portstr, NULL, 10);
        if (nf < 4) user[0] = '\0';
        if (nf < 5) pass[0] = '\0';
    } else {
        /* Third token absent or non-numeric, so the port (if any) is glued to
         * the host and that token is the username:
         * "name host[:port] [user [pass]]" */
        user[0] = '\0';
        pass[0] = '\0';
        nf = sscanf(line, "%31s %127s %63s %63s", name, host, user, pass);
        if (nf < 2)
            return 0;
        if (nf < 3) user[0] = '\0';
        if (nf < 4) pass[0] = '\0';

        char *colon = strrchr(host, ':');
        if (colon != NULL) {
            *colon = '\0';
            port = strtol(colon + 1, NULL, 10);
        }
    }

    if (port < 1 || port > 65535)
        return 0;

    memset(srv, 0, sizeof(*srv));
    strncpy(srv->name, name, sizeof(srv->name) - 1);
    strncpy(srv->host, host, sizeof(srv->host) - 1);
    strncpy(srv->username, user, sizeof(srv->username) - 1);
    strncpy(srv->password, pass, sizeof(srv->password) - 1);
    srv->port = (unsigned short)port;
    return 1;
}

int slpServersParse(const char *text, size_t len) {
    int n = 0;
    const char *p = text;
    const char *end = text + len;

    while (n < SLPCFG_MAX_SERVERS && p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t linelen = nl != NULL ? (size_t)(nl - p) : (size_t)(end - p);

        char line[SLPCFG_NAME_MAX + SLPCFG_HOST_MAX + 8];
        size_t copy = linelen < sizeof(line) - 1 ? linelen : sizeof(line) - 1;
        memcpy(line, p, copy);
        line[copy] = '\0';

        SlpServer srv;
        if (parse_line(line, &srv))
            g_servers[n++] = srv;

        if (nl == NULL)
            break;
        p = nl + 1;
    }

    g_count = n;
    return g_count;
}

int slpServersLoad(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return 0;

    static char buf[SLPCFG_MAX_SERVERS * (SLPCFG_NAME_MAX + SLPCFG_HOST_MAX + 8)];
    size_t used = 0;
    size_t chunk;

    while (used < sizeof(buf) - 1 && (chunk = fread(buf + used, 1, sizeof(buf) - 1 - used, f)) > 0)
        used += chunk;

    fclose(f);
    buf[used] = '\0';
    return slpServersParse(buf, used);
}

int slpServersCount(void) {
    return g_count;
}

const SlpServer *slpServersGet(int index) {
    if (index < 0 || index >= g_count)
        return NULL;
    return &g_servers[index];
}

int slpServersFindByName(const char *name) {
    for (int i = 0; i < g_count; i++) {
        if (strcmp(g_servers[i].name, name) == 0)
            return i;
    }
    return -1;
}
