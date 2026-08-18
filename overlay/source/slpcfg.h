#pragma once
#include <switch.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Client for the sys-slp-client config service "slp:cfg".
 *
 * IPC commands (see notes/slp-cfg-ipc.md — must match the sysmodule):
 *   65000 GetVersion          -> out buffer char[32]
 *   65001 GetState            -> out u32 state, out u32 sel_index, out buffer char[16] ip
 *   65002 SelectServer        -> in u32 index
 *   65003 Start
 *   65004 Stop
 *   65005 Reload
 *
 * state: 0 = stopped, 1 = running. sel_index: selected server in the list.
 */

typedef struct {
    Service s;
} SlpCfgService;

/* Returned by slpCfgGetConfig() when the "slp:cfg" service is not registered,
 * i.e. the sysmodule isn't installed / isn't running. Distinct from a real IPC
 * failure so the UI can show a helpful message instead of a raw error code.
 * Module_Libnx + LibnxError_NotFound is a safe, non-colliding choice. */
#define SLPCFG_RESULT_NOT_INSTALLED MAKERESULT(Module_Libnx, LibnxError_NotFound)

/* Connect to the "slp:cfg" named port.
 * Returns SLPCFG_RESULT_NOT_INSTALLED (without blocking) if the sysmodule is
 * not present -- see the comment in slpcfg.c for why that check matters. */
Result slpCfgGetConfig(SlpCfgService *out);

void slpCfgClose(SlpCfgService *s);

Result slpCfgGetVersion(SlpCfgService *s, char *version);              /* >= 32 bytes */
Result slpCfgGetState(SlpCfgService *s, u32 *state, u32 *selIndex, char *ip); /* ip >= 16 bytes */
Result slpCfgSelectServer(SlpCfgService *s, u32 index);
Result slpCfgStart(SlpCfgService *s);
Result slpCfgStop(SlpCfgService *s);
Result slpCfgReload(SlpCfgService *s);

#ifdef __cplusplus
}
#endif
