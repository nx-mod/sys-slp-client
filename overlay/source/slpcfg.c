#include "slpcfg.h"

enum {
    SlpCfgCmdGetVersion        = 65000,
    SlpCfgCmdGetState          = 65001,
    SlpCfgCmdSelect            = 65002,
    SlpCfgCmdStart             = 65003,
    SlpCfgCmdStop              = 65004,
    SlpCfgCmdReload            = 65005,
};

static const u32 BufferOut = SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out;

/* Atmosphere sm extension: AtmosphereHasService (cmd 65100) -- asks whether a
 * service name is registered WITHOUT blocking. libnx does not wrap this (it's
 * an Atmosphere addition, not stock Horizon), so dispatch it by hand.
 *
 * sm switched from CMIF to TIPC serialization in 12.0.0, and libnx exposes a
 * separate session accessor for each, so pick the right one for the running
 * firmware -- getting this wrong yields a bogus result rather than an error. */
static Result slpAtmosphereHasService(bool *out, SmServiceName name) {
    u8 tmp = 0;
    Result rc;

    if (hosversionAtLeast(12, 0, 0))
        rc = tipcDispatchInOut(smGetServiceSessionTipc(), 65100, name, tmp);
    else
        rc = serviceDispatchInOut(smGetServiceSession(), 65100, name, tmp);

    if (R_SUCCEEDED(rc))
        *out = (tmp != 0);
    return rc;
}

Result slpCfgGetConfig(SlpCfgService *out) {
    /* IMPORTANT: do NOT call smGetService() straight away. On Horizon, asking
     * sm for a service name that is not registered does not fail -- it BLOCKS
     * until someone registers it. With sys-slp-client not installed (or not
     * yet started), that hangs the overlay forever inside doWithSmSession(),
     * which looks to the user like the overlay crashing on open.
     *
     * slpAtmosphereHasService() (above) uses the Atmosphere sm extension that answers the
     * "is it registered?" question without blocking. We are always running
     * under Atmosphere here (this is a Tesla overlay for an Atmosphere
     * sysmodule), so it is safe to rely on it. */
    bool has_service = false;
    Result rc = slpAtmosphereHasService(&has_service, smEncodeName("slp:cfg"));
    if (R_FAILED(rc))
        return rc;

    if (!has_service)
        return SLPCFG_RESULT_NOT_INSTALLED;

    return smGetService(&out->s, "slp:cfg");
}

void slpCfgClose(SlpCfgService *s) {
    serviceClose(&s->s);
}

Result slpCfgGetVersion(SlpCfgService *s, char *version) {
    return serviceDispatch(&s->s, SlpCfgCmdGetVersion,
        .buffer_attrs = { BufferOut },
        .buffers = { { version, 32 } },
    );
}

Result slpCfgGetState(SlpCfgService *s, u32 *state, u32 *selIndex, char *ip) {
    return serviceDispatch(&s->s, SlpCfgCmdGetState,
        .buffer_attrs = { BufferOut, BufferOut, BufferOut },
        .buffers = { { state, sizeof(*state) }, { selIndex, sizeof(*selIndex) }, { ip, 16 } },
    );
}

Result slpCfgSelectServer(SlpCfgService *s, u32 index) {
    return serviceDispatchIn(&s->s, SlpCfgCmdSelect, index);
}

Result slpCfgStart(SlpCfgService *s) {
    return serviceDispatch(&s->s, SlpCfgCmdStart);
}

Result slpCfgStop(SlpCfgService *s) {
    return serviceDispatch(&s->s, SlpCfgCmdStop);
}

Result slpCfgReload(SlpCfgService *s) {
    return serviceDispatch(&s->s, SlpCfgCmdReload);
}
