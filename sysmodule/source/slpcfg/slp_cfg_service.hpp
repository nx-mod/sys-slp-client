/*
 * sys-slp-client — slp:cfg IPC service.
 *
 * Standalone service (not a MITM) the Tesla overlay talks to. Registered at
 * boot, independent of any game, so the overlay can pick a server, start and
 * stop the relay connection, and read status whenever it wants.
 *
 * Commands (must match overlay/source/slpcfg.c — see notes/slp-cfg-ipc.md):
 *   65000 GetVersion          -> out buffer char[32]
 *   65001 GetState            -> out buffer u32, out buffer u32, out buffer char[16]
 *   65002 SelectServer        -> in  u32 index
 *   65003 Start
 *   65004 Stop
 *   65005 Reload
 */
#pragma once

#include <stratosphere.hpp>

namespace slp::ipc {

    class ConfigService {
    public:
        ams::Result GetVersion(const ams::sf::OutAutoSelectBuffer &version);
        ams::Result GetState(const ams::sf::OutAutoSelectBuffer &state,
                             const ams::sf::OutAutoSelectBuffer &sel_index,
                             const ams::sf::OutAutoSelectBuffer &ip);
        ams::Result SelectServer(u32 index);
        ams::Result Start();
        ams::Result Stop();
        ams::Result Reload();
    };

}

#define AMS_SLPCFG_SERVICE_INTERFACE(C, H)                                                                                        \
    AMS_SF_METHOD_INFO(C, H, 65000, ams::Result, GetVersion,   (const ams::sf::OutAutoSelectBuffer &version),   (version),        ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, 65001, ams::Result, GetState,     (const ams::sf::OutAutoSelectBuffer &state, const ams::sf::OutAutoSelectBuffer &sel_index, const ams::sf::OutAutoSelectBuffer &ip), (state, sel_index, ip), ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, 65002, ams::Result, SelectServer, (u32 index),                                          (index),          ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, 65003, ams::Result, Start,        (),                                                   (),               ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, 65004, ams::Result, Stop,         (),                                                   (),               ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, 65005, ams::Result, Reload,       (),                                                   (),               ams::hos::Version_Min, ams::hos::Version_Max)

AMS_SF_DEFINE_INTERFACE(slp::ipc, IConfigService, AMS_SLPCFG_SERVICE_INTERFACE, 0x534C5043 /* "SLPC" */)
