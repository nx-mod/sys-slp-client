/*
 * sys-slp-client — ldn:u MITM interfaces and LDN wire types.
 *
 * The full control-plane data path is implemented (LdnControl in
 * ldn_control.cpp/.hpp) and confirmed working on hardware, including against
 * a real public relay (tekn0.net) with no PC bridge -- three independent
 * games (Diablo III, Advance Wars, MK8DX wireless) create and register rooms
 * correctly. ldn:u traffic is only forwarded to the real service while the
 * relay client is stopped (see LdnMitMService::ShouldMitm) or for a system
 * applet (excluded by program_id floor) -- not as a development-stage
 * fallback.
 *
 * The interface definitions below mirror the official LDN user service.
 * Types are from the ldn_mitm project (Atmosphere-libs, GPL-2.0) and match
 * the real LDN IPC layout — do not reorder fields.
 */
#pragma once

#include <cstdint>
#include <stratosphere.hpp>

/* NOTE: namespace must be nested under ams so Atmosphere's generated sf code
 * resolves unqualified Result/hos to ams::Result/ams::hos (see ldn_mitm). */
namespace ams::slp::ldn {

    constexpr size_t SsidLengthMax = 32;
    constexpr size_t AdvertiseDataSizeMax = 384;
    constexpr size_t UserNameBytesMax = 32;
    constexpr size_t PassphraseLengthMax = 64;
    constexpr int NodeCountMax = 8;

    enum class CommState {
        None,
        Initialized,
        AccessPoint,
        AccessPointCreated,
        Station,
        StationConnected,
        Error
    };

    struct MacAddress {
        uint8_t raw[6];
    };

    struct Ssid {
        uint8_t length;
        char raw[SsidLengthMax + 1];
    };

    struct CommonNetworkInfo {
        MacAddress bssid;
        Ssid ssid;
        int16_t channel;
        int8_t linkLevel;
        uint8_t networkType;
        uint32_t _unk;
    };

    struct NodeInfo {
        uint32_t ipv4Address;
        MacAddress macAddress;
        int8_t nodeId;
        int8_t isConnected;
        char userName[UserNameBytesMax + 1];
        uint8_t _unk1;
        int16_t localCommunicationVersion;
        uint8_t _unk2[16];
    };

    struct LdnNetworkInfo {
        uint8_t unkRandom[16];
        uint16_t securityMode;
        uint8_t stationAcceptPolicy;
        uint8_t _unk1[3];
        uint8_t nodeCountMax;
        uint8_t nodeCount;
        NodeInfo nodes[NodeCountMax];
        uint16_t _unk2;
        uint16_t advertiseDataSize;
        uint8_t advertiseData[AdvertiseDataSizeMax];
        uint8_t _unk3[148];
    };

    struct IntentId {
        uint64_t localCommunicationId;
        uint8_t _unk1[2];
        uint16_t sceneId;
        uint8_t _unk2[4];
    };

    struct SessionId {
        uint64_t high;
        uint64_t low;
    };

    struct NetworkId {
        IntentId intentId;    /* 16 bytes */
        SessionId sessionId;  /* 16 bytes */
    };

    struct NetworkInfo : ams::sf::LargeData {
        NetworkId networkId;
        CommonNetworkInfo common;
        LdnNetworkInfo ldn;
    };

    struct SecurityConfig {
        uint16_t securityMode;
        uint16_t passphraseSize;
        uint8_t passphrase[PassphraseLengthMax];
    };

    struct UserConfig {
        char userName[UserNameBytesMax + 1];
        uint8_t _unk[15];
    };

    struct NetworkConfig {
        IntentId intentId;      /* 16 bytes */
        uint16_t channel;
        uint8_t nodeCountMax;
        uint8_t _unk1;
        uint16_t localCommunicationVersion;
        uint8_t _unk2[10];
    };

    struct CreateNetworkConfig {
        SecurityConfig securityConfig;
        UserConfig userConfig;
        uint8_t _unk[4];
        NetworkConfig networkConfig;
    };

    struct ConnectNetworkData {
        SecurityConfig securityConfig;
        UserConfig userConfig;
        uint32_t localCommunicationVersion;
        uint32_t option;
    };

    struct NodeLatestUpdate : ams::sf::PrefersPointerTransferMode {
        uint8_t stateChange;
        uint8_t _unk[7];
    };

    struct SecurityParameter {
        uint8_t unkRandom[16];
        SessionId sessionId;
    };

    struct ScanFilter {
        NetworkId networkId;
        uint32_t networkType;
        MacAddress bssid;
        Ssid ssid;
        uint8_t unk[16];
        uint32_t flag;
    };

}

/* ICommunicationInterface — the per-game LDN user service object. */
#define AMS_SLP_LDN_ICOMMUNICATION(C, H)                                                                                              \
    AMS_SF_METHOD_INFO(C, H, 0,   Result, GetState,                  (ams::sf::Out<u32> state),                                              (state))                \
    AMS_SF_METHOD_INFO(C, H, 1,   Result, GetNetworkInfo,            (ams::sf::Out<ams::slp::ldn::NetworkInfo> buffer),                          (buffer))               \
    AMS_SF_METHOD_INFO(C, H, 2,   Result, GetIpv4Address,            (ams::sf::Out<u32> address, ams::sf::Out<u32> mask),                    (address, mask))         \
    AMS_SF_METHOD_INFO(C, H, 3,   Result, GetDisconnectReason,       (ams::sf::Out<u32> reason),                                             (reason))               \
    AMS_SF_METHOD_INFO(C, H, 4,   Result, GetSecurityParameter,      (ams::sf::Out<ams::slp::ldn::SecurityParameter> out),                        (out))                  \
    AMS_SF_METHOD_INFO(C, H, 5,   Result, GetNetworkConfig,          (ams::sf::Out<ams::slp::ldn::NetworkConfig> out),                            (out))                  \
    AMS_SF_METHOD_INFO(C, H, 100, Result, AttachStateChangeEvent,    (ams::sf::Out<ams::sf::CopyHandle> handle),                             (handle))               \
    AMS_SF_METHOD_INFO(C, H, 101, Result, GetNetworkInfoLatestUpdate,(ams::sf::Out<ams::slp::ldn::NetworkInfo> buffer, ams::sf::OutArray<ams::slp::ldn::NodeLatestUpdate> pUpdates), (buffer, pUpdates)) \
    AMS_SF_METHOD_INFO(C, H, 102, Result, Scan,                      (ams::sf::Out<u32> count, ams::sf::OutAutoSelectArray<ams::slp::ldn::NetworkInfo> buffer, u16 channel, ams::slp::ldn::ScanFilter filter), (count, buffer, channel, filter)) \
    AMS_SF_METHOD_INFO(C, H, 200, Result, OpenAccessPoint,           (),                                                                   ())                     \
    AMS_SF_METHOD_INFO(C, H, 201, Result, CloseAccessPoint,          (),                                                                   ())                     \
    AMS_SF_METHOD_INFO(C, H, 202, Result, CreateNetwork,             (ams::slp::ldn::CreateNetworkConfig data),                                  (data))                 \
    AMS_SF_METHOD_INFO(C, H, 204, Result, DestroyNetwork,            (),                                                                   ())                     \
    AMS_SF_METHOD_INFO(C, H, 206, Result, SetAdvertiseData,          (ams::sf::InAutoSelectBuffer data),                                    (data))                 \
    AMS_SF_METHOD_INFO(C, H, 300, Result, OpenStation,               (),                                                                   ())                     \
    AMS_SF_METHOD_INFO(C, H, 301, Result, CloseStation,              (),                                                                   ())                     \
    AMS_SF_METHOD_INFO(C, H, 302, Result, Connect,                   (ams::slp::ldn::ConnectNetworkData dat, const ams::slp::ldn::NetworkInfo &data), (dat, data))             \
    AMS_SF_METHOD_INFO(C, H, 304, Result, Disconnect,                (),                                                                   ())                     \
    AMS_SF_METHOD_INFO(C, H, 400, Result, Initialize,                (const ams::sf::ClientProcessId &client_process_id),                    (client_process_id))    \
    AMS_SF_METHOD_INFO(C, H, 401, Result, Finalize,                  (),                                                                   ())                     \
    AMS_SF_METHOD_INFO(C, H, 402, Result, InitializeSystem2,         (u64 unk, const ams::sf::ClientProcessId &client_process_id),           (unk, client_process_id))

AMS_SF_DEFINE_INTERFACE(ams::slp::ldn, ICommunicationInterface, AMS_SLP_LDN_ICOMMUNICATION, 0x85280DC3)

/* IClientProcessMonitorInterface — required by firmware 18.0.0+ games. */
#define AMS_SLP_LDN_CLIENT_PROCESS_MONITOR(C, H) \
    AMS_SF_METHOD_INFO(C, H, 0, Result, RegisterClient, (const ams::sf::ClientProcessId &client_process_id), (client_process_id))

AMS_SF_DEFINE_INTERFACE(ams::slp::ldn, IClientProcessMonitorInterface, AMS_SLP_LDN_CLIENT_PROCESS_MONITOR, 0x4EF8C3F3)

/* ILdnConfig — compatibility with the ldn_mitm plugin config commands. */
namespace ams::slp::ldn {
    struct LdnMitmVersion {
        char raw[32];
    };
}

#define AMS_SLP_LDN_CONFIG(C, H)                                                                                 \
    AMS_SF_METHOD_INFO(C, H, 65001, Result, GetVersion, (ams::sf::Out<ams::slp::ldn::LdnMitmVersion> version), (version)) \
    AMS_SF_METHOD_INFO(C, H, 65005, Result, SetEnabled, (u32 enabled),                                          (enabled))

AMS_SF_DEFINE_INTERFACE(ams::slp::ldn, ILdnConfig, AMS_SLP_LDN_CONFIG, 0x14c8af2c)

/* ILdnMitMService — the service sm exposes to redirect ldn:u. */
#define AMS_SLP_LDN_MITM_SERVICE(C, H)                                                                                        \
    AMS_SF_METHOD_INFO(C, H, 0,     Result, CreateUserLocalCommunicationService, (ams::sf::Out<ams::sf::SharedPointer<ams::slp::ldn::ICommunicationInterface>> out),      (out)) \
    AMS_SF_METHOD_INFO(C, H, 1,     Result, CreateClientProcessMonitor,           (ams::sf::Out<ams::sf::SharedPointer<ams::slp::ldn::IClientProcessMonitorInterface>> out), (out)) \
    AMS_SF_METHOD_INFO(C, H, 65000, Result, CreateLdnMitmConfigService,           (ams::sf::Out<ams::sf::SharedPointer<ams::slp::ldn::ILdnConfig>> out),                    (out))

AMS_SF_DEFINE_MITM_INTERFACE(ams::slp::ldn, ILdnMitMService, AMS_SLP_LDN_MITM_SERVICE, 0x1D8F875E)
