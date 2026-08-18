#include "slp_cfg_service.hpp"
#include "slp_runtime.hpp"

#include <cstring>

namespace slp::ipc {

    namespace {

        constexpr const char *Version = "0.1.0";

        void copy_ip(const ams::sf::OutAutoSelectBuffer &out, const char *ip) {
            char buf[16];
            std::memset(buf, 0, sizeof(buf));
            std::strncpy(buf, ip, sizeof(buf) - 1);
            size_t n = out.GetSize();
            if (n > sizeof(buf))
                n = sizeof(buf);
            std::memcpy(out.GetPointer(), buf, n);
        }

    }

    ams::Result ConfigService::GetVersion(const ams::sf::OutAutoSelectBuffer &version) {
        const size_t n = version.GetSize();
        char buf[32];
        std::memset(buf, 0, sizeof(buf));
        std::strncpy(buf, Version, sizeof(buf) - 1);
        std::memcpy(version.GetPointer(), buf, n < sizeof(buf) ? n : sizeof(buf));
        R_SUCCEED();
    }

    ams::Result ConfigService::GetState(const ams::sf::OutAutoSelectBuffer &state,
                                        const ams::sf::OutAutoSelectBuffer &sel_index,
                                        const ams::sf::OutAutoSelectBuffer &ip) {
        auto &rt = slp::rt::GetRuntime();

        u32 st = (u32)rt.GetState();
        u32 sel = (u32)rt.GetSelectedIndex();
        copy_ip(ip, rt.GetIp());

        std::memcpy(state.GetPointer(), std::addressof(st), sizeof(st));
        std::memcpy(sel_index.GetPointer(), std::addressof(sel), sizeof(sel));
        R_SUCCEED();
    }

    ams::Result ConfigService::SelectServer(u32 index) {
        auto &rt = slp::rt::GetRuntime();
        R_UNLESS(rt.SelectServer(index), ams::sf::hipc::ResultInvalidRequestSize());
        R_SUCCEED();
    }

    ams::Result ConfigService::Start() {
        auto &rt = slp::rt::GetRuntime();
        R_UNLESS(rt.Start(), ams::sf::hipc::ResultInvalidRequestSize());
        R_SUCCEED();
    }

    ams::Result ConfigService::Stop() {
        slp::rt::GetRuntime().Stop();
        R_SUCCEED();
    }

    ams::Result ConfigService::Reload() {
        slp::rt::GetRuntime().ReloadServers();
        R_SUCCEED();
    }

}
