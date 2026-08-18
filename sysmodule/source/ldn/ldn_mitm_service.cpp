#include "ldn_mitm_service.hpp"

#include "ldn_icommunication.hpp"
#include "slpcfg/slp_trace.hpp"

#include <cstring>

namespace ams::slp::ldn {

    Result LdnMitMService::CreateUserLocalCommunicationService(
        ams::sf::Out<ams::sf::SharedPointer<ICommunicationInterface>> out) {
        ::slp::dbg::Trace("ldn: CreateUserLocalCommunicationService (slp stack)");
        out.SetValue(ams::sf::CreateSharedObjectEmplaced<ICommunicationInterface,
                                                          LdnICommunicationService>());
        R_SUCCEED();
    }

    namespace {

        /* Structurally-typed impl (no interface inheritance) so the sf object
         * factory doesn't produce an ambiguous diamond, matching ldn_mitm. */
        class ClientProcessMonitor {
        public:
            Result RegisterClient(const ams::sf::ClientProcessId &client_process_id) {
                AMS_UNUSED(client_process_id);
                ::slp::dbg::Trace("ldn: RegisterClient pid=0x%lx",
                           static_cast<unsigned long>(client_process_id.process_id.value));
                /* M2: accept. Game tracking (for the bsd:u session policy)
                 * lands with the LDN session bookkeeping. */
                R_SUCCEED();
            }
        };

        static_assert(IsIClientProcessMonitorInterface<ClientProcessMonitor>);

    }

    Result LdnMitMService::CreateClientProcessMonitor(
        ams::sf::Out<ams::sf::SharedPointer<IClientProcessMonitorInterface>> out) {
        ::slp::dbg::Trace("ldn: CreateClientProcessMonitor");
        out.SetValue(ams::sf::CreateSharedObjectEmplaced<IClientProcessMonitorInterface,
                                                          ClientProcessMonitor>());
        R_SUCCEED();
    }

    namespace {

        class LdnConfig {
        public:
            Result GetVersion(ams::sf::Out<LdnMitmVersion> version) {
                std::memset(version->raw, 0, sizeof(version->raw));
                std::memcpy(version->raw, "slp 0.1.0", 9);
                R_SUCCEED();
            }

            Result SetEnabled(u32 enabled) {
                AMS_UNUSED(enabled);
                R_SUCCEED();
            }
        };

        static_assert(IsILdnConfig<LdnConfig>);

    }

    Result LdnMitMService::CreateLdnMitmConfigService(
        ams::sf::Out<ams::sf::SharedPointer<ILdnConfig>> out) {
        out.SetValue(ams::sf::CreateSharedObjectEmplaced<ILdnConfig, LdnConfig>());
        R_SUCCEED();
    }

}
