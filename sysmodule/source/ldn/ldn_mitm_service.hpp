/*
 * sys-slp-client — ldn:u MITM service.
 *
 * M2: games that call ldn:u while the slp relay is connected get the real
 * LDN control plane (LdnICommunicationService / LdnControl) so local-wireless
 * titles talk to each other through the relay. When the relay is stopped,
 * ShouldMitm() returns false and the session is forwarded to the real ldn:u
 * service — stock local-wireless play keeps working untouched.
 */
#pragma once

#include <stratosphere.hpp>
#include "ldn_interfaces.hpp"
#include "slpcfg/slp_runtime.hpp"
#include "slpcfg/slp_trace.hpp"

namespace ams::slp::ldn {

    class LdnMitMService : public ams::sf::MitmServiceImplBase {
    public:
        LdnMitMService(std::shared_ptr<::Service> &&s, const ams::sm::MitmProcessInfo &c)
            : ams::sf::MitmServiceImplBase(std::forward<std::shared_ptr<::Service>>(s), c) {}

        /* Intercept ldn:u for real applications while the relay is connected;
         * otherwise the session is forwarded to the real service (stock
         * local-wireless behaviour, and homebrew / home menu are never
         * intercepted when the relay is stopped — which previously caused
         * black screens).
         *
         * Applies the same application check as BsdMitmService::ShouldMitm.
         * This guard had none: it intercepted ldn:u for EVERY process while
         * running, including qlaunch/Home menu and the Album (the applet
         * hbloader hijacks — 0x010000000000100D). LdnControl is a global
         * singleton shared across every accepted client, so an applet
         * touching ldn:u mid-session could clobber a game's CommState.
         *
         * Was a hand-rolled lower-bound-only compare (matching the same bug
         * already fixed in BsdMitmService::ShouldMitm -- this copy's own
         * comment claimed parity with that check but wasn't updated when it
         * was fixed). ams::ncm::IsApplicationId also enforces the upper
         * bound (ApplicationId::End) this never had. */
        static bool ShouldMitm(const ams::sm::MitmProcessInfo &client_info) {
            if (::slp::rt::GetRuntime().GetState() != SLPCFG_STATE_RUNNING)
                return false;

            return ams::ncm::IsApplicationId(client_info.program_id);
        }

        Result CreateUserLocalCommunicationService(
            ams::sf::Out<ams::sf::SharedPointer<ICommunicationInterface>> out);

        Result CreateClientProcessMonitor(
            ams::sf::Out<ams::sf::SharedPointer<IClientProcessMonitorInterface>> out);

        Result CreateLdnMitmConfigService(
            ams::sf::Out<ams::sf::SharedPointer<ILdnConfig>> out);
    };

    static_assert(IsILdnMitMService<LdnMitMService>);

}
