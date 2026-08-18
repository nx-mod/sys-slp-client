#include "lan_addr_map.hpp"
#include "slpcfg/slp_trace.hpp"

namespace slp::netmap {

    namespace {
        u32 g_real_addr = 0;    /* console's real IP,   Ryujinx format */
        u32 g_real_mask = 0;    /* console's real mask, Ryujinx format */

        u32 RealNet()   { return g_real_addr & g_real_mask; }
        u32 RealBcast() { return RealNet() | ~g_real_mask; }
    }

    /* Master switch. OFF = pure forwarding, exactly like ldn_mitm + the
     * switch-lan-play PC client, which do NO address translation at all.
     *
     * Translation was added on the theory that MK8DX rejected the browse reply
     * for arriving off-subnet. That theory predates the real discovery: MK8DX's
     * own crash reports show its LAN thread (enl::TaskThread) was being ABORTED
     * by our nifm MITM (nifm::GetUserServiceSharedPointer ->
     * CmifProxyFactory<IStaticService>), which is now removed. The "rejection"
     * was very likely that abort all along.
     *
     * Rewriting addresses is not free: every protocol layer that derives a
     * crypto nonce from an address (the browse challenge, the Pia session) is
     * corrupted by it -- we already had to special-case broadcasts to stop
     * breaking the challenge MAC. Forward faithfully first; only reintroduce
     * translation if a real on-hardware test proves it is needed. */
    /* OFF -- and it must stay off until something disproves this.
     *
     * The LAN lobby was SEEN WORKING ON HARDWARE before lan_addr_map existed at
     * all. Translation is therefore not required to make a room list, and
     * turning it on moves away from the only configuration ever observed to
     * work. Do not re-enable it to "fix" a missing lobby.
     *
     * Kept below: the reasoning for the one experiment that briefly justified
     * turning it on, so nobody repeats it without reading this first.
     * ---------------------------------------------------------------------
     * Considered 2026-08-17 (rejected).
     *
     * With translation OFF the browse reply demonstrably reaches the game
     * intact -- the trace shows three deliveries of
     *   "RecvFrom fd=2 proxy: 1271 bytes from 0a0d2564:30000"  (10.13.37.100)
     * -- and the game still lists nothing and errors 2618-0006 a couple of
     * seconds in, i.e. when the browse times out. The reply arrives; the game
     * discards it. The one thing wrong with it is the source address: the game
     * believes it is on 10.172.227.x and this came from 10.13.37.100.
     *
     * Translation was written for exactly that, but it only ever ran while the
     * nifm MITM was aborting MK8DX's LAN thread, so it was never given a fair
     * test -- the crash masked whatever it did. nifm is gone now, so this is
     * the untested combination.
     *
     * CONFIRMED (2026-08-17, after the above was written): the real cause was
     * neither the nifm crash nor an off-subnet rejection. `Send()`/`SendTo()`
     * reported the bsd:u {ret, errno} reply in swapped slots, so every
     * successful LAN send looked like a failure to the game regardless of
     * what the reply contained or where it came from. With that fixed and
     * translation still OFF, the LAN lobby lists and the game proceeds to a
     * real join. Off-subnet delivery was never actually the problem. */
    constexpr bool TranslationEnabled = false;

    bool IsTranslationEnabled() { return TranslationEnabled; }

    void SetRealAddress(u32 addr, u32 mask) {
        if (!TranslationEnabled) {
            ::slp::dbg::Trace("netmap: translation DISABLED -- forwarding addresses unmodified");
            g_real_addr = g_real_mask = 0;
            return;
        }

        /* Refuse a real address that already sits inside the virtual subnet:
         * the console is then effectively configured the way the reference
         * stack wants (static 10.13.x.x), everything is already coherent, and
         * translating would only corrupt it. */
        if (addr != 0 && mask != 0 && (addr & VirtualMask) == VirtualNet) {
            ::slp::dbg::Trace("netmap: real addr %u.%u.%u.%u already in virtual subnet -- translation OFF",
                              (addr >> 24) & 0xFF, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF);
            g_real_addr = g_real_mask = 0;
            return;
        }

        g_real_addr = addr;
        g_real_mask = mask;
        ::slp::dbg::Trace("netmap: real %u.%u.%u.%u mask %u.%u.%u.%u -> LAN peers mapped into this subnet",
                          (addr >> 24) & 0xFF, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF,
                          (mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF);
    }

    bool HasRealAddress() {
        return g_real_addr != 0 && g_real_mask != 0;
    }

    u32 VirtualToGame(u32 virt) {
        if (!HasRealAddress())
            return virt;

        /* Virtual broadcast -> the game's own broadcast. */
        if (virt == VirtualBcast || (virt & 0xFF) == 0xFF)
            return RealBcast();

        /* Peer on the virtual subnet -> same host octet on the game's subnet.
         * Never map onto the console's own address (that would look like the
         * game talking to itself); fall back to leaving it alone. */
        if ((virt & VirtualMask) == VirtualNet) {
            const u32 mapped = RealNet() | (virt & ~g_real_mask);
            return (mapped == g_real_addr) ? virt : mapped;
        }
        return virt;
    }

    u32 GameToVirtual(u32 game) {
        if (!HasRealAddress())
            return game;

        /* NEVER translate a broadcast destination.
         *
         * MK8DX's browse request carries an AES-GCM challenge whose NONCE is
         * derived from the destination broadcast address it used. Rewriting
         * 10.172.227.255 -> 10.13.255.255 made the receiver compute a different
         * nonce, so decrypt_request_challenge() failed with "MAC check failed"
         * and the reply could never be built. The relay already floods
         * unknown/broadcast destinations to every peer, so no translation is
         * needed for this to be delivered. Leave it exactly as the game sent it.
         */
        if (game == RealBcast() || (game & 0xFF) == 0xFF)
            return game;

        /* An address on the game's subnet -> the matching virtual peer. */
        if ((game & g_real_mask) == RealNet())
            return VirtualPeerNet | (game & ~g_real_mask & 0xFF);

        return game;
    }

}
