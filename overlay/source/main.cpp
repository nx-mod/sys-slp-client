#define TESLA_INIT_IMPL // If you have more than one file using the tesla header, only define this in the main one
#include <tesla.hpp>    // The Tesla Header

#include <cstdio>
#include <format>
#include <string>

#include "servers.h"
#include "slpcfg.h"

#define TITLE "slp-helper"
#define SERVERS_CONF "sdmc:/config/slp-helper/servers.conf"

/* Presence of this file is what makes Atmosphere's boot2 launcher start the
 * sysmodule at boot. Toggling it does NOT affect the currently-running
 * process (its .nso/.npdm stay open/locked for as long as it's alive) --
 * it only takes effect on the next full console boot. This lets us disable
 * the module (e.g. to free the file for an FTP overwrite) without needing
 * an in-process self-exit IPC command, which is riskier to get right. */
#define BOOT2_FLAG_PATH "sdmc:/atmosphere/contents/4200000000000011/flags/boot2.flag"

static SlpCfgService g_svc;
static bool g_haveSvc = false;
static char g_version[32] = "?";
static Result g_cfg_error = 0;
static u32 g_state_val = 0, g_sel_val = 0;

/* Cached so the periodic refresh() doesn't hit the SD card ~2x/second just to
 * re-read a flag that only ever changes when the user presses A on the toggle.
 * Updated at startup and after every toggle. */
static bool g_launch_enabled = false;

static bool ReadModuleLaunchFlag() {
    bool exists = false;
    tsl::hlp::doWithSDCardHandle([&] {
        FILE *f = fopen(BOOT2_FLAG_PATH, "rb");
        if (f != nullptr) {
            exists = true;
            fclose(f);
        }
    });
    return exists;
}

static void SetModuleLaunchEnabled(bool enable) {
    tsl::hlp::doWithSDCardHandle([&] {
        if (enable) {
            FILE *f = fopen(BOOT2_FLAG_PATH, "wb");
            if (f != nullptr)
                fclose(f);
        } else {
            std::remove(BOOT2_FLAG_PATH);
        }
    });
    /* Re-read rather than assuming: if the write/delete failed (SD full,
     * read-only, path missing) the UI must show what is actually on disk. */
    g_launch_enabled = ReadModuleLaunchFlag();
}

/* ------------------------------------------------------------------ *
 * Server selection page
 *
 * Split off the main page so host:port addresses don't clutter it. Picking
 * any entry -- including the one already selected -- applies and returns.
 * ------------------------------------------------------------------ */
class ServerGui : public tsl::Gui {
public:
    virtual tsl::elm::Element *createUI() override {
        auto frame = new tsl::elm::OverlayFrame(TITLE, "select server");
        auto list = new tsl::elm::List();

        const int count = slpServersCount();
        if (count == 0) {
            list->addItem(new tsl::elm::ListItem("no servers configured"));
            list->addItem(new tsl::elm::ListItem(SERVERS_CONF));
            frame->setContent(list);
            return frame;
        }

        list->addItem(new tsl::elm::CategoryHeader("Select a server"));

        for (int i = 0; i < count && i < SLPCFG_MAX_SERVERS; i++) {
            const SlpServer *srv = slpServersGet(i);
            if (srv == nullptr)
                continue;

            auto *item = new tsl::elm::ListItem(srv->name);
            /* Address shown here (this is the page that's allowed to be busy),
             * with a dot marking the current selection. */
            const bool selected = ((u32)i == g_sel_val);
            item->setValue(std::format("{}{}:{}", selected ? "● " : "",
                                       srv->host, srv->port),
                           !selected);

            const int index = i;
            item->setClickListener([index](u64 keys) {
                if (!(keys & HidNpadButton_A))
                    return false;

                if (g_haveSvc) {
                    slpCfgSelectServer(&g_svc, (u32)index);
                    /* Only bounce the connection if it was actually up --
                     * restarting a stopped relay would silently start it. */
                    if (g_state_val == 1) {
                        slpCfgStop(&g_svc);
                        slpCfgStart(&g_svc);
                    }
                    g_sel_val = (u32)index;
                }
                /* Always return, even when picking the same entry again --
                 * the user asked for it to act as "confirm and go back". */
                tsl::goBack();
                return true;
            });
            list->addItem(item);
        }

        frame->setContent(list);
        return frame;
    }
};

/* ------------------------------------------------------------------ *
 * Main page
 * ------------------------------------------------------------------ */
class MainGui : public tsl::Gui {
public:
    MainGui() {}

    tsl::elm::OverlayFrame *m_frame = nullptr;
    tsl::elm::ListItem *m_status = nullptr;
    tsl::elm::ListItem *m_launchToggle = nullptr;
    tsl::elm::ListItem *m_serverRow = nullptr;
    u32 m_frameCount = 0;

    virtual tsl::elm::Element *createUI() override {
        auto frame = new tsl::elm::OverlayFrame(TITLE, g_version);
        auto list = new tsl::elm::List();
        m_frame = frame;

        if (!g_haveSvc) {
            BuildNotRunningUI(list);
            frame->setContent(list);
            /* Must refresh before returning so the boot toggle shows its state
             * immediately instead of blank until the first update() tick. */
            this->refresh();
            return frame;
        }

        m_status = new tsl::elm::ListItem("State");
        list->addItem(m_status);

        list->addItem(new tsl::elm::CategoryHeader("Controls"));
        AddAction(list, "Start", [] { slpCfgStart(&g_svc); });
        AddAction(list, "Stop", [] { slpCfgStop(&g_svc); });
        AddAction(list, "Restart", [] {
            slpCfgStop(&g_svc);
            slpCfgStart(&g_svc);
        });

        list->addItem(new tsl::elm::CategoryHeader("Server"));
        /* Current server only, by name -- the full list with addresses lives
         * on ServerGui so this page stays uncluttered. */
        if (slpServersCount() == 0) {
            auto *none = new tsl::elm::ListItem("Selected");
            none->setValue("none configured", true);
            list->addItem(none);
            list->addItem(new tsl::elm::ListItem(SERVERS_CONF));
        } else {
            m_serverRow = new tsl::elm::ListItem("Selected");
            m_serverRow->setClickListener([](u64 keys) {
                if (keys & HidNpadButton_A) {
                    tsl::changeTo<ServerGui>();
                    return true;
                }
                return false;
            });
            list->addItem(m_serverRow);
        }

        AddBootToggle(list);

        frame->setContent(list);
        this->refresh();
        return frame;
    }

    virtual void update() override {
        /* ~2x/second. Cheap now: one IPC call, no SD access (flag is cached). */
        if (++m_frameCount % 30 == 0)
            this->refresh();
    }

    virtual bool handleInput(u64, u64, const HidTouchState &,
                             HidAnalogStickState, HidAnalogStickState) override {
        return false;
    }

private:
    template<typename F>
    void AddAction(tsl::elm::List *list, const char *label, F action) {
        auto *item = new tsl::elm::ListItem(label);
        item->setClickListener([this, action](u64 keys) {
            if (keys & HidNpadButton_A) {
                action();
                this->refresh();
                return true;
            }
            return false;
        });
        list->addItem(item);
    }

    void AddBootToggle(tsl::elm::List *list) {
        list->addItem(new tsl::elm::CategoryHeader("Boot"));
        m_launchToggle = new tsl::elm::ListItem("Launch at boot");
        m_launchToggle->setClickListener([this](u64 keys) {
            if (keys & HidNpadButton_A) {
                SetModuleLaunchEnabled(!g_launch_enabled);
                this->refresh();
                return true;
            }
            return false;
        });
        list->addItem(m_launchToggle);
        list->addItem(new tsl::elm::ListItem("(reboot to apply)"));
    }

    void BuildNotRunningUI(tsl::elm::List *list) {
        if (g_cfg_error == SLPCFG_RESULT_NOT_INSTALLED) {
            /* Expected, benign case: overlay opened without the sysmodule
             * running. Explain it instead of showing a raw error code. */
            list->addItem(new tsl::elm::CategoryHeader("Sysmodule not running"));
            list->addItem(new tsl::elm::ListItem("sys-slp-client isn't installed"));
            list->addItem(new tsl::elm::ListItem("or hasn't started yet."));
            list->addItem(new tsl::elm::CategoryHeader("To fix"));
            list->addItem(new tsl::elm::ListItem("1. Install exefs.nsp under"));
            list->addItem(new tsl::elm::ListItem("   contents/4200000000000011/"));
            list->addItem(new tsl::elm::ListItem("2. Enable 'Launch at boot'"));
            list->addItem(new tsl::elm::ListItem("3. Reboot the console"));
        } else {
            list->addItem(new tsl::elm::CategoryHeader("slp:cfg unavailable"));
            list->addItem(new tsl::elm::ListItem(
                std::format("connect failed 0x{:X}", g_cfg_error)));
            list->addItem(new tsl::elm::ListItem("Try rebooting the console."));
        }

        /* The launch-at-boot toggle MUST be reachable here too. It is purely
         * file-based and needs no sysmodule; if it were only on the connected
         * page, switching it off would be a one-way trip -- after the next
         * reboot the service is gone, leaving no way to switch it back on. */
        AddBootToggle(list);
    }

    void refresh() {
        /* Above the g_haveSvc gate on purpose: the boot toggle is file-based
         * and appears on the not-running page too, so it must stay live even
         * with no slp:cfg service to talk to. */
        if (m_launchToggle != nullptr)
            m_launchToggle->setValue(g_launch_enabled ? "Enabled" : "Disabled",
                                     !g_launch_enabled);

        if (!g_haveSvc)
            return;

        u32 state = 0, sel = 0;
        char ip[16] = "";
        if (R_FAILED(slpCfgGetState(&g_svc, &state, &sel, ip))) {
            /* The sysmodule went away (crashed/stopped) while the overlay is
             * open. Say so rather than showing a stale "Running". */
            if (m_status != nullptr)
                m_status->setValue("service lost", true);
            return;
        }
        g_state_val = state;
        g_sel_val = sel;

        std::string stateStr;
        switch (state) {
            case 0: stateStr = "Stopped"; break;
            case 1:
                stateStr = "Running";
                if (ip[0] != '\0')
                    stateStr += std::format("  {}", ip);
                break;
            default: stateStr = "Unknown"; break;
        }
        if (m_status != nullptr)
            m_status->setValue(stateStr, state != 1);

        const SlpServer *srv = slpServersGet((int)sel);

        if (m_serverRow != nullptr)
            m_serverRow->setValue(srv != nullptr ? srv->name : "none", srv == nullptr);

        if (m_frame != nullptr) {
            std::string sub = g_version;
            if (srv != nullptr)
                sub += std::format("  ·  {}", srv->host);
            m_frame->setSubtitle(sub);
        }
    }
};

class SlpHelperOverlay : public tsl::Overlay {
public:
    virtual void initServices() override {
        tsl::hlp::doWithSmSession([&] {
            g_cfg_error = slpCfgGetConfig(&g_svc);
        });
        g_haveSvc = R_SUCCEEDED(g_cfg_error);
        if (g_haveSvc)
            slpCfgGetVersion(&g_svc, g_version);

        tsl::hlp::doWithSDCardHandle([&] {
            slpServersLoad(SERVERS_CONF);
        });
        g_launch_enabled = ReadModuleLaunchFlag();
    }

    virtual void exitServices() override {
        if (g_haveSvc)
            slpCfgClose(&g_svc);
    }

    virtual void onShow() override {}
    virtual void onHide() override {}

    virtual std::unique_ptr<tsl::Gui> loadInitialGui() override {
        return initially<MainGui>();
    }
};

int main(int argc, char **argv) {
    return tsl::loop<SlpHelperOverlay>(argc, argv);
}
