#include "slp_trace.hpp"

#ifdef SLPCFG_DEBUG_TRACE

#include <cstdio>
#include <cstring>

namespace slp::dbg {

    namespace {

        ams::os::SdkMutex g_mutex;
        ams::fs::FileHandle g_file;
        bool g_opened = false;

        void CloseIfOpen() {
            if (g_opened) {
                ams::fs::CloseFile(g_file);
                g_opened = false;
            }
        }

        void OpenIfNeeded() {
            if (g_opened)
                return;

            /* Create if missing (ignore failure: it already exists). */
            ams::fs::CreateFile(SLPCFG_TRACE_PATH, 0,
                                ams::fs::CreateOption_None);

            auto rc = ams::fs::OpenFile(std::addressof(g_file),
                                        SLPCFG_TRACE_PATH,
                                        ams::fs::OpenMode_ReadWrite |
                                        ams::fs::OpenMode_AllowAppend);
            if (rc.IsFailure())
                return;

            g_opened = true;
        }

        u64 NowMs() {
            return ams::os::ConvertToTimeSpan(ams::os::GetSystemTick())
                .GetMilliSeconds();
        }

        void WriteLine(const char *line, size_t len) {
            if (!g_opened)
                return;

            s64 size = 0;
            if (ams::fs::GetFileSize(std::addressof(size), g_file).IsFailure())
                return;

            ams::fs::WriteFile(g_file, size, line, len,
                               ams::fs::WriteOption::Flush);
            /* Close after each write so FTP/other readers can always access
             * the log while the module is running. Debug-only overhead. */
            CloseIfOpen();
        }

    }

    void TraceInit() {
        std::scoped_lock lk(g_mutex);
        OpenIfNeeded();
    }

    void Trace(const char *fmt, ...) {
        std::scoped_lock lk(g_mutex);

        if (!g_opened)
            OpenIfNeeded();
        if (!g_opened)
            return;

        char buf[256];
        int hdr = std::snprintf(buf, sizeof(buf), "[%llu] ",
                                static_cast<unsigned long long>(NowMs()));
        if (hdr < 0 || (size_t)hdr >= sizeof(buf))
            return;

        va_list args;
        va_start(args, fmt);
        int body = std::vsnprintf(buf + hdr, sizeof(buf) - (size_t)hdr, fmt,
                                  args);
        va_end(args);
        if (body < 0)
            return;

        size_t total = (size_t)hdr + (size_t)body;
        if (total > sizeof(buf) - 1)
            total = sizeof(buf) - 1;
        buf[total++] = '\n';
        WriteLine(buf, total);
    }

}

#endif /* SLPCFG_DEBUG_TRACE */
