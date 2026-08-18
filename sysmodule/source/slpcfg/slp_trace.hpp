/*
 * sys-slp-client — lightweight SD trace logger.
 *
 * Boot2-safe (uses ams::fs, no stdio). Appends timestamped lines to
 * sdmc:/slp-trace.log so we can see where a hang/freeze occurs without
 * needing a serial console. All calls are thread-safe; each line is flushed.
 */
#pragma once

#include <stratosphere.hpp>

/* MUST carry the "sdmc:" mount name. ams::fs resolves paths by mount prefix,
 * so a bare "/switch/slp-trace.log" (what this used to be) has no mount to
 * resolve against: every CreateFile/OpenFile failed, g_opened stayed false,
 * and every Trace() call silently became a no-op. The trace log therefore
 * never appeared despite tracing being compiled in -- which cost a full day,
 * because the missing log was misread as "the module aborted before
 * TraceInit()". The heartbeat file worked the whole time precisely because it
 * used "sdmc:/slp-heartbeat.txt". Kept at SD root right next to the heartbeat
 * so both debug artifacts live in one obvious place. Keep the prefix. */
#define SLPCFG_TRACE_PATH "sdmc:/slp-trace.log"

/* Debug-only. Define SLPCFG_DEBUG_TRACE to build with tracing enabled;
 * release builds compile these to nothing (no SD writes, no mutex). */
#ifdef SLPCFG_DEBUG_TRACE

namespace slp::dbg {

    void TraceInit();
    void Trace(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

}

#else

namespace slp::dbg {
    constexpr inline void TraceInit() {}
    template<typename... Args>
    constexpr inline void Trace(const Args &...) {}
}

#endif
