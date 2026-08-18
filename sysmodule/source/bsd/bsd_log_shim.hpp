/*
 * sys-slp-client — LOG_* macro shim for the ported bsd:u MITM.
 *
 * ryu_ldn_nx logs through ryu_ldn::debug::g_logger. We keep the 100+ LOG_*
 * call sites unchanged and map them onto slp::dbg::Trace (boot2-safe,
 * ams::fs, appended to sdmc:/slp-trace.log). When SLPCFG_DEBUG_TRACE is
 * undefined these compile to no-ops.
 *
 * NOTE: the level prefix is glued to the format literal at each call site,
 * so the argument must be a string literal (true for every call site).
 */
#pragma once

#include "../slpcfg/slp_trace.hpp"

#define LOG_ERROR(fmt, ...)   ::slp::dbg::Trace("[BSD:E] " fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)    ::slp::dbg::Trace("[BSD:W] " fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)    ::slp::dbg::Trace("[BSD:I] " fmt, ##__VA_ARGS__)
#define LOG_VERBOSE(fmt, ...) ::slp::dbg::Trace("[BSD:V] " fmt, ##__VA_ARGS__)
