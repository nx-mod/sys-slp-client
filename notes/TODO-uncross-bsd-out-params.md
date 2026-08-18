# TODO (deferred): un-cross the misnamed BSD out-params

**Do NOT do this until LAN/WiFi play is actually working.** It is a pure
readability refactor with real breakage risk, and it touches every BSD command.
Deferred deliberately (user, 2026-08-16: "make a note uncross that later, not
until we get shit running").

## The situation

The bsd:u reply is `{ret, errno}` **positionally**. Several of our MITM handlers
declare their out-params in the opposite order and rely on position anyway:

| command | declared | word0 (`ret`) | word1 (`errno`) | honest? |
|---|---|---|---|---|
| `RecvFrom` | `(out_ret, out_errno, out_addrlen)` | `out_ret` | `out_errno` | ✅ yes |
| `Recv`     | `(out_errno, out_size)` | **`out_errno`** | **`out_size`** | ❌ crossed |
| `Read`     | `(out_errno, out_size)` | **`out_errno`** | **`out_size`** | ❌ crossed |
| `Socket`   | `(out_errno, out_fd)`   | **`out_errno`** | **`out_fd`**   | ❌ crossed |
| `SocketExempt`, `Open`, `EventFd`, `DuplicateSocket` | same shape | same | same | ❌ crossed |

Forwarding to the real service is unaffected: it copies word0/word1 straight
through, so the wrong names cancel out.

## Why it mattered (already fixed 2026-08-16)

The **proxy** paths in `Recv()` and `Read()` trusted the names instead of the
positions, and had them exactly inverted:

```cpp
if (result < 0) { out_errno.SetValue(-result); out_size.SetValue(0); }  // ret=11, errno=0
else            { out_errno.SetValue(0);       out_size.SetValue(result); } // ret=0 => EOF
```

So on a proxied socket **every successful recv() reported ret=0**, which recv()
defines as *orderly shutdown / EOF*, and **every would-block reported ret=11**,
i.e. an 11-byte read of uninitialised buffer. MK8DX therefore took its
connection-lost path and threw "communication error" instead of simply finding
no lobbies — matching the repro "if there are no players on the relay, LAN
crashes". Fixed by writing the correct values positionally while leaving the
names alone; see the comments in `bsd_mitm_service.cpp`.

## The eventual cleanup

Rename so names match positions (`out_errno`->`out_ret`, `out_size`->`out_errno`,
`out_fd`->..., etc.) in `bsd_mitm_service.cpp/.hpp` **and** the matching
`AMS_SF_METHOD_INFO` entries in the interface macro. Purely mechanical, but every
site must move together — an inconsistent rename silently swaps ret/errno again,
which is exactly the class of bug that cost a day here.

**Verify after:** a proxied `recv()` with no data must return `ret=-1,
errno=11`, and a good read must return `ret=N, errno=0`.
