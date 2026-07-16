# 📂 `lsoph`

TUI that lists open files for a given process — a live, colour-coded view of
every file a program (and its children) touches, updated as it happens.

Usage:

```shell
uvx lsoph -p <pid>          # attach to a running process (and its descendants)
uvx lsoph -c <command ...>  # launch a command and monitor it
uvx lsoph -b <backend> ...  # force a specific backend
```

## Backends

lsoph auto-detects which backends are usable on your machine (the required tool
must be installed, or a C compiler present) and picks the best available. There
are two kinds:

- **Tracers** stream real file *events* — open, read, write, close, stat,
  rename, unlink — from an external tracing tool. Accurate and complete, but
  usually need privilege.
- **Pollers** snapshot each process's open files on an interval. Portable and
  low-privilege, but they miss short-lived files and can't see actual I/O.

| Backend    | OS        | Kind    | Needs                     | Notes |
|------------|-----------|---------|---------------------------|-------|
| `strace`   | 🐧        | tracer  | ptrace (root to attach\*) | default & best supported |
| `preload`  | 🐧😈      | preload | a C compiler (no root)    | run mode only; `LD_PRELOAD` shim |
| `truss`    | 😈☀️      | tracer  | privilege                 | FreeBSD / Solaris |
| `dtruss`   | 🍏😈      | tracer  | root (+ SIP off on macOS) | DTrace-based |
| `ktrace`   | 😈        | tracer  | privilege                 | OpenBSD / NetBSD / FreeBSD |
| `fs_usage` | 🍏        | tracer  | root                      | macOS |
| `etw`      | 🪟        | tracer  | admin                     | ETW Kernel-File events |
| `psutil`   | 🐧🍏😈🪟  | poller  | —                         | open files only |
| `lsof`     | 🐧🍏😈    | poller  | —                         | open files only |

🐧 Linux · 🍏 macOS · 😈 BSD · ☀️ Solaris · 🪟 Windows

\* Under the default `kernel.yama.ptrace_scope=1`, `strace` can only *attach* to
your own descendants. To attach to an arbitrary PID, run with `sudo`, lower the
scope, or `setcap cap_sys_ptrace+ep $(command -v strace)`. **Run mode** (`-c`)
works without any of that.

> The `strace`, `preload`, `psutil` and `lsof` backends are exercised on Linux.
> The BSD/macOS tracers (`truss`, `dtruss`, `ktrace`, `fs_usage`) are built and
> tested against their documented output formats but still want a smoke-test on
> real hardware — reports welcome. `etw` is built against the documented
> Kernel-File event layouts and smoke-tested under Wine (where the session
> APIs work but events don't flow); it wants validation on real Windows.

## Future?

* Native Linux backends — `fanotify`, or eBPF (`bpftrace` / BCC)
* `osquery` — one polling backend, three OSes
* `gdb` / `lldb` debugger-scripting backends (cross-platform, slow)
* `DYLD_INSERT_LIBRARIES` shim for macOS (the preload sibling)

Note: `inotify` is intentionally absent — it watches paths, not processes, and
doesn't report which PID caused an event. `fanotify` is the right Linux API.

* [🎬 demo](https://asciinema.org/a/c7T8id39jU7ap6E0D99S5dJ6F)
* [🏠 home](https://bitplane.net/dev/python/lsoph)
* [🐱 github](https://github.com/bitplane/lsoph)
* [🐍 pypi](https://pypi.org/project/lsoph)
