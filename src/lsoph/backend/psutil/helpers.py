# Filename: src/lsoph/backend/psutil/helpers.py
"""Helper functions for the psutil backend. Works with bytes paths."""

import logging
import os
import stat
import sys
from typing import Any

# Attempt to import psutil and handle failure gracefully
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False

log = logging.getLogger(__name__)


def _get_process_info(pid: int) -> psutil.Process | None:
    """Safely get a psutil.Process object."""
    if not PSUTIL_AVAILABLE:
        return None
    try:
        return psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
        # Log non-NoSuchProcess errors at debug level
        if not isinstance(e, psutil.NoSuchProcess):
            log.debug(f"Error getting psutil.Process for PID {pid}: {type(e).__name__}")
        return None


def _get_process_cwd(proc: psutil.Process) -> bytes | None:
    """Safely get the current working directory as bytes."""
    if not PSUTIL_AVAILABLE:
        return None
    try:
        cwd_str = proc.cwd()
        cwd_bytes = os.fsencode(cwd_str)
        log.debug(f"Retrieved CWD for PID {proc.pid}: {cwd_str!r} -> {cwd_bytes!r}")
        return cwd_bytes
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        Exception,
    ) as e:
        log.debug(f"Could not get CWD for PID {proc.pid}: {type(e).__name__}")
        return None


def _fd_paths_from_proc(pid: int) -> list[dict[str, Any]]:
    """Read /proc/<pid>/fd directly (Linux) for every file-backed descriptor.

    psutil.open_files() reports *regular* files only, so device files
    (/dev/zero, /dev/null, ...) a process holds open are invisible to it. The
    /proc fd symlinks cover them; the symlink's own permission bits encode the
    fd's access mode (lr-x = read, l-wx = write, lrwx = read/write). Sockets and
    pipes (targets not starting with "/") are skipped -- sockets are reported
    separately, and pipes are not files.
    """
    fd_dir = os.fsencode(f"/proc/{pid}/fd")
    try:
        entries = os.listdir(fd_dir)
    except OSError as e:
        log.debug(f"Could not list {fd_dir!r}: {type(e).__name__}")
        return []

    files: list[dict[str, Any]] = []
    for name in entries:
        try:
            fd = int(name)
        except ValueError:
            continue
        link = os.path.join(fd_dir, name)
        try:
            target = os.readlink(link)  # bytes in, bytes out
            mode_bits = os.lstat(link).st_mode
        except OSError:
            continue  # fd closed between listdir and readlink
        if not target.startswith(b"/"):
            continue  # pipe:[...], socket:[...], anon_inode:[...]
        if target.endswith(b" (deleted)"):
            target = target[: -len(b" (deleted)")]
        readable = bool(mode_bits & stat.S_IRUSR)
        writable = bool(mode_bits & stat.S_IWUSR)
        mode = ("r" if readable else "") + ("w" if writable else "") or "r"
        files.append({"path": target, "fd": fd, "mode": mode, "type": "file"})
    return files


def _regular_files_from_psutil(proc: psutil.Process) -> list[dict[str, Any]]:
    """Regular open files via psutil (used off Linux, where /proc is absent)."""
    files: list[dict[str, Any]] = []
    pid = proc.pid
    try:
        for f in proc.open_files():
            if hasattr(f, "path") and f.path:
                try:
                    path_bytes = os.fsencode(str(f.path))
                except Exception as enc_err:
                    log.warning(
                        f"Could not encode path '{f.path}' for PID {pid} FD {f.fd}: {enc_err}"
                    )
                    path_bytes = os.fsencode(f"<UNENCODABLE_PATH_FD:{f.fd}>")
            else:
                path_bytes = os.fsencode(f"<NO_PATH_FD:{f.fd}>")
            files.append(
                {
                    "path": path_bytes,
                    "fd": f.fd,
                    "mode": getattr(f, "mode", ""),
                    "type": "file",
                }
            )
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        Exception,
    ) as e:
        log.debug(f"Error accessing open files for PID {pid}: {type(e).__name__}")
    return files


def _get_process_open_files(
    proc: psutil.Process,
) -> list[dict[str, Any]]:  # Dict value for 'path' will be bytes
    """
    Safely get open files and connections for a process.
    Returns paths as bytes.
    """
    if not PSUTIL_AVAILABLE:
        return []

    pid = proc.pid
    # Linux: read /proc/<pid>/fd for the complete fd set (incl. devices);
    # elsewhere fall back to psutil's regular-files-only view.
    if sys.platform.startswith("linux"):
        open_files_data = _fd_paths_from_proc(pid)
    else:
        open_files_data = _regular_files_from_psutil(proc)

    try:  # Get connections
        for conn in proc.connections(kind="all"):
            try:
                # Simplify connection string representation (keep as string for now)
                if conn.laddr:
                    laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}"
                else:
                    laddr_str = "<?:?>"
                if conn.raddr:
                    # Check if raddr has ip and port attributes
                    if hasattr(conn.raddr, "ip") and hasattr(conn.raddr, "port"):
                        raddr_str = f"{conn.raddr.ip}:{conn.raddr.port}"
                    else:  # Handle cases like UNIX sockets where raddr might be a path string
                        raddr_str = str(conn.raddr) if conn.raddr else ""
                else:
                    raddr_str = ""

                conn_type_str = (
                    conn.type.name if hasattr(conn.type, "name") else str(conn.type)
                )

                # Format path string based on connection type/status
                if conn.status == psutil.CONN_ESTABLISHED and raddr_str:
                    path_str = f"<SOCKET:{conn_type_str}:{laddr_str}->{raddr_str}>"
                elif conn.status == psutil.CONN_LISTEN:
                    path_str = f"<SOCKET_LISTEN:{conn_type_str}:{laddr_str}>"
                else:
                    path_str = f"<SOCKET:{conn_type_str}:{laddr_str} fd={conn.fd} status={conn.status}>"

                path_bytes = os.fsencode(path_str)

                open_files_data.append(
                    {
                        "path": path_bytes,  # Store bytes path
                        "fd": conn.fd if conn.fd != -1 else -1,  # Use -1 for invalid FD
                        "mode": "rw",  # Assume read/write for sockets
                        "type": "socket",
                    }
                )
            except (AttributeError, ValueError) as conn_err:
                log.debug(
                    f"Error formatting connection details for PID {pid}: {conn_err} - {conn}"
                )
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        Exception,
    ) as e:
        log.debug(f"Error accessing connections for PID {pid}: {type(e).__name__}")
    return open_files_data
