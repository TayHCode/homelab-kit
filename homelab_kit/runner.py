"""The sole process boundary. Output is bounded and stays in memory."""
import os
import queue
import selectors
import signal
import subprocess
import threading
import time
import uuid
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import BinaryIO


@dataclass
class CommandResult:
    code: int
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    too_large: bool = False
    missing_executable: bool = False


def read_pipes(process: subprocess.Popen, buffers: dict[str, bytearray], deadline: float,
               limit: int) -> tuple[bool, bool]:
    """Windows selectors cannot wait on subprocess pipes; use bounded readers."""
    events: queue.Queue[tuple[str, bytes]] = queue.Queue(maxsize=2)
    stop = threading.Event()

    def read(name: str) -> None:
        stream = getattr(process, name)
        try:
            while not stop.is_set():
                block = stream.read1(65536)
                while not stop.is_set():
                    try:
                        events.put((name, block), timeout=0.1)
                        break
                    except queue.Full:
                        pass
                if not block:
                    return
        except (OSError, ValueError):
            return

    threads = [threading.Thread(target=read, args=(name,), daemon=True) for name in buffers]
    for thread in threads:
        thread.start()
    open_streams = len(buffers)
    try:
        while open_streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return True, False
            try:
                name, block = events.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                continue
            if not block:
                open_streams -= 1
                continue
            buffers[name].extend(block[:max(0, limit + 1 - len(buffers[name]))])
            if len(buffers[name]) > limit:
                return False, True
        return False, False
    finally:
        stop.set()


def windows_pipe() -> tuple[BinaryIO, BinaryIO]:
    """Win32 OpenSSH writes asynchronously; its inherited end must overlap."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    api = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    api.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, *([wintypes.DWORD] * 6), ctypes.c_void_p]
    api.CreateNamedPipeW.restype = wintypes.HANDLE
    api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                               ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    api.CreateFileW.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    name = str(PureWindowsPath("//./pipe") / ("homelab-kit-" + uuid.uuid4().hex))
    invalid = ctypes.c_void_p(-1).value
    # Inbound byte pipe; reject remote clients. Only the child writes overlap.
    server = api.CreateNamedPipeW(name, 1, 8, 1, 65536, 65536, 0, None)
    if server == invalid:
        raise OSError("cannot create subprocess capture pipe")
    client = api.CreateFileW(name, 0x40000000, 0, None, 3, 0x40000000, None)
    if client == invalid:
        api.CloseHandle(server)
        raise OSError("cannot open subprocess capture pipe")
    try:
        read_fd = getattr(msvcrt, "open_osfhandle")(server, os.O_RDONLY | getattr(os, "O_BINARY"))
    except OSError:
        api.CloseHandle(server)
        api.CloseHandle(client)
        raise
    try:
        write_fd = getattr(msvcrt, "open_osfhandle")(client, os.O_WRONLY | getattr(os, "O_BINARY"))
    except OSError:
        os.close(read_fd)
        api.CloseHandle(client)
        raise
    return os.fdopen(read_fd, "rb"), os.fdopen(write_fd, "wb")


def spawn(argv: list[str]) -> subprocess.Popen:
    environment = {**os.environ, "LC_ALL": "C"}
    if os.name != "nt":
        return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, stdin=subprocess.DEVNULL, env=environment)
    with ExitStack() as owned:
        stdout, stdout_writer = windows_pipe()
        owned.enter_context(stdout)
        owned.enter_context(stdout_writer)
        stderr, stderr_writer = windows_pipe()
        owned.enter_context(stderr)
        owned.enter_context(stderr_writer)
        process = subprocess.Popen(argv, stdout=stdout_writer, stderr=stderr_writer, stdin=subprocess.DEVNULL, env=environment)
        stdout_writer.close()
        stderr_writer.close()
        process.stdout, process.stderr = stdout, stderr
        owned.pop_all()  # The caller closes the two readers after bounded capture.
        return process


def windows_job(process: subprocess.Popen):
    """A kill-on-close job retains descendants even if their parent exits."""
    import ctypes
    from ctypes import wintypes

    class Limits(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                    ("flags", wintypes.DWORD), ("min_working_set", ctypes.c_size_t),
                    ("max_working_set", ctypes.c_size_t), ("active_processes", wintypes.DWORD),
                    ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                    ("scheduling", wintypes.DWORD)]

    class Counters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in
                    ("reads", "writes", "other", "read_bytes", "write_bytes", "other_bytes")]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [("limits", Limits), ("io", Counters),
                    ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                    ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]

    win_api = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    suffix = "Object"
    create_job = getattr(win_api, "CreateJob" + suffix + "W")
    set_limits = getattr(win_api, "SetInformationJob" + suffix)
    assign_job = getattr(win_api, "AssignProcessToJob" + suffix)
    create_job.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    create_job.restype = wintypes.HANDLE
    set_limits.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    assign_job.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    win_api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = create_job(None, None)
    info = ExtendedLimits()
    info.limits.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not handle:
        raise OSError("cannot contain subprocess tree")
    if (not set_limits(handle, 9, ctypes.byref(info), ctypes.sizeof(info))
            or not assign_job(handle, int(getattr(process, "_handle")))):
        win_api.CloseHandle(handle)
        raise OSError("cannot contain subprocess tree")
    return lambda: win_api.CloseHandle(handle)


def kill_tree(process: subprocess.Popen) -> None:
    """Kill descendants before reaping their parent, with bounded cleanup."""
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=2, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    process.kill()


def run(argv: list[str], timeout: float = 30, limit: int = 1048576) -> CommandResult:
    if timeout <= 0:
        return CommandResult(-9, timed_out=True)
    deadline = time.monotonic() + timeout
    try:
        process = spawn(argv)
    except FileNotFoundError:
        return CommandResult(127, missing_executable=True)
    except PermissionError:
        return CommandResult(126)
    close_job = None
    if os.name == "nt":
        try:
            close_job = windows_job(process)
        except OSError:
            kill_tree(process)
            process.wait(timeout=2)
            for stream in (process.stdout, process.stderr):
                if stream:
                    stream.close()
            return CommandResult(126)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    timed_out = too_large = False
    try:
        if os.name == "nt":
            timed_out, too_large = read_pipes(process, buffers, deadline, limit)
        else:
            with selectors.DefaultSelector() as selector:
                for name in buffers:
                    selector.register(getattr(process, name), selectors.EVENT_READ, name)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    for key, _ in selector.select(min(remaining, 0.1)):
                        block = os.read(key.fd, 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                        else:
                            buf = buffers[key.data]
                            buf.extend(block[:max(0, limit + 1 - len(buf))])
                            if len(buf) > limit:
                                too_large = True
                    if too_large:
                        break
        if timed_out or too_large:
            if close_job:
                close_job()
                close_job = None
            kill_tree(process)
        process.wait(timeout=2 if timed_out or too_large else max(0.001, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        timed_out = True
        if close_job:
            close_job()
            close_job = None
        kill_tree(process)
        process.wait(timeout=2)
    finally:
        if close_job:
            close_job()
        if process.poll() is None:
            kill_tree(process)
            process.wait(timeout=2)
        for name in buffers:
            getattr(process, name).close()
    return CommandResult(process.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]), timed_out, too_large)
