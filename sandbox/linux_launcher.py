"""Trusted Linux child entry point: confine first, then exec the chosen Python."""

import ctypes
import errno
import os
import sys
from pathlib import Path


# Linux UAPI, for the supported x86_64/aarch64 runtimes.
_CREATE_RULESET, _ADD_RULE, _RESTRICT_SELF = 444, 445, 446
_EXECUTE = 1 << 0
_WRITE_FILE = 1 << 1
_READ_FILE = 1 << 2
_READ_DIR = 1 << 3
_REMOVE_DIR = 1 << 4
_REMOVE_FILE = 1 << 5
_MAKE_DIR = 1 << 7
_MAKE_REG = 1 << 8
_REFER = 1 << 13
_TRUNCATE = 1 << 14
_IOCTL_DEV = 1 << 15
_READ_TREE = _READ_FILE | _READ_DIR
_WRITE_TREE = _WRITE_FILE | _REMOVE_DIR | _REMOVE_FILE | _MAKE_DIR | _MAKE_REG | _REFER | _TRUNCATE
_SCMP_CMP_NE = 1
_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.syscall.restype = ctypes.c_long


class _PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class _SyscallArgument(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint), ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64),
    ]


def _syscall(number, *args):
    result = _LIBC.syscall(number, *args)
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def _allow_path(ruleset, path, access, *, required=True):
    try:
        path_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except FileNotFoundError:
        if required:
            raise
        return
    try:
        rule = _PathRule(access, path_fd)
        _syscall(_ADD_RULE, ruleset, 1, ctypes.byref(rule), 0)  # LANDLOCK_RULE_PATH_BENEATH
    finally:
        os.close(path_fd)


def _restrict_files(repo, temp, venv, interpreter):
    if os.uname().machine not in {"x86_64", "aarch64"}:
        raise OSError("Unsupported Linux sandbox architecture")
    abi = _syscall(_CREATE_RULESET, None, 0, 1)  # LANDLOCK_CREATE_RULESET_VERSION
    if abi < 3:
        raise OSError("Landlock ABI 3 or newer is required")
    handled = ctypes.c_uint64(((1 << 15) - 1) | (_IOCTL_DEV if abi >= 5 else 0))
    ruleset = _syscall(_CREATE_RULESET, ctypes.byref(handled), ctypes.sizeof(handled), 0)
    try:
        for directory in ("/usr", "/lib", "/lib64", "/etc/fonts", "/etc/alternatives"):
            _allow_path(ruleset, directory, _READ_TREE, required=False)
        for name in ("/etc/ld.so.cache", "/etc/localtime", "/etc/mime.types",
                     "/proc/cpuinfo", "/proc/meminfo", "/proc/self/stat",
                     "/proc/self/statm", "/proc/self/status", "/proc/self/limits",
                     "/dev/random", "/dev/urandom"):
            _allow_path(ruleset, name, _READ_FILE, required=False)
        _allow_path(ruleset, "/dev/null", _READ_FILE | _WRITE_FILE)
        if venv:
            _allow_path(ruleset, venv, _READ_TREE)
        _allow_path(ruleset, Path(interpreter).resolve(strict=True), _READ_FILE | _EXECUTE)
        # Landlock also checks the ELF interpreter during exec.
        for loader in ("/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"):
            _allow_path(ruleset, loader, _READ_FILE | _EXECUTE, required=False)
        for directory in (repo, temp):
            _allow_path(ruleset, directory, _READ_TREE | _WRITE_TREE)
        if _LIBC.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        _syscall(_RESTRICT_SELF, ruleset, 0)
    finally:
        os.close(ruleset)


def _restrict_syscalls():
    seccomp = ctypes.CDLL("libseccomp.so.2")
    seccomp.seccomp_init.argtypes = (ctypes.c_uint32,)
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = (ctypes.c_char_p,)
    seccomp.seccomp_rule_add_array.argtypes = (
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
        ctypes.c_uint, ctypes.POINTER(_SyscallArgument),
    )
    seccomp.seccomp_load.argtypes = (ctypes.c_void_p,)
    seccomp.seccomp_release.argtypes = (ctypes.c_void_p,)
    seccomp.seccomp_release.restype = None

    context = seccomp.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        raise OSError("Could not allocate seccomp policy")

    def deny(name, argument=None, *, required=False):
        number = seccomp.seccomp_syscall_resolve_name(name.encode("ascii"))
        if number < 0:
            if required:
                raise OSError(f"Unknown required seccomp syscall: {name}")
            return
        comparer = ctypes.byref(argument) if argument else None
        rc = seccomp.seccomp_rule_add_array(
            context, 0x00050000 | errno.EPERM, number, int(argument is not None), comparer,
        )
        if rc != 0:
            raise OSError(-rc, f"Could not add seccomp rule: {name}")

    try:
        deny("socket", required=True)
        for name in (
            "bind", "connect", "listen", "accept", "accept4",
            "ptrace", "process_vm_readv", "process_vm_writev", "process_madvise",
            "pidfd_open", "pidfd_getfd", "pidfd_send_signal", "process_mrelease",
            "tkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo",
            "setsid", "setpgid", "setns", "unshare",
            "io_uring_setup", "io_uring_enter", "io_uring_register",
            "open_by_handle_at", "open_tree", "move_mount", "fsopen", "fsconfig",
            "fsmount", "fspick", "mount_setattr", "mount", "umount2", "pivot_root",
            "keyctl", "add_key", "request_key", "bpf", "perf_event_open",
            "setpriority", "ioprio_set",
        ):
            deny(name)
        # Permit ordinary self-directed signals, including libc thread cancellation.
        other_process = _SyscallArgument(0, _SCMP_CMP_NE, os.getpid(), 0)
        deny("kill", other_process, required=True)
        deny("tgkill", other_process, required=True)
        nonzero_pid = _SyscallArgument(0, _SCMP_CMP_NE, 0, 0)
        for name in ("prlimit64", "sched_setaffinity", "sched_setparam", "sched_setscheduler",
                     "sched_setattr"):
            deny(name, nonzero_pid)
        rc = seccomp.seccomp_load(context)
        if rc != 0:
            raise OSError(-rc, "Could not load seccomp policy")
    finally:
        seccomp.seccomp_release(context)


def main():
    status_fd = int(sys.argv[1])
    # Only this trusted launcher can write to the status channel; exec closes it.
    os.set_inheritable(status_fd, False)
    repo, temp, venv, interpreter, *arguments = sys.argv[2:]
    stage = b"filesystem"
    try:
        _restrict_files(repo, temp, venv, interpreter)
        stage = b"syscalls"
        _restrict_syscalls()
        stage = b"exec"
        os.write(status_fd, b"ready")
        os.execv(interpreter, [interpreter, "-s", "-B", *arguments])
    except (OSError, AttributeError) as exc:
        detail = str(exc.errno).encode("ascii") if isinstance(exc, OSError) and exc.errno else b"-"
        os.write(status_fd, b"error:" + stage + b":" + detail)
        sys.exit(125)


if __name__ == "__main__":
    main()
