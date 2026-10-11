"""Linux parser restrictions: selected input plus interpreter libraries, no sockets."""

import ctypes
import errno
import os
import platform
import sys
from pathlib import Path


def restrict_parser(input_path):
    if sys.platform != "linux":
        raise OSError("Production parsing requires Linux Landlock and seccomp")
    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, 0, 0, 1)
    if abi < 3:
        raise OSError("Production parsing requires Landlock ABI 3 or newer")

    class Ruleset(ctypes.Structure):
        _fields_ = [("access", ctypes.c_uint64)]

    class Rule(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("access", ctypes.c_uint64), ("fd", ctypes.c_int32)]

    # ABI 3 handles execute/read/write/create/remove/rename/truncate; newer
    # device ioctl access is also denied when the kernel exposes it.
    handled = (1 << (16 if abi >= 5 else 15)) - 1
    attributes = Ruleset(handled)
    ruleset = libc.syscall(444, ctypes.byref(attributes), ctypes.sizeof(attributes), 0)
    if ruleset < 0:
        raise OSError(ctypes.get_errno(), "Could not create parser ruleset")
    try:
        libraries = [Path(sys.base_prefix) / "lib", Path("/usr/lib"), Path("/lib")]
        paths = [(Path(input_path).resolve(), 1 << 2)]
        paths.extend((path, (1 << 2) | (1 << 3)) for path in libraries if path.exists())
        for path, rights in paths:
            descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = Rule(rights, descriptor)
                if libc.syscall(445, ruleset, 1, ctypes.byref(rule), 0):
                    raise OSError(ctypes.get_errno(), "Could not add parser rule")
            finally:
                os.close(descriptor)
        if libc.prctl(38, 1, 0, 0, 0) or libc.syscall(446, ruleset, 0):
            raise OSError(ctypes.get_errno(), "Could not enforce parser ruleset")
    finally:
        os.close(ruleset)

    architecture = platform.machine()
    if architecture == "x86_64":
        audit_arch = 0xC000003E
        denied = [41, 53, 101, 62, 200, 234, 310, 311, 424, 438, 437, 425, 426, 427]
    elif architecture == "aarch64":
        audit_arch = 0xC00000B7
        denied = [198, 199, 117, 129, 130, 131, 270, 271, 424, 438, 437, 425, 426, 427]
    else:
        raise OSError("Unsupported production parser architecture")

    class Filter(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint32),
        ]

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]

    # Reject alternate syscall architectures and x32 before the deny rules.
    instructions = [
        (0x20, 0, 0, 4),
        (0x15, 1, 0, audit_arch),
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),
        (0x35, 0, 1, 0x40000000),
        (0x06, 0, 0, 0x80000000),
    ]
    for number in denied:
        instructions.extend([(0x15, 0, 1, number), (0x06, 0, 0, 0x50000 | errno.EPERM)])
    instructions.append((0x06, 0, 0, 0x7FFF0000))
    filters = (Filter * len(instructions))(*(Filter(*item) for item in instructions))
    program = Program(len(filters), filters)
    if libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise OSError(ctypes.get_errno(), "Could not enforce parser seccomp")
