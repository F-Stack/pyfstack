#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import os
import fcntl as _fcntl

from ._util import is_buffer_object, copy_globals

from ._compat import integer_types, binary_type
from ._fstack import ffi, lib

copy_globals(_fcntl, globals(),
             names_to_ignore=('fcntl', 'flock', 'ioctl', 'lockf'),
             cleanup_globs=False)


def fcntl(fd, cmd, arg=0):
    if isinstance(arg, integer_types):
        c_arg = arg
    elif isinstance(arg, binary_type):
        sz = len(arg)
        if sz > 1024:
            raise ValueError("fcntl string arg too long")
        c_arg = ffi.new("char[%d]" % len(arg), arg)
    else:
        raise ValueError("need integer or bytes")
    res = lib.ff_fcntl(fd, cmd, c_arg)
    if res < 0:
        raise IOError("fcntl: %s" % os.strerror(ffi.errno))

    if isinstance(arg, integer_types):
        return res
    else:
        buf = ffi.buffer(c_arg)
        return bytes(buf)


def ioctl(fd, request, arg=0, mutable_flag=True):
    if isinstance(arg, integer_types):
        c_arg = arg
        res = lib.ff_ioctl(fd, request, c_arg)
        if res < 0:
            raise IOError("ioctl: %s" % os.strerror(ffi.errno))
        return res
    elif isinstance(arg, binary_type):
        sz = len(arg)
        if sz > 1024:
            raise ValueError("fcntl string arg too long")
        c_arg = ffi.new("char[%d]" % len(arg), arg)

        res = lib.ff_ioctl(fd, request, c_arg)
        if res < 0:
            raise IOError("fcntl: %s" % os.strerror(ffi.errno))
        buf = ffi.buffer(c_arg)
        return bytes(buf)
    elif is_buffer_object(arg):
        sz = len(arg)
        if mutable_flag:
            if sz < ffi.IOCTL_BUFSZ:
                c_arg = ffi.new("char[]", bytes(arg))
            else:
                c_arg = ffi.from_buffer(arg)
        else:
            if sz > lib.IOCTL_BUFSZ:
                raise ValueError("ioctl string arg too long")
            else:
                c_arg = ffi.new("char[]", bytes(arg))

        res = lib.ff_ioctl(fd, request, c_arg)
        if res < 0:
            raise IOError("ioctl: %s" % os.strerror(ffi.errno))
        if mutable_flag and sz < lib.IOCTL_BUFSZ:
            buf = ffi.buffer(c_arg, sz)
            arg[:] = buf
        if (mutable_flag):
            return res
        else:
            buf = ffi.buffer(c_arg, sz)
            return bytes(buf)
    else:
        raise ValueError("need integer or bytes")
