#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import sys
import os

from ._compat import integer_types, binary_type
from ._fstack import ffi, lib


@ffi.def_extern()
def loop_func(c_arg):
    fn, args, kwargs = ffi.from_handle(c_arg)
    res = fn(*args, **kwargs)
    return res if isinstance(res, integer_types) else 0


class Fstack(object):
    def __init__(self, config_file, proc_type, proc_id):
        argv = [
            sys.argv[0],
            "--conf=%s" % config_file,
            "--proc-type=%s" % proc_type,
            "--proc-id=%s" % proc_id,
        ]
        self.user_data = None
        argc = len(argv)
        argv_keepalive = [ffi.new("char[]", arg) for arg in argv]
        c_argv = ffi.new("char *[]", argv_keepalive)
        lib.ff_init(argc, c_argv)

    def run(self, fn, *args, **kwargs):
        assert self.user_data is None
        self.user_data = ffi.new_handle((fn, args, kwargs))
        return lib.ff_run(lib.loop_func, self.user_data)


def sysctl(name, namelen, oldp, oldlenp, newp, newlen):
    pass


def route_ctl(req, flag, dst, gw, netmask):
    pass


def rtioctl():
    pass
