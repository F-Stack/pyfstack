#!/usr/bin/env python
# -*- coding:utf-8 -*-
from __future__ import print_function, division, absolute_import
from pyfstack import select, socket, _fstack
from pyfstack._fstack import ffi, lib


def test_select():
    fdset = ffi.new("fd_set*")
    assert lib.FD_ISSET(10, fdset) == 0
    lib.FD_SET(10, fdset)
    assert lib.FD_ISSET(10, fdset) == 1


# def test_poll(mocker):
#     mocker.patch("fstack._fstack.lib.ff_poll")
#     lib.ff_poll.return_value = 120
#     pollobj = select.poll()
#     pollobj.register(1, select.POLLIN)
#     pollobj.register(2, select.POLLOUT)
#     pollobj.poll(10)
#     args, _ = lib.ff_poll.call_args
#     assert args is not None
#     fds, nfds, timeout = args
#     assert timeout == 10
#     assert nfds == 2


def test_epoll():
    pass
