#!/usr/bin/env python
# -*- coding:utf-8 -*-
from __future__ import print_function, division, absolute_import
from pyfstack import select, socket, _fstack
from pyfstack._fstack import ffi, lib
import code


def test_select():
    fdset = ffi.new("fd_set*")
    assert lib.FD_ISSET(10, fdset) == 0
    lib.FD_SET(10, fdset)
    assert lib.FD_ISSET(10, fdset) == 1


# def test_poll(mocker):
#     m = mocker.patch("code.lib.ff_poll")
#     m.return_value = 120
#     pollobj = select.poll()
#     pollobj.register(1, select.POLLIN)
#     pollobj.register(2, select.POLLOUT)
#     pollobj.poll(10)
#     args, _ = m.call_args
#     assert args is not None
#     fds, nfds, timeout = args
#     assert timeout == 10
#     assert nfds == 2


def test_addr():
    # ipv4
    address = ('127.0.0.1', 80)
    addr, addrlen = socket._gen_sockaddr(socket.AF_INET, address)
    sockaddr = ffi.cast("struct linux_sockaddr*", addr)
    assert sockaddr.sa_family == socket.AF_INET
    c_addrlen = ffi.new("socklen_t*", addrlen)
    ip, port = socket._parse_sockaddr(sockaddr, c_addrlen)
    assert socket.inet_pton(socket.AF_INET, ip) == \
        socket.inet_pton(socket.AF_INET, address[0])
    assert port == address[1]

    # ipv6
    address = ('2001:0db8:85a3:0000:0000:8a2e:0370:7334', 80)
    addr, addrlen = socket._gen_sockaddr(socket.AF_INET6, address)
    sockaddr = ffi.cast("struct linux_sockaddr*", addr)
    assert sockaddr.sa_family == socket.AF_INET6
    c_addrlen = ffi.new("socklen_t*", addrlen)
    ip, port = socket._parse_sockaddr(sockaddr, c_addrlen)
    assert socket.inet_pton(socket.AF_INET6, ip) == \
        socket.inet_pton(socket.AF_INET6, address[0])
    assert port == address[1]


def test_epoll():
    pass
