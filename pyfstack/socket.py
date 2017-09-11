#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""



"""
from __future__ import print_function, division, absolute_import
import os
import errno
import socket as _socket
import struct

from ._util import copy_globals
from ._compat import integer_types, binary_type
from ._fstack import ffi, lib


# import attributes from builtin socket module
def __key_check_fn(k):
    includes = (
        'ntohl',
        'ntohs',
        'htonl',
        'htons',
        'inet_aton',
        'inet_ntoa',
        'inet_pton',
        'inet_ntop',
    )
    if k in includes:
        return True
    if k.isupper():
        return True
    return False


copy_globals(_socket, globals(),
             ignore_missing_names=True,
             key_check_fn=__key_check_fn)


class error(IOError):
    def __init__(self, prefix):
        self.prefix = prefix
        self.errno = ffi.errno

    def __str__(self):
        return "%s %s" % (self.prefix, os.strerror(self.errno))


timeout = error


def _gen_sockaddr(af, address):
    ip_s, port = address[0], address[1]
    ip = _socket.inet_pton(af, ip_s)
    if af == AF_INET:
        assert len(ip) == 4
        addr = ffi.new("struct sockaddr_in*")
        addrlen = ffi.sizeof("struct sockaddr_in")
        c_ip = ffi.new("char[4]", ip)
        lib.py_init_ipv4_addr(port, c_ip, addr)
    elif af == AF_INET6:
        assert len(ip) == 16
        addr = ffi.new("struct sockaddr_in6*")
        addrlen = ffi.sizeof("struct sockaddr_in6")
        c_ip = ffi.new("char[16]", ip)
        lib.py_init_ipv6_addr(port, c_ip, addr)
    else:
        raise ValueError("unsupport family.")
    return addr, addrlen


def _gen_empty_sockaddr(af):
    if af == AF_INET:
        addr = ffi.new("struct sockaddr_in*")
        sz = ffi.sizeof("struct sockaddr_in")
    elif af == AF_INET6:
        addr = ffi.new("struct sockaddr_in6*")
        sz = ffi.sizeof("struct sockaddr_in6")
    else:
        raise ValueError("unsupport family.")
    addrlenp = ffi.new("socklen_t*", sz)
    return addr, addrlenp


def _parse_sockaddr(sockaddr, addrlenp):
    addrlen = addrlenp[0]
    af = sockaddr.sa_family
    if af == AF_INET:
        assert addrlen == ffi.sizeof("struct sockaddr_in")
        addr = ffi.cast("struct sockaddr_in*", sockaddr)
        c_port = ffi.new("unsigned short*")
        c_ip = ffi.new("char[4]")
        lib.py_parse_ipv4_addr(c_port, c_ip, addr)
    elif af == AF_INET6:
        addr = ffi.cast("struct sockaddr_in6*", sockaddr)
        c_port = ffi.new("unsigned short*")
        c_ip = ffi.new("char[16]")
        lib.py_parse_ipv6_addr(c_port, c_ip, addr)
    else:
        raise ValueError("unsupport family.")
    ip = bytes(ffi.buffer(c_ip))
    s_ip = _socket.inet_ntop(af, ip)
    port = c_port[0]
    return s_ip, port


def _parse_anc_buf(buf, size):
    socklen_size = ffi.sizeof("socklen_t")
    start = buf
    res = []
    while len(start) > 0:
        if socklen_size == 4:
            m_size, cmsg_level, cmsg_type = struct.unpack("=iii", start)
            cmsg_data = start[12:m_size]
        elif socklen_size == 8:
            m_size, cmsg_level, cmsg_type = struct.unpack("=qii", start)
            cmsg_data = start[16:m_size]
        else:
            raise RuntimeError()
        res.append((cmsg_level, cmsg_type, cmsg_data))
    return res


def _gen_anc_buf(anc_list):
    socklen_size = ffi.sizeof("socklen_t")
    res = []
    for cmsg_level, cmsg_type, cmsg_data in anc_list:
        if socklen_size == 4:
            totallen = 12 + len(cmsg_data)
            bb = struct.pack("=iii", totallen, cmsg_level, cmsg_type)
            res.append(bb + cmsg_data)
        elif socklen_size == 8:
            totallen = 16 + len(cmsg_data)
            bb = struct.pack("=iii", totallen, cmsg_level, cmsg_type)
            res.append(bb + cmsg_data)
        else:
            raise RuntimeError()
    return b''.join(res)


class socket(object):
    def __init__(self, family=AF_INET, type=SOCK_STREAM, proto=0, fileno=None):
        self.family = family
        self.type = type
        self.proto = proto
        if fileno is None:
            self.fd = lib.ff_socket(family, type, proto)
        else:
            self.fd = fileno

    def fileno(self):
        return self.fd

    def setsockopt(self, level, optname, value):
        if isinstance(value, binary_type):
            buflen = len(value)
            optval = ffi.new("char[]", value)
        elif isinstance(value, integer_types):
            # integer
            buflen = 4
            optval = ffi.new("int*", value)
        else:
            raise ValueError("value should be int or bytes in setsockopt")
        ret = lib.ff_setsockopt(self.fd, level, optname, optval, buflen)
        if ret < 0:
            raise error("setsockopt: ")
        return ret

    def getsockopt(self, level, optname, buflen=None):
        if buflen is None:
            is_int = True
            buflen = 4
            optval = ffi.new("int*")
        else:
            is_int = False
            optval = ffi.new("char[]", buflen)
        optlen = ffi.new("socklen_t*", buflen)
        ret = lib.ff_getsockopt(self.fd, level, optname, optval, optlen)
        if ret < 0:
            raise error("getsockopt: ")

        if is_int:
            return optval[0]
        else:
            buf = ffi.buffer(optval, optlen[0])
            return bytes(buf)

    def listen(self, backlog=-1):
        if backlog < 0:
            backlog = min(SOMAXCONN, 128)
        res = lib.ff_listen(self.fd, backlog)
        if res < 0:
            raise error("listen:")

    def bind(self, address):
        addr, addrlen = _gen_sockaddr(self.family, address)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        res = lib.ff_bind(self.fd, sockaddr, addrlen)
        if res < 0:
            raise error("bind: ")

    def accept(self):
        addr, addrlen_p = _gen_empty_sockaddr(AF_INET6)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        while True:
            fd = lib.ff_accept(self.fd, sockaddr, addrlen_p)
            if fd >= 0:
                break
            if ffi.errno == errno.EINTR:
                continue
            raise error("accept:")
        sock = socket(self.family, self.type, self.proto, fd)
        address = _parse_sockaddr(sockaddr, addrlen_p)
        return sock, address

    def connect(self, address):
        addr, addrlen = _gen_sockaddr(self.family, address)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        ret = lib.ff_connect(self.fd, sockaddr, addrlen)
        if ret < 0:
            raise error("connect: ")

    def connect_ex(self, address):
        addr, addrlen = _gen_sockaddr(self.family, address)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        return lib.ff_connect(self.fd, sockaddr, addrlen)

    def close(self):
        res = lib.ff_close(self.fd)
        if res < 0 and ffi.errno != errno.ECONNRESET:
            raise error("close: ")

    def shutdown(self, how):
        res = lib.ff_shutdown(self.fd, how)
        if res < 0:
            raise error("shutdown: ")

    def getpeername(self):
        addr, addrlen_p = _gen_empty_sockaddr(AF_INET6)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        ret = lib.ff_getpeername(self.fd, sockaddr, addrlen_p)
        if ret < 0:
            raise error("getpeername: ")
        return _parse_sockaddr(sockaddr, addrlen_p)

    def getsockname(self):
        addr, addrlen_p = _gen_empty_sockaddr(AF_INET6)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        ret = lib.ff_getsockname(self.fd, sockaddr, addrlen_p)
        if ret < 0:
            raise error("getsockname: ")
        return _parse_sockaddr(sockaddr, addrlen_p)

    def recv(self, bufsize, flags=0):
        if bufsize < 0:
            raise ValueError("negative buffersize in recv")
        cbuf = ffi.new("char[]", bufsize)
        n = lib.ff_recv(self.fd, cbuf, bufsize, flags)
        if n < 0:
            raise error("recv: ")
        buf = ffi.buffer(cbuf, n)
        return bytes(buf)

    def recv_into(self, buf, nbytes=0, flags=0):
        if nbytes == 0:
            nbytes = len(buf)
        cbuf = ffi.from_buffer(buf)
        n = lib.ff_recv(self.fd, cbuf, nbytes, flags)
        if n < 0:
            raise error("recv: ")
        return n

    def recvfrom(self, bufsize, flags=0):
        if bufsize < 0:
            raise ValueError("negative buffersize in recvfrom")
        addr, addrlen_p = _gen_empty_sockaddr(AF_INET6)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        cbuf = ffi.new("char[]", bufsize)

        n = lib.ff_recvfrom(self.fd, cbuf, bufsize, flags, sockaddr, addrlen_p)
        if n < 0:
            raise error("recvfrom: ")
        buf = ffi.buffer(cbuf, n)
        address = _parse_sockaddr(sockaddr, addrlen_p)
        return bytes(buf), address

    def recvfrom_into(self, buf, nbytes=0, flags=0):
        if nbytes == 0:
            nbytes = len(buf)
        cbuf = ffi.from_buffer(buf)
        if nbytes < 0:
            raise ValueError("negative buffersize in recvfrom")

        addr, addrlen_p = _gen_empty_sockaddr(AF_INET6)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)

        n = lib.ff_recvfrom(self.fd, cbuf, nbytes, flags, sockaddr, addrlen_p)
        if n < 0:
            raise error("recvfrom: ")
        address = _parse_sockaddr(sockaddr, addrlen_p)
        return n, address

    def recvmsg(self, bufsize, ancbufsize=0, flags=0):
        if bufsize < 0:
            raise ValueError("negative buffersize in recvfrom")
        if ancbufsize < 0:
            raise ValueError("negative ancbufsize in recvfrom")

        addr, addrlen_p = _gen_empty_sockaddr(AF_INET6)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        cbuf = ffi.new("char[]", bufsize)
        if ancbufsize > 0:
            c_ancbuf = ffi.new("char[]", ancbufsize)
        else:
            c_ancbuf = ffi.NULL
        c_ancbuf_len = ffi.new("int*", ancbufsize)
        c_flags = ffi.new("int*", flags)
        n = lib.py_recvmsg(self.fd, cbuf, bufsize, c_ancbuf,
                           c_ancbuf_len, c_flags, sockaddr, addrlen_p)
        if n < 0:
            raise error("recvmsg:")
        address = _parse_sockaddr(sockaddr, addrlen_p)
        flags = c_flags[0]
        buf = ffi.buffer(cbuf, n)
        ancbuf = ffi.buffer(c_ancbuf, c_ancbuf_len[0])
        ancdata = _parse_anc_buf(bytes(ancbuf))
        return bytes(buf), ancdata, flags, address

    def send(self, data, flags=0):
        n = lib.ff_send(self.fd, data, len(data), flags)
        if n < 0:
            raise error("send: ")
        return n

    def sendto(self, data, *args):
        if len(args) == 1:
            flags = 0
            address = args[0]
        elif len(args) == 2:
            flags = args[0]
            address = args[1]
        else:
            raise TypeError("sendto takes at most 3 arguments(%d given)" %
                            (len(args) + 1))
        addr, addrlen = _gen_sockaddr(self.family, address)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        n = lib.ff_send(self.fd, data, len(data), flags, sockaddr, addrlen)
        if n < 0:
            raise error("sendto: ")
        return n

    def sendmsg(self, buffers, ancdata=0, flags=0, address=None):
        nbuffers = len(buffers)
        ancbuf = _gen_anc_buf(ancdata)
        c_ancbuf = ffi.from_buffer(ancbuf)
        cbuf_list = [ffi.from_buffer(buf) for buf in buffers]
        c_bufv = ffi.new("char *[]", cbuf_list)
        c_lenarr = ffi.new("int[]", [len(buf) for buf in buffers])
        if address is None:
            sockaddr = ffi.NULL
            addrlen = 0
        else:
            addr, addrlen = _gen_sockaddr(self.family, address)
            sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        res = lib.py_sendmsg(self.fd, c_bufv, c_lenarr, nbuffers,
                             c_ancbuf, len(ancbuf), flags, sockaddr, addrlen)
        if res < 0:
            raise error("sendmsg: ")
        return res

    def setblocking(self, blocking):
        flag = 1 if blocking else 0
        res = lib.py_setblocking(self.fd, flag)
        if res < 0:
            raise error("setblocking: ")


def socketpair(family, type, proto):
    sv = ffi.new("int[2]")
    ret = lib.ff_socketpair(family, type, proto, sv)
    if ret < 0:
        raise error("socketpair:")
    fd1, fd2 = sv[0], sv[1]
    return socket(family, type, proto, fd1), socket(family, type, proto, fd2)
