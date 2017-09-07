#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""



"""
from __future__ import print_function, division, absolute_import
import os
import errno
import socket as _socket
from socket import ntohl, ntohs, htonl, htons
import struct

from ._compat import integer_types, binary_type
from ._fstack import ffi, lib


__constant_name = [
    'AF_APPLETALK',
    'AF_ASH',
    'AF_ATMPVC',
    'AF_ATMSVC',
    'AF_AX25',
    'AF_BLUETOOTH',
    'AF_BRIDGE',
    'AF_DECnet',
    'AF_ECONET',
    'AF_INET',
    'AF_INET6',
    'AF_IPX',
    'AF_IRDA',
    'AF_KEY',
    'AF_LLC',
    'AF_NETBEUI',
    'AF_NETLINK',
    'AF_NETROM',
    'AF_PACKET',
    'AF_PPPOX',
    'AF_ROSE',
    'AF_ROUTE',
    'AF_SECURITY',
    'AF_SNA',
    'AF_TIPC',
    'AF_UNIX',
    'AF_UNSPEC',
    'AF_WANPIPE',
    'AF_X25',
    'AI_ADDRCONFIG',
    'AI_ALL',
    'AI_CANONNAME',
    'AI_NUMERICHOST',
    'AI_NUMERICSERV',
    'AI_PASSIVE',
    'AI_V4MAPPED',
    'BDADDR_ANY',
    'BDADDR_LOCAL',
    'BTPROTO_HCI',
    'BTPROTO_L2CAP',
    'BTPROTO_RFCOMM',
    'BTPROTO_SCO',
    'CAPI',
    'EAI_ADDRFAMILY',
    'EAI_AGAIN',
    'EAI_BADFLAGS',
    'EAI_FAIL',
    'EAI_FAMILY',
    'EAI_MEMORY',
    'EAI_NODATA',
    'EAI_NONAME',
    'EAI_OVERFLOW',
    'EAI_SERVICE',
    'EAI_SOCKTYPE',
    'EAI_SYSTEM',
    'EBADF',
    'EINTR',
    'HCI_DATA_DIR',
    'HCI_FILTER',
    'HCI_TIME_STAMP',
    'INADDR_ALLHOSTS_GROUP',
    'INADDR_ANY',
    'INADDR_BROADCAST',
    'INADDR_LOOPBACK',
    'INADDR_MAX_LOCAL_GROUP',
    'INADDR_NONE',
    'INADDR_UNSPEC_GROUP',
    'IPPORT_RESERVED',
    'IPPORT_USERRESERVED',
    'IPPROTO_AH',
    'IPPROTO_DSTOPTS',
    'IPPROTO_EGP',
    'IPPROTO_ESP',
    'IPPROTO_FRAGMENT',
    'IPPROTO_GRE',
    'IPPROTO_HOPOPTS',
    'IPPROTO_ICMP',
    'IPPROTO_ICMPV6',
    'IPPROTO_IDP',
    'IPPROTO_IGMP',
    'IPPROTO_IP',
    'IPPROTO_IPIP',
    'IPPROTO_IPV6',
    'IPPROTO_NONE',
    'IPPROTO_PIM',
    'IPPROTO_PUP',
    'IPPROTO_RAW',
    'IPPROTO_ROUTING',
    'IPPROTO_RSVP',
    'IPPROTO_TCP',
    'IPPROTO_TP',
    'IPPROTO_UDP',
    'IPV6_CHECKSUM',
    'IPV6_DSTOPTS',
    'IPV6_HOPLIMIT',
    'IPV6_HOPOPTS',
    'IPV6_JOIN_GROUP',
    'IPV6_LEAVE_GROUP',
    'IPV6_MULTICAST_HOPS',
    'IPV6_MULTICAST_IF',
    'IPV6_MULTICAST_LOOP',
    'IPV6_NEXTHOP',
    'IPV6_PKTINFO',
    'IPV6_RECVDSTOPTS',
    'IPV6_RECVHOPLIMIT',
    'IPV6_RECVHOPOPTS',
    'IPV6_RECVPKTINFO',
    'IPV6_RECVRTHDR',
    'IPV6_RECVTCLASS',
    'IPV6_RTHDR',
    'IPV6_RTHDRDSTOPTS',
    'IPV6_RTHDR_TYPE_0',
    'IPV6_TCLASS',
    'IPV6_UNICAST_HOPS',
    'IPV6_V6ONLY',
    'IP_ADD_MEMBERSHIP',
    'IP_DEFAULT_MULTICAST_LOOP',
    'IP_DEFAULT_MULTICAST_TTL',
    'IP_DROP_MEMBERSHIP',
    'IP_HDRINCL',
    'IP_MAX_MEMBERSHIPS',
    'IP_MULTICAST_IF',
    'IP_MULTICAST_LOOP',
    'IP_MULTICAST_TTL',
    'IP_OPTIONS',
    'IP_RECVOPTS',
    'IP_RECVRETOPTS',
    'IP_RETOPTS',
    'IP_TOS',
    'IP_TTL',
    'MSG_CTRUNC',
    'MSG_DONTROUTE',
    'MSG_DONTWAIT',
    'MSG_EOR',
    'MSG_OOB',
    'MSG_PEEK',
    'MSG_TRUNC',
    'MSG_WAITALL',
    'MethodType',
    'NETLINK_DNRTMSG',
    'NETLINK_FIREWALL',
    'NETLINK_IP6_FW',
    'NETLINK_NFLOG',
    'NETLINK_ROUTE',
    'NETLINK_USERSOCK',
    'NETLINK_XFRM',
    'NI_DGRAM',
    'NI_MAXHOST',
    'NI_MAXSERV',
    'NI_NAMEREQD',
    'NI_NOFQDN',
    'NI_NUMERICHOST',
    'NI_NUMERICSERV',
    'PACKET_BROADCAST',
    'PACKET_FASTROUTE',
    'PACKET_HOST',
    'PACKET_LOOPBACK',
    'PACKET_MULTICAST',
    'PACKET_OTHERHOST',
    'PACKET_OUTGOING',
    'PF_PACKET',
    'RAND_add',
    'RAND_egd',
    'RAND_status',
    'SHUT_RD',
    'SHUT_RDWR',
    'SHUT_WR',
    'SOCK_DGRAM',
    'SOCK_RAW',
    'SOCK_RDM',
    'SOCK_SEQPACKET',
    'SOCK_STREAM',
    'SOL_HCI',
    'SOL_IP',
    'SOL_SOCKET',
    'SOL_TCP',
    'SOL_TIPC',
    'SOL_UDP',
    'SOMAXCONN',
    'SO_ACCEPTCONN',
    'SO_BROADCAST',
    'SO_DEBUG',
    'SO_DONTROUTE',
    'SO_ERROR',
    'SO_KEEPALIVE',
    'SO_LINGER',
    'SO_OOBINLINE',
    'SO_RCVBUF',
    'SO_RCVLOWAT',
    'SO_RCVTIMEO',
    'SO_REUSEADDR',
    'SO_REUSEPORT',
    'SO_SNDBUF',
    'SO_SNDLOWAT',
    'SO_SNDTIMEO',
    'SO_TYPE',
    'SSL_ERROR_EOF',
    'SSL_ERROR_INVALID_ERROR_CODE',
    'SSL_ERROR_SSL',
    'SSL_ERROR_SYSCALL',
    'SSL_ERROR_WANT_CONNECT',
    'SSL_ERROR_WANT_READ',
    'SSL_ERROR_WANT_WRITE',
    'SSL_ERROR_WANT_X509_LOOKUP',
    'SSL_ERROR_ZERO_RETURN',
    'TCP_CORK',
    'TCP_DEFER_ACCEPT',
    'TCP_INFO',
    'TCP_KEEPCNT',
    'TCP_KEEPIDLE',
    'TCP_KEEPINTVL',
    'TCP_LINGER2',
    'TCP_MAXSEG',
    'TCP_NODELAY',
    'TCP_QUICKACK',
    'TCP_SYNCNT',
    'TCP_WINDOW_CLAMP',
    'TIPC_ADDR_ID',
    'TIPC_ADDR_NAME',
    'TIPC_ADDR_NAMESEQ',
    'TIPC_CFG_SRV',
    'TIPC_CLUSTER_SCOPE',
    'TIPC_CONN_TIMEOUT',
    'TIPC_CRITICAL_IMPORTANCE',
    'TIPC_DEST_DROPPABLE',
    'TIPC_HIGH_IMPORTANCE',
    'TIPC_IMPORTANCE',
    'TIPC_LOW_IMPORTANCE',
    'TIPC_MEDIUM_IMPORTANCE',
    'TIPC_NODE_SCOPE',
    'TIPC_PUBLISHED',
    'TIPC_SRC_DROPPABLE',
    'TIPC_SUBSCR_TIMEOUT',
    'TIPC_SUB_CANCEL',
    'TIPC_SUB_PORTS',
    'TIPC_SUB_SERVICE',
    'TIPC_TOP_SRV',
    'TIPC_WAIT_FOREVER',
    'TIPC_WITHDRAWN',
    'TIPC_ZONE_SCOPE',
]


for name in __constant_name:
    globals()[name] = getattr(_socket, name)


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
        c_ip = ffi.new("char[4]", ip)
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
    addrlen = ffi.new("socklen_t*", sz)
    return addr, addrlen


def _parse_sockaddr(sockaddr, addrlen):
    addrlen = addrlen[0]
    af = sockaddr.sa_family
    if af == AF_INET:
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
            raise RuntimeError
        res.append((cmsg_level, cmsg_type, cmsg_data))
    return res


def _gen_anc_buf(anc_list):
    socklen_size = ffi.sizeof("socklen_t")
    res = []
    for cmsg_level, cmsg_type, cmsg_data in anc_list:
        if socklen_size == 4:
            totallen = 12 + len(cmsg_data)
            bb = struct.pack("=iii", totallen, cmsg_level, cmsg_type)
            res.append(bb+cmsg_data)
        elif socklen_size == 8:
            totallen = 16 + len(cmsg_data)
            bb = struct.pack("=iii", totallen, cmsg_level, cmsg_type)
            res.append(bb+cmsg_data)
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
            buflen = 4
            optval = ffi.new("int*")
        else:
            optval = ffi.new("char[]", buflen)
        optlen = ffi.new("socklen_t*", buflen)
        ret = lib.ff_getsockopt(self.fd, level, optname, optval, optlen)
        if ret < 0:
            raise error("getsockopt: ")
        return optval[0] if buflen == 4 else ffi.string(optval)

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
        addr, addrlen = _gen_empty_sockaddr(AF_INET6)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        while True:
            fd = lib.ff_accept(self.fd, sockaddr, addrlen)
            if fd >= 0:
                break
            if ffi.errno == errno.EINTR:
                continue
            raise error("accept:")
        sock = socket(self.family, self.type, self.proto, fd)
        address = _parse_sockaddr(sockaddr, addrlen)
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
        addr, addrlen = _gen_empty_sockaddr(AF_INET6)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        ret = lib.ff_getpeername(self.fd, sockaddr, addrlen)
        if ret < 0:
            raise error("getpeername: ")
        return _parse_sockaddr(sockaddr, addrlen)

    def getsockname(self):
        addr, addrlen = _gen_empty_sockaddr(AF_INET6)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        ret = lib.ff_getsockname(self.fd, sockaddr, addrlen)
        if ret < 0:
            raise error("getsockname: ")
        return _parse_sockaddr(sockaddr, addrlen)

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
        addr, addrlen = _gen_empty_sockaddr(AF_INET6)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        cbuf = ffi.new("char[]", bufsize)

        n = lib.ff_recvfrom(self.fd, cbuf, bufsize, flags, sockaddr, addrlen)
        if n < 0:
            raise error("recvfrom: ")
        buf = ffi.buffer(cbuf, n)
        address = _parse_sockaddr(sockaddr, addrlen)
        return bytes(buf), address

    def recvfrom_into(self, buf, nbytes=0, flags=0):
        if nbytes == 0:
            nbytes = len(buf)
        cbuf = ffi.from_buffer(buf)
        if nbytes < 0:
            raise ValueError("negative buffersize in recvfrom")

        addr, addrlen = _gen_empty_sockaddr(AF_INET6)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)

        n = lib.ff_recvfrom(self.fd, cbuf, nbytes, flags, sockaddr, addrlen)
        if n < 0:
            raise error("recvfrom: ")
        address = _parse_sockaddr(sockaddr, addrlen)
        return n, address

    def recvmsg(self, bufsize, ancbufsize=0, flags=0):
        if bufsize < 0:
            raise ValueError("negative buffersize in recvfrom")

        addr, addrlen = _gen_empty_sockaddr(AF_INET6)
        sockaddr = ffi.cast("struct linux_sockaddr*", addr)
        cbuf = ffi.new("char[]", bufsize)
        c_ancbuf = ffi.new("char[]", ancbufsize)
        c_ancbuf_len = ffi.new("int*", ancbufsize)
        c_flags = ffi.new("int*", flags)
        n = lib.py_recvmsg(self.fd, cbuf, bufsize, c_ancbuf,
                           c_ancbuf_len, c_flags, sockaddr, addrlen)
        if n < 0:
            raise error("recvmsg:")
        address = _parse_sockaddr(sockaddr, addrlen)
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
            raise TypeError("sendto takes at most 3 arguments (%d given)" % len(args)+1)
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
