#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import math
from collections import defaultdict
# import select as _select

from ._compat import integer_types
from ._fstack import ffi, lib


EPOLLERR = lib.EPOLLERR
EPOLLET = lib.EPOLLET
EPOLLHUP = lib.EPOLLHUP
EPOLLIN = lib.EPOLLIN
EPOLLMSG = lib.EPOLLMSG
EPOLLONESHOT = lib.EPOLLONESHOT
EPOLLOUT = lib.EPOLLOUT
EPOLLPRI = lib.EPOLLPRI
EPOLLRDBAND = lib.EPOLLRDBAND
EPOLLRDNORM = lib.EPOLLRDNORM
EPOLLWRBAND = lib.EPOLLWRBAND
EPOLLWRNORM = lib.EPOLLWRNORM
# EPOLL_CLOEXEC = _select.EPOLL_CLOEXEC
PIPE_BUF = lib.PIPE_BUF
POLLERR = lib.POLLERR
POLLHUP = lib.POLLHUP
POLLIN = lib.POLLIN
POLLMSG = lib.POLLMSG
POLLNVAL = lib.POLLNVAL
POLLOUT = lib.POLLOUT
POLLPRI = lib.POLLPRI
POLLRDBAND = lib.POLLRDBAND
POLLRDNORM = lib.POLLRDNORM
POLLWRBAND = lib.POLLWRBAND
POLLWRNORM = lib.POLLWRNORM

# fliters
KQ_FILTER_READ = lib.EVFILT_READ
KQ_FILTER_WRITE = lib.EVFILT_WRITE
KQ_FILTER_AIO = lib.EVFILT_AIO
KQ_FILTER_VNODE = lib.EVFILT_VNODE
KQ_FILTER_PROC = lib.EVFILT_PROC
# KQ_FILTER_NETDEV = lib.EVFILT_NETDEV
KQ_FILTER_SIGNAL = lib.EVFILT_SIGNAL
KQ_FILTER_TIMER = lib.EVFILT_TIMER

# flags
KQ_EV_ADD = lib.EV_ADD
KQ_EV_DELETE = lib.EV_DELETE
KQ_EV_ENABLE = lib.EV_ENABLE
KQ_EV_DISABLE = lib.EV_DISABLE
KQ_EV_ONESHOT = lib.EV_ONESHOT
KQ_EV_CLEAR = lib.EV_CLEAR
KQ_EV_SYSFLAGS = lib.EV_SYSFLAGS
KQ_EV_FLAG1 = lib.EV_FLAG1
KQ_EV_EOF = lib.EV_EOF
KQ_EV_ERROR = lib.EV_ERROR

# fflags
KQ_NOTE_LOWAT = lib.NOTE_LOWAT


NOTE_DELETE = lib.NOTE_DELETE
NOTE_WRITE = lib.NOTE_WRITE
NOTE_EXTEND = lib.NOTE_EXTEND
NOTE_ATTRIB = lib.NOTE_ATTRIB
NOTE_LINK = lib.NOTE_LINK
NOTE_RENAME = lib.NOTE_RENAME
NOTE_REVOKE = lib.NOTE_REVOKE


NOTE_EXIT = lib.NOTE_EXIT
NOTE_FORK = lib.NOTE_FORK
NOTE_EXEC = lib.NOTE_EXEC
NOTE_PCTRLMASK = lib.NOTE_PCTRLMASK
NOTE_PDATAMASK = lib.NOTE_PDATAMASK
NOTE_TRACK = lib.NOTE_TRACK
NOTE_TRACKERR = lib.NOTE_TRACKERR
NOTE_CHILD = lib.NOTE_CHILD


class error(Exception):
    def __init__(self, ss):
        self.ss = ss

    def __str__(self):
        return self.ss


def select(rlist, wlist, xlist, timeout=None):
    rfd_list = [fd if isinstance(fd, int) else fd.fileno() for fd in rlist]
    wfd_list = [fd if isinstance(fd, int) else fd.fileno() for fd in wlist]
    xfd_list = [fd if isinstance(fd, int) else fd.fileno() for fd in xlist]

    maxfd1 = max(rfd_list + wfd_list + xfd_list) + 1
    rfdset = ffi.new("fd_set*")
    lib.FD_ZERO(rfdset)
    for fd in rfd_list:
        lib.FD_SET(fd, rfdset)

    wfdset = ffi.new("fd_set*")
    lib.FD_ZERO(wfdset)
    for fd in wfd_list:
        lib.FD_SET(fd, wfdset)

    xfdset = ffi.new("fd_set*")
    lib.FD_ZERO(xfdset)
    for fd in xfd_list:
        lib.FD_SET(fd, xfdset)
    if timeout is None:
        tvp = ffi.NULL
    else:
        t1, t2 = math.modf(timeout)
        tv = {"tv_sec": t1, "tv_usec": int(t2*1000)}
        tvp = ffi.new("struct timeval*", tv)
    ret = lib.ff_select(maxfd1, rfdset, wfdset, xfdset, tvp)
    if ret < 0:
        raise error("select: ")
    rreturn = []
    for i, fd in enumerate(rfd_list):
        if lib.FD_ISSET(fd, rfdset) == 1:
            rreturn.append(rlist[i])

    wreturn = []
    for i, fd in enumerate(wfd_list):
        if lib.FD_ISSET(fd, wfdset) == 1:
            wreturn.append(rlist[i])

    xreturn = []
    for i, fd in enumerate(xfd_list):
        if lib.FD_ISSET(fd, xfdset) == 1:
            xreturn.append(rlist[i])
    return rreturn, wreturn, xreturn


class epoll(object):
    def __init__(self, sizehint=-1, epfd=None):
        if sizehint == -1:
            sizehint = lib.FD_SETSIZE - 1
        if sizehint < 0:
            raise ValueError("negative sizehint.")
        if epfd is None:
            self.epfd = lib.ff_epoll_create(sizehint)
        else:
            self.epfd = epfd
        if self.epfd < 0:
            raise error("epoll: ")
        self.events = None
        self.maxevents = 0

    def close(self):
        lib.ff_close(self.epfd)

    def fileno(self):
        return self.epfd

    @classmethod
    def fromfd(cls, fd):
        obj = cls(epfd=fd)
        return obj

    def register(self, fd, eventmask=None):
        if eventmask is None:
            eventmask = EPOLLIN | EPOLLOUT | EPOLLPRI
        ev = ffi.new("struct epoll_event*")
        lib.EPOLL_EV_SET_MASK(ev, eventmask)
        lib.EPOLL_EV_SET_FD(ev, fd)
        err = lib.ff_epoll_ctl(self.epfd, lib.EPOLL_CTL_ADD, fd, ev)
        if err < 0:
            raise error("register: ")

    def modify(self, fd, eventmask):
        ev = ffi.new("struct epoll_event*")

        lib.EPOLL_EV_SET_MASK(ev, eventmask)
        lib.EPOLL_EV_SET_FD(ev, fd)
        err = lib.ff_epoll_ctl(self.epfd, lib.EPOLL_CTL_MOD, fd, ev)
        if err < 0:
            raise error("register: ")

    def unregister(self, fd):
        err = lib.ff_epoll_ctl(self.epfd, lib.EPOLL_CTL_DEL, fd, ffi.NULL)
        if err < 0:
            raise error("unregister:")

    def poll(self, timeout=-1, maxevents=-1):
        if timeout != -1:
            # timeout for epoll_wait is milliseconds
            timeout = int(timeout * 1000)
        if maxevents == -1:
            maxevents = lib.FD_SETSIZE-1
        if maxevents != self.maxevents:
            self.events = ffi.new("struct epoll_event[]", maxevents)
            self.maxevents = maxevents
        nfds = lib.ff_epoll_wait(self.epfd, self.events,
                                 self.maxevents, timeout)
        if nfds < 0:
            raise error("poll: ")
        res = []
        for i in range(nfds):
            ev_struct = self.events[i]
            ev = ffi.addressof(ev_struct)
            res.append((lib.EPOLL_EV_GET_FD(ev), lib.EPOLL_EV_GET_MASK(ev)))
        return res


class poll(object):
    def __init__(self):
        self.fd_ev = {}

    def register(self, fd, eventmask=None):
        if eventmask is None:
            eventmask = POLLIN | POLLPRI | POLLOUT
        self.fd_ev[fd] = eventmask

    def modify(self, fd, eventmask):
        self.fd_ev[fd] = eventmask

    def unregister(self, fd):
        self.fd.ev.pop(fd)

    def poll(self, timeout):
        nfds = len(self.fd_ev)
        fd_list = self.fd_ev.keys()
        fds = ffi.new("struct pollfd[]", nfds)
        for i, fd in enumerate(fd_list):
            fds[i] = [fd, self.fd_ev[fd]]
        ret = lib.ff_poll(fds, nfds, timeout)
        if ret < 0:
            raise error("poll: ")
        result_list = []
        for i in range(nfds):
            if fds[i].revents != 0:
                result_list.append((fds[i].fd, fds[i].revents))
        return result_list


class kevent(object):
    def __init__(self, ident, filter=KQ_FILTER_READ,
                 flags=KQ_EV_ADD, fflags=0, data=0, udata=0):
        self.ident = ident
        self.filter = filter
        self.flags = flags
        self.fflags = fflags
        self.data = data
        self.udata = udata

    def to_c_kevent(self):
        c_ev = ffi.new("struct kevent*")
        self.init_c_kevent(c_ev)
        return c_ev

    def init_c_kevent(self, c_ev):
        c_ev.ident = self.ident
        c_ev.filter = self.filter
        c_ev.flags = self.flags
        c_ev.fflags = self.fflags
        c_ev.data = self.data
        c_ev.udata = ffi.NULL

    @classmethod
    def from_c_kevent(cls, c_ev, udata):
        ev = cls(c_ev.ident, c_ev.filter, c_ev.flags, c_ev.fflags,
                 c_ev.data, udata)
        return ev

    def __str__(self):
        return "Kevent<fd: %d, filter: %d, flags: %d, fflags:%d>" % \
            (self.ident, self.filter, self.flags, self.fflags)


class kqueue(object):
    def __init__(self, kfd=None):
        if kfd is None:
            self.kfd = lib.ff_kqueue()
        else:
            self.kfd = kfd
        if self.kfd < 0:
            raise error("kqueue: ")
        # we don't pass udata to the kevent system call,
        # so we use a dict to track udata attached to every fd
        self.udata_map = defaultdict(lambda: None)
        # cache kevent cdata object array,
        # so we can avoid allocate memory too often
        self.maxevents = -1
        self.events = None

    def close(self):
        res = lib.ff_close(self.kfd)
        if res < 0:
            raise error("close: ")

    def fileno(self):
        return self.kfd

    @classmethod
    def fromfd(cls, fd):
        return cls(fd)

    def control(self, changelist, maxevents, timeout=None):
        if changelist is None:
            c_changelist = ffi.NULL
            nchanges = 0
        else:
            nchanges = len(changelist)
            c_changelist = ffi.new("struct kevent[]", nchanges)
            for i in range(nchanges):
                ev = changelist[i]
                c_ev = ffi.addressof(c_changelist[i])
                ev.init_c_kevent(c_ev)
                # update udata_map
                if ev.flags & KQ_EV_DELETE:
                    self.ev_map.pop(ev.ident, None)
                else:
                    self.udata_map[ev.ident] = ev.udata
        if not isinstance(maxevents, integer_types):
            raise TypeError("maxevents should be positive integer")
        if maxevents < 0:
            raise ValueError("negative maxevents")
        if maxevents == 0:
            c_reslist = ffi.NULL
        else:
            if maxevents == self.maxevents:
                c_reslist = self.events
            else:
                c_reslist = ffi.new("struct kevent[]", maxevents)
                self.maxevents = maxevents
                self.events = c_reslist
        if timeout is None:
            c_timeout = ffi.NULL
        else:
            c_timeout = ffi.new("struct timespec*")
            t1, t2 = math.modf(timeout)
            c_timeout.tv_sec = t1
            c_timeout.tv_nsec = int(t2*1000000)
        res = lib.ff_kevent(self.kfd, c_changelist, nchanges,
                            c_reslist, maxevents, c_timeout)
        if res < 0:
            raise error("control: ")
        result = []
        for i in range(res):
            c_ev = ffi.addressof(c_reslist[i])
            fd = c_ev.ident
            result.append(kevent.from_c_kevent(c_ev, self.udata_map[fd]))
        return result

    def do_each(self, changelist, maxevents, fn, timeout=None):
        pass
