#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import os
import time
import signal
import argparse
from pyfstack import socket, select, fstack
EOL1 = b'\n\n'
EOL2 = b'\n\r\n'
html = [
    b"HTTP/1.1 200 OK\r\n",
    b"Server: F-Stack\r\n",
    b"Date: Sat, 25 Feb 2017 09:26:33 GMT\r\n",
    b"Content-Type: text/html\r\n",
    b"Content-Length: 439\r\n",
    b"Last-Modified: Tue, 21 Feb 2017 09:44:03 GMT\r\n",
    b"Connection: keep-alive\r\n",
    b"Accept-Ranges: bytes\r\n",
    b"\r\n",
    b"<!DOCTYPE html>\r\n",
    b"<html>\r\n",
    b"<head>\r\n",
    b"<title>Welcome to F-Stack!</title>\r\n",
    b"<style>\r\n",
    b"    body {  \r\n",
    b"        width: 35em;\r\n",
    b"        margin: 0 auto; \r\n",
    b"        font-family: Tahoma, Verdana, Arial, sans-serif;\r\n",
    b"    }\r\n",
    b"</style>\r\n",
    b"</head>\r\n",
    b"<body>\r\n",
    b"<h1>Welcome to F-Stack! </h1>\r\n",
    b"\r\n",
    b"<p>For online documentation and support please refer to\r\n",
    b"<a href=\"http://F-Stack.org/\">F-Stack.org</a>.<br/>\r\n",
    b"\r\n",
    b"<p><em>Thank you for using F-Stack.</em></p>\r\n",
    b"</body>\r\n",
    b"</html>",
]

response = b''.join(html)


prev_ts = time.time()

def sig_handler(signum, fram):
    print("receive:", signum)
    os._exit(0)


class KqueueServer(object):
    def __init__(self, address):
        kqobj = select.kqueue()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("listening fd %d" % sock.fileno())
        # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(address)
        sock.listen(1)
        # sock.setblocking(0)
        kev = socket.kevent(sock.fileno())
        kqobj.control([kev], 0)

        self.kqobj = kqobj
        self.sock = sock
        self.connections = {}

    @classmethod
    def loop(cls, srv):
        global prev_ts
        if time.time() - prev_ts > 5:
            prev_ts = time.time()
            print("loop")
        kqobj = srv.kqobj
        sock = srv.sock
        connections = srv.connections
        events = kqobj.control(None, 512)
        for ev in events:
            ev_fd = ev.ident
            print("kevent %s" % ev)
            if ev.flags & select.KQ_EV_EOF:
                conn = connections[ev_fd]
                conn.close()
                del connections[ev_fd]
            elif ev_fd == sock.fileno():
                conn, address = sock.accept()
                print("accept connection (%s:%s)" % (address[0], address[1]))
                # conn.setblocking(0)

                kev = socket.kevent(conn.fileno())
                kqobj.control([kev], 0)
                connections[conn.fileno()] = conn
            elif ev.filter == select.KQ_FILTER_READ:
                conn = connections[ev_fd]
                data = conn.recv(1024)
                print("recv %s", data.decode("utf8"))
                nbytes = conn.send(response)
                print("send %d bytes" % nbytes)
            else:
                raise Exception()


def parse_cmd_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--conf', required=True, help="config file name.")
    parser.add_argument('-t', '--proc-type', required=True, help="process type")
    parser.add_argument('-p', '--proc-id', required=True, help="process id")

    return parser.parse_args()


def main(parsed):
    ffobj = fstack.Fstack(parsed.conf, parsed.proc_type, parsed.proc_id)
    srv = KqueueServer(('0.0.0.0', 80))
    ffobj.run(KqueueServer.loop, srv)


if __name__ == '__main__':
    parsed = parse_cmd_args()
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)
    main(parsed)
