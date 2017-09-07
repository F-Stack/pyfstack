#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
from os import path
from cffi import FFI
CUR_DIR = path.dirname(path.realpath(__file__))
CFSTACK_DIR = path.join(path.dirname(CUR_DIR), "cfstack")
FF_DPDK = path.join(CFSTACK_DIR, "dpdk", "x86_64-native-linuxapp-gcc")


def check_cfstack():
    """
    build f-stack
    """
    if not path.exists(FF_DPDK):
        raise RuntimeError("dpdk needs build, pls run make at the top of source tree")
    FSTACK_LIB_NAME = path.join(CFSTACK_DIR, "lib", "libfstack.a")
    if not path.exists(FSTACK_LIB_NAME):
        raise RuntimeError("fstack needs build, pls run make at the top of source tree")

check_cfstack()


with open(path.join(CUR_DIR, "fstack_source.c")) as f:
    _SOURCE = f.read()
with open(path.join(CUR_DIR, "fstack_cdef.h")) as f:
    _CDEF = f.read()

_LIBS = [
    " -Wl,--whole-archive,-lfstack,--no-whole-archive ",
    " -g -Wl,--no-as-needed -fvisibility=default -pthread -lm -lrt ",
    " -Wl,--whole-archive -lrte_pmd_vmxnet3_uio -lrte_pmd_i40e -lrte_pmd_ixgbe -lrte_pmd_e1000 -lrte_pmd_ring",
    " -Wl,--whole-archive -lrte_hash -lrte_kvargs -Wl,-lrte_mbuf -lethdev -lrte_eal -Wl,-lrte_mempool",
    " -lrte_ring -lrte_cmdline -lrte_cfgfile -lrte_kni -lrte_timer -Wl,-lrte_pmd_virtio",
    " -Wl,--no-whole-archive -lrt -lm -ldl -lm -lcrypto",
]
_LIBS = ' '.join(_LIBS)

ffibuilder = FFI()

ffibuilder.set_source("pyfstack._fstack",
                      _SOURCE,
                      include_dirs=[path.join(CFSTACK_DIR, "lib")],
                      library_dirs=[
                          path.join(CFSTACK_DIR, "lib"),
                          path.join(FF_DPDK, "lib"),
                      ],
                      extra_link_args=_LIBS.split())

ffibuilder.cdef(_CDEF)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
