#!/usr/bin/env python
# -*- coding:utf-8 -*-
import sys
import os
import re
from os import path
import subprocess
from setuptools import setup, find_packages


CUR_DIR = path.dirname(path.realpath(__file__))
CFSTACK_DIR = path.join(CUR_DIR, "cfstack")


needs_pytest = {'pytest', 'test', 'ptr'}.intersection(sys.argv)
pytest_runner = ['pytest-runner'] if needs_pytest else []


def find_version(*paths):
    fname = os.path.join(*paths)
    with open(fname) as fhandler:
        version_file = fhandler.read()
        version_match = re.search(r"^__VERSION__ = ['\"]([^'\"]*)['\"]",
                                  version_file, re.M)

    if not version_match:
        raise RuntimeError("Unable to find version string in %s" % (fname,))

    version = version_match.group(1)
    return version


version = find_version('pyfstack', '__init__.py')


def prepare_cfstack():
    dpdk_target = os.getenv("FF_DPDK_TARGET", "x86_64-native-linuxapp-gcc")
    dpdk_build_dir = path.join(CFSTACK_DIR, "dpdk", dpdk_target)
    if not path.exists(dpdk_build_dir):
        cmd = "make dpdk FF_DPDK_TARGET=%s" % (dpdk_target, )
        subprocess.check_call(cmd, shell=True)
    FSTACK_LIB_NAME = path.join(CFSTACK_DIR, "lib", "libfstack.a")
    if not path.exists(FSTACK_LIB_NAME):
        cmd = "make fstack FF_DPDK_TARGET=%s" % (dpdk_target, )
        subprocess.check_call(cmd, shell=True)


prepare_cfstack()


setup(
    name="pyfstack",
    version=version,
    description="python binding for f-stack",
    long_description=open(path.join(CUR_DIR, "readme.md"), "rt").read(),
    url="https://github.com/f-stack/f-stack/python",
    author="Yu Yang",
    author_email="yyangplus@gmail.com",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: PyPy",
        "License :: OSI Approved :: BSD License",
    ],
    packages=find_packages(),
    install_requires=[
        "cffi>=1.0.0",
    ],
    setup_requires=["cffi>=1.0.0"] + pytest_runner,
    tests_require=[
        'pytest-cov',
        'pytest-randomly',
        'pytest-mock',
        'pytest'
    ],
    cffi_modules=[
        "fstack_cffi/fstack_build.py:ffibuilder",
    ],
)
