# -*- coding: utf-8 -*-
"""
internal python 2/python 3 bridges. Not for external use.
"""

from __future__ import print_function, absolute_import, division


import sys

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] >= 3
PYPY = hasattr(sys, 'pypy_version_info')

## Types

if PY3:
    string_types = (str,)
    integer_types = (int,)
    text_type = str
    binary_type = bytes

else:
    import __builtin__ # pylint:disable=import-error
    string_types = __builtin__.basestring,
    text_type = __builtin__.unicode
    integer_types = (int, __builtin__.long)
    binary_type = str


## Functions
if PY3:
    iteritems = dict.items
    itervalues = dict.values
    xrange = range
else:
    iteritems = dict.iteritems # python 3: pylint:disable=no-member
    itervalues = dict.itervalues # python 3: pylint:disable=no-member
    xrange = __builtin__.xrange
