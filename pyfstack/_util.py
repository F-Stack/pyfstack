# -*- coding: utf-8 -*-
"""
internal utilities, not for external use.
"""

from __future__ import print_function, absolute_import, division

from ._compat import iteritems


class _NONE(object):
    """
    A special object you must never pass to any gevent API.
    Used as a marker object for keyword arguments that cannot have the
    builtin None (because that might be a valid value).
    """
    __slots__ = ()

    def __repr__(self):
        return '<default value>'


_NONE = _NONE()


def copy_globals(source,
                 globs,
                 only_names=None,
                 ignore_missing_names=False,
                 names_to_ignore=(),
                 names_to_include=(),
                 dunder_names_to_keep=('__all__', '__imports__'),
                 cleanup_globs=True,
                 key_check_fn=None):
    """
    Copy attributes defined in `source.__dict__` to the dictionary in globs
    (which should be the caller's globals()).

    Names that start with `__` are ignored (unless they are in
    *dunder_names_to_keep*). Anything found in *names_to_ignore* is
    also ignored.

    If *only_names* is given, only those attributes will be considered.
    In this case, *ignore_missing_names* says whether or not to raise an
    AttributeError if one of those names can't be found.

    If cleanup_globs has a true value, then common things imported but not used
    at runtime are removed, including this function.

    Returns a list of the names copied
    """
    if only_names:
        if ignore_missing_names:
            items = ((k, getattr(source, k, _NONE)) for k in only_names)
        else:
            items = ((k, getattr(source, k)) for k in only_names)
    else:
        items = iteritems(source.__dict__)

    copied = []
    for key, value in items:
        if value is _NONE:
            continue
        if key in names_to_ignore:
            continue
        if key.startswith("__") and key not in dunder_names_to_keep:
            continue
        if key_check_fn and \
           key_check_fn(key) is False and \
           key not in names_to_include:
            continue
        globs[key] = value
        copied.append(key)

    if cleanup_globs:
        if 'copy_globals' in globs:
            del globs['copy_globals']

    return copied


def is_buffer_object(obj):
    try:
        memoryview(obj)
        return True
    except TypeError:
        return False
