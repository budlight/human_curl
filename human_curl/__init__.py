# -*- coding:  utf-8 -*-
"""
HUMAN cURL LIBRARY
~~~~~~~~~~~~~~~~~~

cURL wrapper for Human

Features:
    - Fast
    - Custom HTTP headers
    - Request data/params
    - Multiple file uploading
    - Cookies support (dict or CookieJar)
    - Redirection history
    - Proxy support (http, https, socks4/5)
    - Custom interface for request!
    - Auto decompression of GZipped content
    - Unicode URL support
    - Request timers and another info
    - Certificate validation
    - ipv6 support
    - Basic/Digest authentication
    - OAuth support!
    - Debug request and response headers
    - Multicurl support

:copyright: (c) 2011 - 2012 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""


__title__ = 'human_curl'
__version__ = '2.5.1'
__author__ = 'Kenneth Reitz'
__license__ = 'Apache 2.0'
__copyright__ = 'Copyright 2015 Kenneth Reitz'
__build__ = 0x000012
__maintainer__ = "Alexandr Lispython (alex@obout.ru)"
__package__ = 'human_curl'

def get_version():
    return __version__

from .methods import get, put, head, post, delete, request, options
from .core import Request, Response
from .exceptions import CurlError, InterfaceError, InvalidMethod, AuthError
from .async import AsyncClient, async_client
