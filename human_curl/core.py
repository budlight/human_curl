#!/usr/bin/env python
# -*- coding:  utf-8 -*-
"""
human_curl.core
~~~~~~~~~~~~~~~

Heart of human_curl library


:copyright: Copyright 2011 - 2012 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""

import time
import io
import sys
import tempfile
from os.path import exists as file_exists
from logging import getLogger
from re import compile as re_compile
from string import capwords
from urllib.parse import urlencode, quote_plus
from http.cookiejar import CookieJar
from itertools import chain
from urllib.parse import urlparse, urljoin, urlunparse, parse_qsl
from types import FunctionType


import pycurl
from . import get_version
import simplejson as json
from .auth import AuthManager, BasicAuth
from .exceptions import (InvalidMethod, CurlError, InterfaceError, HTTPError)
from .utils import (decode_gzip, CaseInsensitiveDict, to_cookiejar,
                    morsel_to_cookie, data_wrapper, make_curl_post_files,
                    to_unicode, logger_debug, urlnoencode)

from requests.packages import chardet
from requests.packages.urllib3.util.url import parse_url


try:
    import platform
    if platform.system().lower() != 'windows':
        import signal
        from threading import current_thread
        if current_thread().name == 'MainThread':
            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
except ImportError:
    pass


__all__ = ("Request", "Response", "HTTPError", "InvalidMethod", "CurlError", "CURL_INFO_MAP")

logger = getLogger("human_curl.core")

# DEFAULTS
DEFAULT_TIME_OUT = 15.0
STATUSES_WITH_LOCATION = (301, 302, 303, 305, 307)
PYCURL_VERSION_INFO = pycurl.version_info()
HTTP_GENERAL_RESPONSE_HEADER = re_compile(r"(?P<version>HTTP\/.*?)\s+(?P<code>\d{3})\s+(?P<message>.*)")

try:
    CURL_VERSION = PYCURL_VERSION_INFO[1]
except IndexError as e:
    CURL_VERSION = ""
    logger.warn("Unknown pycURL / cURL version")


PROXIES_TYPES_MAP = {
    'socks5': pycurl.PROXYTYPE_SOCKS5,
    'socks4': pycurl.PROXYTYPE_SOCKS4,
    'http': pycurl.PROXYTYPE_HTTP,
    'https': pycurl.PROXYTYPE_HTTP}


# FULL LIST OF GETINFO OPTIONS
CURL_INFO_MAP = {
    # timers
    # An overview of the six time values available from curl_easy_getinfo()
    # perform() --> NAMELOOKUP --> CONNECT --> APPCONNECT
    # --> PRETRANSFER --> STARTTRANSFER --> TOTAL --> REDIRECT
    "TOTAL_TIME": pycurl.TOTAL_TIME,
    "NAMELOOKUP_TIME": pycurl.NAMELOOKUP_TIME,
    "CONNECT_TIME": pycurl.CONNECT_TIME,
    "APPCONNECT_TIME": pycurl.APPCONNECT_TIME,
    "PRETRANSFER_TIME": pycurl.PRETRANSFER_TIME,
    "STARTTRANSFER_TIME": pycurl.STARTTRANSFER_TIME,
    "REDIRECT_TIME": pycurl.REDIRECT_TIME,
    "HTTP_CODE": pycurl.HTTP_CODE,
    "REDIRECT_COUNT": pycurl.REDIRECT_COUNT,
    "REDIRECT_URL": pycurl.REDIRECT_URL,
    "SIZE_UPLOAD": pycurl.SIZE_UPLOAD,
    "SIZE_DOWNLOAD": pycurl.SIZE_DOWNLOAD,
    "SPEED_DOWNLOAD": pycurl.SPEED_DOWNLOAD,
    "SPEED_UPLOAD": pycurl.SPEED_UPLOAD,
    "HEADER_SIZE": pycurl.HEADER_SIZE,
    "REQUEST_SIZE": pycurl.REQUEST_SIZE,
    "SSL_VERIFYRESULT": pycurl.SSL_VERIFYRESULT,
    "SSL_ENGINES": pycurl.SSL_ENGINES,
    "CONTENT_LENGTH_DOWNLOAD": pycurl.CONTENT_LENGTH_DOWNLOAD,
    "CONTENT_LENGTH_UPLOAD": pycurl.CONTENT_LENGTH_UPLOAD,
    "CONTENT_TYPE": pycurl.CONTENT_TYPE,

    "HTTPAUTH_AVAIL": pycurl.HTTPAUTH_AVAIL,
    "PROXYAUTH_AVAIL": pycurl.PROXYAUTH_AVAIL,
    "OS_ERRNO": pycurl.OS_ERRNO,
    "NUM_CONNECTS": pycurl.NUM_CONNECTS,
    "PRIMARY_IP": pycurl.PRIMARY_IP,
    "CURLINFO_LASTSOCKET": pycurl.LASTSOCKET,
    "EFFECTIVE_URL": pycurl.EFFECTIVE_URL,
    "INFO_COOKIELIST": pycurl.INFO_COOKIELIST,
    "RESPONSE_CODE": pycurl.RESPONSE_CODE,
    "HTTP_CONNECTCODE": pycurl.HTTP_CONNECTCODE,
    # "FILETIME": pycurl.FILETIME
    # "PRIVATE": pycurl.PRIVATE, # (Added in 7.10.3)
    # "CERTINFO": pycurl.CERTINFO,
    # "PRIMARY_PORT": pycurl.PRIMARY_PORT,
    }


def get_code_by_name(name):
    """Returns proxy type code
    """
    return PROXIES_TYPES_MAP[name]


class Request(object):
    r"""A single HTTP / HTTPS requests

    Usage:

    >>> request = Request("GET", "http://google.com")
    >>> print(repr(request))
    <Request: GET [ http://google.com ]>
    >>> request.send()
    >>> response = requests.response
    """

    SUPPORTED_METHODS = ("GET", "HEAD", "POST", "DELETE", "PUT", "OPTIONS")

    def __init__(self, method, url, params=None, data=None, headers=None, cookies=None,
                 files=None, timeout=None, connection_timeout=None, allow_redirects=True,
                 max_redirects=5, proxies=None, auth=None, network_interface=None, use_gzip=None,
                 validate_cert=False, ca_certs=None, cert=None, debug=False, user_agent=None,
                 ip_v6=False, options=None, netrc=False, netrc_file=None, encode_query=None, **kwargs):
        """A single HTTP / HTTPS request

        Arguments:
        - `url`: (string) resource url
        - `method`: (string) one of `self.SUPPORTED_METHODS`
        - `data`: (dict, duple, string) data to send as Content-Disposition form-data
        - `params`: (dict, tuple) of GET params (?param1=value1&param2=value2)
        - `headers`: (dict, tuple) of request headers
        - `cookies`: (dict, tuple or CookieJar) of cookies
        - `files`: (dict, tuple or list) of files
           Example:
               (('field_file_name', '/path/to/file.txt'),
               ('field_file_name', io.open('/path/to/file.txt')),
               ('multiple_files_field', (io.open("/path/to/file.1.txt"), io.open("/path/to/file.1.txt"))),
               ('multiple_files_field', ("/path/to/file.1.txt", "/path/to/file.1.txt")))
        - `timeout`: (float) connection time out
        - `connection_timeout`: (float)
        - `allow_redirects`: (bool) follow redirects parametr
        - `proxy`: (dict, tuple or list) of proxies
           Examples:
               ('http', ('127.0.0.1', 9050))
               ('http', ('127.0.0.1', 9050, ('username', 'password')))
        - `auth`: (dict, tuple or list) for resource base auth
        - `network_interface`: (str) Pepform an operation using a specified interface.
           You can enter interface name, IP address or host name.
        - `use_gzip`: (bool) accept gzipped data
        - `validate_cert`: (bool) validate server certificate
        - `ca_certs`: tells curl to use the specified certificate file to verify the peer.
        - `cert`: (string) tells curl to use the specified certificate file
           when getting a file with HTTPS.
        - `debug`: (bool) use for `pycurl.DEBUGFUNCTION`
        - `user_agent`: (string) user agent
        - `ip_v6`: (bool) use ipv6 protocol
        - `options`: (tuple, list) low level pycurl options using
        """
        self._url = url
        if not method or not isinstance(method, str):
            raise InterfaceError("method argument must be string")

        if method.upper() not in self.SUPPORTED_METHODS:
            raise InvalidMethod("cURL do not support %s method" % method.upper())

        self._method = method.upper()

        self._user_agent = user_agent

        self._headers = data_wrapper(headers)

        if files is not None:
            self._files = make_curl_post_files(files)
        else:
            self._files = None

        self._params = data_wrapper(params)

        # String, dict, tuple, list
        if isinstance(data, (str, type(None))):
            self._data = data
        else:
            self._data = data_wrapper(data)

        if isinstance(cookies, CookieJar):
            self._cookies = cookies
        elif isinstance(cookies, (tuple, dict)):
            self._cookies = to_cookiejar(cookies)
        else:
            self._cookies = None
        if self._cookies is not None:
            self.cookie_file = tempfile.NamedTemporaryFile()

        if isinstance(proxies, type(None)):
            self._proxy = None
        elif isinstance(proxies, dict):
            if proxies.get('https'):

                proxy = parse_url(proxies.get('https'))

                if not proxy.port:
                    port = port_by_scheme.get(proxy.scheme, 80)
                    proxy = proxy._replace(port=port)
                assert proxy.scheme in ("http", "https"), \
                    'Not supported proxy scheme %s' % proxy.scheme
                self._proxy = ('https', (proxy.host, proxy.port))

            elif proxies.get('socks5'):

                proxy = parse_url(proxies.get('socks5'))

                if not proxy.port:
                    port = port_by_scheme.get(proxy.scheme, 1080)
                    proxy = proxy._replace(port=port)
                assert proxy.scheme in ("socks5",), \
                    'Not supported proxy scheme %s' % proxy.scheme
                self._proxy = ('socks5', (proxy.host, proxy.port))



        if not isinstance(network_interface, (str, type(None))):
            raise InterfaceError("Network interface argument must be string or None")

        self._network_interface = network_interface

        if isinstance(auth, AuthManager):
            self._auth = auth
        elif isinstance(auth, tuple):
            self._auth = BasicAuth(*auth)
        elif auth is None:
            self._auth = None
        else:
            raise ValueError("auth must be list, tuple or dict, not %s" % type(auth))

        # follow by location header field
        self._allow_redirects = allow_redirects
        self._max_redirects = max_redirects

        self._timeout = int(timeout or DEFAULT_TIME_OUT)
        self._connection_timeout = connection_timeout

        self._use_gzip = use_gzip

        # Certificates
        self._validate_cert = validate_cert
        self._ca_certs = ca_certs
        self._cert = cert
        self._start_time = time.time()
        self._debug_curl = debug
        self._ip_v6 = ip_v6

        self.response = None

        if options is None:
            self._options = None
        elif isinstance(options, (list, tuple)):
            self._options = data_wrapper(options)
        else:
            raise InterfaceError("options must be None, list or tuple")

        self._curl = None

        self.body_output = io.StringIO()
        self.headers_output = io.StringIO()

        self._netrc = netrc
        self._netrc_file = None

        self._encode_query = encode_query

    def __repr__(self, ):
        # TODO: collect `Request` settings into representation string
        return "<%s: %s [ %s ]>" % (self.__class__.__name__, self._method, self._url)

    @property
    def user_agent(self):
        if not self._user_agent:
            self._user_agent = "Mozilla/5.0 (compatible; human_curl; {0}; +http://h.wrttn.me/human_curl)".format(get_version())
        return self._user_agent

    @property
    def url(self):
        if not self._url:
            self._url = self._build_url()
        return self._url

    def _build_url(self):
        """Build resource url

        Parsing ``self._url``, add ``self._params`` to query string if need

        :return self._url: resource url
        """
        scheme, netloc, path, params, query, fragment = urlparse(self._url)

        # IDN domains support
        netloc = to_unicode(netloc)
        # removed idna encode as it was causing python3 urlunparse to error
        # print(repr(netloc), repr(netloc.encode('idna')))

        if not netloc:
            raise ValueError("Invalid url")
        elif not scheme:
            scheme = "http"

        tmp = []
        if self._params is not None:
            for param, value in self._params:
                if isinstance(value, tuple):
                    for i in value:
                        tmp.append((param, i))
                elif isinstance(value, str):
                    tmp.append((param, value))

        if tmp:
            tmp = parse_qsl(query, keep_blank_values=True) + tmp
        else:
            try:
                tmp = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
            except ValueError:
                tmp = query

        if isinstance(tmp, str):
            encode = quote_plus
            noencode = lambda result: result
        else:
            encode = urlencode
            noencode = urlnoencode

        if self._encode_query:
            query = encode(tmp)
        else:
            query = noencode(tmp)

        del tmp
        # print(repr([scheme, netloc, path, query, fragment]))
        url_unparse_list = [
            scheme.encode('utf8'),
            netloc.encode('idna'),
            path.encode('utf8'),
            params.encode('utf8'),
            query.encode('utf8'),
            fragment.encode('utf8')]

        self._url = urlunparse(url_unparse_list)
        return self._url

    def send(self):
        """Send request to self._url resource

        :return: `Response` object
        """

        try:
            url = self._build_url()
            # print(repr(url))
            opener = self.build_opener(url)
            opener.perform()
            # if close before getinfo, raises pycurl.error can't invote getinfo()
            # opener.close()
        except pycurl.error as e:


            exc = sys.exc_info()[1]
            code = exc.args[0]
            message = exc.args[1]
            raise CurlError(code, message)
        else:
            self.response = self.make_response()

        return self.response

    def make_response(self):
        """Make response from finished opener

        :return response: :class:`Response` object
        """
        response = Response(url=self._url, curl_opener=self._opener,
                            body_output=self.body_output,
                            headers_output=self.headers_output, request=self,
                            cookies=self._cookies)
        try:
            response.parse_cookies()
        except Exception as e:
            logger.error(e, exc_info=True)
        return response

    def setup_writers(self, opener, headers_writer, body_writer):
        """Setup headers and body writers

        :param opener: :class:`pycurl.Curl` object
        :param headers_writer: `StringIO` object
        :param body_writer: `StringIO` object
        """
        # Body and header writers
        opener.setopt(pycurl.HEADERFUNCTION, headers_writer)
        opener.setopt(pycurl.WRITEFUNCTION, body_writer)

    def setup_netrc(self, opener):
        """Setup netrc file

        :paramt opener: :class:`pycurl.Curl` object
        """
        if self._netrc:
            opener.setopt(pycurl.NETRC, 1)

        if self._netrc_file and file_exists(self._netrc_file):
            opener.setopt(pycurl.NETRC_FILE, self._netrc_file)


    @staticmethod
    def clean_opener(opener):
        """Reset opener options

        :param opener: :class:`pycurl.Curl` object
        :return opener: clean :`pycurl.Curl` object
        """
        opener.reset()
        return opener


    def build_opener(self, url, opener=None):
        """Compile pycurl.Curl instance

        Compile `pycurl.Curl` instance with given instance settings
        and return `pycurl.Curl` configured instance, StringIO instances
        of body_output and headers_output

        :param url: resource url
        :return: an ``(opener, body_output, headers_output)`` tuple.
        """
        # http://curl.haxx.se/mail/curlpython-2005-06/0004.html
        # http://curl.haxx.se/mail/lib-2010-03/0114.html

        opener = opener or pycurl.Curl()

        if getattr(opener, "dirty", True):
            # print("cleaning opener" , url)
            opener = self.clean_opener(opener)

        logger.debug("open url: %s" % repr(url))
        opener.setopt(pycurl.URL, url)
        opener.setopt(pycurl.NOSIGNAL, 1)


        if isinstance(self._auth, AuthManager):
            self._auth.setup_request(self)
            self._auth.setup(opener)
        elif self._netrc:
            self.setup_netrc(opener)
        else:
            opener.unsetopt(pycurl.USERPWD)

        if self._headers:
            logger.debug("Setup custom headers %s" %
                         "\r\n".join(["%s: %s" % (f, v) for f, v
                                      in list(CaseInsensitiveDict(self._headers).items())]))
            opener.setopt(pycurl.HTTPHEADER, ["%s: %s" % (f, v) for f, v
                                              in list(CaseInsensitiveDict(self._headers).items())])

        # Option -L  Follow  "Location: "  hints
        if self._allow_redirects is True:
            logger.debug("Allow redirects")
            opener.setopt(pycurl.FOLLOWLOCATION, self._allow_redirects)
            if self._max_redirects:
                opener.setopt(pycurl.MAXREDIRS, self._max_redirects)

        # Set timeout for a retrieving an object
        if self._timeout is not None:
            logger.debug("Set timeout: %s" % self._timeout)
            opener.setopt(pycurl.TIMEOUT, self._timeout)
        if self._connection_timeout is not None:
            logger.debug("Set connect timeout: %s" % self._timeout)
            opener.setopt(pycurl.CONNECTTIMEOUT, self._connection_timeout)

        # Setup debug output write function
        if isinstance(self._debug_curl, FunctionType):
            logger.debug("Setup %s as debug function" % self._debug_curl.__name__)
            opener.setopt(pycurl.VERBOSE, 1)
            opener.setopt(pycurl.DEBUGFUNCTION, self._debug_curl)
        elif self._debug_curl is True:
            opener.setopt(pycurl.VERBOSE, 1)
            opener.setopt(pycurl.DEBUGFUNCTION, logger_debug)
        else:
            opener.setopt(pycurl.VERBOSE, 0)

        # Send allow gzip encoding header
        if self._use_gzip is not None:
            logger.debug("Use gzip")
            opener.setopt(pycurl.ENCODING, "gzip,deflate")

        # Specify network interface (ip address) for query
        if self._network_interface is not None:
            logger.debug("Use custom network interface %s" % self._network_interface)
            opener.setopt(pycurl.INTERFACE, self._network_interface)

        # Setup proxy for request
        if self._proxy is not None:
            logger.debug("Use proxies %s - %s" % self._proxy)
            if len(self._proxy) > 2:
                proxy_type, proxy_addr, proxy_auth = self._proxy
            else:
                proxy_type, proxy_addr = self._proxy
                proxy_auth = None

            opener.setopt(pycurl.PROXY, proxy_addr[0])
            opener.setopt(pycurl.PROXYPORT, proxy_addr[1])
            opener.setopt(pycurl.PROXYTYPE, get_code_by_name(proxy_type))

            if proxy_type.upper() in ("CONNECT", "SSL", "HTTPS"):
                # if CONNECT proxy, need use HTTPPROXYTUNNEL
                opener.setopt(pycurl.HTTPPROXYTUNNEL, 1)
            if proxy_auth:
                if len(proxy_auth) == 2:
                    opener.setopt(pycurl.PROXYUSERPWD, "%s:%s" % proxy_auth)
                else:
                    raise InterfaceError("Proxy auth data must be tuple")

        logger.debug("Setup user agent %s" % repr(self.user_agent))

        opener.setopt(pycurl.USERAGENT, self.user_agent)

        if self._validate_cert not in (None, False):
            logger.debug("Validate certificate")
            # Verify that we've got the right site; harmless on a non-SSL connect.
            opener.setopt(pycurl.SSL_VERIFYPEER, 1)
            opener.setopt(pycurl.SSL_VERIFYHOST, 2)
        else:
            opener.setopt(pycurl.SSL_VERIFYPEER, 0)
            opener.setopt(pycurl.SSL_VERIFYHOST, 0)

        if self._ca_certs is not None:
            logger.debug("Use ca cert %s" % self._ca_certs)
            if file_exists(self._ca_certs):
                opener.setopt(pycurl.CAINFO, self._ca_certs)

        # (HTTPS) Tells curl to use the specified certificate file when getting a
        # file with HTTPS. The certificate must be in PEM format.
        # If the optional password isn't specified, it will be queried for on the terminal.
        # Note that this certificate is the private key and the private certificate concatenated!
        # If this option is used several times, the last one will be used.
        if self._cert:
            logger.debug("Use self._cert")
            opener.setopt(pycurl.SSLCERT, self._cert)

        if self._ip_v6:
            opener.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_WHATEVER)
        else:
            logger.debug("IPRESOLVE_V4")
            opener.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)

        # opener.setopt(c.NOPROGRESS, 0)
        # opener.setopt(c.PROGRESSFUNCTION, self._progress_callback)

        # Add cookies from self._cookies
        if self._cookies is not None:
            opener.setopt(pycurl.COOKIEJAR, self.cookie_file.name)
            chunks = []
            for cookie in self._cookies:
                name, value = cookie.name, cookie.value
                ## if isinstance(name, unicode):
                ##     name = name.encode("utf-8")
                ## if isinstance(value, unicode):
                ##     value = value.encode("utf-8")
                name = quote_plus(name)
                value = quote_plus(value)
                chunks.append('%s=%s;' % (name, value))
            if chunks:
                logger.debug("setting cookie chunks")
                opener.setopt(pycurl.COOKIE, ''.join(chunks))
        else:
            # set empty cookie to activate cURL cookies
            logger.debug("setting blank cookies")
            opener.setopt(pycurl.COOKIELIST, '')

        curl_options = {
            "GET": pycurl.HTTPGET,
            "POST": pycurl.POST,
            # "PUT": pycurl.UPLOAD,
            "PUT": pycurl.PUT,
            "HEAD": pycurl.NOBODY}

        logger.debug("Use method %s for request" % repr(self._method))
        if self._method in list(curl_options.keys()):
            opener.setopt(curl_options[self._method], True)
        elif self._method in self.SUPPORTED_METHODS:
            opener.setopt(pycurl.CUSTOMREQUEST, self._method)
        else:
            raise InvalidMethod("cURL request do not support %s" %
                                self._method)

        # Responses without body
        if self._method in ("OPTIONS", "HEAD"):
            opener.setopt(pycurl.NOBODY, True)

        if self._method in ("POST", "PUT", "DELETE"):
            if self._files:
                post_params = self._files
                if isinstance(self._data, (tuple, list, dict)):
                    post_params.extend(make_curl_post_files(self._data))
                opener.setopt(opener.HTTPPOST, post_params)
            else:
                if isinstance(self._data, str):
                    logger.debug(("self._data is string"))
                    logger.debug(("self._data", self._data))
                    request_buffer = io.StringIO(self._data)

                    # raw data for body request
                    opener.setopt(pycurl.READFUNCTION, request_buffer.read)
                    def ioctl(cmd):
                        logger.debug(("cmd", cmd))
                        if cmd == pycurl.IOCMD_RESTARTREAD:
                            request_buffer.seek(0)

                    opener.setopt(pycurl.IOCTLFUNCTION, ioctl)
                    if self._method == "PUT":
                        opener.setopt(pycurl.PUT, True)
                        opener.setopt(pycurl.INFILESIZE, len(self._data))
                    else:
                        opener.setopt(pycurl.POST, True)
                        opener.setopt(pycurl.POSTFIELDSIZE, len(self._data))
                elif isinstance(self._data, (tuple, list, dict)):
                    # use multipart/form-data;
                    # opener.setopt(opener.HTTPPOST, data_wrapper(self._data))

                    # use postfields to send vars as application/x-www-form-urlencoded
                    opener.setopt(pycurl.POSTFIELDS, urlencode(data_wrapper(self._data)))

        if isinstance(self._options, (tuple, list)):
            for key, value in self._options:
                logger.debug("setting key: %s, value: %s" % (key, value))
                opener.setopt(key, value)

        self.body_output = io.BytesIO()
        self.headers_output = io.BytesIO()

        self.setup_writers(opener, self.headers_output.write, self.body_output.write)

        self._opener = opener

        return opener


class Response(object):
    """Response object
    """

    def __init__(self, url, curl_opener, body_output, headers_output,
                 request=None, cookies=None):
        """
        Arguments:
        :param url: resource url
        :param curl_opener: :class:`pycurl.Curl` object
        :param body_output: :StringIO instance
        :param headers_output: :StringIO instance
        :param request: :class:`Request` instance
        :param cookies_jar: :class:`CookieJar` instance
        """

        # Requested url
        self._request_url = url
        self._url = None

        # Request object
        self._request = request

        # Response headers
        self._headers = None

        # Cookies dictionary
        self._cookies = None
        if isinstance(cookies, CookieJar):
            self._cookies_jar = cookies
        elif isinstance(cookies, (tuple, dict)):
            self._cookies_jar = to_cookiejar(cookies)
        else:
            self._cookies_jar = None

        # Seconds from request start to finish
        self.request_time = None
        self._curl_opener = curl_opener

        # StringIO object for response body
        self._body_output = body_output
        # StringIO object for response headers
        self._headers_output = headers_output

        # :Response status code
        self._status_code = None

        # Unziped end decoded response body
        self._content = None

        # Redirects history
        self._history = []

        # list of parsed headers blocks
        self._headers_history = []

        # get data from curl_opener.getinfo before curl_opener.close()
        self._response_info = dict()
        self._get_curl_info()

        # not good call methods in __init__
        # it's really very BAD
        # DO NOT UNCOMMENT
        # self._parse_headers_raw()


    def __repr__(self):
        return "<%s: %s >" % (self.__class__.__name__, self.status_code)

    def _get_curl_info(self):
        """Extract info from `self._curl_opener` with getinfo()

        """
        for field, value in list(CURL_INFO_MAP.items()):
            try:
                field_data = self._curl_opener.getinfo(value)
            except Exception as e:
                logger.warn(e)
                continue
            else:
                self._response_info[field] = field_data
        self._url = self._response_info.get("EFFECTIVE_URL")
        return self._response_info

    @property
    def request(self):
        return self._request

    @property
    def url(self):
        if not self._url:
            self._get_curl_info()
        return self._url

    @property
    def status_code(self):
        if not self._status_code:
            self._status_code = int(self._curl_opener.getinfo(pycurl.HTTP_CODE))
        return self._status_code


    def raise_for_status(self):
        http_error_msg = ''

        if 400 <= self.status_code < 500:
            http_error_msg = '%s Client Error' % (self.status_code)

        elif 500 <= self.status_code < 600:
            http_error_msg = '%s Server Error' % (self.status_code)

        if http_error_msg:
            raise HTTPError(code=self.status_code, message=http_error_msg, response=self)


    @property
    def cookiesjar(self):
        """Returns cookie jar object
        """
        if not self._cookies_jar:
            self._cookies_jar = CookieJar()
            # add cookies from self._cookies
        return self._cookies_jar

    @property
    def content(self):
        """Returns decoded self._content
        """
        import zlib
        if not self._content:
            if 'gzip' in self.headers.get('Content-Encoding', '') and \
                   'zlib' not in pycurl.version:
                try:
                    self._content = decode_gzip(self._body_output.getvalue())
                except zlib.error as e:
                    raise
            else:
                self._content = self._body_output.getvalue()
        return self._content

    @property
    def apparent_encoding(self):
        """The apparent encoding, provided by the chardet library"""
        return chardet.detect(self.content)['encoding']

    @property
    def text(self):
        """Content of the response, in unicode.
        If Response.encoding is None, encoding will be guessed using
        ``chardet``.
        The encoding of the response content is determined based solely on HTTP
        headers, following RFC 2616 to the letter. If you can take advantage of
        non-HTTP knowledge to make a better guess at the encoding, you should
        set ``r.encoding`` appropriately before accessing this property.
        """

        # Try charset from content-type
        content = None
        encoding = None

        if not self.content:
            return str('')

        # Fallback to auto-detected encoding.
        if encoding is None:
            encoding = self.apparent_encoding

        # Decode unicode from given encoding.
        try:
            content = str(self.content, encoding, errors='replace')
        except (LookupError, TypeError):
            # A LookupError is raised if the encoding was not found which could
            # indicate a misspelling or similar mistake.
            #
            # A TypeError can be raised if encoding is None
            #
            # So we try blindly encoding.
            content = str(self.content, errors='replace')

        return content

    def json(self):
        """Returns the json-encoded content of a response
        """
        try:
            return json.loads(self.content)
        except ValueError:
            return None

    @staticmethod
    def _split_headers_blocks(raw_headers):
        i = 0
        blocks = []

        raw_headers = raw_headers.decode('utf-8')
        for item in raw_headers.strip().split("\r\n"):
            if item.startswith("HTTP"):
                blocks.append([item])
                i = len(blocks) - 1
            elif item:
                blocks[i].append(item)
        # print(repr(blocks))
        return blocks

    def _parse_headers_raw(self):
        """Parse response headers and save as instance vars
        """
        def parse_header_block(raw_block):
            r"""Parse headers block

            Arguments:
            - `block`: raw header block

            Returns:
            - `headers_list`:
            """
            block_headers = []
            for header in raw_block:
                if not header:
                    continue
                elif not header.startswith("HTTP"):
                    field, value = [u.strip() for u in header.split(":", 1)]
                    if field.startswith("Location"):
                        # maybe not good
                        if not value.startswith("http"):
                            value = urljoin(self.url, value)
                        self._history.append(value)
                    if value[:1] == value[-1:] == '"':
                        value = value[1:-1] # strip "
                    block_headers.append((field, value.strip()))
                elif header.startswith("HTTP"):
                    # extract version, code, message from first header
                    try:
                        version, code, message = HTTP_GENERAL_RESPONSE_HEADER.findall(header)[0]
                    except Exception as e:
                        logger.warn(e)
                        continue
                    else:
                        block_headers.append((version, code, message))
                else:
                    # raise ValueError("Wrong header field")
                    pass
            return block_headers

        raw_headers = self._headers_output.getvalue()

        for raw_block in self._split_headers_blocks(raw_headers):
            block = parse_header_block(raw_block)
            self._headers_history.append(block)

        last_header = self._headers_history[-1]
        self._headers = CaseInsensitiveDict(last_header[1:])

        if not self._history:
            self._history.append(self.url)


    def parse_cookies(self):
        from http.cookies import SimpleCookie, CookieError

        if not self._headers_history:
            self._parse_headers_raw()

        # Get cookies from endpoint
        cookies = []
        for header in chain(*self._headers_history):
            if len(header) > 2:
                continue

            key, value = header[0], header[1]

            if key.lower().startswith("set-cookie"):

                try:
                    cookie = SimpleCookie()
                    cookie.load(value)
                    cookies.extend(list(cookie.values()))

                    # update cookie jar
                    for morsel in list(cookie.values()):
                        if isinstance(self._cookies_jar, CookieJar):
                            self._cookies_jar.set_cookie(morsel_to_cookie(morsel))
                except CookieError as e:
                    logger.warn(e)
        self._cookies = dict([(cookie.key, cookie.value) for cookie in cookies])
        return self._cookies

    @property
    def headers(self):
        """Returns response headers
        """
        if not self._headers:
            self._parse_headers_raw()
        return self._headers

    @property
    def cookies(self):
        """Returns list of BaseCookie object

        All cookies in list are ``Cookie.Morsel`` instance

        :return self._cookies: cookies list
        """
        if not self._cookies:
            self.parse_cookies()
        return self._cookies

    @property
    def history(self):
        """Returns redirects history list

        :return: list of `Response` objects
        """
        if not self._history:
            self._parse_headers_raw()
        return self._history
