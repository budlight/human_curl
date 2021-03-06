#!/usr/bin/env python
# -*- coding:  utf-8 -*-
"""
human_curl.tests
~~~~~~~~~~~~~~~~

Unittests for human_curl

:copyright: (c) 2011 - 2012 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""

import io
import os
import time
import pycurl
import http.cookiejar
from http.cookies import Morsel
import json
import uuid
from random import randint, choice
from string import ascii_letters, digits
import logging
from urllib.parse import urljoin
import unittest
import urllib.request, urllib.parse, urllib.error
from types import FunctionType
from urllib.parse import urlencode

import human_curl as requests
from human_curl import Request, Response
from human_curl import AsyncClient
from human_curl.auth import *
from human_curl.utils import *

from human_curl.exceptions import (CurlError, InterfaceError)

logger = logging.getLogger("human_curl.test")

async_logger = logging.getLogger("human_curl.core")
async_logger.setLevel(logging.DEBUG)

## # Add the log message handler to the logger
## # LOG_FILENAME = os.path.join(os.path.dirname(__file__), "debug.log")
## # handler = logging.handlers.FileHandler(LOG_FILENAME)
handler = logging.StreamHandler()

formatter = logging.Formatter("%(levelname)s %(asctime)s %(module)s [%(lineno)d] %(process)d %(thread)d | %(message)s ")

handler.setFormatter(formatter)

async_logger.addHandler(handler)


TEST_METHODS = (
    ('get', requests.get),
    ('post', requests.post),
    ('head', requests.head),
    ('delete', requests.delete),
    ('put', requests.put),
    ('options', requests.options))

# Use https://github.com/Lispython/httphq
HTTP_TEST_URL = os.environ.get('HTTP_TEST_URL', 'http://httpbin.org')
HTTPS_TEST_URL = os.environ.get('HTTPS_TEST_URL', 'http://httpbin.org')


CurlError("Use {0} as test server".format(HTTP_TEST_URL))

def build_url(*parts):
    return urljoin(HTTP_TEST_URL, "/".join(parts))

def build_url_secure(*parts):
    return urljoin(HTTPS_TEST_URL, "/".join(parts))

TEST_SERVERS = (build_url, build_url_secure)

def stdout_debug(debug_type, debug_msg):
    """Print messages
    """
    debug_types = ('I', '<', '>', '<', '>')
    if debug_type == 0:
        print(('%s' % debug_msg.strip()))
    elif debug_type in (1, 2):
        for line in debug_msg.splitlines():
            print(('%s %s' % (debug_types[debug_type], line)))
    elif debug_type == 4:
        print(('%s %r' % (debug_types[debug_type], debug_msg)))


def random_string(num=10):
    return ''.join([choice(ascii_letters + digits) for x in range(num)])


class BaseTestCase(unittest.TestCase):

    @staticmethod
    def random_string(num=10):
        return random_string(10)

    def random_dict(self, num=10):
        return dict([(self.random_string(10), self.random_string(10))for x in range(10)])

    def request_params(self):
        data = self.random_dict(10)
        data['url'] = build_url("get")
        data['method'] = 'get'

        return data


class RequestsTestCase(BaseTestCase):

    def test_build_url(self):
        self.assertEquals(build_url("get"), HTTP_TEST_URL + "/" + "get")
        self.assertEquals(build_url("post"), HTTP_TEST_URL + "/" + "post")
        self.assertEquals(build_url("redirect", "3"), HTTP_TEST_URL + "/" + "redirect" + "/" + "3")

    def tests_invalid_url(self):
        self.assertRaises(ValueError, requests.get, "wefwefwegrer")

    def test_url(self):
        self.assertEquals(requests.get(build_url("get")).url, build_url("get"))

    def test_request(self):
        for method, method_func in TEST_METHODS:
            r = method_func(build_url(method))
            self.assertTrue(isinstance(r, Response))

    def test_HTTP_GET(self):
        r = requests.get(build_url("get"))
        self.assertEquals(r.status_code, 200)

    def test_HTTP_POST(self):
        r = requests.post(build_url("post"))
        self.assertEquals(r.status_code, 200)

    """
    def test_HTTP_HEAD(self):
        r = requests.head(build_url("head"))
        self.assertEquals(r.status_code, 200)
    def test_HTTP_OPTIONS(self):
        r = requests.options(build_url("options"))
        self.assertEquals(r.status_code, 200)
    """

    def test_HTTP_PUT(self):
        r = requests.put(build_url("put"))
        self.assertEquals(r.status_code, 200)
        r2 = requests.put(build_url("put"),
                          data='kcjbwefjhwbcelihbflwkh')
        self.assertEquals(r2.status_code, 200)

    def test_HTTP_DELETE(self):
        r = requests.delete(build_url("delete"))
        self.assertEquals(r.status_code, 200)



    def test_HEADERS(self):
        import string
        headers = (("test-header", "test-header-value"),
                   ("Another-Test-Header", "kjwbrlfjbwekjbf"))

        r = requests.get(build_url("headers"), headers=headers)
        self.assertEquals(r.status_code, 200)

        r_json = json.loads(r.text)
        for field, value in headers:
            self.assertEquals(r_json['headers'].get(string.capwords(field, "-")), value)

    def test_PARAMS(self):
        params = {'q': 'test param'}
        r = requests.get(build_url("get""?test=true"), params=params)
        self.assertEquals(r.status_code, 200)
        args = json.loads(r.text)['args']
        self.assertEquals(args['q'], params['q'])
        self.assertEquals(args["test"], "true")

    def test_POST_DATA(self):
        random_key = "key_" + uuid.uuid4().hex[:10]
        random_value = "value_" + uuid.uuid4().hex
        r = requests.post(build_url('post'),
                          data={random_key: random_value})
        self.assertEquals(r.status_code, 200)

    def test_PUT_DATA(self):
        random_key = "key_" + uuid.uuid4().hex[:10]
        random_value = "value_" + uuid.uuid4().hex
        r = requests.put(build_url('put'),
                          data={random_key: random_value})
        self.assertEquals(r.status_code, 200)

    def test_POST_RAW_DATA(self):
        random_key = "key_" + uuid.uuid4().hex[:10]
        random_value = "value_" + uuid.uuid4().hex
        data = "%s:%s" % (random_key, random_value)
        r = requests.post(build_url('post'),
                          data=data)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.text.find(data) != -1)

    def test_PUT_RAW_DATA(self):
        random_key = "key_" + uuid.uuid4().hex[:10]
        random_value = "value_" + uuid.uuid4().hex
        data = "%s:%s" % (random_key, random_value)
        r = requests.put(build_url('put'),
                          data=data)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.text.find(data) != -1)

    def test_FILES(self):
        files = {'test_file': io.open('test_human_curl.py'),
                 'test_file2': io.open('README.rst')}
        r = requests.post(build_url('post'),
                          files=files)
        json_response = json.loads(r.text)
        self.assertEquals(r.status_code, 200)
        for k, v in list(files.items()):
            self.assertTrue(k in list(json_response['files'].keys()))

    def test_POST_DATA_and_FILES(self):
        files = {'test_file': io.open('test_human_curl.py'),
               'test_file2': io.open('README.rst')}
        random_key1 = "key_" + uuid.uuid4().hex[:10]
        random_value1 = "value_" + uuid.uuid4().hex
        random_key2 = "key_" + uuid.uuid4().hex[:10]
        random_value2 = "value_" + uuid.uuid4().hex
        r = requests.post(build_url('post'),
                          data={random_key1: random_value2,
                                random_key2: random_value2},
                          files=files)

        self.assertEquals(r.status_code, 200)

    def test_PUT_DATA_and_FILES(self):
        files = {'test_file': io.open('test_human_curl.py'),
                 'test_file2': io.open('README.rst')}
        random_key1 = "key_" + uuid.uuid4().hex[:10]
        random_key2 = "key_" + uuid.uuid4().hex[:10]
        random_value2 = "value_" + uuid.uuid4().hex
        r = requests.put(build_url('put'),
                          data={random_key1: random_value2,
                                random_key2: random_value2},
                          files=files)

        self.assertEquals(r.status_code, 200)

    def test_cookies_jar(self):
        random_key = "key_" + uuid.uuid4().hex[:10]
        random_value = "value_" + uuid.uuid4().hex
        random_key2 = "key_" + uuid.uuid4().hex[:10]
        random_value2 = "value_" + uuid.uuid4().hex

        cookies = ((random_key, random_value),
                   (random_key2, random_value2))

        cookies_jar = http.cookiejar.CookieJar()

        r1 = requests.get(build_url("cookies", "set", random_key, random_value),
                     cookies=cookies_jar, debug=stdout_debug)

        self.assertEquals(r1.cookies[random_key], random_value)
        rtmp = requests.get(build_url("cookies", "set", random_key2, random_value2),
                            cookies=cookies_jar, debug=stdout_debug)

        for cookie in cookies_jar:
            if cookie.name == random_key:
                self.assertEquals(cookie.value, random_value)

        r3 = requests.get(build_url('cookies'), cookies=cookies_jar, debug=stdout_debug)
        json_response = json.loads(r3.text)
        print(json_response)

        for k, v in cookies:
            self.assertEquals(json_response['cookies'][k], v)

    def test_send_cookies(self):
        random_key = "key_" + uuid.uuid4().hex[:10]
        random_value = "value_" + uuid.uuid4().hex
        random_key2 = "key_" + uuid.uuid4().hex[:10]
        random_value2 = "value_" + uuid.uuid4().hex

        cookies = ((random_key, random_value),
                   (random_key2, random_value2))

        r = requests.get(build_url('cookies'), cookies=cookies)
        #                          debug=stdout_debug)
        json_response = json.loads(r.text)
        # print(json_response)
        self.assertEquals(json_response['cookies'][random_key], random_value)

    def test_basic_auth(self):
        username = uuid.uuid4().hex
        password = uuid.uuid4().hex
        auth_manager = BasicAuth(username, password)

        r = requests.get(build_url('basic-auth', username, password),
                         auth=auth_manager)
        self.assertEquals(r.status_code, 200)
        json_response = json.loads(r.text)
        # print(json_response)
        # self.assertEquals(json_response['password'], password)
        self.assertEquals(json_response['user'], username)
        self.assertEquals(json_response['authenticated'], True)
        # self.assertEquals(json_response['auth-type'], 'basic')

    """
    def test_digest_auth(self):
        username = uuid.uuid4().hex
        password = uuid.uuid4().hex
        auth_manager = DigestAuth(username, password)

        r = requests.get(build_url('digest-auth/auth/', username, password),
                         auth=auth_manager, allow_redirects=True)
        self.assertEquals(r.status_code, 200)
        json_response = json.loads(r.text)
        # self.assertEquals(json_response['password'], password)
        self.assertEquals(json_response['user'], username)
        self.assertEquals(json_response['authenticated'], True)
        # self.assertEquals(json_response['auth-type'], 'digest')
    """

    def test_auth_denied(self):
        username = "hacker_username"
        password = "hacker_password"
        http_auth = (username, password)

        r = requests.get(build_url('basic-auth', "username", "password"), auth=http_auth)
        self.assertEquals(r.status_code, 401)

    def test_multivalue_params(self):
        random_key = "key_" + uuid.uuid4().hex[:10]
        random_value1 = "value_" + uuid.uuid4().hex
        random_value2 = "value_" + uuid.uuid4().hex
        r = requests.get(build_url("get"),
                         params={random_key: (random_value1, random_value2)})

        self.assertEquals(build_url("get?%s" %
                                    urlencode(((random_key, random_value1), (random_key, random_value2)))), r.url)

        json_response = json.loads(r.text)
        self.assertTrue(random_value1 in json_response['args'][random_key])
        self.assertTrue(random_value2 in json_response['args'][random_key])

    def test_multivalue_post_data(self):
        random_key = "key_" + uuid.uuid4().hex[:10]
        random_value1 = "value_" + uuid.uuid4().hex
        random_value2 = "value_" + uuid.uuid4().hex
        r = requests.post(
            build_url("post"),
            data={random_key: (random_value1, random_value2)})

        json_response = json.loads(r.text)
        # print(json_response)

        self.assertTrue(random_value1 in json_response['form'][random_key])
        self.assertTrue(random_value2 in json_response['form'][random_key])

    def test_redirect(self):
        r = requests.get(build_url("redirect", '3'), allow_redirects=True)
        self.assertEquals(r.status_code, 200)
        self.assertEquals(len(r.history), 3)
        self.assertEquals(r.url, build_url("get"))
        self.assertEquals(r._request_url, build_url("redirect/3").encode('utf8  '))
        self.assertRaises(CurlError, requests.get, build_url("redirect", '7'),
                          allow_redirects=True)

    def test_gzip(self):
        r = requests.get(build_url("gzip"), use_gzip=True)
        print((r.request._headers))
        print((r.headers))

        self.assertEquals(r.headers['Content-Encoding'], 'gzip')

        json_response = json.loads(r.text)
        self.assertEquals(json_response['gzipped'], True)

    def test_response_info(self):
        r = requests.get(build_url("get"))

    def test_unicode_domains(self):
        r = requests.get("http://➡.ws/pep8")
        self.assertEquals(r.url, 'http://xn--hgi.ws/pep8')

    def test_hooks(self):
        def pre_hook(r):
            r.pre_hook = True

        def post_hook(r):
            r.post_hook = True

        def response_hook(r):
            r._status_code = 700
            return r

        r1 = requests.get(build_url("get"), hooks={'pre_request': pre_hook,
                                                   'post_request': post_hook})
        self.assertEquals(r1._request.pre_hook, True)
        self.assertEquals(r1._request.post_hook, True)

        r2 = requests.get(build_url("get"), hooks={'response_hook': response_hook})
        self.assertEquals(r2._status_code, 700)

    def test_json_response(self):
        random_key = "key_" + uuid.uuid4().hex[:10]
        random_value1 = "value_" + uuid.uuid4().hex
        random_value2 = "value_" + uuid.uuid4().hex
        r = requests.get(build_url("get"),
                         params={random_key: (random_value1, random_value2)})

        self.assertEquals(build_url("get?%s" %
                                    urlencode(((random_key, random_value1), (random_key, random_value2)))), r.url)

        json_response = json.loads(r.text)
        self.assertTrue(isinstance(r.json, dict))
        self.assertEquals(json_response, r.json)
        self.assertTrue(random_value1 in r.json['args'][random_key])
        self.assertTrue(random_value2 in r.json['args'][random_key])

    def test_get_encode_query(self):
        params = {'q': 'value with space and @'}
        key, value = 'email', 'user@domain.com'
        response = requests.get(build_url("get""?%s=%s" % (key, value)), params=params)
        self.assertEquals(response.status_code, 200)
        self.assertEqual("{0}/get?email=user%40domain.com&q=value+with+space+and+%40".format(HTTP_TEST_URL).encode('utf8    '), response.request._url)
        args = json.loads(response.text)['args']
        self.assertEquals(args['q'], params['q'])
        self.assertEquals(args[key], value)

    def test_get_no_encode_query(self):
        params = {'q': 'value with space and @'}
        key, value = 'email', 'user@domain.com'

        # Invalid by HTTP spec
        try:
            # print(build_url("get?%s=%s" % (key, value)))
            response = requests.get(build_url("get?%s=%s" % (key, value)), params=params, encode_query=False)
        except CurlError as e:
            self.assertEqual(e.code, 52)
        else:
            self.assertEquals(response.status_code, 400)
            self.assertEqual("{0}/get?email=user@domain.com&q=value with space and @".format(HTTP_TEST_URL).encode('utf8'), response.request._url)

    def test_request_key_with_empty_value(self):
        key = "key"
        value = ""
        url = build_url("get""?%s=%s" % (key, value))
        response = requests.get(url)
        self.assertEqual(url.encode('utf8'), response.request.url)

    def test_request_key_no_equal(self):
        key = "key+"
        url = build_url("get""?%s" % key)
        response = requests.get(url)
        self.assertEqual("{0}/get?key%2B".format(HTTP_TEST_URL).encode('utf8'), response.request.url)

    def test_request_key_no_equal_and_params(self):
        key = "key"
        params = {"a": "b"}
        url = build_url("get""?%s" % key)
        response = requests.get(url, params=params)
        self.assertEqual((url + "=" + "&a=b").encode('utf8'), response.request.url)


class ResponseTestCase(BaseTestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass


class RequestTestCase(BaseTestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass


class UtilsTestCase(BaseTestCase):

    def test_case_insensitive_dict(self):
        test_data = {
            "lower-case-key": uuid.uuid4().hex,
            "UPPER-CASE-KEY": uuid.uuid4().hex,
            "CamelCaseKey": uuid.uuid4().hex}
        cidict = CaseInsensitiveDict(test_data)

        for k, v in list(test_data.items()):
            self.assertTrue(cidict[k], v)

    def test_cookies_from_jar(self):
        test_cookie_jar = http.cookiejar.CookieJar()

        cookies_dict = from_cookiejar(test_cookie_jar)

        for cookie in test_cookie_jar:
            self.assertEquals(cookies_dict[cookie.name], cookie.value)

    def test_jar_from_cookies(self):
        cookies_dict = dict([(uuid.uuid4().hex, uuid.uuid4().hex) for x in range(10)])
        cookies_list = [(uuid.uuid4().hex, uuid.uuid4().hex) for x in range(10)]

        cookiejar1 = to_cookiejar(cookies_dict)
        cookiejar2 = to_cookiejar(cookies_list)

        for cookie in cookiejar1:
            self.assertEquals(cookie.value, cookies_dict[cookie.name])

        for cookie in cookiejar2:
            for k, v in cookies_list:
                if k == cookie.name:
                    self.assertEquals(cookie.value, v)

    def test_decode_gzip(self):
        from gzip import GzipFile


        data_for_gzip = Request.__doc__
        tmp_buffer = io.BytesIO()

        gziped_buffer = GzipFile(
            fileobj=tmp_buffer,
            mode="wb",
            compresslevel=7)

        gziped_buffer.write(data_for_gzip)
        gziped_buffer.close()

        gzipped_data = tmp_buffer.getvalue()
        tmp_buffer.close()
        self.assertEquals(data_for_gzip, decode_gzip(gzipped_data))

    def test_morsel_to_cookie(self):
        from time import strftime, localtime
        time_template = "%a, %d-%b-%Y %H:%M:%S GMT"
        m = Morsel()
        m['domain'] = ".yandex"
        m['domain'] = ".yandex.ru"
        m['path'] = "/"
        m['expires'] = "Fri, 27-Aug-2021 17:43:25 GMT"
        m.key = "dj2enbdj3w"
        m.value = "fvjlrwnlkjnf"

        c = morsel_to_cookie(m)
        self.assertEquals(m.key, c.name)
        self.assertEquals(m.value, c.value)
        for x in ('expires', 'path', 'comment', 'domain',
                  'secure', 'version'):
            if x == 'expires':
                self.assertEquals(m[x], strftime(time_template, localtime(getattr(c, x, None))))
            elif x == 'version':
                self.assertTrue(isinstance(getattr(c, x, None), int))
            else:
                self.assertEquals(m[x], getattr(c, x, None))

    def test_data_wrapper(self):
        random_key1 = "key_" + uuid.uuid4().hex[:10]
        random_key2 = "key_" + uuid.uuid4().hex[:10]
        random_key3 = "key_" + uuid.uuid4().hex[:10]
        random_value1 = "value_" + uuid.uuid4().hex
        random_value2 = "value_" + uuid.uuid4().hex
        random_value3 = "value_" + uuid.uuid4().hex

        test_dict = {random_key1: random_value1,
                     random_key2: [random_value1, random_value2],
                     random_key3: (random_value2, random_value3)}
        test_list = ((random_key1, random_value1),
                     (random_key2, [random_value1, random_value2]),
                     (random_key3, (random_value2, random_value3)))

        control_list = ((random_key1, random_value1),
                        (random_key2, random_value1),
                        (random_key2, random_value2),
                        (random_key3, random_value2),
                        (random_key3, random_value3))

        converted_dict = data_wrapper(test_dict)
        for k, v in control_list:
            tmp = []
            for k2, v2 in converted_dict:
                if k2 == k:
                    tmp.append(v2)
            self.assertTrue(v in tmp)

        converted_list = data_wrapper(test_list)
        for k, v in control_list:
            tmp = []
            for k2, v2 in converted_list:
                if k2 == k:
                    tmp.append(v2)
            self.assertTrue(v in tmp)

    def test_curl_post_files(self):
        test_files = (('field_file_name', './README.rst'),
                      ('field_file_name2', io.open('./setup.py')),
                      ('multiple_files_field', (io.open("./README.rst"), "./setup.py")))

        curl_files_dict = make_curl_post_files(test_files)

        for k, v in curl_files_dict:
            if isinstance(v, (tuple, list)):
                self.assertTrue(isinstance(v, (tuple, list)))
                self.assertTrue(os.path.exists(v[1]))
                self.assertEquals(v[0], pycurl.FORM_FILE)
            else:
                assert False


class AuthManagersTestCase(BaseTestCase):


    def test_parse_dict_header(self):
        value = '''username="Mufasa",
                 realm="testrealm@host.com",
                 nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
                 uri="/dir/index.html",
                 qop=auth,
                 nc=00000001,
                 cnonce="0a4f113b",
                 response="6629fae49393a05397450978507c4ef1",
                 opaque="5ccc069c403ebaf9f0171e9517f40e41"'''

        parsed_header = parse_dict_header(value)
        self.assertEquals(parsed_header['username'], "Mufasa")
        self.assertEquals(parsed_header['realm'], "testrealm@host.com")
        self.assertEquals(parsed_header['nonce'], "dcd98b7102dd2f0e8b11d0f600bfb0c093")
        self.assertEquals(parsed_header['uri'], "/dir/index.html")
        self.assertEquals(parsed_header['qop'], "auth")
        self.assertEquals(parsed_header['nc'], "00000001")



    def test_escape(self):
        self.assertEquals(urllib.parse.unquote(url_escape("http://sp.example.com/")),
                          "http://sp.example.com/")




    def test_generate_nonce(self):
        self.assertEquals(len(generate_nonce(8)), 8)

    def test_generate_verifier(self):
        self.assertEquals(len(generate_nonce(8)), 8)






    def test_normalize_parameters(self):
        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\\u2766,+CA'
        parameters = 'address=41%20Decatur%20St%2C%20San%20Francisc%E2%9D%A6%2C%20CA&category=animal&q=monkeys'
        self.assertEquals(parameters, normalize_parameters(url))

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\\u2766,+CA'
        self.assertEquals(parameters, normalize_parameters(url))

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\xe2\x9d\xa6,+CA'
        self.assertEquals(parameters, normalize_parameters(url))

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc%E2%9D%A6,+CA'
        self.assertEquals(parameters, normalize_parameters(url))

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc%E2%9D%A6,+CA'
        self.assertEquals(parameters, normalize_parameters(url))



    def test_normalize_url(self):
        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\\u2766,+CA'
        control_url = "http://api.simplegeo.com/1.0/places/address.json"

        self.assertEquals(control_url, normalize_url(url))

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\\u2766,+CA'
        self.assertEquals(control_url, normalize_url(url))

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\xe2\x9d\xa6,+CA'
        self.assertEquals(control_url, normalize_url(url))

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc%E2%9D%A6,+CA'
        self.assertEquals(control_url, normalize_url(url))

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc%E2%9D%A6,+CA'
        self.assertEquals(control_url, normalize_url(url))





class AsyncTestCase(BaseTestCase):


    def success_callback(self, async_client, opener, response, **kwargs):
        self.assertTrue(isinstance(opener.request, Request))
        self.assertTrue(isinstance(response, Response))
        self.assertTrue(isinstance(async_client, AsyncClient))
        self.assertTrue(response.text.find(async_client._default_user_agent) != -1)

    def fail_callback(self, async_client, opener, errno, errmsg, **kwargs):
        self.assertTrue(isinstance(async_client, AsyncClient))

    def test_AsyncClient_core(self):
        async_client = AsyncClient(size=20)

        self.assertEquals(async_client._num_conn, 20)
        self.assertEquals(async_client._remaining, 0)
        self.assertEquals(async_client.success_callback, None)
        self.assertEquals(async_client.fail_callback, None)
        self.assertEquals(async_client._openers_pool, None)
        self.assertEquals(async_client._data_queue, [])
        self.assertEquals(async_client.connections_count, 0)

        async_client.add_handler(url=build_url("/get"),
                                 method="get",
                                 params={"get1": "get1 value",
                                         "get2": "get2 value"},
                                 success_callback=self.success_callback,
                                 fail_callback=self.fail_callback)
        self.assertEquals(len(async_client._data_queue), 1)
        self.assertTrue(isinstance(async_client._data_queue[0], dict))

        params = self.random_dict(10)

        async_client.get(url=build_url("/get"), params=params,
                         success_callback=self.success_callback,
                         fail_callback=self.fail_callback)
        self.assertTrue(isinstance(async_client._data_queue[1], dict))
        self.assertEquals(async_client._data_queue[1]['params'], params)
        self.assertEquals(async_client.connections_count, 2)

    def test_async_get(self):
        async_client_global = AsyncClient(success_callback=self.success_callback,
                                          fail_callback=self.fail_callback)

        params = self.random_dict(10)
        url = build_url("get")

        self.assertEquals(async_client_global.get(url, params=params), async_client_global)
        self.assertEquals(len(async_client_global._data_queue), 1)

        # Test process_func
        def process_func(num_processed, remaining, num_urls,
                         success_len, error_len):
            print(("\nProcess {0} {1} {2} {3} {4}".format(num_processed, remaining, num_urls,
                                                         success_len, error_len)))
            self.assertEquals(num_urls, 2)

        def fail_callback(request, errno, errmsg, async_client, opener):
            self.assertTrue(isinstance(request, Request))
            self.assertTrue(isinstance(async_client, AsyncClient))
            self.assertEquals(async_client, async_client_global)
            self.assertEquals(errno, 6)
            self.assertEquals(errmsg, "Couldn't resolve host '{0}'".format(request.url[7:]))
        async_client_global.get("http://fwbefrubfbrfybghbfb4gbyvrv.com", params=params,
                                fail_callback=fail_callback)
        self.assertEquals(len(async_client_global._data_queue), 2)
        async_client_global.start(process_func)

    def test_setup_opener(self):
        async_client = AsyncClient()

        data = self.random_dict(10)
        data['url'] = build_url("get")
        data['method'] = 'get'
        opener = async_client.get_opener()

        self.assertEquals(getattr(opener, 'success_callback', None), None)
        self.assertEquals(getattr(opener, 'fail_callback', None), None)
        self.assertEquals(getattr(opener, 'request', None), None)

        data['success_callback'] = lambda **kwargs: kwargs
        data['fail_callback'] = lambda **kwargs: kwargs

        async_client.configure_opener(opener, data)
        self.assertTrue(isinstance(opener.request, Request))
        self.assertTrue(isinstance(opener.success_callback, FunctionType))
        self.assertTrue(isinstance(opener.fail_callback, FunctionType))


    def test_add_handler(self):
        async_client = AsyncClient()
        data = self.request_params()


        self.assertRaises(InterfaceError, async_client.add_handler, **data)

        data['success_callback'] = lambda **kwargs: kwargs
        data['fail_callback'] = lambda **kwargs: kwargs

        async_client.add_handler(**data)
        self.assertEquals(async_client._data_queue[0], data)
        self.assertEquals(async_client._num_urls, 1)
        self.assertEquals(async_client._remaining, 1)

    def test_get_opener(self):
        async_client = AsyncClient()
        opener = async_client.get_opener()
        self.assertEquals(opener.fp, None)
        self.assertNotEqual(opener, None)


    def test_AsyncClient_contextmanager(self):
        with AsyncClient(success_callback=self.success_callback,
                         fail_callback=self.fail_callback) as async_client_global:

            params = self.random_dict(10)
            url = build_url("get")

            self.assertEquals(async_client_global.get(url, params=params), async_client_global)
            self.assertEquals(len(async_client_global._data_queue), 1)

            # Test process_func
            def process_func(num_processed, remaining, num_urls,
                             success_len, error_len):
                print(("\nProcess {0} {1} {2} {3} {4}".format(num_processed, remaining, num_urls,
                                                             success_len, error_len)))
                self.assertEquals(num_urls, 2)

            def fail_callback(request, errno, errmsg, async_client, opener):
                self.assertTrue(isinstance(request, Request))
                self.assertTrue(isinstance(async_client, AsyncClient))
                self.assertEquals(async_client, async_client_global)
                self.assertEquals(errno, 6)
                self.assertEquals(errmsg, "Couldn't resolve host '{0}'".format(request.url[7:]))
            async_client_global.get("http://fwbefrubfbrfybghbfb4gbyvrv.com", params=params,
                                    fail_callback=fail_callback)
            self.assertEquals(len(async_client_global._data_queue), 2)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(RequestsTestCase))
    suite.addTest(unittest.makeSuite(ResponseTestCase))
    suite.addTest(unittest.makeSuite(RequestTestCase))
    suite.addTest(unittest.makeSuite(UtilsTestCase))
    suite.addTest(unittest.makeSuite(AuthManagersTestCase))
    suite.addTest(unittest.makeSuite(AsyncTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest="suite")
