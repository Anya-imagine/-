import configparser
import sys
import os
import logging
import pycurl
import requests
import json
import time
import threading
import queue
import re
import base64
import hashlib
import zlib
import gzip
import io
import struct
import binascii
import ipaddress
import urllib.parse
from collections import deque
from io import BytesIO
from urllib.parse import unquote
from dataclasses import dataclass, field
from typing import Callable, Optional, Any
from enum import Enum, IntEnum
import magic
from requests_aws4auth import AWS4Auth
from _socket import IPPROTO_AH
import functools

from .BSB import BSB
from .field import FieldManager, FieldType, FIELD_FLAG_CNT, FIELD_FLAG_FAKE, FIELD_FLAG_IPPRE, FIELD_FLAG_NODB
from .session import Session
from .singleton import field_manager
from .parsers import PARSER_UNREGISTER, parsers_classify_tcp, parsers_register, parsers_unregister
from .plugins import (
    PLUGIN_HP_OHC, PLUGIN_HP_OMB, plugins_callback_http_on_body,
    plugins_callback_http_on_header_complete, plugins_callback_http_on_header_field,
    plugins_callback_http_on_header_field_raw, plugins_callback_http_on_header_value,
    plugins_callback_http_on_message_begin, plugins_callback_http_on_url, PLUGIN_HP_OMC,
    plugins_callback_http_on_message_complete
)
from .constants import (
    FIELD_TYPE_IP_GHASH,
    FIELD_FLAG_CNT,
    FIELD_FLAG_IPPRE,
    FIELD_FLAG_FAKE,
    FIELD_TYPE_STR_HASH,
    FIELD_FLAG_FORCE_UTF8,
    FIELD_FLAG_NODB,
    FIELD_TYPE_STR_ARRAY,
    FIELD_TYPE_INT_GHASH
)

config = configparser.ConfigParser()
# Set default configuration values
config.supportSha256 = True  # Enable SHA256 support by default

ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY_ID')
SECRET_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
REGION = os.environ.get('AWS_REGION', 'us-east-1')  # 设置默认区域

z_strm = zlib.compressobj()
z_strm_lock = threading.Lock()

HTTP_MAX_HEADERS_SIZE = 1024 * 80
HTTP_MAX_METHOD = 6
ULLONG_MAX = 0xFFFFFFFFFFFFFFFF

HTTP_PRIORITY_BEST = 0
HTTP_PRIORITY_NORMAL = 1
HTTP_PRIORITY_DROPABLE = 2

PROXY_CONNECTION = "proxy-connection"
PRIORITY_MAX = 10
CONNECTION = "connection"
CONTENT_LENGTH = "content-length"
TRANSFER_ENCODING = "transfer-encoding"
UPGRADE = "upgrade"
CHUNKED = "chunked"
KEEP_ALIVE = "keep-alive"
CLOSE = "close"


class flags(IntEnum):
    F_CHUNKED = 1 << 0
    F_CONNECTION_KEEP_ALIVE = 1 << 1
    F_CONNECTION_CLOSE = 1 << 2
    F_TRAILING = 1 << 3
    F_UPGRADE = 1 << 4
    F_SKIPBODY = 1 << 5


class state(Enum):
    s_dead = 1
    s_start_req_or_res = 2
    s_res_or_resp_H = 3
    s_start_res = 4
    s_res_H = 5
    s_res_HT = 6
    s_res_HTT = 7
    s_res_HTTP = 8
    s_res_first_http_major = 9
    s_res_http_major = 10
    s_res_first_http_minor = 11
    s_res_http_minor = 12
    s_res_first_status_code = 13
    s_res_status_code = 14
    s_res_status = 15
    s_res_line_almost_done = 16

    s_start_req = 17

    s_req_method = 18
    s_req_spaces_before_url = 19
    s_req_schema = 20
    s_req_schema_slash = 21
    s_req_schema_slash_slash = 22
    s_req_server_start = 23
    s_req_server = 24
    s_req_server_with_at = 25
    s_req_path = 26
    s_req_query_string_start = 27
    s_req_query_string = 28
    s_req_fragment_start = 29
    s_req_fragment = 30
    s_req_http_start = 31
    s_req_http_H = 32
    s_req_http_HT = 33
    s_req_http_HTT = 34
    s_req_http_HTTP = 35
    s_req_first_http_major = 36
    s_req_http_major = 37
    s_req_first_http_minor = 38
    s_req_http_minor = 39
    s_req_line_almost_done = 40

    s_header_field_start = 41
    s_header_field = 42
    s_header_value_start = 43
    s_header_value = 44
    s_header_value_lws = 45

    s_header_almost_done = 46

    s_chunk_size_start = 47
    s_chunk_size = 48
    s_chunk_parameters = 49
    s_chunk_size_almost_done = 50

    s_headers_almost_done = 51
    s_headers_done = 52

    s_chunk_data = 53
    s_chunk_data_almost_done = 54
    s_chunk_data_done = 55

    s_body_identity = 56
    s_body_identity_eof = 57

    s_message_done = 58


class ClientAuth:
    def __init__(self):
        self.client_cert = None
        self.client_key = None
        self.client_key_pass = None


class HeaderStates(IntEnum):
    h_general = 0
    h_C = 1
    h_CO = 2
    h_CON = 3

    h_matching_connection = 4
    h_matching_proxy_connection = 5
    h_matching_content_length = 6
    h_matching_transfer_encoding = 7
    h_matching_upgrade = 8

    h_connection = 9
    h_content_length = 10
    h_transfer_encoding = 11
    h_upgrade = 12

    h_matching_transfer_encoding_chunked = 13
    h_matching_connection_keep_alive = 14
    h_matching_connection_close = 15

    h_transfer_encoding_chunked = 16
    h_connection_keep_alive = 17
    h_connection_close = 18


class HttpParserType(IntEnum):
    HTTP_REQUEST = 0
    HTTP_RESPONSE = 1
    HTTP_BOTH = 2


class HttpErrno(IntEnum):
    HPE_OK = 0
    HPE_CB_message_begin = 1
    HPE_CB_status_complete = 2
    HPE_CB_url = 3
    HPE_CB_header_field = 4
    HPE_CB_header_value = 5
    HPE_CB_headers_complete = 6
    HPE_CB_body = 7
    HPE_CB_message_complete = 8
    HPE_INVALID_EOF_STATE = 9
    HPE_HEADER_OVERFLOW = 10
    HPE_CLOSED_CONNECTION = 11
    HPE_INVALID_VERSION = 12
    HPE_INVALID_STATUS = 13
    HPE_INVALID_METHOD = 14
    HPE_INVALID_URL = 15
    HPE_INVALID_HOST = 16
    HPE_INVALID_PORT = 17
    HPE_INVALID_PATH = 18
    HPE_INVALID_QUERY_STRING = 19
    HPE_INVALID_FRAGMENT = 20
    HPE_LF_EXPECTED = 21
    HPE_INVALID_HEADER_TOKEN = 22
    HPE_INVALID_CONTENT_LENGTH = 23
    HPE_INVALID_CHUNK_SIZE = 24
    HPE_INVALID_CONSTANT = 25
    HPE_INVALID_INTERNAL_STATE = 26
    HPE_STRICT = 27
    HPE_PAUSED = 28
    HPE_UNKNOWN = 29

    @property
    def description(self):
        return _errno_descriptions.get(self, "Unknown error")


_errno_descriptions = {
    HttpErrno.HPE_OK: "success",
    HttpErrno.HPE_CB_message_begin: "the on_message_begin callback failed",
    # ... 其他错误码描述根据头文件内容补充
    HttpErrno.HPE_STRICT: "strict mode assertion failed"
}

MAX_URL_LENGTH = 1024


def callback_no_advance(func):
    def wrapper(parser):
        ret = func(parser)
        if ret == 0:
            parser.nread = 0
            parser.http_errno = HttpErrno.HPE_OK
        return ret
    return wrapper


class HttpParser:
    def __init__(self):
        self.type = HttpParserType.HTTP_REQUEST
        self.state = state.s_dead
        self.header_state = HeaderStates.h_general
        self.index = 0
        self.prefix = 0
        self.flags = 0
        self.nread = 0
        self.content_length = 0
        self.http_major = 0
        self.http_minor = 0
        self.status_code = 0
        self.method = HttpMethod.HTTP_GET
        self._http_errno = HttpErrno.HPE_OK  # 使用私有属性
        self.upgrade = 0
        self.data = {}

    @property
    def http_errno(self) -> HttpErrno:
        return self._http_errno
        
    @http_errno.setter
    def http_errno(self, value):
        self._http_errno = value

    def callback_data(self, part_type: str):
        return self.data.get(part_type)

    def mark(self, part_name: str):
        self.data[part_name] = self.nread

    def strict_check(self, condition):
        if condition:
            self.http_errno = HttpErrno.HPE_STRICT
            return True
        return False

    def parsing_header(self):
        return self.state >= state.s_header_field_start and self.state <= state.s_header_value_lws

    def callback_notify(self, for_event):
        if for_event == "message_begin":
            return http_callback_on_message_begin(self)
        elif for_event == "url":
            return http_callback_on_url(self, self.data["url"], self.nread - self.data["url"])
        elif for_event == "header_field":
            return http_callback_on_header_field(self, self.data["header_field"], self.nread - self.data["header_field"])
        elif for_event == "header_value":
            return http_callback_on_header_value(self, self.data["header_value"], self.nread - self.data["header_value"])
        elif for_event == "headers_complete":
            return http_callback_on_headers_complete(self)
        elif for_event == "body":
            return http_callback_on_body(self, self.data["body"], self.nread - self.data["body"])
        elif for_event == "message_complete":
            return http_callback_on_message_complete(self)
        return 0

    @callback_no_advance
    def on_headers_complete(self):
        # 回调处理逻辑
        return 0

    def set_errno(self, e):
        # 设置解析器错误码
        self.http_errno = e

    @property
    def errno(self):
        # 获取当前错误码对应的枚举值
        return self.http_errno


@dataclass
class HttpInfo:
    session: Optional['Session'] = None

    def __init__(self):
        self.url_string = None
        self.host_string = None
        self.cookie_string = None
        self.auth_string = None
        self.proxy_auth_string = None
        self.value_string = []
        self.header = [[]]
        self.pos = []
        self.method_counts = []
        self.check_sum = []
        self.magic_string = [None, None]
        self.magic_detector = magic.Magic(mime=True)
        self.url_bytes = bytearray()

        self.parsers = HttpParser()
        self.wparsers = 2
        self.inheader = 2
        self.invalue = 2
        self.inbody = 2
        self.url_which = 1
        self.which = 1
        self.is_connect = 2
        self.reclassify = 2
        self.http2upgrade = 1

    def on_url(self, data, length):
        # 初始化或追加URL片段
        if not self.url_bytes:
            self.url_bytes.extend(data[:length])
        else:
            self.url_bytes.extend(data[:length])

        url_string = self.url_bytes.decode('utf-8', errors='ignore')


method_strings = [
    "GET",  # 0
    "HEAD",  # 1
    "POST",  # 2
    "PUT",  # 3
    "DELETE",  # 4
    "CONNECT",  # 5
    "OPTIONS",  # 6
    "TRACE",  # 7
    "PATCH"  # 8
]


class HttpMethod(IntEnum):
    HTTP_DELETE = 0
    HTTP_GET = 1
    HTTP_HEAD = 2
    HTTP_POST = 3
    HTTP_PUT = 4
    HTTP_CONNECT = 5
    HTTP_OPTIONS = 6
    HTTP_TRACE = 7
    HTTP_COPY = 8
    HTTP_LOCK = 9
    HTTP_MKCOL = 10
    HTTP_MOVE = 11
    HTTP_PROPFIND = 12
    HTTP_PROPPATCH = 13
    HTTP_SEARCH = 14
    HTTP_UNLOCK = 15
    HTTP_REPORT = 16
    HTTP_MKACTIVITY = 17
    HTTP_CHECKOUT = 18
    HTTP_MERGE = 19
    HTTP_MSEARCH = 20
    HTTP_NOTIFY = 21
    HTTP_SUBSCRIBE = 22
    HTTP_UNSUBSCRIBE = 23
    HTTP_PATCH = 24
    HTTP_PURGE = 25

    @classmethod
    def method_str(cls, m: int) -> str:
        try:
            return cls(m).name[5:]  # Remove HTTP_ prefix
        except ValueError:
            return "UNKNOWN"


class HttpParserSettings:
    def __init__(self):
        self.on_message_begin = None
        self.on_url = None
        self.on_status = None
        self.on_header_field = None
        self.on_header_value = None
        self.on_headers_complete = None
        self.on_body = None
        self.on_message_complete = None


class HttpRequest:
    def __init__(self):
        self.easy = None
        self.url = None
        self.key = None
        self.data_in = None
        self.used = 0
        self.size = 0
        self.retries = 0
        self.write_callback = None
        self.uw = None

    def open_socket_callback(self, purpose, address, server_name):
        pass

    def close_socket_callback(self, fd, server_name):
        pass

    def write_callback(self, data):
        pass


class HttpResponseCallback:
    def __init__(self):
        self.func = None
        self.uw = None


class HttpReadCallback:
    def __init__(self):
        self.func = None
        self.uw = None


class HttpHeaderCallback:
    def __init__(self):
        self.func = None
        self.uw = None


class HttpServerName:
    def __init__(self):
        self.name = None
        self.allowed_at_seconds = 0


class HttpServer:
    def __init__(self):
        self.sync_request = HttpRequest()
        self.sync_requests = threading.Lock()
        self.insecure = False
        self.client_auth = None
        self.user_pwd = None
        self.aws_sigv4 = None
        self.timeout = 30
        self.max_retries = 3
        self.print_errors = True
        self.header_callback = None
        self.server_names = []
        self.server_names_pos = 0


def http_send_sync(server: HttpServer, method: str, key: str, key_len: int, data: bytes, data_len: int, headers: list, return_len: bool, code: int) -> bytes:
    header_list = []
    if headers:
        for header in headers:
            header_list = header_list.append(header)

    server.sync_requests = threading.Lock()
    if not server.sync_request.easy:
        easy = server.sync_request.easy = pycurl.Curl()
        if config.debug >= 2:
            easy.setopt(pycurl.VERBOSE, 1)
        easy.setopt(pycurl.WRITEFUNCTION, http_curl_write_callback)
        easy.setopt(pycurl.WRITEDATA, server.sync_request)
        easy.setopt(pycurl.CONNECTTIMEOUT, 10)
        easy.setopt(pycurl.TIMEOUT, server.timeout)
        easy.setopt(pycurl.TCP_KEEPALIVE, 1)

    else:
        easy = server.sync_request.easy

    if server.insecure:
        easy.setopt(pycurl.SSL_VERIFYPEER, 0)
        easy.setopt(pycurl.SSL_VERIFYHOST, 0)

    if config.ca_trust_file:
        easy.setopt(pycurl.CAINFO, config.ca_trust_file)

    if server.client_auth:
        easy.setopt(pycurl.SSLCERT, server.client_auth.client_cert)
        easy.setopt(pycurl.SSLKEY, server.client_auth.client_key)
        if server.client_auth.client_key_pass:
            easy.setopt(pycurl.SSLKEYPASSWD, server.client_auth.client_key_pass)

    if method[0] != 'G':
        easy.setopt(pycurl.CUSTOMREQUEST, method)
        easy.setopt(pycurl.POSTFIELDSIZE, data_len)
        easy.setopt(pycurl.POSTFIELDS, data)

    else:
        easy.setopt(pycurl.CUSTOMREQUEST, None)
        easy.setopt(pycurl.HTTPGET, 1)

    easy.setopt(pycurl.USERAGENT, "arkime")

    if header_list:
        easy.setopt(pycurl.HTTPHEADER, header_list)

    if server.user_pwd:
        easy.setopt(pycurl.USERPWD, server.user_pwd)

    if server.aws_sigv4:
        easy.setopt(pycurl.AWS_SIGV4, server.aws_sigv4)

    if key_len == -1:
        key_len = len(key)

    if key_len > 1000:
        exit("ERROR - URL too long %.*s", key_len, key)

    server.sync_request.key[0:key_len] = key[0:key_len]
    server.sync_request.key[key_len] = 0
    server.sync_request.retries = server.max_retries

    while True:
        requests = threading.Lock()
        http_add_request(server, server.sync_request, -1)
        requests.unlock()

        server.sync_request.used = 0
        c = pycurl.Curl()
        res = easy.perform()

        if res != pycurl.E_OK:
            if server.sync_request.retries >= 0:
                now = datetime.time()
                current_seconds = int(time.time())
                seconds = int(now.timestamp())
                microseconds = int(now.microseconds)

                server.server_names[server.server_names_pos].allowed_at_seconds = now.tv_sec + 30
                logging.log("Retry %s error '%s'", server.sync_request.url, res.easy_strerror())
                server.sync_request.retries -= 1
                continue

            logging.log("libcurl failure %s error '%s'", server.sync_request.url, res.easy_strerror())
            server.sync_request.unlock()

            if header_list:
                easy.setopt(pycurl.HTTPHEADER, header_list)
                del header_list[:]  # 清空列表防止内存泄漏
            return 0
        break

    if header_list:
        easy.setopt(pycurl.HTTPHEADER, header_list)
        del header_list[:]

    if server.sync_request.data_in:
        server.sync_request.data_in[server.sync_request.used] = 0

    response_code = 0
    easy.getinfo(pycurl.RESPONSE_CODE, response_code)
    if code:
        code = response_code

    if config.log_es_requests or (server.print_errors and response_code / 100 != 2):
        total_time = 0
        connect_time = 0
        upload_size = 0
        download_size = 0

        easy.getinfo(pycurl.TOTAL_TIME, total_time)
        easy.getinfo(pycurl.CONNECT_TIME, connect_time)
        easy.getinfo(pycurl.SIZE_UPLOAD, upload_size)
        easy.getinfo(pycurl.SIZE_DOWNLOAD, download_size)

        logging.log("%d/%d SYNC %d %s %.0f/%.0f %.0fms %.0fms",
                    1, 1,
                    response_code,
                    server.sync_request.url,
                    upload_size,
                    download_size,
                    connect_time * 1000,
                    total_time * 1000)

        data_in = server.sync_request.data_in
        server.sync_request.data_in = 0
        server.sync_request.unlock()
        return data_in

def http_send_timer_callback(unused):
    while True:
        request = HttpRequest
        requests = threading.Lock()
        for priority in range(0, PRIORITY_MAX):
            # 初始化不同优先级的请求队列
            requests = [deque() for _ in range(PRIORITY_MAX)]
            if request:
                break

        if not request:
            requests_timer = 0
            requests = threading.UNLOCK()
            return False

        muti = pycurl.CurlMulti()

        easy = pycurl.Curl()
        easy.setopt(pycurl.URL, request.url)
        muti.add_handle(easy)

    return False

def http_curl_write_callback(contents, size, nmemb, request_p):
    request = request_p
    sz = size * nmemb
    c = pycurl.Curl()
    if request.read_func:
        if not request.read_func(contents, sz, request.uw):
            return sz
        return 0
    if not request.data_in:
        content_length = c.getinfo(pycurl.CONTENT_LENGTH_DOWNLOAD)
        request.used = sz
        request.size = max(sz, content_length)
        request.data_in = bytearray(request.size + 1)  # 创建预分配缓冲区
        request.data_in[:sz] = contents[:sz]  # 写入数据
        return sz
    if request.used + sz >= request.size:
        request.size += request.used + sz
        request.dataIn += bytearray(request.sieze + 1 - len(request.dataIn))
    request.dataIn[request.used: request.used + len(contents)] = contents
    request.used += sz
    return sz

def http_curlm_header_function(buffer, size, nitems, request_p):
    request = request_p
    sz = size * nitems
    i = sz
    while i > 0 and (buffer[i - 1] == '\r' or buffer[i - 1] == '\n'):
        buffer[i - 1] = 0
        i -= 1

    colon = buffer.find(b':', 0, sz)
    if not colon:
        return sz

    colon = 0
    colon += 1
    while colon.isspace():
        colon += 1
    request.server.header_callback(request.url, buffer, colon, buffer + i - colon, request.uw)
    return sz

requests_timer = 0

def http_add_request(server: HttpServer, request: HttpRequest, priority):
    now = datetime.now()
    current_seconds = int(time.time())
    seconds = int(now.timestamp())

    if not request.easy:
        request.easy = pycurl.Curl()
        if config.debug >= 2:
            request.easy.setopt(pycurl.VERBOSE, True)
        if server.insecure:
            request.easy.setopt(pycurl.SSL_VERIFYPEER, 0)
            request.easy.setopt(pycurl.SSL_VERIFYHOST, 0)
        ca_trust_file = config.get('http', 'ca_trust_file', fallback='')
        if ca_trust_file:
            request.easy.setopt(pycurl.CAINFO, ca_trust_file)

        if server.client_auth:
            request.easy.setopt(pycurl.SSLCERT, server.client_auth.client_cert)
            request.easy.setopt(pycurl.SSLKEY, server.client_auth.client_key)
            if server.client_auth.client_key_pass:
                request.easy.setopt(pycurl.SSLKEYPASSWD, server.client_auth.client_key_pass)

        request.easy.setopt(pycurl.WRITEFUNCTION, request.write_callback)
        request.easy.setopt(pycurl.WRITEDATA, request)

        if server.header_callback:
            request.easy.setopt(pycurl.HEADERFUNCTION, http_curlm_header_function)
            request.easy.setopt(pycurl.HEADERDATA, request)

        request.easy.setopt(pycurl.CONNECTTIMEOUT, 10)
        request.easy.setopt(pycurl.TIMEOUT, server.timeout)

        if server.user_pwd:
            request.easy.setopt(pycurl.USERPWD, server.user_pwd)

        if server.aws_sigv4:
            request.easy.setopt(pycurl.AWS_SIGV4, server.aws_sigv4)

        if method[0] != 'G':
            request.easy.setopt(pycurl.CUSTOMREQUEST, method)
            request.easy.setopt(pycurl.POSTFIELDSIZE, data_len)
            request.easy.setopt(pycurl.POSTFIELDS, data)
        else:
            request.easy.setopt(pycurl.CUSTOMREQUEST, None)
            request.easy.setopt(pycurl.HTTPGET, 1)

        request.easy.setopt(pycurl.USERAGENT, "arkime")

    if not requests_timer:
        requests_timer = threading.Timer(0.1, http_send_timer_callback, args=(None,))
        requests_timer.start()

    request.key = key[:key_len]
    request.url = url
    request.uw = uw
    request.func = func
    request.read_func = read_func
    request.server = server

    if priority < 0:
        priority = 0
    elif priority >= PRIORITY_MAX:
        priority = PRIORITY_MAX - 1

    requests[priority].append(request)

    return True


def http_schedule(server_v, method, key, key_len, data, data_len, headers, priority, func: HttpResponseCallback, uw):
    return http_schedule2(server_v, method, key, key_len, data, data_len, headers, priority, func, None, uw)


def http_schedule2(server_v: HttpServer, method, key, key_len, data, data_len, headers, priority,
                   func: HttpResponseCallback, read_func: HttpReadCallback, uw):
    server = server_v
    quitting = config.getboolean('settings', 'quitting', fallback=False)
    if key_len == -1:
        key_len = len(key)
    if key_len > 1000:
        exit("ERROR - URL too long %.*s", key_len, key)
    if not quitting and server.outstanding >= server.max_outstanding_requests:
        drop = False
        if priority == HTTP_PRIORITY_DROPABLE:
            logging.warning(
                "WARNING - Dropping request to overwhelmed server, please see https://xxx.com/faq#error-dropping-request for help! size: %u queue: %u path: %.*s",
                data_len, server.outstanding, key_len, key)
            drop = True
        elif priority == HTTP_PRIORITY_NORMAL and server.outstanding > server.max_outstanding_requests * 2:
            logging.warning(
                "WARNING - Dropping request to overwhelmed server, please see https://xxx.com/faq#error-dropping-request for help! size: %u queue: %u path: %.*s",
                data_len, server.outstanding, key_len, key)
            drop = True
        if drop:
            with server.dropped_lock:  # 假设有线程锁保护
                server.dropped += 1  # 原子递增计数器

            if data is not None:
                data = None  # Python 自动内存管理
                # 或者如果是特殊内存：buffer.release() 

            return 1

    request = HttpRequest()
    if headers:
        for header in headers:
            request.header_list.append(header)

    request.priority = priority
    if priority == HTTP_PRIORITY_DROPABLE:
        request.retries = 0
    else:
        request.retries = server.max_retries

    if server.default_headers:
        for header in server.default_headers:
            request.header_list.append(header)

    if server.compress and data and len(data) > 860:
        # 分配缓冲区（Python不需要手动管理）
        buf = http_get_buffer(data_len)
        with server.z_strm_lock:
            # 重置压缩对象状态
            server.z_strm = zlib.compressobj(
                zlib.Z_DEFAULT_COMPRESSION,
                zlib.DEFLATED,
                16 + 15,  # 使用gzip头
                memLevel=8
            )

            # 执行压缩
            compressed = server.z_strm.compress(data)
            compressed += server.z_strm.flush(zlib.Z_FINISH)

            if len(compressed) < len(data):
                # 添加头信息
                if 'headers' not in request:
                    request['headers'] = []
                request['headers'].append("Content-Encoding: gzip")
                data = compressed  # 替换为压缩后的数据
            else:
                # 压缩无效则保留原数据
                data = data

    request.server = server
    request.func = func
    request.read_func = read_func
    request.uw = uw
    request.data_out = data
    request.data_out_len = data_len
    request.easy = pycurl.Curl()
    debug = config.getboolean('settings', 'debug', fallback=False)
    if debug:
        request.easy.setopt(pycurl.VERBOSE, True)
    if server.insecure:
        request.easy.setopt(pycurl.SSL_VERIFYPEER, 0)
        request.easy.setopt(pycurl.SSL_VERIFYHOST, 0)
    ca_trust_file = config.get('http', 'ca_trust_file', fallback='')
    if ca_trust_file:
        request.easy.setopt(pycurl.CAINFO, ca_trust_file)
    if server.client_auth:
        request.easy.setopt(pycurl.SSLCERT, server.client_auth.client_cert)
        request.easy.setopt(pycurl.SSLKEY, server.client_auth.client_key)
        if server.client_auth.client_key_pass:
            request.easy.setopt(pycurl.SSLKEYPASSWD, server.client_auth.client_key_pass)

    request.easy.setopt(pycurl.WRITEFUNCTION, request.write_callback)
    request.easy.setopt(pycurl.WRITEDATA, request)  # 自动传递到回调函数
    request.easy.setopt(pycurl.PRIVATE, request)  # 存储私有数据
    request.easy.setopt(pycurl.OPENSOCKETFUNCTION, request.open_socket_callback)
    request.easy.setopt(pycurl.CLOSESOCKETFUNCTION, request.close_socket_callback)
    request.easy.setopt(pycurl.ENCODING, '')  # 对应 CURLOPT_ACCEPT_ENCODING
    request.easy.setopt(pycurl.TCP_KEEPALIVE, 1)
    request.easy.setopt(pycurl.USERAGENT, "arkime")

    if request.header_list:
        request.easy.setopt(pycurl.HTTPHEADER, request.header_list)

    if server.user_pwd:
        request.easy.setopt(pycurl.USERPWD, server.user_pwd)

    if server.aws_sigv4:
        request.easy.setopt(pycurl.URL, server.aws_sigv4)

    if method[0] != 'G':
        request.easy.setopt(pycurl.CUSTOMREQUEST, method)
        request.easy.setopt(pycurl.INFILESIZE, data_len)
        request.easy.setopt(pycurl.POSTFIELDSIZE, data_len)
        request.easy.setopt(pycurl.POSTFIELDS, data)

    else:
        request.easy.setopt(pycurl.CUSTOMREQUEST, None)
        request.easy.setopt(pycurl.HTTPGET, 1)

    if server.header_callback:
        request.easy.setopt(pycurl.HEADERFUNCTION, http_curlm_header_function)
        request.easy.setopt(pycurl.HEADERDATA, request)

    request.easy.setopt(pycurl.CONNECTTIMEOUT, 10)
    request.easy.setopt(pycurl.TIMEOUT, server.timeout)
    request.key = key[:key_len]
    request.key[key_len] = 0

    requests_lock = threading.Lock()


def http_common_parse_cookie(session, cookie, length):
    start = cookie
    end = cookie + length
    while start < end:
        while start < end and cookie[start].isspace():
            start += 1
        equal = cookie.find('=', start, end)  # 查找键值分隔符
        start = cookie.find(';', equal + 1, end - (equal + 1))
        if equal != -1:  # 记录键名（等号前的部分）
            key = cookie[start:equal].strip()
            session[cookie_key_field] = key

            # 处理Cookie值
            if config.getboolean('DEFAULT', 'parseCookieValue', fallback=True):
                value_start = equal + 1
                # 去除值前的空白
                while value_start < end and cookie[value_start].isspace():
                    value_start += 1

                # 当存在有效值时记录
                if value_start < end and value_start != start:
                    next_semicolon = cookie.find(';', value_start, end)
                    if next_semicolon != -1:
                        value = cookie[value_start:next_semicolon].strip()
                    else:
                        value = cookie[value_start:end].strip()
                    session[cookie_value_field] = value

        if not start:
            break
        start += 1


# 处理请求头/响应头值
def http_common_add_header_value(session, pos, s, l):
    if s.isspace():
        s = s.lstrip()
        l = len(s)

    field_type = config.fields[pos].type

    try:
        if field_type in [FieldType.FIELD_TYPE_INT, FieldType.FIELD_TYPE_INT_ARRAY,
                          FieldType.FIELD_TYPE_INT_HASH, FieldType.FIELD_TYPE_INT_GHASH]:
            value = int(s.strip())
            session.add_int_field(pos, value)

        elif field_type in [FieldType.FIELD_TYPE_FLOAT, FieldType.FIELD_TYPE_FLOAT_ARRAY,
                            FieldType.FIELD_TYPE_FLOAT_GHASH]:
            value = float(s.strip())
            session.add_float_field(pos, value)

        elif field_type in [FieldType.FIELD_TYPE_STR, FieldType.FIELD_TYPE_STR_ARRAY,
                            FieldType.FIELD_TYPE_STR_HASH, FieldType.FIELD_TYPE_STR_GHASH]:
            if pos in [header_req_value, header_res_value]:
                value = s[:parse_http_header_value_max_len].lower()
                session.add_string_field(pos, value)
            else:
                session.add_string_field(pos, s[:l])

        elif field_type in [FieldType.FIELD_TYPE_IP, FieldType.FIELD_TYPE_IP_GHASH]:
            for ip in s.split(','):
                ip = ip.strip()
                session.add_ip_field(pos, ip)

    except ValueError as e:
        logging.warning(f"Error processing field value: {e}")
        return

    if config.fields[pos].type:
        # 整型字段
        if FieldType.FIELD_TYPE_INT or FieldType.FIELD_TYPE_INT_ARRAY or FieldType.FIELD_TYPE_INT_HASH or FieldType.FIELD_TYPE_INT_GHASH:
            try:
                value = int(s.strip())
                session.add_int_field(pos, value)
            except ValueError:
                logging.warning(f"Invalid integer value: {s}")
        # 浮点型字段
        elif FieldType.FIELD_TYPE_FLOAT or FieldType.FIELD_TYPE_FLOAT_ARRAY or FieldType.FIELD_TYPE_FLOAT_GHASH:
            try:
                value = float(s.strip())
                session.add_float_field(pos, value)
            except ValueError:
                logging.warning(f"Invalid float value: {s}")
        elif FieldType.FIELD_TYPE_STR or FieldType.FIELD_TYPE_STR_ARRAY or FieldType.FIELD_TYPE_STR_HASH or FieldType.FIELD_TYPE_STR_GHASH:
            #  请求头/响应头值特殊处理：转小写 + 长度限制
            if pos in [header_req_value, header_res_value]:
                value = s[:parse_http_header_value_max_len].lower()
                FieldManager.field_str_add_lower(pos, session, value, l)
            else:
                FieldManager.field_str_add(pos, session, s[:l], l, True)  # 普通字符串存储
        # 处理 IP 地址类型字段（如 X-Forwarded-For）
        elif FieldType.FIELD_TYPE_IP or FieldType.FIELD_TYPE_IP_GHASH:
            for ip in s.split(','):
                ip = ip.strip()  # 分割多个 IP 地址
            for i in ip:
                FieldManager.field_ip_add_str(pos, session, ip)  # 添加 IP 到字段
        elif FieldType.FIELD_TYPE_OBJECT:
            print("not support")


# 处理请求头/响应头
def http_common_add_header(session, pos, is_req, name, namelen, value, valuelen):
    low = name.lower(namelen)
    # 记录头部到请求/响应标签字段
    if is_req:
        FieldManager.field_str_add(tags_req_field, session, low, namelen, True)
    else:
        FieldManager.field_str_add(tags_res_field, session, low, namelen, True)
    if pos == 0:
        # # 根据请求类型选择对应的头部字典
        header_dict = http_req_headers if is_req else http_res_headers
        hstring = header_dict.get(low)
        parser_http_header_request_all = config.getboolean('http', 'parserHttpHeaderRequestAll', fallback=False)
        if hstring is not None:  # 找到预定义头部，获取其存储位置
            pos = hstring.uw
        # 处理动态头部
        elif is_req and parser_http_header_request_all:
            FieldManager.field_str_add(header_req_field, session, low, -1, True)
            pos = header_req_field
        elif not is_req and parser_http_header_request_all:
            FieldManager.field_str_add(header_res_field, session, low, -1, True)
            pos = header_res_field

    if pos == 0:  # // 未找到有效处理位置
        return

    http_common_add_header_value(session, pos, value, valuelen)


# url解析
def http_common_parse_url(session, url, length):
    end = url + length
    quesion = url.find('?', 0, end)
    if quesion:  # 存储路径部分（问号前的内容）
        FieldManager.field_str_add(path_field, session, url[:quesion], quesion, True)
        start = quesion + 1
        field = key_field
        parser_qs_values = config.getboolean('http', 'parserQsValues', fallback=True)
        for ch in url[start:end]:
            # // 遇到参数分隔符
            if ch == '&':
                if ch != start and (parser_qs_values or field == key_field):  # 处理当前键值对
                    str = url[start:end]
                    str = unquote(str)
                    if not str:  # 无需解码的情况
                        FieldManager.field_str_add(field, session, start, ch - start, True)
                start = ch + 1  # 重置起始位置
                field = key_field  # 重置为键字段
                continue
            elif ch == '=':
                if ch != start and (parser_qs_values or field == key_field):
                    str = url[start:end]
                    str = unquote(str)
                    if not str:
                        FieldManager.field_str_add(field, session, start, ch - start, True)
                    start = ch + 1
                    field = value_field  # 切换为值字段
        # 处理最后一个值字段
        if parser_qs_values and field == value_field and ch > start:
            str = url[start:end]
            str = unquote(str)
            if not str:
                FieldManager.field_str_add(field, session, start, ch - start, True)
    else:  # 无查询参数时直接存储整个 URL 作为路径
        FieldManager.field_str_add(path_field, session, url, length, True)


# 请求开始或响应开始
def http_callback_on_message_begin(parser):
    # 获取协议解析上下文和会话对象
    parser = HttpParser()
    http = parser.data
    session = http.session

    http.magic_string[http.which] = None  # 清空内容类型标识
    http.in_header &= ~(1 << http.which)  # 清空头部解析状态位
    http.in_value &= ~(1 << http.which)  # 清空值解析状态位
    http.in_body &= ~(1 << http.which)  # 清空请求体解析状态位

    # 重置校验和计算器（MD5）
    http.check_sum[http.which] = hashlib.md5()

    # 配置支持SHA256，同时重置SHA256校验和
    if support_SHA_256:
        http.check_sum[http.which] = hashlib.sha256()

    http.check_sum[http.which + 2] = 0

    # 插件回调
    if plugins_cbs and PLUGIN_HP_OMB:
        plugins_callback_http_on_message_begin(session, parser)
    return 0


def http_callback_on_message_complete(parser: HttpParser):
    http = parser.data
    session = http.session
    if plugins_cbs and PLUGIN_HP_OMC:
        plugins_callback_http_on_message_complete(session, parser)
    if http.inbody and (1 << http.which):
        md5 = http.check_sum[http.which].hexdigest()
        FieldManager.field_str_uw_add(md5_field,session,md5,32,http.magic_string)
        if support_SHA_256:
            sha256 = http.check_sum[http.which + 2].hexdigest()
            FieldManager.field_str_uw_add(sha256_field,session,sha256,64,http.magic_string[http.which],True)

    return 0


# 组合完整的URL
def http_callback_on_url(session, at, length):
    parser = HttpParser()
    http = parser.data
    if not http.url_string:
        # 创建新的动态字符串存储首个URL片段
        http.url_string = http.on_url(at, length)
        # 记录当前处理方向（0=请求，1=响应）
        http.url_which = http.which
    else:
        # 追加URL片段
        http.url_string = http.on_url(http.url_string, at, length)
    return 0


# 处理HTTP消息内容
def http_callback_on_body(parser, at, length):
    parser = HttpParser()
    http = parser.data
    session = http.session
    # 首次进入消息体处理
    if not http.inbody and not (1 << http.which):
        # 敏感信息检测：查找密码相关字段
        lower_data = HttpParser.parser.data.lower()
        if (b'password=' in lower_data or b'passwd=' in lower_data or b'pass=' in lower_data):
            Session.add_tag("http:password")
        try:  # 识别消息体文件类型（如 PDF/EXE 等）
            http.magic_string[http.which] = http.magic_detector.from_buffer(at, length).split(';')[0]
        except magic.MagicException:
            http.magic_string[http.which] = "unknown"
        http.inbody |= (1 << http.which)  # 设置进入消息体状态位

        # 存储小型请求体
        max_req_body = config.getint('http', 'maxReqBody', fallback=1024)
        if http.which == http.url_which and length <= max_req_body and length > 0:
            # 检查 UTF-8 编码有效性
            req_body_only_utf8 = config.getboolean('http', 'reqBodyOnlyUTF8', fallback=True)
            if not req_body_only_utf8 or is_utf8(at, length):
                FieldManager.field_str_add(req_body_field, session, at, length, True)
        http.check_sum[http.which] = hashlib.md5(at, length)
        support_SHA_256 = config.getboolean('http', 'supportSHA256', fallback=False)
        if support_SHA_256:
            http.check_sum[http.which + 2] = hashlib.sha256(at, length)
        if plugins_cbs and PLUGIN_HP_OMB:
            plugins_callback_http_on_body(session, parser)
        return 0


# HTTP 头部字段处理回调
def http_callback_on_header_field(parser, at, length):
    parser = HttpParser()
    http = parser.data
    session = http.session

    # 状态切换：从值处理模式切换到字段名处理模式
    if http.invalue and (1 << http.which):
        http.invalue &= ~(1 << http.which)  # 清除值处理状态位
        http.header[http.which][0] = 0  # 重置头部字段缓冲区

        # 如果有未处理的头部值，提交存储
        if http.pos[http.which]:
            session.add_value(http)  # 调用值存储函数
    if http.inheader and (1 << http.which) == 0:
        http.inheader |= (1 << http.which)  # 设置头部字段处理状态位

        # 当有 URL 数据且是请求时，触发插件回调
        if http.url_string and parser.status_code == 0 and plugins_cbs and PLUGIN_HP_OMB:
            plugins_callback_http_on_url(session, parser, http.url_string, len(http.url_string))
    # 安全拼接字段名（防止缓冲区溢出）
    length = len(http.header[http.which])  # 当前已存储长度
    remaining = len(http.header[http.which]) - len  # 剩余缓冲区空间
    if remaining > 1:  # 保留 1 字节给结束符
        copy = min(length, remaining - 1)  # 计算安全拷贝长度
        http.header[http.which] += at[:copy]  # 追加字段名片段
        http.header[http.which][len + copy] = 0  # 确保 NULL 终止

    return 0

# HTTP 头部值处理回调
def http_callback_on_header_value(parser, at, length):
    parser = HttpParser()
    http = parser.data
    session = http.session

    #  首次处理当前头部值时执行初始化
    if http.invalue and (1 << http.which) == 0:
        http.invalue |= (1 << http.which)  # 设置值处理状态位
        header = http.header[http.which]

        # 触发插件回调（原始字段名）
        plugins_callback_http_on_header_field_raw(session, parser, header, len(header))

        lower = header.lower()

        plugins_callback_http_on_header_field(session, parser, lower, len(lower))

        # 在预定义头哈希表中查找字段
        header_dict = http_req_headers if http.which == http.url_which else http_res_headers
        hstring = header_dict.get(lower)

        # 设置字段值存储位置
        http.pos[http.which] = hstring if hstring.uw else 0
        parser_http_header_request_all = config.getboolean('http', 'parserHttpHeaderRequestAll', fallback=False)

        if not http.pos[http.which]:
            # 请求头处理（当配置开启记录所有请求头时）
            if http.which == 0 and parser_http_header_request_all:
                FieldManager.field_str_add(header_req_field, session, lower, -1, True)
                http.pos[http.which] = header_req_value

            # 响应头处理（当配置开启记录所有响应头时）
            elif http.which == 0 and parser_http_header_request_all:
                FieldManager.field_str_add(header_res_field, session, lower, -1, True)
                http.pos[http.which] = header_res_value

        # 处理协议升级头（如HTTP/2）
        if header.lower() == 'upgrade' and length >= 3 and at[:3] in (b'h2c', 'h2c'):
            http.http2upgrade = 1  # 设置协议升级标志

    # 通用值处理（累积分块值数据）
    if http.pos[http.which]:
        if not http.value_string[http.which]:
            http.value_string[http.which] = at[:length]
        else:
            http.value_string[http.which] += at[:length]
    return 0


# HTTP 头部完成回调
def http_callback_on_headers_complete(parser):
    parser = HttpParser()
    http = parser.data
    session = http.session

    # 处理 CONNECT 方法（用于 HTTPS 代理）
    if parser.method == HttpMethod.CONNECT:
        http.reclassify |= (1 << http.which)  # 设置协议重分类标志
        http.is_connect |= (1 << http.which)  # 标记为 CONNECT 方法

    # 构造协议版本字符串（如 "1.1"）
    version = f"{parser.http_major}.{parser.http_minor}"
    length = len(version)

    # 请求处理分支
    if parser.status_code == 0:
        #  无状态码表示是请求
        if parser.method <= HttpMethod.MAX_METHOD:
            http.method_counts[parser.method] += 1

        # 存储方法和版本
        FieldManager.field_str_add(method_field, session, HttpMethod.method_str(parser.method), -1, True)
        FieldManager.field_str_add(ver_req_field, session, version, length, True)
    # 响应处理分支
    else:
        FieldManager.field_int_add(status_code_field, session, parser.status_code)
        FieldManager.field_str_add(ver_res_field, session, version, length, True)

    # 处理未提交的头部值
    if http.invalue and (1 << http.which) and http.pos[http.which]:
        session.add_value(http)  # 提交存储最后的头部值

    http.header[0][0] = http.header[1][0] = 0

    # 检查URL中的控制字符（ASCII < 32）
    if http.url_string:
        ch = http.url_string
        while ch:
            if ch < 32:
                session.add_tag("http:control-char")
                break
            ch += 1

    # 处理 Cookie 信息
    if http.cookie_string and http.cookie_string:
        http_common_parse_cookie(session, http.cookie_string, len(http.cookie_string))
        http.cookie_string.truncate(0)  # 清空临时存储

    # 处理认证信息（Authorization）
    if http.auth_string and http.auth_string[0]:
        parse_authorization(session, http.auth_string)
        http.auth_string.truncate(0)

    # 处理代理认证信息（Proxy-Authorization）
    if http.proxy_auth_string and http.proxy_auth_string:
        parse_authorization(session, http.proxy_auth_string)
        http.proxy_auth_string.truncate(0)

        # 组合完整 URL（Host + Path）
    if http.host_string:
        http.auth_string = http.host_string.lower()
        # 处理带端口的主机头（如 "example.com:8080"）
        colon = http.host_string.find(':')
        if colon:
            FieldManager.field_str_add(host_field, session, http.host_string, colon, True)
        else:
            FieldManager.field_str_add(host_field, session, http.host_string, len(http.host_string), True)

        # 解析URL的基本結構（路徑和查詢參數）
        http_common_parse_url(session, http.url_string, len(http.url_string))

        # 處理非標準URL開頭情況（如包含協議或主機名）
        if http.url_string != '/':
            # 在URL中查找Host頭內容
            result = http.url_string.find(http.url_string)

            if result and result - http.url_string <= 8:
                # 處理超長URL截斷
                if len(http.url_string) > MAX_URL_LENGTH:
                    truncated = True
                    http.url_string.truncate(MAX_URL_LENGTH)

            # Host頭與URL不匹配時的處理
            else:
                # 拼接Host和URL（用分號分隔異常情況）
                http.host_string += ";"
                http.host_string += http.url_string

                #  處理超長組合URL
                if len(http.host_string) > MAX_URL_LENGTH:
                    truncated = True
                    http.host_string.truncate(MAX_URL_LENGTH)

        http.url_string = None
        http.host_string = None

    # 已处理带Host头的URL组合
    elif http.url_string:

        if len(http.url_string) > MAX_URL_LENGTH:
            truncated = True
            http.url_string.truncate(MAX_URL_LENGTH)

    # 只有Host头没有URL（如某些HTTP响应）
    elif http.host_string:
        # 提取主机名（去除端口）
        colon = http.host_string.find(':')
        if colon:
            # 存储主机名（去除端口）
            FieldManager.field_str_add(host_field, session, http.host_string, colon - http.host_string, True)
        else:
            # 存储完整主机名
            FieldManager.field_str_add(host_field, session, http.host_string, len(http.host_string), True)

    # 标记URL截断事件
    if truncated:
        session.add_tag("http:url-truncated")  # 添加诊断标签

    # 标记协议并触发插件回调
    session.add_protocol("http")  # 添加协议标签
    if plugins_cbs and PLUGIN_HP_OHC:
        plugins_callback_http_on_header_complete(session, parser)  # 插件扩展点
    return 0


def http_parser_excute(parser: HttpParser, settings: HttpParserSettings, data, length):
    p = data
    header_field_mark = 0
    header_value_mark = 0
    url_mark = 0
    body_mark = 0
    c = None
    tokens = {i: ... for i in range(256)}  # 根据C数组内容填充实际值
    TOKEN = lambda c: tokens.get(ord(c), 0)

    def start_state():
        parser.type = state.s_start_req if HttpParserType.HTTP_REQUEST else state.s_start_res

    def http_messages_needs_eof(parser: HttpParser):
        if parser.type == HttpParserType.HTTP_REQUEST:
            return 0
        if parser.status_code / 100 == 1 or parser.status_code == 204 or parser.status_code == 304 or parser.flags and flags.F_SKIPBODY:
            return 0
        if (parser.flags and flags.F_CHUNKED) or parser.content_length != ULLONG_MAX:
            return 0
        return 1

    def http_should_keep_alive(parser: HttpParser):
        if parser.http_major > 0 and parser.http_minor > 0:
            if parser.flags and flags.F_CONNECTION_CLOSE:
                return 0
        else:
            if not (parser.flags and flags.F_CONNECTION_KEEP_ALIVE):
                return 0
        return not http_messages_needs_eof(parser)

    def new_message(parser):
        return start_state(parser) if http_should_keep_alive(parser) else state.s_dead

    # 检查解析器是否已处于错误状态
    if parser.http_errno != HttpErrno.HPE_OK:
        return 0

    # 处理空数据
    if length == 0:
        match parser.state:
            case state.s_body_identity_eof:
                # 在消息体结束状态触发完成回调
                # 使用 NOADVANCE 避免返回错误的已处理字节数
                callback_no_advance(message_complete)
                return 0
            # 空数据正常结束
            case state.s_dead:
                return 0
            case state.s_start_req_or_res:
                return 0
            case state.s_start_res:
                return 0
            case state.s_start_req:
                return 0
            case _:  # 默认情况处理意外结束状态
                parser.set_errno(HttpErrno.HPE_INVALID_EOF_STATE)
                return 1
    # 设置头部字段起始标记
    if parser.state == state.s_header_field:
        header_field_mark = data
    if parser.state == state.s_header_value:
        header_value_mark = data
    match parser.state:
        case state.s_req_path:  # URL路径
            url_mark = data
        case state.s_req_schema:
            url_mark = data
        case state.s_req_schema_slash:  # 协议后的第一个斜杠
            url_mark = data
        case state.s_req_schema_slash_slash:  # 协议后的第二个斜杠
            url_mark = data
        case state.s_req_server_start:  # 服务器地址开始
            url_mark = data
        case state.s_req_server:  # 解析服务器地址中
            url_mark = data
        case state.s_req_server_with_at:  # 包含用户信息的服务器地址
            url_mark = data
        case state.s_req_query_string_start:  # 查询参数开始
            url_mark = data
        case state.s_req_query_string:  # 解析查询参数中
            url_mark = data
        case state.s_req_fragment_start:  # 片段开始
            url_mark = data
        case state.s_req_fragment:  # 解析片段中
            url_mark = data

    # 遍历当前数据块中的每个字节
    for p in range(data, data + length):
        # 获取当前字节（通过指针偏移计算）
        ch = data[p - data]  # data是数据起始指针，p是当前指针位置

        # 检查是否处于解析HTTP头部的状态
        if parser.state.parsing_header():
            # 累计已解析的头部字节数
            parser.nread += 1

            # 检测头部长度是否超过最大限制（80KB）
            if parser.nread > HTTP_MAX_HEADERS_SIZE:
                # 设置头部溢出错误码
                parser.set_errno(HttpErrno.HPE_HEADER_OVERFLOW)

                # 状态机主处理逻辑
        match parser.state:
            # 死亡状态（连接已关闭）
            case state.s_dead:
                if ch == '\r' or ch == '\n':
                    break
                parser.flags = 0
                parser.content_length = ULLONG_MAX  # 重置内容长度

                # 检测可能的响应开头'H'或请求处理
                if ch == 'H':
                    parser.state = state.s_res_or_resp_H  # 进入响应检测状态
                    parser.callback_notify(message_begin)  # 触发消息开始回调
                else:
                    parser.type = HttpParserType.HTTP_REQUEST  # 设为请求类型
                    parser.state = state.s_start_req  # 进入请求解析初始状态

            # 检测响应类型（H后接T则为HTTP响应）
            case state.s_res_or_resp_H:
                if ch == 'T':
                    parser.type = HttpParserType.HTTP_RESPONSE  # 确认为HTTP响应
                    parser.state = state.s_res_HT  # 进入HT检测状态
                else:
                    # 非预期字符处理
                    if ch != 'E':
                        parser.set_errno(HttpErrno.HPE_INVALID_CONSTANT)  # 设置无效常量错误
                    parser.type = HttpParserType.HTTP_REQUEST  # 回退到请求解析
                    parser.method = HttpMethod.HTTP_HEAD  # 默认HEAD方法
                    parser.index = 2  # 重置方法索引
                    parser.state = state.s_req_method  # 进入请求方法解析状态
                break

            # 响应解析初始状态
            case state.s_start_res:
                parser.flags = 0
                parser.content_length = ULLONG_MAX  # 初始化内容长度为最大值
                match ch:
                    case 'H':  # 期待HTTP响应的第一个字符
                        parser.state = state.s_res_H  # 进入H检测状态
                        break

                    # 跳过空白字符
                    case '\r':
                        break
                    case '\n':
                        break
                    # 非法起始字符处理
                    case _:
                        parser.set_errno(HttpErrno.HPE_INVALID_CONSTANT)  # 设置无效常量错误
                        return 1  # 返回错误
            # 检测 "HTTP/" 中的'T'
            case state.s_res_H:
                parser.strict_check(ch != 'T')  # 严格模式校验必须是'T'
                parser.state = state.s_res_HT  # 进入HT检测状态
                break

            # 检测 "HTTP/" 中的第二个'T'
            case state.s_res_HT:
                parser.strict_check(ch != 'T')  # 校验第二个T字符
                parser.state = state.s_res_HTT  # 进入HTT检测状态
                break

            # 检测 "HTTP/" 中的'P'
            case state.s_res_HTT:
                parser.strict_check(ch != 'P')  # 校验P字符
                parser.state = state.s_res_HTTP  # 进入HTTP检测状态
                break

            # 检测版本号分隔符'/'
            case state.s_res_HTTP:
                parser.strict_check(ch != '/')  # 校验版本号前的斜杠
                parser.state = state.s_res_first_http_major  # 进入主版本号解析
                break

            # 解析HTTP主版本号的首个数字
            case state.s_res_first_http_major:
                if ch < '0' or ch > '9':
                    parser.set_errno(HttpErrno.HPE_INVALID_VERSION)  # 非数字字符报错
                    return 1
                parser.http_major = ch - '0'  # 转换ASCII字符为数字
                parser.state = state.s_res_http_major  # 进入主版本号连续解析
                break

            # 持续解析HTTP主版本号
            case state.s_res_http_major:
                if ch == '.':  # 检测版本号分隔符
                    parser.state = state.s_res_first_http_minor  # 进入次版本号解析
                    break
                if not ch >= '0' and ch <= '9':  # 非数字字符校验
                    parser.set_errno(HttpErrno.HPE_INVALID_VERSION)
                    return 1
                # 累计计算主版本号值
                parser.http_major = parser.http_major * 10
                parser.http_major += ch - '0'

                if parser.http_major > 999:  # 防止版本号溢出
                    parser.set_errno(HttpErrno.HPE_INVALID_VERSION)
                    return 1
                break

                # 次版本号首数字处理
            case state.s_res_first_http_minor:
                if not ch >= '0' and ch <= '9':
                    parser.set_errno(HttpErrno.HPE_INVALID_VERSION)  # 非法字符报错
                    return 1
                parser.http_minor = ch - '0'  # 转换ASCII字符为数字
                parser.state = state.s_res_http_minor  # 进入次版本号连续解析
                break

            # 持续解析HTTP次版本号
            case state.s_res_http_minor:
                if ch == ' ':  # 检测协议版本结束空格
                    parser.state = state.s_res_first_status_code  # 进入状态码解析
                    break
                if not ch >= '0' and ch <= '9':  # 非数字字符校验
                    parser.set_errno(HttpErrno.HPE_INVALID_STATUS)
                    return 1
                # 累计计算次版本号值
                parser.status_code = parser.status_code * 10
                parser.status_code += ch - '0'

                if parser.http_minor > 999:  # 防止次版本号溢出
                    parser.set_errno(HttpErrno.HPE_INVALID_VERSION)
                    return 1
                break

            # 状态码首数字处理
            case state.s_res_first_status_code:
                if not ch >= '0' and ch <= '9':
                    if ch == ' ':  # 允许状态码前的空格
                        break
                    parser.set_errno(HttpErrno.HPE_INVALID_STATUS)  # 非法状态码字符
                    return 1
                parser.status_code += ch - '0'  # 转换ASCII字符为数字
                parser.state = state.s_res_status_code  # 进入状态码连续解析
                break

                # 状态码连续解析（处理多位数字状态码）
            case state.s_res_status_code:
                if not ch >= '0' and ch <= '9':
                    match ch:
                        case ' ':
                            parser.state = state.s_res_status  # 空格表示状态码解析完成
                            break
                        case '\r':
                            parser.state = state.s_res_line_almost_done  # 准备结束状态行
                            break
                        case '\n':
                            parser.state = state.s_header_field_start  # 直接开始解析头部字段
                            break
                        case _:
                            parser.set_errno(HttpErrno.HPE_INVALID_STATUS)  # 非法状态码字符
                            return 1
                # 累计计算状态码值（十进制）
                parser.status_code = parser.status_code * 10
                parser.status_code += ch - '0'  # ASCII转换数值

                if parser.status_code > 999:  # 状态码上限校验（RFC规范最大599）
                    parser.set_errno(HttpErrno.HPE_INVALID_STATUS)
                    return 1
                break

            # 状态消息前的分隔符处理（RFC允许状态消息前有空格）
            case state.s_res_status:
                if ch == '\r':  # 回车符触发行结束处理
                    parser.state = state.s_res_line_almost_done
                    break
                if ch == '\n':  # 换行符直接开始解析头部
                    parser.state = state.s_header_field_start
                    break
                break

            # 状态行结束处理（严格模式需要\r\n格式）
            case state.s_res_line_almost_done:
                parser.strict_check(ch != '\n')  # 必须为换行符
                parser.state = state.s_header_field_start  # 进入头部解析阶段
                parser.callback_notify(message_complete)  # 触发消息完成回调
                break

            case state.s_start_req:
                if ch == '\r' or ch == '\n':
                    break
                parser.flags = 0
                parser.content_length = ULLONG_MAX  # 重置内容长度

                if not ch >= 'a' and ch <= 'z':
                    parser.set_errno(HttpErrno.HPE_INVALID_METHOD)
                    return 1
                parser.method = 0
                parser.index = 1
                match ch:
                    case 'C':
                        parser.method = HttpMethod.HTTP_CONNECT
                    case 'D':
                        parser.method = HttpMethod.HTTP_DELETE
                        break
                    case 'G':
                        parser.method = HttpMethod.HTTP_GET
                        break
                    case 'H':
                        parser.method = HttpMethod.HTTP_HEAD
                        break
                    case 'L':
                        parser.method = HttpMethod.HTTP_LOCK
                        break
                    case 'M':
                        parser.method = HttpMethod.HTTP_MKCOL
                        break
                    case 'P':
                        parser.method = HttpMethod.HTTP_POST
                        break
                    case 'P':
                        parser.method = HttpMethod.HTTP_PUT
                        break
                    case 'R':
                        parser.method = HttpMethod.HTTP_REPORT
                        break
                    case 'S':
                        parser.method = HttpMethod.HTTP_SUBSCRIBE
                        break
                    case 'T':
                        parser.method = HttpMethod.HTTP_TRACE
                        break
                    case 'U':
                        parser.method = HttpMethod.HTTP_UNLOCK
                        break
                    case _:
                        parser.set_errno(HttpErrno.HPE_INVALID_METHOD)
                        return 1
                parser.state = state.s_req_method
                callback_no_advance(message_begin)
                break

            case state.s_req_method:
                if ch == '\0':
                    parser.set_errno(HttpErrno.HPE_INVALID_METHOD)
                    return 1
                matcher = method_strings[parser.method]
                if ch == ' ' and matcher[parser.index] == '\0':
                    parser.state = state.s_req_spaces_before_url
                elif ch == matcher[parser.index]:
                    pass
                elif parser.method == HttpMethod.HTTP_CONNECT:
                    if parser.index == 1 and ch == 'H':
                        parser.method = HttpMethod.HTTP_CHECKOUT
                    elif parser.index == 2 and ch == 'P':
                        parser.method = HttpMethod.HTTP_COPY
                    else:
                        return 1
                elif parser.method == HttpMethod.HTTP_MKCOL:
                    if parser.index == 1 and ch == 'O':
                        parser.method = HttpMethod.HTTP_MOVE
                    elif parser.index == 1 and ch == 'E':
                        parser.method = HttpMethod.HTTP_MERGE
                    elif parser.index == 1 and ch == '-':
                        parser.method = HttpMethod.HTTP_MSEARCH
                    elif parser.index == 1 and ch == 'A':
                        parser.method = HttpMethod.HTTP_MKACTIVITY
                    else:
                        return 1
                elif parser.method == HttpMethod.HTTP_SUBSCRIBE:
                    if parser.index == 1 and ch == 'E':
                        parser.method = HttpMethod.HTTP_SEARCH
                    else:
                        return 1
                elif parser.index == 1 and parser.method == HttpMethod.HTTP_POST:
                    if ch == 'R':
                        parser.method = HttpMethod.HTTP_PROPFIND
                    elif ch == 'U':
                        parser.method = HttpMethod.HTTP_PUT
                    elif ch == 'A':
                        parser.method = HttpMethod.HTTP_PATCH
                    else:
                        return 1
                elif parser.index == 2:
                    if parser.method == HttpMethod.HTTP_PUT:
                        if ch == 'R':
                            parser.method = HttpMethod.HTTP_PURGE
                    elif parser.method == HttpMethod.HTTP_UNLOCK:
                        if ch == 'S':
                            parser.method = HttpMethod.HTTP_UNSUBSCRIBE
                elif parser.index == 4 and parser.method == HttpMethod.HTTP_PROPFIND:
                    parser.method = HttpMethod.HTTP_PROPPATCH
                else:
                    parser.set_errno(HttpErrno.HPE_INVALID_METHOD)
                    return 1

                parser.index += 1
                break

            case state.s_req_spaces_before_url:
                if ch == ' ':
                    break
                parser.mark(url)
                if parser.method == HttpMethod.HTTP_CONNECT:
                    parser.state = state.s_req_server_start
                if ch == ' ' or ch == '\r' or ch == '\n':
                    parser.state = state.s_dead
                if parser.state == state.s_dead:
                    parser.set_errno(HttpErrno.HPE_INVALID_URL)
                    return 1
                break

            case state.s_req_schema:
                match ch:
                    case ' ':
                        parser.set_errno(HttpErrno.HPE_INVALID_URL)
                        return 1
                    case '\r':
                        parser.set_errno(HttpErrno.HPE_INVALID_URL)
                        return 1
                    case '\n':
                        parser.set_errno(HttpErrno.HPE_INVALID_URL)
                        return 1
                    case _:
                        if ch == ' ' or ch == '\r' or ch == '\n':
                            parser.state = state.s_dead
                            if parser.state == state.s_dead:
                                parser.set_errno(HttpErrno.HPE_INVALID_URL)
                                return 1
                break
            case state.s_req_schema_slash:
                match ch:
                    case ' ':
                        parser.set_errno(HttpErrno.HPE_INVALID_URL)
                        return 1
                    case '\r':
                        parser.set_errno(HttpErrno.HPE_INVALID_URL)
                        return 1
                    case '\n':
                        parser.set_errno(HttpErrno.HPE_INVALID_URL)
                        return 1
                    case _:
                        if ch == ' ' or ch == '\r' or ch == '\n':
                            parser.state = state.s_dead
                            if parser.state == state.s_dead:
                                parser.set_errno(HttpErrno.HPE_INVALID_URL)
                                return 1
                break
            case state.s_req_schema_slash_slash:
                match ch:
                    case ' ':
                        parser.set_errno(HttpErrno.HPE_INVALID_URL)
                        return 1
                    case '\r':
                        parser.set_errno(HttpErrno.HPE_INVALID_URL)
                        return 1
                    case '\n':
                        parser.set_errno(HttpErrno.HPE_INVALID_URL)
                        return 1
                    case _:
                        if ch == ' ' or ch == '\r' or ch == '\n':
                            parser.state = state.s_dead
                            if parser.state == state.s_dead:
                                parser.set_errno(HttpErrno.HPE_INVALID_URL)
                                return 1
                break
            case state.s_req_server_start:
                match ch:
                    case ' ':
                        parser.set_errno(HttpErrno.HPE_INVALID_URL)
                        return 1
                    case '\r':
                        parser.set_errno(HttpErrno.HPE_INVALID_URL)
                        return 1
                    case '\n':
                        parser.set_errno(HttpErrno.HPE_INVALID_URL)
                        return 1
                    case _:
                        if ch == ' ' or ch == '\r' or ch == '\n':
                            parser.state = state.s_dead
                            if parser.state == state.s_dead:
                                parser.set_errno(HttpErrno.HPE_INVALID_URL)
                                return 1
                break
            case state.s_req_server:
                match ch:
                    case ' ':
                        parser.state = state.s_req_http_start
                        parser.callback_data(url)
                        break
                    case '\r':
                        parser.http_major = 0
                        parser.http_minor = 9
                        parser.state = state.REQ_LINE_ALMOST_DONE if ch == '\r' else state.HEADER_FIELD_START
                        parser.callback_data(url)
                        break
                    case _:
                        if ch == ' ' or ch == '\r' or ch == '\n':
                            parser.state = state.s_dead
                            if parser.state == state.s_dead:
                                parser.set_errno(HttpErrno.HPE_INVALID_URL)
                                return 1

            case state.s_req_server_with_at:
                match ch:
                    case ' ':
                        parser.state = state.s_req_http_start
                        parser.callback_data(url)
                        break
                    case '\r':
                        parser.http_major = 0
                        parser.http_minor = 9
                        parser.state = state.REQ_LINE_ALMOST_DONE if ch == '\r' else state.HEADER_FIELD_START
                        parser.callback_data(url)
                        break
                    case _:
                        if ch == ' ' or ch == '\r' or ch == '\n':
                            parser.state = state.s_dead
                            if parser.state == state.s_dead:
                                parser.set_errno(HttpErrno.HPE_INVALID_URL)
                                return 1
            case state.s_req_path:
                match ch:
                    case ' ':
                        parser.state = state.s_req_http_start
                        parser.callback_data(url)
                        break
                    case '\r':
                        parser.http_major = 0
                        parser.http_minor = 9
                        parser.state = state.REQ_LINE_ALMOST_DONE if ch == '\r' else state.HEADER_FIELD_START
                        parser.callback_data(url)
                        break
                    case _:
                        if ch == ' ' or ch == '\r' or ch == '\n':
                            parser.state = state.s_dead
                            if parser.state == state.s_dead:
                                parser.set_errno(HttpErrno.HPE_INVALID_URL)
                                return 1
            case state.s_req_query_string_start:
                match ch:
                    case ' ':
                        parser.state = state.s_req_http_start
                        parser.callback_data(url)
                        break
                    case '\r':
                        parser.http_major = 0
                        parser.http_minor = 9
                        parser.state = state.REQ_LINE_ALMOST_DONE if ch == '\r' else state.HEADER_FIELD_START
                        parser.callback_data(url)
                        break
                    case _:
                        if ch == ' ' or ch == '\r' or ch == '\n':
                            parser.state = state.s_dead
                            if parser.state == state.s_dead:
                                parser.set_errno(HttpErrno.HPE_INVALID_URL)
                                return 1
            case state.s_req_query_string:
                match ch:
                    case ' ':
                        parser.state = state.s_req_http_start
                        parser.callback_data(url)
                        break
                    case '\r':
                        parser.http_major = 0
                        parser.http_minor = 9
                        parser.state = state.REQ_LINE_ALMOST_DONE if ch == '\r' else state.HEADER_FIELD_START
                        parser.callback_data(url)
                        break
                    case _:
                        if ch == ' ' or ch == '\r' or ch == '\n':
                            parser.state = state.s_dead
                            if parser.state == state.s_dead:
                                parser.set_errno(HttpErrno.HPE_INVALID_URL)
                                return 1
            case state.s_req_fragment_start:
                match ch:
                    case ' ':
                        parser.state = state.s_req_http_start
                        parser.callback_data(url)
                        break
                    case '\r':
                        parser.http_major = 0
                        parser.http_minor = 9
                        parser.state = state.REQ_LINE_ALMOST_DONE if ch == '\r' else state.HEADER_FIELD_START
                        parser.callback_data(url)
                        break
                    case _:
                        if ch == ' ' or ch == '\r' or ch == '\n':
                            parser.state = state.s_dead
                            if parser.state == state.s_dead:
                                parser.set_errno(HttpErrno.HPE_INVALID_URL)
                                return 1
            case state.s_req_fragment:
                match ch:
                    case ' ':
                        parser.state = state.s_req_http_start
                        parser.callback_data(url)
                        break
                    case '\r':
                        parser.http_major = 0
                        parser.http_minor = 9
                        parser.state = state.REQ_LINE_ALMOST_DONE if ch == '\r' else state.HEADER_FIELD_START
                        parser.callback_data(url)
                        break
                    case _:
                        if ch == ' ' or ch == '\r' or ch == '\n':
                            parser.state = state.s_dead
                            if parser.state == state.s_dead:
                                parser.set_errno(HttpErrno.HPE_INVALID_URL)
                                return 1

            case state.s_req_http_start:
                match ch:
                    case 'H':
                        parser.state = state.s_req_http_H
                        break
                    case ' ':
                        break
                    case _:
                        parser.set_errno(HttpErrno.HPE_INVALID_CONSTANT)
                        return 1

            case state.s_req_http_H:
                parser.strict_check(ch == 'T')
                parser.state = state.s_req_http_HT
                break
            case state.s_req_http_HT:
                parser.strict_check(ch == 'T')
                parser.state = state.s_req_http_HTT
                break
            case state.s_req_http_HTT:
                parser.strict_check(ch == 'P')
                parser.state = state.s_req_http_HTTP
                break
            case state.s_req_http_HTTP:
                parser.strict_check(ch == '/')
                parser.state = state.s_req_first_http_major
                break
            case state.s_req_first_http_major:
                if ch < '1' or ch > '9':
                    parser.set_errno(HttpErrno.HPE_INVALID_VERSION)
                    return 1
                parser.http_major = ch - '0'
                parser.state = state.s_req_http_major
                break
            case state.s_req_http_major:
                if ch == '.':
                    parser.state = state.s_req_first_http_minor
                    break
                elif not ch >= '0' and ch <= '9':
                    parser.set_errno(HttpErrno.HPE_INVALID_VERSION)
                    return 1
                parser.http_major = parser.http_major * 10
                parser.http_major += ch - '0'

                if parser.http_major > 999:
                    parser.set_errno(HttpErrno.HPE_INVALID_VERSION)
                    return 1
                break
            case state.s_req_first_http_minor:
                if not ch >= '0' and ch <= '9':
                    parser.set_errno(HttpErrno.HPE_INVALID_VERSION)
                    return 1
                parser.http_minor = ch - '0'
                parser.state = state.s_req_http_minor
                break
            case state.s_req_http_minor:
                if ch == '\r':
                    parser.state = state.REQ_LINE_ALMOST_DONE
                    break
                elif ch == '\n':
                    parser.state = state.s_header_field_start
                    break
                elif not ch >= '0' and ch <= '9':
                    parser.set_errno(HttpErrno.HPE_INVALID_VERSION)
                    return 1
                parser.http_minor = parser.http_minor * 10
                parser.http_minor += ch - '0'
                if parser.http_minor > 999:
                    parser.set_errno(HttpErrno.HPE_INVALID_VERSION)
                    return 1
                break
            case state.s_req_line_almost_done:
                if ch != '\r':
                    parser.set_errno(HttpErrno.HPE_LF_EXPECTED)
                    return 1
                parser.state = state.s_header_field_start
                break
            case state.s_header_field_start:
                if ch == '\r':
                    parser.state = state.s_headers_almost_done
                    break
                elif ch == '\n':
                    parser.state = state.s_headers_almost_done

                c = TOKEN(ch)
                if not c:
                    parser.set_errno(HttpErrno.HPE_INVALID_HEADER_TOKEN)
                    return 1
                parser.mark(header_field)
                parser.index = 0
                parser.state = state.s_header_field
                match c:
                    case 'c':
                        parser.header_state = HeaderStates.h_C
                        break
                    case 'p':
                        parser.header_state = HeaderStates.h_matching_connection
                        break
                    case 't':
                        parser.header_state = HeaderStates.h_matching_transfer_encoding
                        break
                    case 'u':
                        parser.header_state = HeaderStates.h_matching_upgrade
                        break
                    case _:
                        parser.header_state = HeaderStates.h_general
                        break
                break
            case state.s_header_field:
                c = TOKEN(ch)
                if c:
                    match parser.header_state:
                        case HeaderStates.h_general:
                            parser.index += 1
                            parser.header_state = HeaderStates.h_CO if ch == 'o' else HeaderStates.h_general
                        case HeaderStates.h_CO:
                            parser.index += 1
                            parser.header_state = HeaderStates.h_CON if ch == 'n' else HeaderStates.h_general
                        case HeaderStates.h_CON:
                            parser.index += 1
                            match c:
                                case 'n':
                                    parser.header_state = HeaderStates.h_matching_connection
                                    break
                                case 't':
                                    parser.header_state = HeaderStates.h_matching_content_length
                                    break
                                case _:
                                    parser.header_state = HeaderStates.h_general
                                    break

                            break
                        case HeaderStates.h_matching_connection:
                            parser.index += 1
                            if parser.index > len(CONNECTION) - 1 or c != CONNECTION[parser.index]:
                                parser.header_state = HeaderStates.h_general
                            elif parser.index == len(CONNECTION) - 2:
                                parser.header_state = HeaderStates.h_connection
                            break

                        case HeaderStates.h_matching_proxy_connection:
                            parser.index += 1
                            if parser.index > len(PROXY_CONNECTION) - 1 or c != PROXY_CONNECTION[parser.index]:
                                parser.header_state = HeaderStates.h_general
                            elif parser.index == len(PROXY_CONNECTION) - 2:
                                parser.header_state = HeaderStates.h_connection
                            break

                        case HeaderStates.h_matching_content_length:
                            parser.index += 1
                            if parser.index > len(CONTENT_LENGTH) - 1 or c != CONTENT_LENGTH[parser.index]:
                                parser.header_state = HeaderStates.h_general
                            elif parser.index == len(CONTENT_LENGTH) - 2:
                                parser.header_state = HeaderStates.h_content_length
                            break

                        case HeaderStates.h_matching_transfer_encoding:
                            parser.index += 1
                            if parser.index > len(TRANSFER_ENCODING) - 1 or c != TRANSFER_ENCODING[parser.index]:
                                parser.header_state = HeaderStates.h_general
                            elif parser.index == len(TRANSFER_ENCODING) - 2:
                                parser.header_state = HeaderStates.h_transfer_encoding
                            break

                        case HeaderStates.h_matching_upgrade:
                            parser.index += 1
                            if parser.index > len(UPGRADE) - 1 or c != UPGRADE[parser.index]:
                                parser.header_state = HeaderStates.h_general
                            elif parser.index == len(UPGRADE) - 2:
                                parser.header_state = HeaderStates.h_upgrade
                            break

                        case HeaderStates.h_connection:
                            if ch != ' ':
                                parser.header_state = HeaderStates.h_general
                            break
                        case HeaderStates.h_content_length:
                            if ch != ' ':
                                parser.header_state = HeaderStates.h_general
                            break
                        case HeaderStates.h_transfer_encoding:
                            if ch != ' ':
                                parser.header_state = HeaderStates
                        case HeaderStates.h_upgrade:
                            if ch != ' ':
                                parser.header_state = HeaderStates.h_general
                            break
                        case _:
                            assert False, "Unknown header_state"
                            break
                    break
                if ch == ':':
                    parser.state = state.s_header_value_start
                    parser.callback_data(header_field)
                    break
                elif ch == '\r':
                    parser.state = state.s_headers_almost_done
                    parser.callback_data(header_field)
                    break
                elif ch == '\n':
                    parser.state = state.s_headers_field_start
                    parser.callback_data(header_field)
                    break
                parser.state = state.s_header_value_start
                parser.callback_data(header_field)
                break

            case state.s_header_value_start:
                if ch == ' ' or ch == '\t':
                    break
                parser.mark(header_value)
                parser.state = state.s_header_value
                parser.index = 0

                if ch == '\r':
                    parser.header_state = HeaderStates.h_general
                    parser.state = state.s_headers_almost_done
                    parser.callback_data(header_value)
                    break
                elif ch == '\n':
                    parser.state = state.s_header_field_start
                    parser.callback_data(header_value)
                    break
                c = ch.lower()
                match parser.header_state:
                    case HeaderStates.h_upgrade:
                        parser.flags |= flags.F_UPGRADE
                        parser.header_state = HeaderStates.h_general
                        break
                    case HeaderStates.h_transfer_encoding:
                        if 'c' == c:
                            parser.header_state = HeaderStates.h_matching_transfer_encoding_chunked
                        else:
                            parser.header_state = HeaderStates.h_general
                        break
                    case HeaderStates.h_content_length:
                        if not ch >= '0' and ch <= '9':
                            parser.set_errno(HttpErrno.HPE_INVALID_CONTENT_LENGTH)
                            return 1
                        parser.content_length = ch - '0'
                        break

                    case HeaderStates.h_connection:
                        if c == 'k':
                            parser.header_state = HeaderStates.h_matching_connection_keep_alive
                        elif c == 'c':
                            parser.header_state = HeaderStates.h_matching_connection_close
                        else:
                            parser.header_state = HeaderStates.h_general
                        break
                    case _:
                        parser.header_state = HeaderStates.h_general
                        break
                break
            case state.s_header_value:
                if ch == '\r':
                    parser.header_state = HeaderStates.h_general
                    parser.callback_data(header_value)
                    break
                if ch == '\n':
                    parser.state = state.s_header_field_start
                    parser.callback_data(header_value)

                c = ch.lower()

                match parser.header_state:
                    case HeaderStates.h_general:
                        break
                    case HeaderStates.h_connection:
                        assert False, "Shouldn't get here."
                        break
                    case HeaderStates.h_transfer_encoding:
                        assert False, "Shouldn't get here."
                        break
                    case HeaderStates.h_content_length:
                        t = 0
                        if ch == ' ':
                            break
                        if not ch >= '0' and ch <= '9':
                            parser.set_errno(HttpErrno.HPE_INVALID_CONTENT_LENGTH)
                            return 1
                        t = parser.content_length
                        t *= 10
                        t += ch - '0'
                        if t < parser.content_length or t == ULLONG_MAX:
                            parser.set_errno(HttpErrno.HPE_INVALID_CONTENT_LENGTH)
                            return 1
                        parser.content_length = t
                        break
                    case HeaderStates.h_matching_transfer_encoding_chunked:
                        parser.index += 1
                        if parser.index > len(CHUNKED) - 1 or c != CHUNKED[parser.index]:
                            parser.header_state = HeaderStates.h_general
                        elif parser.index == len(CHUNKED) - 2:
                            parser.header_state = HeaderStates.h_transfer_encoding_chunked
                        break
                    case HeaderStates.h_matching_connection_keep_alive:
                        parser.index += 1
                        if parser.index > len(KEEP_ALIVE) - 1 or c != KEEP_ALIVE[parser.index]:
                            parser.header_state = HeaderStates.h_general
                        elif parser.index == len(KEEP_ALIVE) - 2:
                            parser.header_state = HeaderStates.h_connection_keep_alive
                        break
                    case HeaderStates.h_matching_connection_close:
                        parser.index += 1
                        if parser.index > len(CLOSE) - 1 or c != CLOSE[parser.index]:
                            parser.header_state = HeaderStates.h_general
                        elif parser.index == len(CLOSE) - 2:
                            parser.header_state = HeaderStates.h_connection_close
                        break
                    case HeaderStates.h_transfer_encoding_chunked:
                        if ch != ' ':
                            parser.header_state = HeaderStates.h_general
                        break
                    case HeaderStates.h_connection_keep_alive:
                        if ch != ' ':
                            parser.header_state = HeaderStates.h_general
                        break
                    case HeaderStates.h_connection_close:
                        if ch != ' ':
                            parser.header_state = HeaderStates.h_general
                        break
                    case _:
                        parser.state = state.s_header_value
                        parser.header_state = HeaderStates.h_general
                        break
                break
            case state.s_headers_almost_done:
                parser.strict_check(ch != '\n')
                parser.state = state.s_header_value_lws
                match parser.header_state:
                    case HeaderStates.h_connection_keep_alive:
                        parser.flags |= flags.F_CONNECTION_KEEP_ALIVE
                        break
                    case HeaderStates.h_connection_close:
                        parser.flags |= flags.F_CONNECTION_CLOSE
                        break
                    case HeaderStates.h_transfer_encoding_chunked:
                        parser.flags |= flags.F_CHUNKED
                        break
                    case _:
                        break
                break
            case state.s_header_value_lws:
                if ch == ' ' or ch == '\t':
                    parser.state = state.s_header_value_start
                else:
                    parser.state = state.s_header_field_start
                break
            case state.s_header_almost_done:
                parser.strict_check(ch != '\n')
                if parser.flags and flags.F_TRAILING:
                    parser.state = new_message()
                    parser.callback_notify(message_complete)
                    break
                parser.state = state.s_headers_done
                parser.upgrade = parser.flags and flags.F_UPGRADE or parser.method == HttpMethod.HTTP_CONNECT
                if settings.on_headers_complete:
                    match settings.on_headers_complete(parser):
                        case 0:
                            break
                        case 1:
                            parser.flags |= flags.F_SKIPBODY
                            break
                        case _:
                            parser.set_errno(HttpErrno.HPE_CB_headers_complete)
                            return p - data
                if parser.http_errno != HttpErrno.HPE_OK:
                    return p - data
            case state.s_headers_done:
                parser.strict_check(ch != '\n')
                parser.nread = 0
                if parser.upgrade:
                    parser.state = new_message()
                    parser.callback_notify(message_complete)
                    return (p - data) + 1
                if parser.flags and flags.F_SKIPBODY:
                    parser.state = new_message()
                    parser.callback_notify(message_complete)
                elif parser.flags and flags.F_CHUNKED:
                    parser.state = state.s_chunk_size_start
                else:
                    if parser.content_length == 0:
                        parser.state = new_message()
                        parser.callback_notify(message_complete)
                    elif parser.content_length != ULLONG_MAX:
                        parser.state = state.s_body_identity
                    else:
                        if parser.type == HttpParserType.HTTP_REQUEST or not http_messages_needs_eof(parser):
                            parser.state = new_message()
                            parser.callback_notify(message_complete)
                        else:
                            parser.state = state.s_body_identity_eof

                break
            case state.s_body_identity:
                to_read = min(parser.content_length, ((data + len) - p))
                assert (parser.content_length != 0 and parser.content_length != ULLONG_MAX)
                parser.mark(body)
                parser.content_length -= to_read
                p += to_read - 1
                if parser.content_length == 0:
                    parser.state = state.s_message_done
                    parser.callback_data(body, p - body_mark + 1, p - data)
                break
            case state.s_body_identity_eof:
                parser.mark(body)
                p = data + len - 1
                break
            case state.s_message_done:
                parser.state = new_message()
                parser.callback_notify(message_complete)
                break
            case state.s_chunk_size_start:
                assert (parser.nread == 1)
                assert (parser.flags and flags.F_CHUNKED)
                unhex_val = unhex[ch]
                if unhex_val == -1:
                    parser.set_errno(HttpErrno.HPE_INVALID_CHUNK_SIZE)
                    return 1
                parser.content_length = unhex_val
                parser.state = state.s_chunk_size
                break
            case state.s_chunk_size:
                t = 0
                assert (parser.flags and flags.F_CHUNKED)
                if ch == '\r':
                    parser.state = state.s_chunk_size_almost_done
                    break
                unhex_val = unhex[ch]
                if unhex_val == -1:
                    if ch == ';' or ch == ' ':
                        parser.state = state.s_chunk_parameters
                        break
                    parser.set_errno(HttpErrno.HPE_INVALID_CHUNK_SIZE)
                    return 1
                t = parser.content_length
                t *= 16
                t += unhex_val

                # Overflow?
                if t < parser.content_length or t == ULLONG_MAX:
                    parser.set_errno(HttpErrno.HPE_INVALID_CHUNK_SIZE)
                    return 1
                parser.content_length = t
                break
            case state.s_chunk_parameters:
                assert (parser.flags and flags.F_CHUNKED)
                if ch == '\r':
                    parser.state = state.s_chunk_size_almost_done
                    break
                break
            case state.s_chunk_size_almost_done:
                assert (parser.flags and flags.F_CHUNKED)
                parser.strict_check(ch != '\n')
                parser.nread = 0
                if parser.content_length == 0:
                    parser.flags |= flags.F_TRAILING
                    parser.state = state.s_header_field_start
                else:
                    parser.state = state.s_chunk_data
                break
            case state.s_chunk_data:
                to_read = min(parser.content_length, ((data + len) - p))
                assert (parser.flags and flags.F_CHUNKED)
                assert (parser.content_length != 0 and parser.content_length != ULLONG_MAX)
                parser.mark(body)
                parser.content_length -= to_read
                p += to_read - 1
                if parser.content_length == 0:
                    parser.state = state.s_chunk_data_almost_done
                break
            case state.s_chunk_data_almost_done:
                assert (parser.flags and flags.F_CHUNKED)
                assert (parser.content_length == 0)
                parser.strict_check(ch != '\r')
                parser.state = state.s_chunk_data_done
                parser.callback_data(body)
                break
            case state.s_chunk_data_done:
                assert (parser.flags and flags.F_CHUNKED)
                parser.strict_check(ch != '\n')
                parser.nread = 0
                parser.state = state.s_chunk_size_start
                break
            case _:
                assert (0 and "unhandled statr")
                parser.set_errno(HttpErrno.HPE_INVALID_INTERNAL_STATE)
                return 1
        assert sum([int(header_field_mark is not None), int(header_value_mark is not None), int(url_mark is not None),
                    int(body_mark is not None)]) <= 1, "Multiple callback marks set simultaneously"
        callback_no_advance(header_field)
        callback_no_advance(header_value)
        callback_no_advance(url)
        callback_no_advance(body)
        return len
    if parser.http_errno == HttpErrno.HPE_OK:
        parser.set_errno(HttpErrno.HPE_UNKNOWN)
    return p - data


# HTTP 数据流处理入口
def http_parse(session, uw, data, remaining, which):
    http = uw

    # HTTP/2 升级处理
    if http.http2upgrade:
        # 调用TCP分类器处理后续数据
        parsers_classify_tcp(session, data, remaining, which)
        return PARSER_UNREGISTER  # 注销当前HTTP解析器

    http.which = which

    # CONNECT 方法处理 
    if http.is_connect:
        # 检查是否需要重新分类协议
        if http.reclassify and (1 << which):
            http.reclassify &= ~(1 << which)
            parsers_classify_tcp(session, data, remaining, which)  # 重新分类协议

            if http.reclassify == 0 and http.is_connect == 0x3:
                parsers_unregister(session, uw)
            return 0

    # 协议解析主循环
    if http.wparsers and (1 << http.which) == 0:
        # 检查当前方向解析器是否启用
        return 0
    while remaining > 0:
        # 循环处理数据流
        # 执行HTTP解析
        length = http_parser_excute(http.parsers[http.which], parser_settings, data, remaining)
        if length <= 0:  # 解析出错或完成
            http.wparsers &= ~(1 << http.which)  # 关闭当前方向解析器
            if not http.wparsers:  # 所有方向解析器都关闭时
                parsers_unregister(session, uw)  # 注销解析器
            break
        data += len
        remaining -= length
    return 0


# HTTP 会话保存回调
def http_save(session, uw, final):
    http = uw
    for cnt in range(0, HTTP_MAX_METHOD):
        if not http.method_counts[cnt]:
            continue
        #  将方法计数存入对应字段
        FieldManager.field_int_add(method_count_fields[cnt], session, http.method_counts[cnt])
        http.method_counts[cnt] = 0  # 重置计数器

    if not final:  # 非最终保存时提前返回
        return

    # 客户端→服务端方向解析器清理
    if http.wparsers & 0x1:
        http_parser_excute(http.parsers[0], parser_settings, 0, 0)

    # 服务端→客户端方向解析器清理
    if http.wparsers & 0x2:
        http_parser_excute(http.parsers[1], parser_settings, 0, 0)
        http.magic_detector.update(http.magic_string[0], http.magic_string[1])


def http_parser_init(parser: HttpParser, t: HttpParserType):
    data = parser.data
    parser.data = data
    parser.type = t
    parser.state = state.s_start_req if t == HttpParserType.HTTP_REQUEST else (
        state.s_start_res if t == HttpParserType.HTTP_RESPONSE else state.s_start_req_or_res)
    parser.http_errno = HttpErrno.HPE_OK


# HTTP 协议分类初始化函数
def http_classify(session, data, length, which, uw):
    # （已标记HTTP协议则返回）
    if session.has_protocol('http'):
        return

    # 标记会话为HTTP协议
    session.add_protocol('http')
    http = HttpInfo()

    # 创建MD5校验对象（双向
    http.check_sum[0] = hashlib.md5()
    http.check_sum[1] = hashlib.md5()

    # 按需创建SHA256校验对象
    if config.supportSha256:
        http.checksum[2] = hashlib.sha256()  # 请求SHA256
        http.checksum[3] = hashlib.sha256()  # 响应SHA256

    # 初始化HTTP解析器
    http_parser_init(http.parsers[0], HttpParserType.HTTP_BOTH)  # 初始化客户端→服务端解析器
    http_parser_init(http.parsers[1], HttpParserType.HTTP_BOTH)  # 初始化服务端→客户端解析器

    http.wparsers = 3  # 二进制 11，表示双向解析器均启用
    http.parsers[0].data = http  # 绑定上下文到解析器
    http.parsers[1].data = http

    http.session = session  # 保存会话引用

    parsers_register(session, http_parse, http, http_save)


#  HTTP 解析器全局初始化函数
def parser_init():
    global host_field, urls_field, xhr_field, ua_field, tags_req_field, header_req_field, header_req_value 
    global header_res_field, header_res_value, md5_field, ver_req_field, ver_res_field, status_field 
    global path_field, key_field, value_field, cookie_key_field, cookie_value_field
    global method_field, magic_field, user_field, at_field, req_body_field, sha256_field

    config.http_methods = [
        "DELETE",  # 0
        "GET",  # 1
        "HEAD",  # 2
        "POST",  # 3
        "PUT",  # 4
        "CONNECT",  # 5
        "OPTIONS",  # 6
        "TRACE",  # 7
        "PATCH",  # 8
        # 如果需要终止符可以添加空字符串
        # ""
    ]
    
    # Use the field_manager instance instead of FieldManager class
    from analyzers.field import field_manager
    
    host_field = field_manager.field_define("http", "lotermfield",
                                          "host.http", "Hostname", "http.host",
                                          "HTTP host header field",
                                          FieldType.FIELD_TYPE_STR_HASH,
                                          FIELD_FLAG_CNT,
                                          "aliases", "[\"http.host\"]",
                                          "category", "host",
                                          None)

    field_manager.field_define("http", "lotextfield",
                             "host.http.tokens", "Hostname Tokens", "http.hostTokens",
                             "HTTP host Tokens header field",
                             FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_FAKE,
                             "aliases", "[\"http.host.tokens\"]",
                             None)

    urls_field = field_manager.field_define("http", "termfield",
                                          "http.uri", "URI", "http.uri",
                                          "URIs for request",
                                          FieldType.FIELD_TYPE_STR_HASH,
                                          FIELD_FLAG_CNT,
                                          "category", "[\"url\",\"host\"]",
                                          None)

    field_manager.field_define("http", "lotextfield",
                             "http.uri.tokens", "URI Tokens", "http.uriTokens",
                             "URIs Tokens for request",
                             FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_FAKE,
                             None)
    xff_field = field_manager.field_define("http", "ip",
                                         "ip.xff", "XFF IP", "http.xffIp",
                                         "X-Forwarded-For Header",
                                         FieldType.FIELD_TYPE_IP_GHASH,
                                         FIELD_FLAG_CNT | FIELD_FLAG_IPPRE,
                                         "category", "ip",
                                         None)

    ua_field = field_manager.field_define("http", "termfield",
                                         "http.user-agent", "Useragent", "http.useragent",
                                         "User-Agent Header",
                                         FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                         None)

    field_manager.field_define("http", "lotextfield",
                              "http.user-agent.tokens", "Useragent Tokens", "http.useragentTokens",
                              "User-Agent Header Tokens",
                              FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_FAKE,
                              None)

    tags_req_field = field_manager.field_define("http", "lotermfield",
                                               "http.hasheader.dst", "Has Dst Header", "http.responseHeader",
                                               "Response has header present",
                                               FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                               None)

    header_req_field = field_manager.field_define("http", "lotermfield",
                                                 "http.header.request.field", "Request Header Fields",
                                                 "http.requestHeaderField",
                                                 "Contains Request header fields",
                                                 FieldType.FIELD_TYPE_STR_ARRAY, FIELD_FLAG_NODB,
                                                 None)

    header_req_value = field_manager.field_define("http", "lotermfield",
                                                 "http.hasheader.src.value", "Request Header Values",
                                                 "http.requestHeaderValue",
                                                 "Contains request header values",
                                                 FieldType.FIELD_TYPE_STR_ARRAY, FIELD_FLAG_CNT,
                                                 None)

    header_res_field = field_manager.field_define("http", "lotermfield",
                                                 "http.header.response.field", "Response Header fields",
                                                 "http.responseHeaderField",
                                                 "Contains response header fields",
                                                 FieldType.FIELD_TYPE_STR_ARRAY, FIELD_FLAG_NODB,
                                                 None)

    header_res_value = field_manager.field_define("http", "lotermfield",
                                                 "http.hasheader.dst.value", "Response Header Values",
                                                 "http.responseHeaderValue",
                                                 "Contains response header values",
                                                 FieldType.FIELD_TYPE_STR_ARRAY, FIELD_FLAG_CNT,
                                                 None)

    field_manager.field_define("http", "lotermfield",
                              "http.hasheader", "Has Src or Dst Header", "hhall",
                              "Shorthand for http.hasheader.src or http.hasheader.dst",
                              0, FIELD_FLAG_FAKE,
                              "regex", "^http\\\\.hasheader\\\\.(?:(?!(cnt|value)$).)*$",
                              None)

    field_manager.field_define("http", "lotermfield",
                              "http.hasheader.value", "Has Value in Src or Dst Header", "hhvalueall",
                              "Shorthand for http.hasheader.src.value or http.hasheader.dst.value",
                              0, FIELD_FLAG_FAKE,
                              "regex", "^http\\\\.hasheader\\\\.(src|dst)\\\\.value$",
                              None)

    md5_field = field_manager.field_define("http", "lotermfield",
                                          "http.md5", "Body MD5", "http.md5",
                                          "MD5 of http body response",
                                          FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                          "category", "md5",
                                          None)

    if config.supportSha256:
        sha256_field = field_manager.field_define("http", "lotermfield",
                                                 "http.sha256", "Body SHA256", "http.sha256",
                                                 "SHA256 of http body response",
                                                 FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                                 "category", "sha256",
                                                 None)

    field_manager.field_define("http", "termfield",
                              "http.version", "Version", "httpversion",
                              "HTTP version number",
                              0, FIELD_FLAG_FAKE,
                              "regex", "^http.version.[a-z]+$",
                              None)

    ver_req_field = field_manager.field_define("http", "termfield",
                                              "http.version.src", "Src Version", "http.clientVersion",
                                              "Request HTTP version number",
                                              FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                              None)
    ver_res_field = field_manager.field_define("http", "termfield",
                                              "http.version.dst", "Dst Version", "http.serverVersion",
                                              "Response HTTP version number",
                                              FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                              None)

    path_field = field_manager.field_define("http", "termfield",
                                           "http.uri.path", "URI Path", "http.path",
                                           "Path portion of URI",
                                           FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                           None)

    key_field = field_manager.field_define("http", "termfield",
                                          "http.uri.key", "QS Keys", "http.key",
                                          "Keys from query string of URI",
                                          FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                          None)

    value_field = field_manager.field_define("http", "termfield",
                                            "http.uri.value", "QS Values", "http.value",
                                            "Values from query string of URI",
                                            FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                            None)

    cookie_key_field = field_manager.field_define("http", "termfield",
                                                 "http.cookie.key", "Cookie Keys", "http.cookieKey",
                                                 "The keys to cookies sent up in requests",
                                                 FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                                 None)

    cookie_value_field = field_manager.field_define("http", "termfield",
                                                   "http.cookie.value", "Cookie Values", "http.cookieValue",
                                                   "The values to cookies sent up in requests",
                                                   FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                                   None)

    method_field = field_manager.field_define("http", "termfield",
                                             "http.method", "Request Method", "http.method",
                                             "HTTP Request Method",
                                             FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                             None)

    magic_field = field_manager.field_define("http", "termfield",
                                            "http.bodymagic", "Body Magic", "http.bodyMagic",
                                            "The content type of body determined by libfile/magic",
                                            FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                            None)

    user_field = field_manager.field_define("http", "termfield",
                                           "http.user", "User", "http.user",
                                           "HTTP Auth User",
                                           FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                           "category", "user",
                                           None)

    at_field = field_manager.field_define("http", "lotermfield",
                                         "http.authtype", "Auth Type", "http.authType",
                                         "HTTP Auth Type",
                                         FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                         None)

    status_field = field_manager.field_define("http", "integer",
                                             "http.statuscode", "Status Code", "http.statuscode",
                                             "Response HTTP numeric status code",
                                             FieldType.FIELD_TYPE_INT_GHASH, FIELD_FLAG_CNT,
                                             None)

    req_body_field = field_manager.field_define("http", "termfield",
                                               "http.reqbody", "Request Body", "http.requestBody",
                                               "HTTP Request Body",
                                               FieldType.FIELD_TYPE_STR_HASH, FIELD_FLAG_CNT,
                                               None)

    # Register HTTP methods
    for cnt in range(len(config.http_methods)):
        method = config.http_methods[cnt]  # Use the config.http_methods list directly
        if method:
            field_manager.field_str_add(method_field, None, method, -1, False)

    # Initialize HTTP related data structures
    httpReqHeaders = {}
    httpResHeaders = {}

    httpReqHeaders["x-forwarded-for"] = xff_field
    httpReqHeaders["user-agent"] = ua_field
    httpReqHeaders["host"] = host_field

    # Initialize parser settings and other components
    from analyzers.parsers import parsers_classifier_register_port, PARSERS_PORT_TCP
    parsers_classifier_register_port("http", None, 80, PARSERS_PORT_TCP, http_classify, 0, 542)

# Setup logging
logging.basicConfig(level=logging.INFO)
http_logger = logging.getLogger("HTTP_MODULE")

# Create a decorator to track function calls
def track_http_calls(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # 打印详细的函数调用信息
        arg_str = ""
        if len(args) > 0:
            # 限制参数打印长度，避免输出过长
            arg_str = ", ".join([str(type(a)) + (f"={str(a)[:50]}" if len(str(a)) < 50 else "=<...>") for a in args])
        
        http_logger.info(f"⚡ 调用HTTP函数: {func.__name__}({arg_str})")
        
        # 如果有Session参数，打印其信息
        for arg in args:
            if hasattr(arg, 'protocols') and isinstance(arg.protocols, list):
                http_logger.info(f"  - 会话协议: {arg.protocols}")
            elif hasattr(arg, 'fields') and isinstance(arg.fields, dict):
                field_names = list(arg.fields.keys())
                http_logger.info(f"  - 会话字段: {field_names}")
        
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        # 记录函数执行时间
        http_logger.info(f"  - 耗时: {(end_time - start_time)*1000:.2f}ms")
        
        # 根据返回值类型提供不同的输出
        if result is not None:
            result_type = type(result).__name__
            if isinstance(result, (int, float, bool, str)):
                http_logger.info(f"  - 返回值 ({result_type}): {result}")
            elif hasattr(result, '__len__'):
                http_logger.info(f"  - 返回值 ({result_type}): 长度={len(result)}")
            else:
                http_logger.info(f"  - 返回值类型: {result_type}")
        
        return result
    return wrapper

# Add the decorator to all HTTP functions
# Find all functions that start with http_ and apply the decorator
current_module = sys.modules[__name__]
for name in dir(current_module):
    if name.startswith("http_"):
        func = getattr(current_module, name)
        if callable(func):
            setattr(current_module, name, track_http_calls(func))

# Keep the original parser_init function
original_parser_init = None
if "parser_init" in dir(current_module):
    original_parser_init = current_module.parser_init

# Override parser_init to report when it's called
@track_http_calls
def parser_init():
    http_logger.info("🔄 初始化HTTP解析器")
    if original_parser_init:
        return original_parser_init()
    return None

# Replace the original parser_init
if original_parser_init:
    current_module.parser_init = parser_init
