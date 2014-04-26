# vim:fileencoding=utf-8:sw=4:et:syntax=python

SOCKET_TIMEOUT = 10*1000
UAGENT_CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11"

http = require('http')
url = require("url")
shared_urls = require('../shared/urls')
shared_tools = require('../shared/tools')
sogou = require('../shared/sogou')
string_starts_with = shared_tools.string_starts_with;
to_title_case = shared_tools.to_title_case

class Logger:
    def __init__(self, level=None):
        # level from python logging.__init__
        self.CRITICAL = 50
        self.ERROR = 40
        self.WARN = 30
        self.INFO = 20
        self.DEBUG = 10
        self.NOTSET = 0

        if level is None:
            level = self.INFO
        self.level = level

    def set_level(self, level):
        self.level = level

    def _log(self, level, *args):
        if level >= self.level:
            console.log(*args)
    def msg(self, *args): # force message?
        self._log(self.NOTSET, *args)
    def debug(self, *args):
        self._log(self.DEBUG, *args)
    def info(self, *args):
        self._log(self.INFO, *args)
    def log(self, *args):
        self.info(*args)
    def warn(self, *args):
        self._log(self.WARN, *args)
    def error(self, *args):
        self._log(self.ERROR, *args)
    def critical(self, *args):
        self._log(self.CRITICAL, *args)
logger = Logger()

def add_sogou_headers(req_headers, hostname):
    sogou_auth = sogou.new_sogou_auth_str()
    timestamp = Math.round(Date.now() / 1000).toString(16)
    sogou_tag = sogou.compute_sogou_tag(timestamp, hostname)

    req_headers['X-Sogou-Auth'] = sogou_auth
    req_headers['X-Sogou-Timestamp'] = timestamp
    req_headers['X-Sogou-Tag'] = sogou_tag
    req_headers['X-Forwarded-For'] = shared_tools.new_random_ip()

def is_valid_url(target_url):
    for white_pattern in shared_urls.url_regex_whitelist:
        if white_pattern.test(target_url):
            return False
    for url_pattern in shared_urls.url_regex_list:
        if url_pattern.test(target_url):
            return True
    if string_starts_with(target_url, 'http://httpbin.org'):
        return True
    return False

def renew_sogou_server(callback, depth=0):
    new_addr = sogou.new_sogou_proxy_addr();

    if depth >= 10:
        callback(new_addr)
        return

    headers = {
        "Accept-Language": "en-US,en;q=0.8,zh-CN;q=0.6,zh;q=0.4,zh-TW;q=0.2",
        "Accept-Encoding": "deflate",
        "Accept": "text/html,application/xhtml+xml," +
            "application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": UAGENT_CHROME,
        "Accept-Charset": "gb18030,utf-8;q=0.7,*;q=0.3"
    }
    options = {
        host: new_addr,
        headers: headers,
    }

    def on_response (res):
        if 400 == res.statusCode:
            callback(new_addr);
        else:
            logger.warn('[ub.uku.js] statusCode for %s is unexpected: %d',
                new_addr, res.statusCode)
            renew_sogou_server(callback, depth + 1)
    req = http.request(options, on_response)

    # http://goo.gl/G2CoU

    def on_socket(socket):
        def on_socket_timeout():
            req.abort()
            logger.warn('[ub.uku.js] Timeout for %s. Aborted.', new_addr)
        socket.setTimeout(SOCKET_TIMEOUT, on_socket_timeout)

    req.on('socket', on_socket)

    def on_error(err):
        logger.warn('[ub.uku.js] Error when testing %s: %s', new_addr, err)
        renew_sogou_server(callback, depth + 1);
    req.on('error', on_error)
    req.end()

def filtered_request_headers(headers, forward_cookie):
    ret_headers = {}

    for field in Object.keys(headers):
        if string_starts_with(field, 'proxy-'):
            if field == 'proxy-connection':
                ret_headers.Connection = headers['proxy-connection'];
        elif field == 'cookie':
            if forward_cookie:
                ret_headers.Cookie = headers.cookie;
        elif field == 'user-agent':
            if (headers['user-agent'].indexOf('CloudFront') != -1 or
                    headers['user-agent'].indexOf('CloudFlare') != -1):
                ret_headers['User-Agent'] = UAGENT_CHROME
            else:
                ret_headers['User-Agent'] = headers['user-agent']
        elif field != 'via' and (not string_starts_with(field, 'x-')):
            # in case some servers do not recognize lower-case headers,
            # such as hacker news
            ret_headers[to_title_case(field)] = headers[field]

    return ret_headers

USER_DOMAIN_LIST = None
def fetch_user_domain():
    """Fetch a list of domains for the filtered ub.uku urls"""
    nonlocal USER_DOMAIN_LIST
    if USER_DOMAIN_LIST !== None:
        return USER_DOMAIN_LIST

    domain_dict = {}
    for u in shared_urls.url_list:
        # FIXME: can we do https proxy?
        #if u.indexOf("https") is 0: continue
        parsed_url = url.parse(u)
        hostname = parsed_url.hostname
        if hostname and hostname not in domain_dict:
            domain_dict[hostname] = True
    domain_list = Object.keys(domain_dict)
    USER_DOMAIN_LIST = domain_list
    return USER_DOMAIN_LIST

exports.logger = logger
exports.add_sogou_headers = add_sogou_headers
exports.is_valid_url = is_valid_url
exports.renew_sogou_server = renew_sogou_server
exports.filtered_request_headers = filtered_request_headers
exports.fetch_user_domain = fetch_user_domain
