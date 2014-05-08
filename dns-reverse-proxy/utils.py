# vim:fileencoding=utf-8:sw=4:et:syntax=python

SOCKET_TIMEOUT = 10*1000
UAGENT_CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11"
RATE_LIMITER_DENY_TIMEOUT = 5*60 # in seconds

http = require('http')
net = require("net")
url = require("url")
dns = require("dns")
EventEmitter = require("events").EventEmitter
shared_urls = require('../shared/urls')
shared_tools = require('../shared/tools')
sogou = require('../shared/sogou')
string_starts_with = shared_tools.string_starts_with;
to_title_case = shared_tools.to_title_case

# Possible IP prefixes of sogou proxy
SOGOU_IPS = ["121.195.", "123.126.", "220.181."]

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

class SogouManager(EventEmitter):
    """Provide active Sogou proxy"""
    def __init__(self, dns_server):
        self.dns_server = dns_server
        self.sogou_network = None

    def new_proxy_address(self):
        new_addr = sogou.new_sogou_proxy_addr();
        if self.sogou_network:
            good_net = new_addr.indexOf(self.sogou_network) >= 0
            while not good_net:
                new_addr = sogou.new_sogou_proxy_addr();
                good_net = new_addr.indexOf(self.sogou_network) >= 0
        return new_addr

    def renew_sogou_server(self, depth=0):
        new_addr = self.new_proxy_address()

        new_ip = None

        # use a give DNS to lookup ip of sogou server
        if self.dns_server and not net.isIPv4(new_addr):
            def _lookup_cb(name, ip):
                addr_info = {
                        "address": name,
                        "ip": ip
                        }
                self.check_sogou_server(addr_info, depth)
            self.dns_server.lookup(new_addr, _lookup_cb)
        else:
            addr_info = {"address": new_addr}
            self.check_sogou_server(addr_info, depth)

    def _on_check_sogou_success(self, addr_info):
        """Called when sogou server check success"""
        self.emit("renew-address", addr_info)

        # check if ISP DNS hijacked sogou proxy domain name
        domain = addr_info["address"]
        def _on_lookup(err, addr, family):
            valid = False
            for sgip in SOGOU_IPS:
                if addr.indexOf(sgip) is 0:
                    valid = True
                    break
            if not valid:
                logger.warn("WARN: sogou IP (%s -> %s) seems invalid",
                        domain, addr)
        if not addr_info["ip"]:
            dns.lookup(addr_info["address"], 4, _on_lookup)
        else:
            _on_lookup(None, addr_info["ip"], None)

    def check_sogou_server(self, addr_info, depth=0):
        """check validity of proxy.
        emit "renew-address" on success
        """
        if depth >= 10:
            self.emit("renew-address", addr_info)
            return

        new_addr = addr_info["address"]
        new_ip = addr_info["ip"]

        headers = {
            "Accept-Language": "en-US,en;q=0.8,zh-CN;q=0.6,zh;q=0.4,zh-TW;q=0.2",
            "Accept-Encoding": "deflate",
            "Accept": "text/html,application/xhtml+xml," +
                "application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": UAGENT_CHROME,
            "Accept-Charset": "gb18030,utf-8;q=0.7,*;q=0.3"
        }

        options = {
            host: new_ip or new_addr,
            headers: headers,
        }
        logger.debug("check sogou adderss:", addr_info, options.host)

        def on_response (res):
            if 400 == res.statusCode:
                self._on_check_sogou_success(addr_info)
            else:
                logger.error('[ub.uku.js] statusCode for %s is unexpected: %d',
                    new_addr, res.statusCode)
                self.renew_sogou_server(depth + 1)
        req = http.request(options, on_response)

        # http://goo.gl/G2CoU
        def on_socket(socket):
            def on_socket_timeout():
                req.abort()
                logger.error('[ub.uku.js] Timeout for %s. Aborted.', new_addr)
            socket.setTimeout(SOCKET_TIMEOUT, on_socket_timeout)
        req.on('socket', on_socket)

        def on_error(err):
            logger.error('[ub.uku.js] Error when testing %s: %s', new_addr, err)
            self.renew_sogou_server(depth + 1);
        req.on('error', on_error)
        req.end()

class RateLimiter:
    """rate limiter
       Limit access rate the a server per client. Prevent all kind of DDoS
    """
    def __init__(self, options):
        """
            options:
                rate-limit: access/sec
                deny-timeout: timeout for reactive on denied IP
        """
        self.options = options
        self.deny_timeout = RATE_LIMITER_DENY_TIMEOUT * 1000 # millisec
        if options["deny-timeout"]:
            self.deny_timeout = options["deny-timeout"] * 1000
        self.interval_reset = None
        self.access_counts = {}
        self.deny_map = {}
        self.start()

    def _do_reset(self):
        """Reset rate count and deny queue"""
        if Object.keys(self.access_counts) > 0:
            self.access_counts = {}
        now = Date.now()
        for k in Object.keys(self.deny_map):
            time_stamp = self.deny_map[k]
            if now > time_stamp:
                del self.deny_map[k]

    def over_limit(self, saddr):
        """Check if the rate limit is over for a source address"""
        if self.options["rate-limit"] < 0:
            return False # no limit

        if self.deny_map[saddr]:
            return True

        ret = False
        ac_count = self.access_counts[saddr] or 0
        ac_count += 1
        self.access_counts[saddr] = ac_count
        if ac_count > self.options["rate-limit"]:
            logger.warn("DoS Attack:", saddr)
            ret = True
            del self.access_counts[saddr]
            self.deny_map[saddr] = Date.now() + self.deny_timeout
        return ret

    def start(self):
        """start the periodic check"""
        if self.options["rate-limit"] <= 0:
            return
        if self.interval_reset:
            clearInterval(self.interval_reset)
            self.interval_reset = None

        def _do_reset():
            self._do_reset()
        self.interval_reset = setInterval(_do_reset, 1000) # 1 sec

    def stop(self):
        """stop the periodic check"""
        if self.interval_reset:
            clearInterval(self.interval_reset)
            self.interval_reset = None
        self.access_counts = {}
        self.deny_map = {}

def createRateLimiter(options):
    rl = RateLimiter(options)
    return rl

def createSogouManager(dns_server):
    s = SogouManager(dns_server)
    return s

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
        if u.indexOf("https") is 0: continue
        parsed_url = url.parse(u)
        hostname = parsed_url.hostname
        if hostname and hostname not in domain_dict:
            domain_dict[hostname] = True
    domain_list = Object.keys(domain_dict)
    USER_DOMAIN_LIST = domain_list
    return USER_DOMAIN_LIST

def get_public_ip(cb):
    """get public ip from http://httpbin.org/ip then call cb"""
    def _on_ip_response(res):
        content = ""
        def _on_data(x):
            nonlocal content
            content += x.toString("utf-8")

        def _on_end():
            content_json = JSON.parse(content)
            lookup_ip = content_json["origin"]
            cb(lookup_ip)

        def _on_error(err):
            logger.error("Err on get public ip:", err)

        res.on('data',_on_data)
        res.on('end', _on_end)
        res.on("error", _on_error)

    http.get("http://httpbin.org/ip", _on_ip_response)

exports.logger = logger
exports.add_sogou_headers = add_sogou_headers
exports.is_valid_url = is_valid_url
exports.createSogouManager = createSogouManager
exports.createRateLimiter = createRateLimiter
exports.filtered_request_headers = filtered_request_headers
exports.fetch_user_domain = fetch_user_domain
exports.get_public_ip = get_public_ip
