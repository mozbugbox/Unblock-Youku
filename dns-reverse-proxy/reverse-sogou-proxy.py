# vim:fileencoding=utf-8:sw=4:et:syntax=python

httpProxy = require("http-proxy")
http = require("http")

sogou = require('../shared/sogou')
shared_tools = require('../shared/tools')
dns_proxy = require("./dns-proxy")
server_utils = require('./utils')
log = server_utils.logger

HTTP_RATE_LIMIT = 10 # 5 proxy require/sec

MAX_ERROR_COUNT = {
    "reset_count": 1,
    "refuse_count": 2,
    "timeout_count": 4,
}

class ReverseSogouProxy:
    def __init__(self, options):
        """
            options:
                listen_port: dns proxy port. default: 80
                listen_address: dns proxy address. default: 0.0.0.0
                sogou_dns: dns used to lookup sogou server ip
                sogou_network: sogou network: "dxt" or "edu"
        """
        self.options = options
        self.sogou_renew_timeout = 10*60*1000
        self.request_id = 1

        self.sogou_port = 80
        self.proxy_host = "0.0.0.0"
        self.proxy_port = 80
        if options["listen_port"]:
            self.proxy_port = options["listen_port"]
        if options["listen_address"]:
            self.proxy_host = options["listen_address"]

        self.proxy = self.setup_proxy(options)
        self.server = self.setup_server(options)

        rate_limit = self.options["http_rate_limit"] or HTTP_RATE_LIMIT
        self.rate_limiter = server_utils.createRateLimiter({
            "rate-limit": rate_limit,
            })

        self.reset_sogou_flags()
        self.setup_sogou_manager()
        self.sogou_info = {"address": sogou.new_sogou_proxy_addr()}

    def setup_sogou_manager(self):
        """Manage which sogou proxy server we choose"""
        dns_resolver = None
        if self.options["sogou_dns"]:
            sg_dns = self.options["sogou_dns"]
            log.info("Sogou proxy DNS solver:", sg_dns)
            dns_resolver = dns_proxy.createDnsResolver(sg_dns)
        self.sogou_manager = server_utils.createSogouManager(dns_resolver)
        self.sogou_manager.sogou_network = self.options["sogou_network"]

        def _on_renew_address(addr_info):
            log.info("renewed sogou server:", addr_info)
            self.sogou_info = addr_info
            self.reset_sogou_flags()
        self.sogou_manager.on("renew-address", _on_renew_address)

        self.renew_sogou_server(True)

    def reset_sogou_flags(self):
        """sogou server renew related flags"""
        self.in_changing_sogou = False
        self.reset_count = 0
        self.refuse_count = 0
        self.timeout_count = 0

    def renew_sogou_server(self, forced=False):
        """Change to a new sogou proxy server"""
        need_reset = forced
        for k in Object.keys(MAX_ERROR_COUNT):
            if getattr(self, k) > MAX_ERROR_COUNT[k]:
                need_reset = True
                break
        if need_reset is False: return

        if self.in_changing_sogou is True: return
        self.in_changing_sogou = True
        log.debug("changing sogou server...")
        self.sogou_manager.renew_sogou_server()

    def setup_proxy(self, options):
        """create the node proxy server instance"""
        proxy = httpProxy.createServer()
        def on_error(err, req, res):
            self._on_proxy_error(err, req, res)
        def on_proxy_response(res):
            self._on_proxy_response(res)
        proxy.on("error", on_error)
        proxy.on("proxyRes", on_proxy_response)
        return proxy

    def setup_server(self, options):
        """create the standard node http server to accept request"""
        def on_request(req, res):
            self.do_proxy(req, res)

        def _on_connection(sock):
            self._on_server_connection(sock)

        def _on_client_error(err, socket):
            log.error("HTTP Server clientError:", err)

        server = http.createServer(on_request)
        server.on("connection", _on_connection)
        server.on("clientError", _on_client_error)

        return server

    def do_proxy(self, req, res):
        """The handler of node proxy server"""
        proxy = self.proxy

        # We fake hosting http pages. But we are actually a proxy.
        # A httpd server normally receives path to the GET/POST request, but
        # being a proxy, the request need to be absolute URI, not just path.
        if req.url.indexOf("http") is not 0:
            host = req.headers["host"] or req.headers["Host"]
            url = "http://" + host + req.url
            req.url = url
        else:
            url = req.url
        to_use_proxy = server_utils.is_valid_url(url)

        log.debug("sogou:", self.sogou_info)
        log.debug("do_proxy req.url:", url, to_use_proxy)
        req.headers["X-Droxy-SG"] = "" + to_use_proxy
        req.headers["X-Droxy-RID"] = "" + self.request_id
        self.request_id += 1

        # cannot forward cookie settings for other domains in redirect mode
        forward_cookies = False
        if shared_tools.string_starts_with(req.url, 'http'):
            forward_cookies = True

        if to_use_proxy:
            si = self.sogou_info
            sogou_host = si["ip"] or si["address"]
            server_utils.add_sogou_headers(req.headers, req.headers["host"])
            proxy_options = {
                    "target": {
                        "host": sogou_host, "port": self.sogou_port,
                        #host: "localhost", port: 9010,
                    },
                    "toProxy": True,
            }
        else:
            proxy_options = {
                    "target": req.url,
            }

        # log.debug("do_proxy headers before:", req.headers)
        headers = server_utils.filtered_request_headers(
                req.headers, forward_cookies)
        req.headers = headers
        log.debug("do_proxy[%s] headers:", headers["X-Droxy-Rid"], headers,
                req.socket.remoteAddress)

        proxy.web(req, res, proxy_options)

    def _on_server_connection(self, sock):
        """Prevent DoS"""
        remote_addr = sock.remoteAddress
        if self.rate_limiter.over_limit(remote_addr):
            sock.destroy()

    def _on_proxy_error(self, err, req, res):
        log.error("_on_proxy_error:", err, req.headers["host"], req.url)
        if 'ECONNRESET' is err.code:
            self.reset_count += 1
        elif 'ECONNREFUSED' is err.code:
            self.refuse_count += 1
        elif 'ETIMEDOUT' is err.code:
            self.timeout_count += 1
        else:
            self.reset_count += 1 # unknown error
        self.renew_sogou_server()

    def _on_proxy_response(self, res):
        #log.debug(res)
        req = res.req
        to_use_proxy = int(req._headers["x-droxy-sg"])
        req_id = int(req._headers["x-droxy-rid"])
        mitm = False
        if res.statusCode >= 400:
            #log.debug("_on_proxy_response:", res)
            via = res.headers["via"]

            if not via:
                via = res.headers["Via"]
            if (to_use_proxy == "true" and
                    (not via or via.indexOf("sogou-in.domain") < 0)):
                # someone crapped on our request, mostly chinacache
                mitm = True
        if mitm is True:
            s = res.socket
            log.warn("We are fucked by man-in-the-middle[%d]:\n",
                    req_id, res.headers, res.statusCode,
                    s.remoteAddress + ":" + s.remotePort)
            # 502: Bad Gateway
            res.statusCode = 502
            self.refuse_count += 1
            self.renew_sogou_server()
        else:
            log.debug("_on_proxy_response[%d] headers:", req_id,
                    res.headers, res.statusCode)

    def start(self):
        log.info("Sogou proxy listens on %s:%d",
                self.proxy_host, self.proxy_port)
        self.server.listen(self.proxy_port, self.proxy_host)

        # change sogou server periodically
        def on_renew_timeout():
            self.renew_sogou_server(True)
        sogou_renew_timer = setInterval(on_renew_timeout,
                self.sogou_renew_timeout)
        sogou_renew_timer.unref()

def createServer(options):
    s = ReverseSogouProxy(options)
    return s

def main():
    """Run test"""
    log.set_level(log.DEBUG)
    def run_local_proxy():
        proxy = httpProxy.createServer()
        def on_request(req, res):
            proxy.web(req, res, {"target": req.url})
        http.createServer(on_request).listen(9010)

    run_local_proxy()
    options = {"listen_port":8080, "listen_address":"127.0.0.1",
            "sogou_dns": "8.8.4.4"}
    s = ReverseSogouProxy(options)
    s.start()

    client_options = { "host": "127.0.0.1", "port": 8080,
        "path": "http://httpbin.org/ip", "headers": { "Host": "httpbin.org" } }
    # wait a few sec to get a valid sogou proxy ip first
    log.info("wait for a while...")
    def on_client_start():
        log.info("start download...")
        def on_response(res):
            res.pipe(process.stdout)

        http.get(client_options, on_response)
    setTimeout(on_client_start , 12000)

if require.main is JS("module"):
    main()

exports.ReverseSogouProxy = ReverseSogouProxy
exports.createServer = createServer
