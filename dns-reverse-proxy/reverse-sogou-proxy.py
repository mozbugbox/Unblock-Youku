# vim:fileencoding=utf-8:sw=4:et:syntax=python

httpProxy = require("http-proxy")
http = require("http")

sogou = require('../shared/sogou')
shared_tools = require('../shared/tools')
dns_proxy = require("./dns-proxy")
server_utils = require('./utils')
logger = server_utils.logger

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
        """
        self.options = options
        self.sogou_renew_timeout = 10*60*1000

        self.sogou_port = 80
        self.proxy_host = "0.0.0.0"
        self.proxy_port = 80
        if options["listen_port"]:
            self.proxy_port = options["listen_port"]
        if options["listen_address"]:
            self.proxy_host = options["listen_address"]

        self.proxy = self.setup_proxy(options)
        self.server = self.setup_server(options)

        self.reset_sogou_flags()
        self.setup_sogou_manager()
        self.sogou_info = {"address": sogou.new_sogou_proxy_addr()}

    def setup_sogou_manager(self):
        dns_resolver = None
        if self.options["sogou_dns"]:
            sg_dns = self.options["sogou_dns"]
            logger.info("Sogou proxy DNS solver:", sg_dns)
            dns_resolver = dns_proxy.createDnsResolver(sg_dns)
        self.sogou_manager = server_utils.createSogouManager(dns_resolver)
        self.sogou_manager.sogou_network = self.options["sogou_network"]

        def _on_renew_address(addr_info):
            logger.info("renewed sogou server:", addr_info)
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
        logger.debug("changing sogou server...")
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
        server = http.createServer(on_request)
        return server

    def do_proxy(self, req, res):
        """The handler of node proxy server"""
        proxy = self.proxy
        req.headers["DNS-Reverse-Proxy"] = self.proxy_port

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

        logger.debug("sogou:", self.sogou_info)
        logger.debug("do_proxy req.url:", url, to_use_proxy)

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

        # logger.debug("do_proxy headers before:", req.headers)
        headers = server_utils.filtered_request_headers(
                req.headers, forward_cookies)
        req.headers = headers
        logger.debug("do_proxy headers:", headers)

        proxy.web(req, res, proxy_options)

    def _on_proxy_error(self, err, req, res):
        logger.debug("_on_proxy_error:", err)
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
        if res.statusCode >= 400:
            #logger.debug("_on_proxy_response:", res)
            via = res.headers["via"]
            if not via:
                via = res.headers["Via"]
            if not via or via.indexOf("sogou-in.domain") < 0:
                # someone crapped on our request, mostly chinacache
                # 502: Bad Gateway
                s = res.socket
                logger.warn("We are fucked by man-in-the-middle:\n",
                        res.headers, res.statusCode,
                        s.remoteAddress + ":" + s.remotePort)
                res.statusCode = 502
                self.refuse_count += 1
                self.renew_sogou_server()
        else:
            logger.debug("_on_proxy_response headers:", res.headers)

    def start(self):
        opt = self.options
        logger.info("Sogou proxy listens on %s:%d",
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

def test_main():
    logger.set_level(logger.DEBUG)
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
    logger.info("wait for a while...")
    def on_client_start():
        logger.info("start download...")
        def on_response(res):
            res.pipe(process.stdout)

        http.get(client_options, on_response)
    setTimeout(on_client_start , 12000)

exports.ReverseSogouProxy = ReverseSogouProxy
exports.createServer = createServer
exports.test_main = test_main
