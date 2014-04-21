#!/usr/bin/python
# vim:fileencoding=utf-8:sw=4:et:syntax=python

httpProxy = require("http-proxy")
http = require("http")

sogou = require('../shared/sogou')
shared_tools = require('../shared/tools')
server_utils = require('./utils')
logger = server_utils.logger

MAX_ERROR_COUNT = {
    "reset_count": 1,
    "refuse_count": 2,
    "timeout_count": 4,
}

class ReverseSogouProxy:
    def __init__(self, options):
        self.options = options
        self.sogou_renew_timeout = 10*60*1000

        self.sogou_port = 80
        self.proxy_host = "0.0.0.0"
        self.proxy_port = 80
        if options["port"]:
            self.proxy_port = options["port"]
        if options["ip"]:
            self.proxy_host = options["ip"]

        self.proxy = self.setup_proxy(options)
        self.server = self.setup_server(options)

        self.reset_sogou_flags()
        self.sogou_host = sogou.new_sogou_proxy_addr()
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

        def on_new_server(new_addr):
            logger.info("renewed sogou server:", new_addr)
            self.sogou_host = new_addr
            self.reset_sogou_flags()
        server_utils.renew_sogou_server(on_new_server)

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
        logger.debug("sogou:", self.sogou_host)
        to_use_proxy = server_utils.is_valid_url(req.url)

        # cannot forward cookie settings for other domains in redirect mode
        forward_cookies = False
        if shared_tools.string_starts_with(req.url, 'http'):
            forward_cookies = True

        if to_use_proxy:
            server_utils.add_sogou_headers(req.headers, req.headers["host"]);
            proxy_options = {
                    "target": {
                        "host": self.sogou_host, "port": self.sogou_port,
                        #host: "localhost", port: 9010,
                    },
                    "toProxy": True,
            }
        else:
            proxy_options = {
                    "target": req.url,
            }
        headers = server_utils.filtered_request_headers(
                req.headers, forward_cookies)
        req.headers = headers
        logger.debug(headers)

        proxy.web(req, res, proxy_options)

    def _on_proxy_error(self, err, req, res):
        logger.debug("_on_proxy_error:", err)
        if 'ECONNRESET' is err.code:
            self.reset_count += 1
        elif 'ECONNREFUSED' is err.code:
            self.refuse_count += 1
        elif 'ETIMEDOUT' is err.code:
            self.timeout_count += 1
        self.renew_sogou_server()
    def _on_proxy_response(self, res):
        logger.debug("_on_proxy_response:", res)
        if res.statusCode == 404:
            via = res.headers["via"]
            if not via:
                via = res.headers["Via"]
            if not via or via.indexOf("sogou-in.domain") < 0:
                # someone crapped on our request, mostly chinacache
                # 502: Bad Gateway
                res.statusCode = 502
                self.refuse_count += 1
                self.renew_sogou_server()
                logger.warn("We are fucked by man-in-the-middle:\n",
                        res.headers)

    def start(self):
        opt = self.options
        self.server.listen(self.proxy_port, self.proxy_host)

        # change sogou server periodically
        def on_renew_timeout():
            self.renew_sogou_server(True)
        sogou_renew_timer = setInterval(on_renew_timeout,
                self.sogou_renew_timeout)
        sogou_renew_timer.unref()

def test_main():
    def run_local_proxy():
        proxy = httpProxy.createServer()
        def on_request(req, res):
            proxy.web(req, res, {"target": req.url})
        http.createServer(on_request).listen(9010)

    run_local_proxy()
    options = {"port":8080, "ip":"127.0.0.1"}
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


exports.test_main = test_main
