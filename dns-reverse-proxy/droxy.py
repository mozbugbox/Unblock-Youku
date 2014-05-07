# vim:fileencoding=utf-8:sw=4:et:syntax=python

path = require("path")
fs = require("fs")

dnsproxy = require("./dns-proxy")
reversesogouproxy = require("./reverse-sogou-proxy")
utils = require("./utils")
log = utils.logger


appname = "ub.uku.droxy"

def load_resolv_conf():
    """Parse /etc/resolv.conf and return 1st dns host found"""
    fname = "/etc/resolv.conf"
    data = fs.readFileSync(fname, "utf-8")
    lines = data.split("\n")
    dns_host = None
    for line in lines:
        if line[0] == "#":continue
        parts = line.split(" ")
        if parts[0].toLowerCase() == "nameserver":
            dns_host = parts[1]
            break
    return dns_host

def load_dns_map(target_ip):
    """Create a DNS router to map a list of domain name to a target ip"""
    if not target_ip:
        target_ip = "127.0.0.1"
    domain_list = utils.fetch_user_domain()
    dmap = {}
    for domain in domain_list:
        dmap[domain] = target_ip

    # our proxy test server
    dmap["httpbin.org"] = target_ip
    #log.debug(dmap)
    return dmap

def load_router_from_file(fname, dns_map):
    """Load domain -> ip map from a JSON file"""
    data = fs.readFileSync(fname, "utf-8")
    # fix loose JSON: extra comma before }]
    data = data.replace(/,(\s*[\}|\]])/g, '$1')
    rdict = JSON.parse(data)
    for k in Object.keys(rdict):
        dns_map[k] = rdict[k]

def load_extra_url_list(fname):
    """Add extra url list to the shared urls
    The input file is a JSON file with a single array of url pattern strings
    """
    data = fs.readFileSync(fname, "utf-8")
    data = data.replace(/,(\s*[\}|\]])/g, '$1')
    url_list = JSON.parse(data)

    shared_urls = require("../shared/urls.js")
    url_regex = shared_urls.urls2regexs(url_list)
    for u in url_list:
        shared_urls.url_list.push(u)
    for r in url_regex:
        shared_urls.url_regex_list.push(r)

def run_servers(argv):
    if argv["extra_url_list"]:
        fname_extra_ul = argv["extra_url_list"]
        if not (fname_extra_ul and fs.existsSync(fname_extra_ul)):
            log.error("extra url filter file not found:", fname_extra_ul)
            process.exit(2)
        load_extra_url_list(fname_extra_ul)

    # setup dns proxy
    dns_options = {
            "listen_address": "0.0.0.0",
            "listen_port": argv["dns_port"],
            "dns_relay": not argv["dns_no_relay"],
            "dns_rate_limit": int(argv["dns_rate_limit"]),
            }
    if argv["ip"]:
        dns_options["listen_address"] = argv["ip"]
    if argv["dns_host"]:
        dns_options["dns_host"] = argv["dns_host"]
    if not dns_options["dns_host"]:
        dns_options["dns_host"] = load_resolv_conf()
    log.debug("dns_options:", dns_options)

    # setup http proxy
    sogou_proxy_options = {
            "listen_port": argv["http_port"],
            "listen_address": "127.0.0.1",
            "sogou_dns": argv["sogou_dns"],
            "sogou_network": argv["sogou_network"],
            }
    if argv["ip"]:
        sogou_proxy_options["listen_address"] = argv["ip"]

    # https proxy
    #sogou_proxy_options_s = JSON.parse(JSON.stringify(sogou_proxy_options))
    #sogou_proxy_options_s["listen_port"] = 443
    #log.debug("sogou_proxy_options_s:", sogou_proxy_options_s)
    log.debug("sogou_proxy_options:", sogou_proxy_options)

    target_ip = argv["ext_ip"] or sogou_proxy_options["listen_address"]
    dns_map = load_dns_map(target_ip)

    if argv["dns_extra_router"]:
        fname_extra_rt = argv["dns_extra_router"]
        if not (fname_extra_rt and fs.existsSync(fname_extra_rt)):
            log.error("extra router file not found:", fname_extra_rt)
            process.exit(2)
        else:
            load_router_from_file(fname_extra_rt, dns_map)
    #log.debug("dns_map:", dns_map)

    drouter = dnsproxy.createBaseRouter(dns_map)

    ip_pat = /^(\d+\.){3}\d+$/
    if not ip_pat.test(target_ip):
        drouter.replace_target(target_ip)

    dproxy = dnsproxy.createServer(dns_options, drouter)
    sproxy = reversesogouproxy.createServer(sogou_proxy_options)
    dproxy.start()
    sproxy.start()

def expand_user(txt):
    """Expand tild (~/) to user home directory"""
    if txt == "~" or txt[:2] == "~/":
        txt = process.env.HOME + txt.substr(1)
    return txt

def fix_keys(dobj):
    """replace "-" in dict keys to "_" """
    for k in Object.keys(dobj):
        if k[0] == "#":
            del dobj[k]
        elif "-" in k:
            nk = k.replace(/-/g, "_")
            dobj[nk] = dobj[k]
            del dobj[k]

def load_config(argv):
    """Load config file and update argv"""
    cfile = argv.config
    cfile = expand_user(cfile)
    if not (cfile and fs.existsSync(cfile)):
        return

    # load config file as a JSON file
    data = fs.readFileSync(cfile, "utf-8")
    # naiive fix dict with unquoted keys
    data = data.replace(RegExp('([\'"])?(#?[-_a-zA-Z0-9]+)([\'"])?:', "g"),
            '"$2": ')
    # extra comma before }]
    data = data.replace(/,(\s*[\}|\]])/g, '$1')
    log.debug("config data:", data)

    cdict = JSON.parse(data)
    fix_keys(cdict)

    for k in Object.keys(cdict):
        argv[k] = cdict[k]

def parse_args():
    """Cmdline argument parser"""
    optimist = require("optimist")

    # config file location. Borrow from blender
    # http://wiki.blender.org/index.php/Doc:2.6/Manual/Introduction/Installing_Blender/DirectoryLayout
    os = require("os")
    platform = os.platform()
    if platform == "win32":
        config_dir = "AppData"
    elif platform == "darwin": # Mac OSX
        config_dir = "Library/:Application Support"
    else:
        config_dir = ".config"
    config_path = path.join(expand_user("~/"), config_dir, appname,
            "config.json")

    cmd_args = {
            "ip": {
                "description": "local IP address to listen on",
                "default": "0.0.0.0",
                },
            "dns-host": {
                "description"
                    : "remote dns host. default: first in /etc/resolve.conf",
                },
            "sogou-dns": {
                "description"
                    : "DNS used to lookup IP of sogou proxy servers",
                "default": None,
                },
            "sogou-network": {
                "description"
                    : 'choose between "edu" and "dxt"',
                "default": None,
                },
            "extra-url-list": {
                "description"
                    : "load extra url redirect list from a JSON file",
                },
            /* Advanced usage
            "dns-extra-router": {
                "description"
                    : "load extra domain -> ip map for DNS from a JSON file",
                },
            */
            "ext-ip": {
                "description": \
                    'for public DNS, the DNS proxy route to the given ' +
                    'public IP. If set to "lookup", try to find the ' +
                    'public IP through http://httpbin.org/ip. If a ' +
                    'domain name is given, the IP will be lookup ' +
                    'through DNS',
                "default": None,
                },
            "dns-no-relay": {
                "description"
                    : "don't relay un-routed domain query to upstream DNS",
                "boolean": True,
                },
            "dns-rate-limit": {
                "description"
                    : "DNS query rate limit per sec per IP. -1 = no limit",
                "default": 20,
                },
            "dns-port": {
                "description"
                    : "local port for the DNS proxy to listen on. " +
                      "Useful with port forward",
                "default": 53,
                },
            "http-port": {
                "description"
                    : "local port for the HTTP proxy to listen on. " +
                      "Useful with port forward",
                "default": 80,
                },
            "config": {
                "description": "load the given configuration file",
                "default": config_path,
                "alias": "c",
                },
            "debug": {
                "description": "debug mode",
                "boolean": True,
                "alias": "D",
                },
            "help": {
                "alias": "h",
                "description": "print help message",
                "boolean": True,
                },
            }

    opt = optimist.usage(
        "DNS Reverse Proxy(droxy) server with unblock-youku\n" +
        "Usage:\n\t$0 [--options]", cmd_args).wrap(78)

    argv = opt.argv
    # remove alias entries
    for k in Object.keys(cmd_args):
        item = cmd_args[k]
        akey = item["alias"]
        if akey:
            del argv[akey]
    fix_keys(argv)

    if argv["sogou_network"]:
        sd = argv["sogou_network"]
        if not (sd == "dxt" or sd == "edu"):
            opt.showHelp()
            log.error('*** Error: Bad value for option --sogou-network %s',
                    sd)
            process.exit(code=2)

    if argv.help:
        opt.showHelp()
        process.exit(code=0)
    return argv

def main():
    argv = parse_args()
    if argv.debug:
        log.set_level(log.DEBUG)
        log.debug("argv:", argv)
    load_config(argv)
    log.debug("with config:", argv)
    run_servers(argv)

if require.main is JS("module"):
    main()

exports.main = main
