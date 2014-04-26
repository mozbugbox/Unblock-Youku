# vim:fileencoding=utf-8:sw=4:et:syntax=python

path = require("path")
fs = require("fs")

utils = require("./utils")
log = utils.logger

dnsproxy = require("./dns-proxy")
reversesogouproxy = require("./reverse-sogou-proxy")

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
    #log.debug(dmap)
    return dmap

def run_servers(argv):
    # setup dns proxy
    dns_options = {
            "listen_address": "0.0.0.0",
            "listen_port": 53
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
            "listen_port": 80,
            "listen_address": "127.0.0.1",
            }
    if argv["ip"]:
        sogou_proxy_options["listen_address"] = argv["ip"]

    # https proxy
    #sogou_proxy_options_s = JSON.parse(JSON.stringify(sogou_proxy_options))
    #sogou_proxy_options_s["listen_port"] = 443
    #log.debug("sogou_proxy_options_s:", sogou_proxy_options_s)
    log.debug("sogou_proxy_options:", sogou_proxy_options)

    dns_map = load_dns_map(sogou_proxy_options["listen_address"])

    drouter = dnsproxy.createBaseRouter(dns_map)
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
    """replace "-" in dict keys to "_". """
    for k in Object.keys(dobj):
        if "-" in k:
            nk = k.replace("-", "_")
            dobj[nk] = dobj[k]
            del dobj[k]

def load_config(argv):
    """Load config file and update argv"""
    cfile = argv.config
    cfile = expand_user(cfile)
    if not (cfile and fs.existsSync(cfile)):
        return

    # load config file as a javascript source file
    data = fs.readFileSync(cfile, "utf-8")
    # naiive fix dict with unquoted keys
    data = data.replace(RegExp('([\'"])?([a-zA-Z0-9_-]+)([\'"])?:', "g"),
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
                "description": "local IP address to listens on",
                "default": "0.0.0.0",
                },
            "dns-host": {
                "description"
                    : "remote dns host. default: first in /etc/resolve.conf",
                },
            "config": {
                "description": "load the given configuration file",
                "default": config_path,
                "alias": "c",
                },
            "help": {
                "alias": "h",
                "description": "print help message",
                "boolean": True,
                },
            "debug": {
                "description": "debug mode",
                "boolean": True,
                "alias": "D",
                },
            }

    opt = optimist.usage(
        "DNS Reverse Proxy(droxy) server with unblock-youku\n" +
        "Usage:\n\t$0 [--options]", cmd_args)

    argv = opt.argv
    # remove alias entries
    for k in Object.keys(cmd_args):
        item = cmd_args[k]
        akey = item["alias"]
        if akey:
            del argv[akey]
    fix_keys(argv)

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

main()
