# vim:fileencoding=utf-8:sw=4:et:syntax=python

# RFC5625: DNS Proxy Implementation Guidelines
# https://tools.ietf.org/html/rfc5625
dgram = require("dgram")
EventEmitter = require("events").EventEmitter

BUFFER_SIZE = 2048 # STANDARD size should be 512 but who knows
DEFAULT_TTL = 30 # time to live for our fake A record
DNS_PORT = 53
DNS_ENCODING = "ascii"
DNS_POINTER_FLAG = 0xC0

# 8.8.8.8 google
# 8.8.4.4 google
# 156.154.70.1 Dnsadvantage
# 156.154.71.1 Dnsadvantage
# 208.67.222.222 OpenDNS
# 208.67.220.220 OpenDNS
# 198.153.192.1 Norton
# 198.153.194.1 Norton
DNS_DEFAULT_HOST = "8.8.8.8"

DNS_FLAGS = {
    QR: 0x01 << 15,
    OPCODE: 0x0F << 11,
    AA: 0x01 << 10,
    TC: 0x01 << 9,
    RD: 0x01 << 8,
    RA: 0x01 << 7,
    RCODE: 0x0F << 0,
}

DNS_CLASSES = {
        IN: 1,
        CS: 2,
        CH: 3,
        HS: 4,
        }

QUERY_TYPES = {
        A: 1,
        NS: 2,
        CNAME: 5,
        SOA: 6,
        PTR: 12,
        MX: 15,
        TXT: 16,
        RP: 17,
        AFSDB: 18,
        SIG: 24,
        KEY: 25,
        AAAA: 28,
        LOC: 29,
        SRV: 33,
        NAPTR: 35,
        KX: 36,
        CERT: 37,
        DNAME: 39,
        OPT: 41,
        APL: 42,
        DS: 43,
        SSHFP: 44,
        IPSECKEY: 45,
        RRSIG: 46,
        NSEC: 47,
        DNSKEY: 48,
        DHCID: 49,
        NSEC3: 50,
        NSEC3PARAM: 51,
        TLSA: 52,
        HIP: 55,
        SPF: 99,
        TKEY: 249,
        TSIG: 250,
        IXFR: 251,
        AXFR: 252,
        "*": 255,
        CAA: 257,
        TA: 32768,
        DLV: 32769,
        }

def read_domain(buf, offset):
    """ parse encoded domain names
    03www05baidu03com00 => www.baidu.com
    """
    domain = []
    raw_offset = -1
    #console.warn("read_domain", buf, offset)
    while True:
        llen = buf.readUInt8(offset); offset += 1
        if llen == 0: break
        is_pointer_type = llen & DNS_POINTER_FLAG
        if is_pointer_type is not 0:
            # pointer type point to another label with global 16bit offset
            lower_llen = buf.readUInt8(offset); offset += 1
            if raw_offset < 0:
                # save domain name offset at 1st pointer type
                raw_offset = offset
            offset = ((llen & (~DNS_POINTER_FLAG)) << 8 | lower_llen)
            continue # reread label from the new offset

        label = buf.toString(DNS_ENCODING, offset, offset + llen)
        domain.push(label)
        offset += llen

    if raw_offset >= 0:
        offset = raw_offset
    ret = {
            "name": domain.join("."),
            "offset": offset,
            "has_pointer_type": raw_offset >= 0
            }
    #console.warn(ret)
    return ret

def write_domain(buf, name, offset, do_compress=True):
    """Write a domain name in DNS encoding"""
    #console.log("name", name)
    if not buf.offset_cache:
        buf.offset_cache = {}
    #console.warn("Packable?", do_compress, name, buf.offset_cache)
    if name in buf.offset_cache and do_compress is True:
        pointer = buf.offset_cache[name]
        buf.writeUInt16BE((DNS_POINTER_FLAG<<8)|pointer, offset); offset += 2
        #console.warn("compressed:", name)
    else:
        # record offset of each piece for label compression
        parts = name.split(".")
        buf.offset_cache[name] = offset
        wlen = buf.write(parts[0], offset + 1, DNS_ENCODING)
        buf.writeUInt8(wlen, offset); offset += 1
        offset += wlen
        if parts.length > 1:
            tail = parts.slice(1)
            offset = write_domain(buf, tail.join("."), offset, do_compress)
        else:
            buf.writeUInt8(0, offset); offset += 1
    return offset

def decode_base64_label(label_string):
    lbuf = Buffer(label_string, "base64")
    name_info = read_domain(lbuf, 0)
    return name_info["name"]

#console.log(read_domain(Buffer("\03www\04sohu\03com\00", "binary"), 0))
#console.log(read_domain(Buffer("\04sohu\03com\xC0\x0B\02cn\00", "binary"), 0))

def encode_ip(aip):
    """Encode a string ip to uint32 coded as base64"""
    buf = Buffer(4)
    parts = aip.split(".")
    for i, d in enumerate(parts):
        buf[i] = parseInt(d)
    #console.log(buf.readUInt32BE(0))
    return buf.toString("base64", 0, 4)
#console.log(encode_ip("127.0.0.1"), "fwAAAQ==")

class DnsError(Error):
    def __init__(self, msg):
        self.name = Error
        self.message = msg

class DnsMessage:
    def __init__(self, buf=None):
        self.id = 0
        self.flags = 0
        self.question = []
        self.answer = []
        self.authority = []
        self.additional = []
        self.has_pointer_type = False

        if buf is not None:
            self.parse_buffer(buf)

    def parse_buffer(self, buf):
        offset = 0
        offset = self.parse_header(buf, offset)
        offset = self.parse_records(buf, offset)

    def parse_header(self, buf, offset):
        self.id = buf.readUInt16BE(offset); offset += 2
        self.flags = buf.readUInt16BE(offset); offset += 2
        return offset

    def parse_records(self, buf, offset):
        question_count = buf.readUInt16BE(offset); offset += 2
        answer_count = buf.readUInt16BE(offset); offset += 2
        authority_count = buf.readUInt16BE(offset); offset += 2
        additional_count = buf.readUInt16BE(offset); offset += 2
        self.question, offset = self.parse_question(buf, offset,
                question_count)
        self.answer, offset = self.parse_resource_record(buf, offset,
                answer_count)
        self.authority, offset = self.parse_resource_record(buf, offset,
                authority_count)
        self.additional, offset = self.parse_resource_record(buf, offset,
                additional_count)
        return offset

    def parse_one_question(self, buf, offset):
        """Parse one piece of the question record"""
        domain_info = read_domain(buf, offset)
        if domain_info["has_pointer_type"] == True:
            self.has_pointer_type = True
        offset = domain_info["offset"]
        qtype = buf.readUInt16BE(offset); offset += 2
        klass = buf.readUInt16BE(offset); offset += 2
        data = {
            "name": domain_info["name"],
            "type": qtype,
            "class": klass
            }
        return data, offset

    def parse_question(self, buf, offset, count):
        """
            QNAME: domain name
            QTYPE: query type: A, MX, ...
            QCLASS: request record being requested
        """
        questions = []
        for i in [0 til count]:
            data, offset = self.parse_one_question(buf, offset)
            questions.push(data)
        return questions, offset

    def parse_resource_record(self, buf, offset, count):
        """
            The RR data
            QNAME: domain name
            QTYPE: query type: A, MX, ...
            QCLASS: request record being requested
            TTL:   time to live in seconds (uint32)
            RLENGTH: record length (uint16)
            RDATA: record data (For A query, a uint32 for IP)
        """
        resource_record = []
        for i in [0 til count]:
            data, offset = self.parse_one_question(buf, offset)
            data["ttl"] = buf.readUInt32BE(offset); offset += 4
            rdlen = buf.readUInt16BE(offset); offset += 2
            tmp_buf = Buffer(BUFFER_SIZE)
            tmp_offset = 0
            # <<DNS and BIND>> Appendix A
            # Appendix A. DNS Message Format and Resource Records
            if data["type"] in [QUERY_TYPES.CNAME, QUERY_TYPES.DNAME,
                    QUERY_TYPES.PTR, QUERY_TYPES.NS,
                    QUERY_TYPES.MADNAME, QUERY_TYPES.MGMNAME,
                    QUERY_TYPES.MR]:
                label_info = read_domain(buf, offset)
                clen = write_domain(tmp_buf, label_info["name"], 0, False)
                data["rdata"] = tmp_buf.toString("base64", 0, clen)
            elif data["type"] in [QUERY_TYPES.MX]:
                delta = 0
                pref = buf.readUInt16BE(offset); delta += 2
                clen = tmp_buf.writeUInt16BE(pref, tmp_offset); tmp_offset += 2
                label_info = read_domain(buf, offset + delta)
                clen = write_domain(tmp_buf, label_info["name"], tmp_offset,
                        False)
                data["rdata"] = tmp_buf.toString("base64", 0, clen)
            elif data["type"] in [QUERY_TYPES.SOA]:
                label_info = read_domain(buf, offset)
                clen = write_domain(tmp_buf, label_info["name"], tmp_offset,
                        False)
                tmp_offset = clen
                label_info = read_domain(buf, label_info["offset"])
                clen = write_domain(tmp_buf, label_info["name"], clen, False)
                tmp_offset = clen
                extra_len = 5*4
                buf.copy(tmp_buf, tmp_offset, label_info["offset"],
                        label_info["offset"] + extra_len)
                data["rdata"] = tmp_buf.toString("base64", 0,
                        tmp_offset + extra_len)
            else:
                data["rdata"] = buf.toString("base64", offset, offset + rdlen)
            offset += rdlen
            resource_record.push(data)
        #console.warn("resource_record", resource_record)
        return resource_record, offset

    def write_buf(self, buf):
        """Output the message to a buf suitable to socket send"""
        offset = 0
        offset = self.write_headers(buf, offset)
        offset = self.write_records(buf, offset)
        return offset

    def write_headers(self, buf, offset):
        buf.writeUInt16BE(self.id, offset); offset += 2
        buf.writeUInt16BE(self.flags, offset); offset += 2
        return offset

    def write_records(self, buf, offset):
        buf.writeUInt16BE(len(self.question), offset); offset += 2
        buf.writeUInt16BE(len(self.answer), offset); offset += 2
        buf.writeUInt16BE(len(self.authority), offset); offset += 2
        buf.writeUInt16BE(len(self.additional), offset); offset += 2

        offset = self.write_questions(buf, self.question, offset)
        offset = self.write_resource_record(buf, self.answer, offset)
        offset = self.write_resource_record(buf, self.authority, offset)
        offset = self.write_resource_record(buf, self.additional, offset)
        return offset

    def write_one_question(self, buf, data, offset):
        offset = write_domain(buf, data["name"], offset)
        buf.writeUInt16BE(data["type"], offset); offset += 2
        buf.writeUInt16BE(data["class"], offset); offset += 2
        return offset

    def write_questions(self, buf, questions, offset):
        for data in questions:
            offset = self.write_one_question(buf, data, offset)
        return offset

    def write_resource_record(self, buf, resource_record, offset):
        for rr in resource_record:
            offset = self.write_one_question(buf, rr, offset)
            buf.writeUInt32BE(rr["ttl"], offset); offset += 4
            # FIXME: rdata can be label compressed too, decode like read
            wlen = buf.write(rr["rdata"], offset + 2, "base64")
            buf.writeUInt16BE(wlen, offset); offset += 2
            offset += wlen
        return offset

@external
class EventEmitter:
    pass
class DnsLookupError(DnsError):
    pass

class DnsUDPClient(EventEmitter):
    """Query remote dns server to get a response
        Emit Events:
            "resolved",
            "timeout"
        kinda heavy to create an object for each query
    """
    def __init__(self, options):
        self.options = options
        self.timeout = 10000 # in sec
        self.timeout_id = -1
        self.client = None

    def lookup(self, msg):
        """msg: DnsMessage, or Buffer"""
        client = dgram.createSocket("udp4")
        self.client = client
        client.unref()
        client.on("message", def (b, r):
                self._on_message(b, r)
            )

        if isinstance(msg, Buffer):
            buf = msg
            offset = buf.length
        elif isinstance(msg, DnsMessage):
            buf = Buffer(BUFFER_SIZE)
            offset = msg.write_buf(buf)
        else:
            tp = typeof msg
            raise DnsLookupError("Unknown msg type when lookup(): " + tp)

        #console.warn(buf, offset, DNS_PORT, self.options["dns_host"])
        client.send(buf, 0, offset, DNS_PORT, self.options["dns_host"])
        self.timeout_id = setTimeout(def():
                self.kill_me
            , self.timeout)

    def _on_message(self, buf, remote_info):
        nonlocal BUFFER_SIZE
        #console.warn("DnsUDPClient._on_message()")
        if buf.length > BUFFER_SIZE:
            BUFFER_SIZE = buf.length

        self.emit("resolved", buf)
        if self.timeout_id != -1:
            clearTimeout(self.timeout_id)
        self.client.close()

    def kill_me(self):
        """on timeout, close the udp socket"""
        #console.warn("kill_me()")
        self.client.close()
        self.timeout_id = -1
        self.emit("timeout")

class DnsProxy:
    def __init__(self, options, router=None):
        """Router is used to route local name to ip
            options:
                listen_port: dns proxy port. default: 53
                listen_address: dns proxy address. default: 0.0.0.0
                dns_host: remote DNS server we do real DNS lookup.
                          default: 8.8.8.8
            router: a router class to direct domain name to fake ip.
                    Should have a method router.lookup(domain_name)
                    return an ip address or None

        """
        if router is None:
            router = BaseRouter()
        self.timeout = 30 * 1000 # milliseconds
        self.router = router
        if not options["dns_host"]:
            options["dns_host"] = DNS_DEFAULT_HOST
        self.options = options
        self.query_map = {}
        self.usock = dgram.createSocket("udp4")
        self.usock.on("message", def(b, r):
                self._on_dns_message(b, r)
            )
        self.usock.on("listening", def():
                self._on_dns_listening()
            )
        self.usock.on("error", def(err):
                self._on_dns_error(err)
            )

    def _on_dns_message(self, buf, remote_info):
        #console.log("remote info:", remote_info)
        nonlocal BUFFER_SIZE
        if buf.length > BUFFER_SIZE:
            BUFFER_SIZE = buf.length
        dns_msg = DnsMessage(buf)
        raddress = remote_info.address
        rport = remote_info.port
        ret = self.local_router_lookup(dns_msg, rport, raddress)
        if ret is False:
            self.remote_lookup(buf, dns_msg, rport, raddress)

    def local_router_lookup(self, dns_msg, rport, raddress):
        """Short cut, if only an "A" query for routed domains,
           send out a "A" response immediately
        """
        ret = False
        aname = None
        ip = None
        for q in dns_msg.question:
            rec_name = q["name"]
            if (q["type"] in [QUERY_TYPES.A] and
                    self.router.lookup(rec_name) is not None):
                aname = rec_name
                ip = self.router.lookup(rec_name)
                ret = True
            else:
                ret = False
                break
        if ret is True:
            send_msg = self.create_a_message(dns_msg.id, aname, ip)
            send_msg.question = dns_msg.question
            buf = Buffer(BUFFER_SIZE)
            length = send_msg.write_buf(buf)
            self.send_response(buf, length, rport, raddress)
        return ret

    def remote_lookup(self, buf, dns_msg, rport, raddress):
        dns_client = DnsUDPClient(self.options)
        query_key = dns_msg.id + raddress + rport
        d = Date()
        time_stamp = d.getTime()
        self.query_map[query_key] = [dns_client, time_stamp]
        dns_client.on("resolved", def(buf):
            self.handle_lookup_result(buf, rport, raddress)
        )
        dns_client.lookup(dns_msg)

    def _on_dns_error(self, err):
        console.log(err)

    def _on_dns_listening(self):
        addr = self.usock.address()
        console.log("DNS proxy listens on %s:%d", addr.address, addr.port)

    def create_a_message(self, msg_id, name, ip):
        """Create a DnsMessage with type "A" query result"""
        msg = DnsMessage()
        msg.id = msg_id
        msg.flags = DNS_FLAGS.QR | DNS_FLAGS.AA | DNS_FLAGS.RD | DNS_FLAGS.RA
        msg.answer = [{
            "name": name,
            "type": QUERY_TYPES.A,
            "class": DNS_CLASSES.IN,
            "ttl": DEFAULT_TTL,
            "rdata": encode_ip(ip)
            }]
        return msg

    def handle_lookup_result(self, buf, rport, raddress):
        """process remote real dns lookup response"""
        msg = DnsMessage(buf)
        changed = False
        aliases = {}

        for records in [msg.answer, msg.authority, msg.additional]:
            for record in records:
                rec_name = record["name"]
                if record["type"] in [QUERY_TYPES.A, QUERY_TYPES.AAAA]:
                    ip = self.router.lookup(rec_name)
                    if ip is None and rec_name in aliases:
                        ip = aliases[rec_name]
                    if ip is not None:
                        record["rdata"] = encode_ip(ip)
                        changed = True
                if record["type"] in [QUERY_TYPES.CNAME, QUERY_TYPES.DNAME]:
                    cname = decode_base64_label(record["rdata"])
                    ip = self.router.lookup(rec_name)
                    if ip is not None:
                        aliases[cname] = ip
                    elif rec_name in aliases:
                        aliases[cname] = aliases[rec_name]
        #changed = True; console.warn("changed:", changed)
        if changed is True:
            buf = Buffer(BUFFER_SIZE)
            offset = msg.write_buf(buf)
        else:
            offset = buf.length
        query_key = msg.id + raddress + rport
        d = Date()
        time_stamp = d.getTime()
        if time_stamp in self.query_map:
            del self.query_map[time_stamp]
        self.send_response(buf, offset, rport, raddress)

    def send_response(self, buf, length, rport, raddress):
        #console.warn("send_response:", rport, raddress)
        self.usock.send(buf, 0, length, rport, raddress)

    def start(self, ip="0.0.0.0"):
        port = self.options["listen_port"] or DNS_PORT
        #console.warn("listen port", port)
        if ["listen_ip"] in self.options:
            ip = self.options["listen_ip"]

        self.usock.bind(port, ip)
        self.clean_interval = setInterval(def ():
                self.clean_query_map()
            , 10*1000)

    def clean_query_map(self):
        """Clean up query map periodically"""
        d = Date()
        now = d.getTime()
        #console.log(now/1000)
        for k in self.query_map:
            time_stamp = k[1]
            if (now - time_stamp) > self.timeout:
                del self.query_map[k]

class BaseRouter:
    """Route domain address to known ip:
        www.sohu.com ==> 127.0.0.1
    """
    def __init__(self, address_map):
        self.address_map = address_map
    def set(self, domain, ip):
        """Add a new domain => ip route"""
        self.address_map[domain] = ip
    def lookup(self, address):
        result = None
        if address in self.address_map:
            result = self.address_map[address]
        return result

def main_test():
    router = BaseRouter({"www.sohu.com": "127.0.0.1"})
    options = {"dns_host": "8.8.8.8", "listen_port": 2000}
    DnsProxy(options, router).start()

    childp = require("child_process")
    qs = ["www.sohu.com", "www.sohu.com mx", "fhk.a.sohu.com"]
    cmd_prefix = "/usr/bin/dig @127.0.0.1 -p 2000 "
    def rerun(error, stdout, stderr): # recursive exec dns query cmd
        if stdout: console.log(stdout)
        if error: console.log(error)
        if qs.length > 0:
            cmd = cmd_prefix + qs.pop()
            console.log("$", cmd)
            childp.exec(cmd, rerun)
        else: process.exit(code=0)
    rerun()

main_test()
exports.DnsProxy = DnsProxy
exports.BaseRouter = BaseRouter
