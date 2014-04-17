# vim:fileencoding=utf-8:sw=4:et:syntax=python

# RFC5625: DNS Proxy Implementation Guidelines
# https://tools.ietf.org/html/rfc5625
dgram = require("dgram")
EventEmitter = require("events").EventEmitter

DEFAULT_TTL = 30 # time to live for our fake A record
DNS_PORT = 53
DNS_ENCODING = "ascii"
DNS_POINTER_FLAG = 0xC0

DNS_FLAGS = {
    QR: 0x01 << 15,
    OPCODE: 0x0F << 11,
    AA: 0x01 << 10,
    TC: 0x01 << 9,
    RD: 0x01 << 8,
    RA: 0x01 << 7,
    RCODE: 0x0F << 0,
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
    is_pointer_type = 0
    while True:
        llen = buf.readUInt8(offset); offset += 1
        if llen == 0: break
        if is_pointer_type is 0:
            is_pointer_type = llen & DNS_POINTER_FLAG
            if is_pointer_type is not 0:
                # pointer type point to another label with global 16bit offset
                lower_llen = buf.readUInt8(offset); offset += 1
                raw_offset = offset # save domain name offset
                offset = ((llen & (~DNS_POINTER_FLAG)) << 8 | lower_llen)
                continue # reread label from the new offset

        label = buf.toString(DNS_ENCODING, offset, offset + llen)
        domain.push(label)
        offset += llen

    if is_pointer_type is not 0:
        offset = raw_offset
    ret = {
            "name": domain.join("."),
            "offset": offset,
            "has_pointer_type": is_pointer_type != 0
            }
    return ret

def write_domain(buf, name, offset):
    parts = name.split(".")
    for p in parts:
        wlen = buf.write(p, offset + 1, DNS_ENCODING)
        buf.writeUInt8(wlen, offset); offset += 1
        offset += wlen
    buf.writeUInt8(0, offset); offset += 1
    return offset

console.log(read_domain(Buffer("\03www\04sohu\03com\00", "binary"), 0))
console.log(read_domain(Buffer("\04sohu\03com\xC0\x0B\02cn\00", "binary"), 0))

def encode_ip(aip):
    """Encode a string ip to uint32 coded as base64"""
    buf = Buffer(4)
    parts = aip.split(".")
    for i, d in enumerate(parts):
        buf[i] = parseInt(d)
    #console.log(buf.readUInt32BE(0))
    return buf.toString("base64", 0, 4)
console.log(encode_ip("127.0.0.1"), "fwAAAQ==")

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
        ofset = self.parse_header(buf, offset)
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
            data, offset = parse_one_question(self, buf, offset)
            questions.push(data)
        return (questions, offset)

    def parse_resource_record(self, buf, offset, count):
        """
            QNAME: domain name
            QTYPE: query type: A, MX, ...
            QCLASS: request record being requested
            TTL:   time to live in seconds (uint32)
            RLENGTH: record length (uint16)
            RDATA: record data (For A query, a uint32 for IP)
        """
        resource_record = []
        for i in [0 til count]:
            data, offset = parse_one_question(self, buf, offset)
            data["ttl"] = buf.readUInt32BE(offset); offset += 4
            rdlen = buf.readUInt16BE(offset); offset += 2
            data["rdata"] = buf.toString("base64", offset, offset + rdlen)
            offset += rdlen
            resource_record.push(data)
        return resource_record, offset

    def write_buf(self, buf):
        offset = 0
        offset = self.write_headers(buf, offset)

    def write_headers(self, buf, offset):
        buf.writeUInt16BE(self.id, offset); offset += 2
        buf.writeUInt16BE(self.flags, offset); offset += 2
        return offset

    def write_records(self, buf, offset):
        buf.writeUInt16BE(len(self.question), offset); offset += 2
        buf.writeUInt16BE(len(self.answer), offset); offset += 2
        buf.writeUInt16BE(len(self.authority), offset); offset += 2
        buf.writeUInt16BE(len(self.additional), offset); offset += 2

        self.write_questions(self, buf, self.question, offset)
        self.write_resource_record(self, buf, self.answer, offset)
        self.write_resource_record(self, buf, self.authority, offset)
        self.write_resource_record(self, buf, self.additional, offset)
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
            wlen = buf.write(rr["rdata"], offset + 2, "base64")
            buf.writeUInt16BE(wlen, offset); offset += 2
            offset += wlen
        return offset

@external
class EventEmitter:
    pass
class DnsUDPClient(EventEmitter):
    """Emit "resolved", "timeout" event on done"""
    def __init__(self, config):
        self.config = config
        self.timeout = 3
        self.timeout_id = -1

    def lookup(self, msg):
        client = dgram.createSocket("udp4")
        client.unref()
        client.on("message", self._on_message)
        data = msg
        client.send(msg, 0, msg.length, DNS_PORT, self.config["dns_host"])
        self.client = client
        self.timeout_id = setTimeout(self.kill_me, self.timeout)

    def _on_message(self, buf, remote_info):
        self.emit("resolved", buf)
        cancelTimeout(self.timeout_id)
        self.client.close()

    def kill_me(self):
        self.client.close()
        self.emit("timeout")

class DnsProxy:
    def __init__(self, options, router):
        self.router = router
        self.options = options
        self.usock = dgram.createSocket("udp4")
        self.usock.on("message", self.on_dns_message)
        self.usock.on("listening", self.on_dns_listening)
        self.usock.on("error", self.on_dns_error)

    def _on_dns_message(self, buf, remote_info):
        console.log(remote_info)
        dns_msg = DnsMessage(buf)

    def _on_dns_error(self, err):
        console.log(err)

    def _on_dns_listening(self):
        addr = self.usock.address()
        console.log("DNS proxy listens on %s:%d", addr.address, addr.port)

    def _get_response(self, data):
        pass



    def start(self, ip="0.0.0.0"):
        port = DNS_PORT
        self.usock.bind(port, ip)

