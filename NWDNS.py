
import struct
import socket
import random
import time
import sys


# Some useful enumerations:

RCODE_OK = 0
RCODE_FMT = 1
RCODE_SERVFAIL = 2
RCODE_NXNAME = 3
RCODE_NOIMPLEMENT = 4
RCODE_REFUSE = 5

rcode_names = {0 : 'RCODE_OK',
               1 : 'RCODE_FMT',
               2 : 'RCODE_SERVFAIL',
               3 : 'RCODE_NXNAME',
               4 : 'RCODE_NOIMPLEMENT',
               5 : 'RCODE_REFUSE',
               16: 'RCODE_BADVERS'}

def rcodeName(rcode):
    if rcode in rcode_names:
        return rcode_names[rcode]
    return "Unknown:%x" % rcode

RTYPE_A     = 1
RTYPE_NS    = 2
RTYPE_CNAME = 5
RTYPE_SOA   = 6
RTYPE_NULL  = 10
RTYPE_PTR   = 12
RTYPE_MX    = 15
RTYPE_TXT   = 16
RTYPE_OPT   = 41
RTYPE_AAAA  = 28
RTYPE_ANY   = 255

# A deliberately bogus RTYPE for testing
# Wire format is encoded/decoded the same as TXT
RTYPE_ICSI  = 169
# Needed because RTYPE_ICSI is a meta value,
# which bind has decreed that the rules don't apply to
RTYPE_ICSI2 = 1169

rtype_names = {1 : 'RTYPE_A',
               2 : 'RTYPE_NS',
               5 : 'RTYPE_CNAME',
               6 : 'RTYPE_SOA',
               10 : 'RTYPE_NULL',
               12 : 'RTYPE_PTR',
               15 : 'RTYPE_MX',
               16 : 'RTYPE_TXT',
               28 : 'RTYPE_AAAA',
               41 : 'RTYPE_OPT',
               46 : 'RTYPE_RRSIG',
               169 : 'RTYPE_ICSI',
               1169 : 'RTYPE_ICSI2',
               255 : 'RTYPE_ANY'}

OPCODE_QUERY = 0
OPCODE_IQUERY = 1
OPCODE_STATUS = 2

opcode_names = {0 : 'OPCODE_QUERY',
                1 : 'OPCODE_IQUERY',
                2 : 'OPCODE_STATUS'}


# An internal class used for DNS name compression/decompression.
class DNSNamepacker:
    def __init__(self):
        self.names = {}
    def pack(self, name, index):
        if name == "":
            return struct.pack("B", 0)
        if(name in self.names):
            value = self.names[name] | 0xc000
            return struct.pack("H", socket.htons(value))
        self.names[name] = index
        values = name.split('.', 1)
        if(len(values) == 1):
            return struct.pack("B", len(values[0])) + values[0] + \
                struct.pack("B", 0)
        return struct.pack("B", len(values[0])) + values[0] + \
            self.pack(values[1], index + len(values[0]) + 1)

    def unpack(self, data, index, recurseCount = 0):

        val = struct.unpack("B", data[index])[0]
        if(val == 0):
            return ("", 1)
        val = socket.ntohs(struct.unpack("H", data[index:index+2])[0])
        if(recurseCount > 100):
            raise ValueError, "Loop in name compression"

        if((val & 0xc000) == 0xc000):
            return (self.unpack(data, val & ~0xc000, recurseCount+1)[0], 2)

        val = struct.unpack("B", data[index])[0]
        name = data[index+1:index+1+val]
        resp = self.unpack(data, index+1+val, recurseCount)
        if(resp[0] == ""):
            return (name, val + resp[1] + 1)
        else:
            # I THINK the length is right.  Things
            # seem to be working so I'm pretty confident
            return (name + "." +  resp[0], val + resp[1] + 1)



# A modified namepacker which can create loops in the name
# and evil out-of-range pointers
class DNSEvilpacker(DNSNamepacker):
    def __init__(self):
        self.start = 0
        DNSNamepacker.__init__(self)
    def pack(self, name, index):
        if(self.start == 0):
            self.start = index
        if(name in self.names):
            value = self.names[name] | 0xc000
            return struct.pack("H", socket.htons(value))
        self.names[name] = index
        values = name.split('.', 1)
        if(len(values) == 1):
            if(values[0] == 'loop'):
                # print "Evil loop back to %i" % index
                value = index | 0xc000
                return struct.pack("B", len(values[0])) + values[0] + \
                    struct.pack("H", socket.htons(value))
            elif(values[0] == 'evil'):
                # print "Evil pointer to 1024"
                value = 1024 | 0xc000
                return struct.pack("B", len(values[0])) + values[0] + \
                    struct.pack("H", socket.htons(value))
            else:
                return struct.pack("B", len(values[0])) + values[0] + \
                    struct.pack("B", 0)
        return struct.pack("B", len(values[0])) + values[0] + \
            self.pack(values[1], index + len(values[0]) + 1)



# class which defines an SOA record

class DNSSOA:
    def __init__(self, mname, rname, values):
        self.mname = mname
        self.rname = rname
        self.serial = values[0]
        self.refresh = values[1]
        self.retry = values[2]
        self.expire = values[3]
        self.minimum = values[4]

    def __repr__(self):
        return "SOA: (mname: %s rname: %s serial: %i refresh: %i retry: %i expire: %i minimum: %i)" % (self.mname, self.rname, self.serial, self.refresh, self.retry, self.expire, self.minimum)

    def shortRepr(self):
        return "SOA: %s %s" % (self.mname, self.rname)


# The class which defines the DNS header fields.

# id: 16b DNS transaction ID
# qr: Query (False) or Response (True).  Default to False
# opcode: Defaults to 0 (normal lookup)
# aa: Is this an authoritative answer.  Default to False
# tc: Is this message truncated?  Default to False
# rd: Does the query desire recursino?  Default to False
# ra: Does the server support recursion?  Default to False
# rcode: Response code.  Default to 0 (ok)
# qdcount: Number of questions
# ancount: Number of answer records
# nscount: Number of authority records
# arcount: Number of additional records

class DNSHeader:
    def unpack(self, data):
        if(len(data) < 12):
            raise ValueError, "Bad Received Packet: too short a header"
        data_frag = data[0:12]
        unpacked_data = struct.unpack("HBBHHHH", data_frag)
        self.id     =  socket.ntohs(unpacked_data[0])
        flag1   = unpacked_data[1]
        self.qr      = (flag1 & 0x80) != 0
        self.opcode  = (flag1 & 0x78) >> 3
        self.aa      = (flag1 & 0x04) != 0
        self.tc      = (flag1 & 0x02) != 0
        self.rd      = (flag1 & 0x01) != 0
        flag2   = unpacked_data[2]
        self.ra      = (flag2 & 0x80) != 0
        self.rcode   = (flag2 & 0x0F)

        self.qdcount = socket.ntohs(unpacked_data[3])
        self.ancount = socket.ntohs(unpacked_data[4])
        self.nscount = socket.ntohs(unpacked_data[5])
        self.arcount = socket.ntohs(unpacked_data[6])
        return self;

    def pack(self):
        flag1 = 0;
        if(self.qr): flag1 = flag1 | 0x80
        flag1 = flag1 | ((self.opcode & 0xf) << 3)
        if(self.aa): flag1 = flag1 | 0x4
        if(self.tc): flag1 = flag1 | 0x2
        if(self.rd): flag1 = flag1 | 0x1
        
        flag2 = 0;
        if(self.ra): flag2 = flag2 | 0x80
        flag2 = flag2 | (self.rcode & 0xf)

        resp = struct.pack("HBBHHHH",
                           socket.htons(self.id),
                           flag1,
                           flag2,
                           socket.htons(self.qdcount),
                           socket.htons(self.ancount),
                           socket.htons(self.nscount),
                           socket.htons(self.arcount))
        return resp
                           
    def __init__(self):
        self.id = random.randint(0,0xffff)
        self.qr = False
        self.opcode = 0
        self.aa = False
        self.tc = False
        self.rd = False
        self.ra = False
        self.z  = 0
        self.rcode = 0
        self.qdcount = 0
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0

    def cloneFrom(self, header):
        self.id = random.randint(0, 0xffff)
        self.qr = header.qr
        self.opcode = header.opcode
        self.aa = header.aa
        self.tc = header.tc
        self.rd = header.rd
        self.ra = header.ra
        self.z = header.z
        self.rcode = header.rcode
        self.qdcount = header.qdcount
        self.ancount = header.ancount
        self.nscount = header.nscount
        self.arcount = header.arcount

    def shortRepr(self):
        return "Header: ID %4x, qr: %s, op: %s rcode: %s" % \
            (self.id, self.qr, opcode_names[self.opcode],
             rcode_names[self.rcode])
    def __repr__(self):
        return "DNS Header: ID: %4x, qr: %s, opcode: %s, aa: %s, " \
            "tc: %s, rd: %s, ra: %s, rcode: %s, qdcount: %i " \
            "ancount: %i nscount: %i arcount: %i" % \
            (self.id, self.qr, opcode_names[self.opcode], 
             self.aa, self.tc, self.rd,
             self.ra, rcode_names[int(self.rcode)], 
             self.qdcount, self.ancount, self.nscount, self.arcount)

# DNS Question class
# qname (string): The name of the question
# qtype (int): Defaults to A record (RTYPES are subset of QTYPES)
# qclass (int): Defaults to 1 (Internet)

class DNSQuestion:
    def __init__(self):
        self.qname   = ""
        self.qtype  = RTYPE_A
        self.qclass = 1
        self.unpackLen = 0

    def cloneFrom(self, question):
        self.qname = question.qname
        self.qtype = question.qtype
        self.qclass = question.qclass
        self.unpackLen = question.unpackLen
        return self

    def shortRepr(self):
        return "Question: %s type %s" % (self.qname, rtype_names[self.qtype])
    def __repr__(self):
        qtype_msg = "%i" % self.qtype
        if(self.qtype in rtype_names):
            qtype_msg = rtype_names[self.qtype]
        return "DNS question: qname: %s qtype: %s qclass: %i length: %i" % \
            (self.qname, qtype_msg, self.qclass, self.unpackLen)
    def unpack(self, data, at):
        self.qname = ""
        self.qname, namelen = DNSNamepacker().unpack(data, at)
        index = at+namelen

        self.unpackLen = namelen + 4
        values = struct.unpack("HH",data[index:index+4])
        self.qtype = socket.ntohs(values[0])
        self.qclass = socket.ntohs(values[1])
        return self

    def pack(self, index, namepacker):
        data = ""
        data = namepacker.pack(self.qname, index)
        data += struct.pack("HH", 
                            socket.htons(self.qtype),
                            socket.htons(self.qclass))
        return data


# DNS Answer class.  A DNS recource record
# name (string)
# type (int): RTYPE in question
# class (int): defalts to 1 (Internet)
# ttl (int): Time to live (32b integer)
# rdata (string): The resource data itself
#      For A records, its a string for the IP address
#      For NS/CNAME, it is the name it points to

class DNSAnswer:
    def __init__(self, name = None, rtype = None, rdata = None, ttl = None):
        self.name = ""
        if(name is not None): self.name = name
        self.ref = 0
        self.refat = 0
        self.refindex = 0
        self.rtype = 0
        self.unpackLen = 0
        if(rtype is not None): self.rtype = rtype
        self.rclass = 1
        self.ttl = 1
        if(ttl is not None): self.ttl = ttl
        self.rdata = 0
        if(rdata is not None): self.rdata = rdata

    def cloneFrom(self, answer):
        self.name = answer.name
        self.ref = answer.ref
        self.refat = answer.refat
        self.refindex = answer.refindex
        self.rtype = answer.rtype
        self.unpackLen = answer.unpackLen
        self.rtype = answer.rtype
        self.rclass = answer.rclass
        self.ttl = answer.ttl
        self.rdata = answer.rdata
        return self

    def shortRepr(self):
        rdata = self.rdata
        if(self.rtype == RTYPE_SOA):
            rdata = self.rdata.shortRepr()
        rname = "%i" % self.rtype
        if self.rtype in rtype_names:
            rname = "%s" % rtype_names[self.rtype]
        return "name: %s rtype: %s rdata: %s" % (self.name, 
                                                 rname,
                                                 rdata)

    def __repr__(self):
        rtype_msg = "%i" % self.rtype
        if(self.rtype in rtype_names):
            rtype_msg = rtype_names[self.rtype]

        return "DNS answer: name: %s rtype: %s rclass: %i ttl: %i rdata: %s" % \
            (self.name, rtype_msg, self.rclass, self.ttl, self.rdata)

    def pack(self, index, namepacker):
        data = namepacker.pack(self.name, index)
        data += struct.pack("HH", socket.htons(self.rtype), 
                            socket.htons(self.rclass))
        data += struct.pack("I", socket.htonl(self.ttl) & 0xffffffffL)
        if(self.rtype == RTYPE_A):
            data += struct.pack("H", socket.htons(4));
            data += socket.inet_aton(self.rdata)
        elif(self.rtype == RTYPE_CNAME or self.rtype == RTYPE_NS 
             or self.rtype == RTYPE_PTR):
            resp = namepacker.pack(self.rdata, index + len(data) + 2)
            data += struct.pack("H", socket.htons(len(resp))) + resp
        elif(self.rtype == RTYPE_TXT or self.rtype == RTYPE_ICSI or
             self.rtype == RTYPE_ICSI2):
            # the RTYPE_TXT is a series of 0 or more
            # length (1 byte) + string (<255 in length)
            tmp = ""
            for item in self.rdata:
                tmp += struct.pack("B%is" % len(item),
                                   len(item), item)
            data += struct.pack("H", socket.htons(len(tmp)))
            data += tmp
        elif(self.rtype == RTYPE_AAAA):
            data += struct.pack("H", socket.htons(16))
            data += socket.inet_pton(socket.AF_INET6, self.rdata)
        elif(self.rtype == RTYPE_SOA):
            resp = namepacker.pack(self.rdata.mname, index + len(data) + 2)
            resp2 = namepacker.pack(self.rdata.rname, index + len(data) + 2
                                    + len(resp))
            data += struct.pack("H", socket.htons(len(resp)
                                                  + len(resp2)
                                                  + 20)) + resp + resp2
            data += struct.pack("I", socket.htonl(self.rdata.serial) 
                                & 0xffffffffL)
            data += struct.pack("I", socket.htonl(self.rdata.refresh)
                                & 0xffffffffL)
            data += struct.pack("I", socket.htonl(self.rdata.retry)
                                & 0xffffffffL)
            data += struct.pack("I", socket.htonl(self.rdata.expire)
                                & 0xffffffffL)
            data += struct.pack("I", socket.htonl(self.rdata.minimum)
                                & 0xffffffffL)
        elif(self.rtype == RTYPE_OPT):
            if self.rdlength != 0 or self.rdata != None:
                print "Unable to pack data in opt fields"
            data += struct.pack("H", socket.htons(self.rdlength))

        else:
            print "Unable to pack rtype %i" % self.rtype
            sys.stdout.flush()
            ""
            # raise ValueError, "Bad RTYPE of %i" % self.rtype
        return data

    def unpack(self, data, at):
        self.name = ""

        self.name, namelen = DNSNamepacker().unpack(data, at)
        index = at+namelen

        values = struct.unpack("HHIH",data[index: index+10])
        self.rtype = socket.ntohs(values[0])
        self.rclass = socket.ntohs(values[1])
        self.ttl = socket.ntohl(values[2])
        self.rdlength = socket.ntohs(values[3])
        self.unpackLen = namelen + 10 + self.rdlength
        if(self.rtype == RTYPE_A):
            self.rdata = socket.inet_ntoa(data[index+10: index+14])
        elif(self.rtype == RTYPE_NS or self.rtype == RTYPE_CNAME or
             self.rtype == RTYPE_PTR):
            self.rdata = DNSNamepacker().unpack(data, index+10)[0]
        elif(self.rtype == RTYPE_AAAA):
            self.rdata = socket.inet_ntop(socket.AF_INET6,
                                          data[index+10:index+26])
        elif(self.rtype == RTYPE_SOA):
            mname, len1 = DNSNamepacker().unpack(data, index+10)
            rname, len2 = DNSNamepacker().unpack(data, index+10+len)
            values = struct.unpack("IIIII", 
                                   data[index+10+len1+len2:index+10+len1+len2+20])
            self.rdata = DNSSOA(mname, rname, values)
        elif(self.rtype == RTYPE_OPT):
            self.edns_udp_size = self.rclass            

            values = struct.unpack("BBH", data[index + 4: index+8])
            self.edns_rcode = values[0]
            self.edns_version = values[1]
            self.edns_flags = socket.ntohs(values[2])

            if self.rdlength != 0:
                print "Unable to handle EDNS options of any data"
                self.rdlength = 0;
                self.edns_has_rdata = True
            else:
                self.edns_has_rdata = False
            self.rdata = None

        elif(self.rtype == RTYPE_TXT or self.rtype == RTYPE_ICSI or 
             self.rtype == RTYPE_ICSI2):
            rdata = data[index+10: index+self.rdlength+10]
            res = []
            at = 0
            # RTYPE_TXT is a string of 0 or more length (1 byte) 
            # + string (<255B) data, of the full rdlength
            while at < len(rdata):
                data_length = struct.unpack("B", rdata[at])[0]
                res_str = rdata[at+1: at+1+data_length]
                at += data_length + 1
                res.append(res_str)
            self.rdata = res

        else:
            if self.rtype in rtype_names:
                sys.stderr.write("Unable to parse rtype %s\n" % 
                                 rtype_names[self.rtype])
            else:
                sys.stderr.write("Unable to parse rtype %i\n" % self.rtype)
        return self




# Root class for handling DNS messages
# header is the DNSHeader
# question is a single DNSQuestion
# answer/authority/additional are lists of DNSAnswers
class DNSMessage():
    def __init__(self, data = None):
        self.header = DNSHeader()
        self.question = [DNSQuestion()]
        self.answer = []
        self.authority = []
        self.additional = []
        self.evil = False
        if(data is not None):
            self.unpack(data)
        self.timestamp = time.time()

        # Field set on sending/receiving by 
        # any other library using it.
        self.serverIP = ''

    def cloneFrom(self, message):
        self.header.cloneFrom(message.header)
        self.evil = message.evil
        self.question = []
        for item in message.question:
            self.question.append(DNSQuestion().cloneFrom(item))
        self.answer = []
        for item in message.answer:
            self.answer.append(DNSAnswer().cloneFrom(item))
        self.authority = []
        for item in message.authority:
            self.authority.append(DNSAnswer().cloneFrom(item))
        self.additional = []
        for item in message.additional:
            self.additional.append(DNSAnswer().cloneFrom(item))
        return self

    def unpack(self, data):
        self.header   = self.header.unpack(data)
        self.question = []
        inMessage = 12
        for i in range(self.header.qdcount):
            resp = DNSQuestion().unpack(data,inMessage)
            inMessage += resp.unpackLen
            self.question.append(resp)
        for i in range(self.header.ancount):
            resp = DNSAnswer().unpack(data,inMessage)
            inMessage += resp.unpackLen
            self.answer.append(resp)
        for i in range(self.header.nscount):
            resp = DNSAnswer().unpack(data,inMessage)
            inMessage += resp.unpackLen
            self.authority.append(resp)
        for i in range(self.header.arcount):
            resp = DNSAnswer().unpack(data,inMessage)
            inMessage += resp.unpackLen
            self.additional.append(resp)
        return self

    def shortRepr(self):
        msg = "DNS Message: server %s ts %f\n" % \
            (self.serverIP, self.timestamp)
        msg += self.header.shortRepr() + '\n'
        for item in self.question:
            msg += "qstn: " + item.shortRepr() + '\n'
        for item in self.answer:
            msg += "answ: " + item.shortRepr() + '\n'
        for item in self.authority:
            msg += "auth: " + item.shortRepr() + '\n'
        for item in self.additional:
            msg += "addl: " + item.shortRepr() + '\n'

        return msg[0:len(msg) - 1]


    def __repr__(self):
        msg = ""
        msg += "DNS Message: server %s timestamp %f\n" % \
            (self.serverIP, self.timestamp)
        msg += self.header.__repr__() + "\n"
        for item in self.question:
            msg += "question: " + item.__repr__() + "\n"
        for item in self.answer:
            msg += "ans: " + item.__repr__() + "\n"
        for item in self.authority:
            msg += "auth: " + item.__repr__() + "\n"
        for item in self.additional:
            msg += "addl: " + item.__repr__() + "\n"
        return msg[0:len(msg)-1]

    def pack(self):
        namepack = DNSNamepacker()
        if(self.evil):
            namepack = DNSEvilpacker()
        self.header.qdcount = len(self.question)
        self.header.ancount = len(self.answer)
        self.header.nscount = len(self.authority)
        self.header.arcount = len(self.additional)
        data = self.header.pack()
        for i in self.question:
            data += i.pack(len(data), namepack)
        for i in self.answer:
            data += i.pack(len(data), namepack)
        for i in self.authority:
            data += i.pack(len(data), namepack)
        for i in self.additional:
            data += i.pack(len(data), namepack)
        
        return data

