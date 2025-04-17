#!/usr/bin/env python

# This is a tool designed to create a bulk scan of DNS information
# and output it to a JSON format for top 100k domains for testing of
# the DNS resolver architecture for HW1

import random
import sys
import socket
import NWDNS



lookups = []
root = "198.41.0.4"
pps = 0

dns_socket = socket.socket(socket.AF_INET,
                           socket.SOCK_DGRAM,
                           socket.IPPROTO_UDP)
dns_socket.settimeout(1)

# The heart of the mappings:

# This maps the domain ("." or more specific)
# to a series of server names
nameservers = {}

# This maps names to A-records or AA records
names = {}



# Load all the names and randomly shuffle
def loadfile(filename):
    global lookups
    with open(filename) as f:
        for line in f:
            lookups.append(line)
    random.shuffle(lookups)
    lookups = lookups[:1000]



# This gets the root data and prepopulates things.
def proberoot():
    msg = NWDNS.DNSMessage()
    msg.question[0] = NWDNS.DNSQuestion()
    msg.question[0].qname = '.'
    msg.question[0].qtype = NWDNS.RTYPE_NS
    dns_socket.sendto(msg.pack(), (root, 53))
    data, addr = dns_socket.recvfrom(512)
    r = NWDNS.DNSMessage(data)
    ns = []
    for name in r.answer:
        ns.append(name.rdata)
    nameservers['.'] = ns
    for name in r.additional:
        if name.rtype == NWDNS.RTYPE_A:
            names[name.name] = name.rdata

if __name__ == '__main__':
    print("Running Bulk Scan tool")
    if len(sys.argv) < 3:
        print("Usage: python bulkscan.py <filename> packets-per-second")
        exit(1)
    loadfile(sys.argv[1])
    pps = int(sys.argv[2])
    proberoot()

