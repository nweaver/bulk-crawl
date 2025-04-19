#!/usr/bin/env python3
import json
# This is a tool designed to create a bulk scan of DNS information
# and output it to a JSON format for top 100k domains for testing of
# the DNS resolver architecture for HW1

import random
import struct
import sys
import socket
import threading
import time
import NWDNS
import queue



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

# and this is for cnames
cnames = {}

nxnames = {}

# Sentinels for finishing
sender_done = False

msg_queue = queue.Queue()

# Load all the names and randomly shuffle
def loadfile(filename):
    global lookups
    with open(filename) as f:
        for line in f:
            lookups.append(line.strip())
    random.shuffle(lookups)
    # lookups = lookups[:5]



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
            if name.name not in names:
                names[name.name] = []
            names[name.name].append(name.rdata)

# We are using a two-thread model, a sending thread that maintains the
# caches and handles the data, and a receive thread that just receives DNS messages.

def send_thread():
    global sender_done
    sys.stderr.write("Starting sender\n")
    sys.stderr.flush()
    ts = time.time()
    count = 0;
    for i in range(15):
        for name in lookups:
            name = "www." + name
            while name in cnames:
                name = cnames[name]
            if name not in names:
                count += 1
                if(count % 1000 == 0):
                    sys.stderr.write(".")
                    sys.stderr.flush()
                while ts + (1.0 / pps) > time.time():
                    time.sleep(.25 / pps)
                ts = time.time()
                m = NWDNS.DNSMessage()
                m.question[0].qname = name
                m.question[0].qtype = NWDNS.RTYPE_A
                try:
                    dns_socket.sendto(m.pack(), (find_ns(name), 53))
                except Exception as e:
                    pass
                while msg_queue.qsize() > 0:
                    msg = msg_queue.get()
                    update_cache(msg)
        random.shuffle(lookups)
    sender_done = True

def find_ns(name):
    current = name
    while True:
        if current in nameservers:
            servers = nameservers[current]
            server = random.choice(servers)
            failcount = 0
            while server not in names or len(names[server]) == 0:
                server = random.choice(servers)
                failcount += 1
                if failcount > 10:
                    raise Exception("Cound Not Find an A record for a nameserver")
            return random.choice(names[server])
        if len(current.split(".")) > 1:
            current = current.split(".", 1)[1]
        else:
            current = "."

def update_cache(msg):
    global nameservers
    global names
    global cnames
    global nxnames
    question = msg.question[0].qname
    if msg.header.rcode == NWDNS.RCODE_NXNAME:
        nxnames[question] = True;
    if msg.header.rcode != NWDNS.RCODE_OK:
        return
    if len(msg.answer) > 0:
        names[question] = []
        for name in msg.answer:
            if name not in names[question]:
                if name.rtype == NWDNS.RTYPE_A:
                    names[question].append(name.rdata)
                if name.rtype == NWDNS.RTYPE_CNAME:
                    cnames[question] = name.rdata
    if len(msg.authority) > 0:
        ns = []
        name = None
        for auth in msg.authority:
            if auth.rtype == NWDNS.RTYPE_NS:
                name = auth.name
                if name not in ns:
                    ns.append(auth.rdata)
        if name:
            nameservers[name] = ns
    if len(msg.additional) > 0:
        # this SHOULD bailywick check but for purposes of generating
        # crawl data for testing I'm not going to bother...
        for additional in msg.additional:
            if additional.rtype == NWDNS.RTYPE_A:
                if additional.name not in names:
                    names[additional.name] = []
                if additional.rdata not in names[additional.name]:
                    names[additional.name].append(additional.rdata)


def recv_thread():
    sys.stderr.write("Starting receiver\n")
    sys.stderr.flush()
    while not sender_done:
        recv_packet()

def recv_packet():
    try:
        data, addr = dns_socket.recvfrom(512)
        r = NWDNS.DNSMessage(data)
        msg_queue.put(r)
        sys.stdout.flush()
    except Exception as e:
        print(e)
        pass





if __name__ == '__main__':
    print("Running Bulk Scan tool")
    if len(sys.argv) < 4:
        print("Usage: python bulkscan.py <filename> packets-per-second <output>")
        exit(1)
    loadfile(sys.argv[1])
    pps = int(sys.argv[2])
    proberoot()
    threading.Thread(target=recv_thread, daemon=False).start()
    t = threading.Thread(target=send_thread)
    t.start()
    t.join()
    #print("Names: %s" % json.dumps(names))
    #print("NS: %s" % nameservers)
    #print("CNAME: %s" % cnames)
    #print("NX: %s" % nxnames)
    with open(sys.argv[3], "w") as outfile:
        json.dump(names, outfile)
        outfile.write("\n")
        json.dump(nameservers, outfile)
        outfile.write("\n")
        json.dump(cnames, outfile)
        outfile.write("\n")
        json.dump(nxnames, outfile)
        outfile.write("\n")


