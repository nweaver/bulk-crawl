#!/usr/bin/env python 


import sys
import threading
import Queue
import socket

import time

import random

import NWDNS

sys.stderr.write("Usage %s netmask pps\n" % sys.argv[0])


dns_socket = socket.socket(socket.AF_INET, 
                           socket.SOCK_DGRAM, 
                           socket.IPPROTO_UDP)
dns_socket.settimeout(1)



queries = [
    'www.xxx.com',
    'www.facebook.com',
    'www.twitter.com',
    'www.mit.edu',
    'www.google.com',
    'www.bing.com',
    'research.queries.contact.nweaver.at.icsi.berkeley.edu.for.information'

]

servers = ['121.52.160.152',
           '10.0.1.1']

send_queue = Queue.Queue()

finished = False

sender_done = False

receiver_done = False

# Max packets-per-second
pps = int(sys.argv[2])

def send_thread():
    global sender_done
    sys.stderr.write("Starting sender\n")
    sys.stderr.flush()
    ts = time.time()
    while not finished or not send_queue.empty():
        server = send_queue.get()
        try:
            for item in queries:
                while ts + (1.0 / pps) > time.time():
                    time.sleep(.25 / pps)
                ts = time.time()
                m = NWDNS.DNSMessage()
                m.header.rd = True
                m.question[0] = NWDNS.DNSQuestion()
                m.question[0].qname = item

                dns_socket.sendto(m.pack(),(server, 53))
        except:
            pass
        send_queue.task_done()

    sender_done = True

def recv_thread():
    global receiver_done
    sys.stderr.write("Starting receiver\n")
    sys.stderr.flush()
    while not sender_done:
        recv_packet()
    for x in range(5):
        recv_packet()
    receiver_done = True

def recv_packet():
    try:
        data, addr = dns_socket.recvfrom(512)
        r = NWDNS.DNSMessage(data)
        for a in r.answer:
            print "%s\t%s\t%s\t%s\t%s" % \
                (addr[0],
                 addr[1],
                 a.name,
                 a.rdata,
                 a.ttl)
        sys.stdout.flush()
    except:
        pass


#for item in queries:
#    for server in servers:


threading.Thread(target=send_thread).start()
threading.Thread(target=recv_thread).start()

netmask = int(sys.argv[1])
remander = 32 - netmask
remmask = 2**remander - 1

for x in range(2**netmask):
    x = x << (32 - netmask)
    y = random.randint(0, remmask)
    x = x | y
    if x >> 24 != 0:
        ip = '%i.%i.%i.%i' % \
            (x >> 24,
             x >> 16 & 0xff,
             x >> 8 & 0xff,
             x & 0xff)
        while send_queue.qsize() > 1000:
            time.sleep(1)
        send_queue.put(ip)


#for x in servers:
#    send_queue.put(x)

finished = True
send_queue.join()
                    
while not receiver_done:
    time.sleep(1)

