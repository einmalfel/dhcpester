#! /usr/bin/python2

from __future__ import print_function

import time
import sys
import itertools
from threading import Thread, Semaphore, Lock
from random import randint

from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, DHCPTypes


def say(*args):
    with say.lock:
        print(*args)
say.lock = Lock()


# Python2.x has no standard barrier implementation
class Barrier:
    def __init__(self, n):
        self.n = n
        self.count = 0
        self.mutex = Semaphore(1)
        self.barrier = Semaphore(0)

    def wait(self):
        self.mutex.acquire()
        self.count += 1
        self.mutex.release()
        if self.count == self.n:
            self.barrier.release()
        self.barrier.acquire()
        self.barrier.release()


class Sender(Thread):
    _d_count = itertools.count(start=1)
    _r_count = itertools.count(start=1)

    def __init__(self, mac):
        self.mac = mac
        self.last_XID = None
        Thread.__init__(self)
        self.daemon = True
        self._offer_barrier = Barrier(2)
        self._ip = None
        self._server_ip = None

    def process_offer(self, ip, server_ip):
        self._ip = ip
        self._server_ip = server_ip
        self._offer_barrier.wait()

    @staticmethod
    def _get_chaddr(mac):
        return ''.join(map(lambda x: chr(int(x, 16)), mac.split(':')))

    def setup_general_bootp_packet(self):
        self.last_XID = randint(1, 900000000)
        return (Ether(src=self.mac, dst='FF:FF:FF:FF:FF:FF') /
                IP(src='0.0.0.0', dst='255.255.255.255') /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=[self._get_chaddr(self.mac)], xid=self.last_XID))

    def run(self):
        discover_packet = (self.setup_general_bootp_packet() /
                           DHCP(options=[('message-type', 'discover'),
                                         'end']))
        sendp(discover_packet, verbose=0)
        say('Discover', self._d_count.next(), 'sent', self.mac)
        self._offer_barrier.wait()
        request_packet = (self.setup_general_bootp_packet() /
                          DHCP(options=[('message-type', 'request'),
                                        ('server_id', self._server_ip),
                                        ('requested_addr', self._ip),
                                        'end']))
        sendp(request_packet, verbose=0)
        time.sleep(1)
        say('Request', self._r_count.next(), 'sent', self.mac)


class Receiver(Thread):
    _o_count = itertools.count(start=1)
    _a_count = itertools.count(start=1)
    _n_count = itertools.count(start=1)

    def __init__(self, senders):
        Thread.__init__(self)
        self.daemon = True
        self._senders = senders

    def process_packet(self, packet):
        for s in self._senders:
            if s.last_XID == packet[BOOTP].xid:
                if DHCPTypes[packet[DHCP].options[0][1]] == 'offer':
                    say('Offer', self._o_count.next(), 'received', s.mac,
                        packet[BOOTP].yiaddr)
                    s.process_offer(packet[BOOTP].yiaddr, packet[BOOTP].siaddr)
                elif DHCPTypes[packet[DHCP].options[0][1]] == 'ack':
                    say('Ack', self._a_count.next(), 'received ', s.mac,
                        packet[BOOTP].yiaddr)
                    self._senders.remove(s)
                elif DHCPTypes[packet[DHCP].options[0][1]] == 'nak':
                    say('Nack', self._n_count.next(), 'received ', s.mac)
                    self._senders.remove(s)
                    # restart sequence for this MAC
                    new_sender = Sender(s.mac)
                    self._senders.append(new_sender)
                    new_sender.start()
                break
        else:
            say('Warning: unknown XID')

    def run(self):
        sniff(lfilter=lambda x: UDP in x and x[UDP].dport == 68,
              prn=self.process_packet,
              store=1)


# TODO ensure MACs are unique
def random_mac():
    mac = [0xDE, 0xAD,
           randint(0x00, 0x29), randint(0x00, 0x7f),
           randint(0x00, 0xff), randint(0x00, 0xff)]
    return ':'.join(map(lambda x: '%02x' % x, mac))


# set maximum socket buffer size to 1M to prevent overflow
with open('/proc/sys/net/core/rmem_max', 'w') as f:
    f.write('1000000')

try:
    N = int(sys.argv[1])
except (ValueError, IndexError):
    N = 5
    say('The only CLI argument this script accept is a number of DHCP clients '
        'to emulate. Using default:', N)

senders = [Sender(random_mac()) for n in range(N)]
r = Receiver(senders)
r.start()

map(lambda x: x.start(), senders)

while senders:
    time.sleep(1)
