# This file will simulate a switch.
from scapy.all import *
from multiprocessing import Process, Queue
import sys, traceback
import logging
import collections
from switch import Switch

# this is the number of checksums for an interface to store
checker_backlog = 16 # networking people and the number 16, LOL

logging.getLogger("scapy").setLevel(logging.ERROR)

class FancySwitch(Switch):
    # dict of circular buffers of frames that have been sent out interface x, indexed by interface
    sent_frames = {}
    # this is a mapping of interfaces to lists of interfaces that go to the same places
    interface_equivalency = {}
    def _add_interface(self, iface_name):
        # add interface just like a regular switch
        iface = super(FancySwitch, self)._add_interface(iface_name)
        # make the circular buffer to check against before broadcasting something
        self.sent_frames[iface] = collections.deque(maxlen=checker_backlog)

    def _forward_packet(self, pkt, iface):
        eth_header = pkt['Ethernet']
        # Map source port to interface
        # TODO: Handle multiple instances of one address
        if not eth_header.src in self.hosts:
            self.hosts[eth_header.src] = iface
            #print "Found host %s on interface %s " %(eth_header.src, iface)
        elif self.hosts[eth_header.src] != iface:
            if iface in self.interface_equivalency: 
                if self.hosts[eth_header.src] not in self.interface_equivalency[iface]:
                    self.interface_equivalency[iface].add(self.hosts[eth_header.src])
            else:
                self.interface_equivalency[iface] = [self.hosts[eth_header.src]]


        # Check dictionary (if not a broadcast MAC) for mapping between destination and interface
        if eth_header.dst != "ff:ff:ff:ff:ff:ff":
            try:
                dst_iface = self.hosts[eth_header.dst]
                if iface == dst_iface:
                    return
                # If mapping is found, forward frame
                print "%s -> %s on %s -> %s" %(eth_header.src, eth_header.dst, iface, dst_iface)
                dst_iface.outgoing.put(str(pkt))
                return
            except KeyError:
                pass
        # Otherwise, broadcast to all interfaces except the one the frame
        # was received on
        for dst_iface in self.interfaces:
            if dst_iface != iface:
                pkt_hash = pkt.hashret()
                if pkt_hash not in self.sent_frames[dst_iface]:
                    self.sent_frames[dst_iface].append(pkt_hash)
                    print "%s -> %s (bcast) on %s -> %s" %(eth_header.src, eth_header.dst, iface, dst_iface)
                    dst_iface.outgoing.put(str(pkt))

    def pick_interface(self,):
        
