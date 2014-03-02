# This file will simulate a switch.
from scapy.all import *
from multiprocessing import Process, Queue
import sys, traceback
import logging
import collections
from switch import Switch

# this is the number of checksums for an interface to store
checker_backlog = 64 # networking people and the number 16, LOL

logging.getLogger("scapy").setLevel(logging.ERROR)

class FancySwitch(Switch):
    # dict of circular buffers of frames that have been sent out interface x, indexed by interface
    sent_frames = {}
    # this is a mapping of interfaces to lists of interfaces that go to the same places
    interface_equivalency = {}
    # the "keep the buffer circular" queue
    circular_queue = collections.deque()
    
    def _add_interface(self, iface_name):
        # add interface just like a regular switch
        iface = super(FancySwitch, self)._add_interface(iface_name)
        
    def _process_packet(self, pkt, iface):
        if self.hosts[eth_header.src] != iface and not self._check_hash(pkt.hashret(), iface) and eth_headder.src in self.hosts:
            if iface in self.interface_equivalency:
                if self.hosts[eth_header.src] not in self.interface_equivalency[iface]:
                    self.interface_equivalency[iface].append(self.hosts[eth_header.src])
                    print "%s: %s" %(iface, [str(x) for x in self.interface_equivalency[iface]])
            else:
                self.interface_equivalency[iface] = [self.hosts[eth_header.src]]
                print "%s: %s" %(iface, [str(x) for x in self.interface_equivalency[iface]])

    def _forward_packet(self, pkt, iface):
        eth_header = pkt['Ethernet']
        # Map source port to interface
        # TODO: Handle multiple instances of one address
        if not eth_header.src in self.hosts:
            self.hosts[eth_header.src] = iface
            #print "Found host %s on interface %s " %(eth_header.src, iface)

        # Check dictionary (if not a broadcast MAC) for mapping between destination and interface
        if eth_header.dst != "ff:ff:ff:ff:ff:ff":
            try:
                dst_iface = self.hosts[eth_header.dst]
                if iface == dst_iface:
                    return
                # If mapping is found, forward frame
                #print "%s -> %s on %s -> %s" %(eth_header.src, eth_header.dst, iface, dst_iface)
                if dst_iface not in self.interface_equivalency[iface]:
                    dst_iface.send(pkt)
                else:
                    print "Not sending duplicate packet."
                return
            except KeyError:
                pass
        # Otherwise, broadcast to all interfaces except the one the frame
        # was received on
        for dst_iface in self.interfaces:
            if dst_iface != iface:
                if self._check_hash(pkt.hashret(), dst_iface):
                    #print "%s -> %s (bcast) on %s -> %s" %(eth_header.src, eth_header.dst, iface, dst_iface)
                    dst_iface.send(pkt)

    def _check_hash(self, pkt_hash, iface):
        if pkt_hash in self.sent_frames and iface in self.sent_frames[pkt_hash]:
            return False
        else:
            self.circular_queue.append(pkt_hash)
            if pkt_hash in self.sent_frames:
                self.sent_frames[pkt_hash].append(iface)
            else:
                self.sent_frames[pkt_hash] = [iface]
            if len(self.circular_queue) >= checker_backlog:
                self.sent_frames.pop(self.circular_queue.pop())
            return True
