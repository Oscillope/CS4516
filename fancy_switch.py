# This file will simulate a switch.
from scapy.all import *
from multiprocessing import Process, Queue
import sys, traceback
import logging
from switch import Switch

logging.getLogger("scapy").setLevel(logging.ERROR)

class FancySwitch(Switch):
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
                return sendp(pkt, iface=dst_iface, verbose=False)
            except KeyError:
                pass
        # Otherwise, broadcast to all interfaces except the one the frame
        # was received on
        for dst_iface in self.queues.keys():
            if dst_iface != iface:
                #print "%s -> %s (bcast) on %s -> %s" %(eth_header.src, eth_header.dst, iface, dst_iface)
                sendp(pkt, iface=dst_iface, verbose=False)
        return
