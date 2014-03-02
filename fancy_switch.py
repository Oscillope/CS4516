# This file will simulate a switch.
from scapy.all import *
from multiprocessing import Process, Queue
import sys, traceback
import logging
import collections
from switch import Switch
from random import choice

# this is the number of checksums for an interface to store
checker_backlog = 64 # networking people and powers of 2, LOL

logging.getLogger("scapy").setLevel(logging.ERROR)

class FancySwitch(Switch):
    # dict of circular buffers of frames that have been sent out interface x, indexed by interface
    sent_frames = {}
    # this is a mapping of interfaces to lists of interfaces that go to the same places
    interface_equivalency = {}
    # the "keep the buffer circular" queue
    circular_queue = collections.deque()
    # this keeps track of the current flows
    flow_table = {}

    def _add_interface(self, iface_name):
        # add interface just like a regular switch
        iface = super(FancySwitch, self)._add_interface(iface_name)
        
    def _process_packet(self, pkt, iface):
        # Check for our special packets.
        if pkt.dst == "ff:ff:ff:ff:ff:ff" and pkt.src == "08:00:27:10:e2:69":
            try:
                src_iface_name = str(pkt.load).strip('\0')
                print "Raw data: %s on %s" %(src_iface_name, iface.name)
                for src_iface in self.interfaces:
                    print "Comparing %s (%d) to %s (%d)." %(src_iface.name, len(src_iface.name), src_iface_name, len(src_iface_name))
                    if src_iface.name == src_iface_name:
                        self._duplex_equivalency(src_iface, iface)
                        break
            except AttributeError:
                return []
            
        # Map source port to interface
        # TODO: Handle multiple instances of one address
        if not pkt.src in self.hosts:
            self.hosts[pkt.src] = iface
            print "Found host %s on interface %s " %(pkt.src, iface)
        
        
            
        #print "iface forwarding match: %s hash check: %s MAC in hosts: %s" %(str(self.hosts[eth_header.src] != iface), str(self._check_hash(str(pkt), iface)), str(eth_header.src in self.hosts))
        # Check dictionary (if not a broadcast MAC) for mapping between destination and interface
        # Set up list of interfaces
        ifaces = []
        #if this is already in the flow table, just foreward it
        ip_mac_pair = self._get_ip_mac_pair(pkt)
        if ip_mac_pair in flow_table:
            return flow_table[ip_mac_pair]
        if pkt.dst != "ff:ff:ff:ff:ff:ff":
            try:
                dst_iface = self.hosts[pkt.dst]
                if iface == dst_iface:
                    return []  # this is because it is going out on the interface it came in on, which is dumb
                if (iface in self.interface_equivalency and dst_iface not in self.interface_equivalency[iface]) or iface not in self.interface_equivalency:
                    #print "%s -> %s on %s -> %s" %(pkt.src, pkt.dst, iface, dst_iface)
                    ifaces = [dst_iface]
                else:
                    print "Found interface in equivalency table, and I THREW IT ON THE GROOOOOUUUUUUNNNDDDD."
                    #so this is where we need to set up flows for bandwidth sharing
                    #I would imagine most of the "flows" that we care about will all be IP, if not then you are having a bad day and will not be going to the internet today
                    if ip_mac_pair is not None: #make sure that we can actually constructed the flow table key
                        #this is where we decide on the interface and make a flow
                        flow_table[ip_mac_pair] = self._pick_iface(dst_iface)
                    else:
                        print 'dropping protocol of type %s' %(pkt.type)
                    return []
            except KeyError:
                #print "Key shortage. Ask LNL for help with %s." %(pkt.dst)
                pass
        
        # Attempt to find duplicate interfaces
        # OLD CODE (unneeded?): and pkt.src in self.hosts
        if self.hosts[pkt.src] != iface and self._check_hash(str(pkt)):
            if len(ifaces) == 1:
                self._duplex_equivalency(iface, self.hosts[pkt.src])
            else:
                # Make an empty broadcast frame.
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="08:00:27:10:e2:69")/Raw(load=iface.name)
                # Send it out.
                sendp(pkt, iface=iface.name, verbose=True)
                
        if len(ifaces) == 1:
            return ifaces
            
        # Otherwise, broadcast to all interfaces except the one the frame
        # was received on
        for dst_iface in self.interfaces:
            if dst_iface != iface:
                if (iface in self.interface_equivalency and dst_iface not in self.interface_equivalency[iface]) or iface not in self.interface_equivalency:
                    #print "%s -> %s (bcast) on %s -> %s" %(pkt.src, pkt.dst, iface, dst_iface)
                    ifaces.append(dst_iface)
                else:
                    print "Found equivalent interface, and I THREW IT ON THE GROOUUUUUND."
        return ifaces
        
    def _forward_packet(self, pkt, ifaces):
        if len(ifaces) == 0:
            return
        pkt_hash = str(pkt)
        if len(self.circular_queue) >= checker_backlog:
            self.sent_frames.pop(self.circular_queue.pop())
        self.circular_queue.append(pkt_hash)
        if not pkt_hash in self.sent_frames:
            self.sent_frames[pkt_hash] = []
        
        print "%s -> %s on %s" %(pkt.src, pkt.dst, [x.name for x in ifaces])
        for dst_iface in ifaces:
            self.sent_frames[pkt_hash].append(dst_iface)
            dst_iface.send(pkt)
        #print [x.name for x in self.sent_frames[pkt_hash]]

    # Returns true if the hash is found in the dictionary of sent frames.
    def _check_hash(self, pkt_hash):
        return pkt_hash in self.sent_frames
        
    #Adds iface2 to iface1's equivalency table and vice versa.
    def _duplex_equivalency(self, iface1, iface2):
        print "Binding %s to %s." %(iface1.name, iface2.name)
        if iface1.name == iface2.name:
            return
        if iface1 in self.interface_equivalency:
            if iface2 not in self.interface_equivalency[iface1]:
                self.interface_equivalency[iface1].append(iface2)
                print "%s: %s" %(iface1, [str(x) for x in self.interface_equivalency[iface1]])
            else:
                return
        else:
            self.interface_equivalency[iface1] = [iface2]
            print "%s: %s" %(iface1, [str(x) for x in self.interface_equivalency[iface1]])
        self._duplex_equivalency(iface2, iface1)

    def _get_ip_mac_pair(self, pkt):
        if pkt.type == 0x800: # ethertype is IP?
            print('butts')
            return (pkt['IP'].src,pkt.dst)
        return None
    # picks an interface out of the set of dst_iface and its equivalents, if you give a dst that does not have any, it will be unhappy, strategy for now is just to pick randomly, which should produce some evenness but not much
    def _pick_iface(self, dst_iface):
        potential_ifaces = self.interface_equivalency[dst_iface]
        potential_ifaces.append(dst_iface)
        return choice(potential_ifaces)
