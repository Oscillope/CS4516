# This file will simulate a switch.
import pcapy
from scapy.all import *
from multiprocessing import Process, Queue
import sys, traceback
import logging

logging.getLogger("scapy").setLevel(logging.ERROR)

class Interface:
    incoming = None
    outgoing = None
    name = None
    process = None
    
    def __init__(self, name):
        self.incoming = Queue()
        self.outgoing = Queue()
        self.name = name
        self.process = Process(target=self.run)

    def activate(self):
        self.process.start()

    def deactivate(self):
        try:
            self.process.terminate()
            self.process.join()
        except:
            print "Problem deactivating interface:"
            traceback.print_exc(file=sys.stdout)

    def _handle_packet(self, hdr, frame):
        self.incoming.put(str(frame))

    def run(self):
        try:
            sniffer = pcapy.open_live(self.name, 1024, True, 100)
            sniffer.loop(-1, self._handle_packet)
            # TODO: send outgoing packets waiting in queue
            # sendp(pkt, iface=dst_iface, verbose=False)
        except KeyboardInterrupt:
            sys.exit(0)
        except:
            print "Unexpected error:"
            traceback.print_exc(file=sys.stdout)
        
    def __str__(self):
        return self.name

class Switch(object):
    # List of interface objects
    interfaces = []
    # Dictionary mapping hosts to interface objects
    hosts = {}

    def __init__(self, iface_list=None):
        if iface_list is None:
            raise RuntimeError("You must specify at least one interface to switch on")
        for iface in iface_list:
            self._add_interface(iface)

    def _add_interface(self, iface_name):
        # Create object for interface info
        interface = Interface(iface_name)
        self.interfaces.append(interface)
    
    def _forward_packet(self, pkt, iface):
        #print "Forwarding packet!"
        eth_header = pkt['Ethernet']
        # Map source port to interface
        # TODO: Handle multiple instances of one address
        if not eth_header.src in self.hosts:
            self.hosts[eth_header.src] = iface
            print "Found host %s on interface %s " %(eth_header.src, iface)
        
        
        # Check dictionary (if not a broadcast MAC) for mapping between destination and interface
        if eth_header.dst != "ff:ff:ff:ff:ff:ff":
            try:
                dst_iface = self.hosts[eth_header.dst]
                if iface == dst_iface:
                    return
                # If mapping is found, forward frame on interface
                print "%s -> %s on %s -> %s" %(eth_header.src, eth_header.dst, iface, dst_iface)
                dst_iface.outgoing.put(pkt)
                # This process is now done with this packet
                return
            except KeyError:
                pass
        # Otherwise, broadcast to all interfaces except the one the frame
        # was received on
        for dst_iface in self.interfaces:
            if dst_iface != iface:
                print "%s -> %s (bcast) on %s -> %s" %(eth_header.src, eth_header.dst, iface, dst_iface)
                dst_iface.outgoing.put(str(pkt))
    
    def switch_forever(self):
        # Start up interfaces
        for iface in self.interfaces:
            iface.activate()
        # Switch forever
        while True:
            try:
                # For each interface, send a frame off the queue
                for iface in self.interfaces:
                    queue = iface.incoming
                    # Send one frame off each non-empty queue
                    if not queue.empty():
                        self._forward_packet(Ether(queue.get()), iface)
            except IndexError:
                pass
            except KeyboardInterrupt:
                print "Keyboard interrupt detected, exiting..."
                for iface in self.interfaces:
                    iface.deactivate()
                sys.exit(0)
            except:
                print "Unexpected error:"
                traceback.print_exc(file=sys.stdout)
