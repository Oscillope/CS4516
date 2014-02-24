# This file will simulate a switch.
from scapy.all import *
from multiprocessing import Process, Queue
import sys, traceback
import logging

logging.getLogger("scapy").setLevel(logging.ERROR)

class Switch(object):
    # Dictionary mapping interface names to frame queues
    queues = {}
    # Mapping of interface names to active interface processes
    processes = {}
    # Dictionary mapping destinations to interfaces
    hosts = {}

    def __init__(self, iface_list=None):
        if iface_list is None:
            raise RuntimeError("You must specify at least one interface to switch on")
        for iface in iface_list:
            self._add_interface(iface)

    def _add_interface(self, iface):
        # Initialize frame queue and map to interface
        queue = Queue()
        self.queues[iface] = queue
        # Create process for sniffing interface
        proc = Process(target=self._activate_interface, args=(iface,queue))
        # Add process to list
        self.processes[iface] = proc
        # Start sniffing interface
        proc.start()

    def _activate_interface(self, iface, queue):
        try:
            # Sniff specified interface for Ethernet packets and put them
            # into the queue
            sniff(prn=lambda(packet): self._handle_packet(packet, queue), iface=iface, store=0)
        except:
            print "Unexpected error:"
            traceback.print_exc(file=sys.stdout)
            
    def _handle_packet(self, packet, queue):
        queue.put(str(packet))
    
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
        
    def switch_forever(self):
        # Switch forever
        while True:
            try:
                # For each interface, send a frame off the queue
                for iface, queue in self.queues.items():
                    # Send one frame off each non-empty queue
                    if not queue.empty():
                        self._forward_packet(Ether(queue.get()), iface)
            except IndexError:
                pass
            except KeyboardInterrupt:
                print "Keyboard interrupt detected, exiting..."
                for process in self.processes.values():
                    process.terminate()
                    process.join()
                sys.exit(0)
            except:
                print "Unexpected error:"
                traceback.print_exc(file=sys.stdout)
