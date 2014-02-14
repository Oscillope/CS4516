# This file will simulate a switch.
from scapy.all import *
from multiprocessing import Process, Queue
import sys, traceback

class Switch:
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
            sniff(prn=lambda(packet, queue): self._handle_packet(packet, queue), iface=iface)
        except:
            print "Unexpected error:"
            traceback.print_exc(file=sys.stdout)
            sys.exit(1)
            
    def _handle_packet(self, packet, queue):
        queue.put(packet)
        print "Recieved packet!", packet.show()
    
    def _forward_packet(self, pkt, iface):
        eth_header = pkt['Ethernet']
        # Map source port to interface
        # TODO: Handle multiple instances of one address
        hosts[eth_header.src] = iface

        # Check dictionary (if not a broadcast MAC) for mapping between destination and interface
        if eth_header.dst != "FF:FF:FF:FF:FF:FF":
            try:
                dst_iface = hosts[eth_header.dst]
                # If mapping is found, forward frame
                print "Sending packet!", packet.show()
                return sendp(pkt, iface=dst_iface)
            except KeyError:
                pass
        # Otherwise, broadcast to all interfaces except the one the frame
        # was received on
        for dst_iface in self.queues.keys():
            if dst_iface != iface:
                print "Sending packet!", packet.show()
                sendp(pkt, iface=dst_iface)
        return
        
    def switch_forever(self):
        # Switch forever
        while True:
            try:
                # For each interface, send a frame off the queue
                for iface, queue in self.queues.items():
                    # Send one frame off each non-empty queue
                    if not queue.empty():
                        self.forward_packet(queue.get(), iface)
                # Join any processes that may have terminated
                for iface, process in self.processes.items():
                    # Check if any interfaces crashed
                    process.join(None)
                    # If the interface process is dead, log it
                    if not process.is_alive:
                        print "Interface %s terminated unexpectedly"%(iface)
            except:
                print "Unexpected error:"
                traceback.print_exc(file=sys.stdout)
