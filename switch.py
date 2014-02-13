# This file will simulate a switch.
from scapy.all import *
from multiprocessing import Process, Queue

class Switch:
    # Dictionary mapping interface names to frame queues
    queues = {}
    # List of active interface processes
    processes = []
    # Dictionary mapping destinations to interfaces
    hosts = {}

    def add_interface(self, iface):
        # Initialize frame queue and map to interface
        queue = Queue()
        queues[queue] = iface
        # Create process for sniffing interface
        proc = Process(target=self.start_switching, args=(iface,queue))
        # Add process to list
        processes.append(proc)
        # Start sniffing interface
        proc.start()

	def activate_interface(self, iface, queue):
	    # Sniff specified interface for Ethernet packets and put them
	    # into the queue
		sniff(filter="ether", prn=lambda(pkt):queue.put(pkt), iface=iface)
	
	def forward_packet(self, pkt, iface):
	    eth_header = pkt['Ethernet']
	    # Map source port to interface
	    # TODO: Handle multiple instances of one address
	    hosts[eth_header.src] = iface

	    # Check dictionary (if not a broadcast MAC) for mapping between destination and interface
	    if(eth_header.dst !="FF:FF:FF:FF:FF:FF"):
	        try:
	            dst_iface = hosts[eth_header.dst]
        	    # TODO: If mapping is found, forward frame
	    	    raise RuntimeError("Unimplimented")
	    	    return
            except KeyError:
                pass
        # TODO: Otherwise, broadcast to all interfaces except the one the frame
	    # was received on
	    raise RuntimeError("Unimplimented")
	    return
		
	def switch_forever(self):
	    # Switch forever
		while True:
		    # For each interface, send a frame off the queue
		    for queue, iface in queues:
		        # Send one frame off each non-empty queue
		        if not queue.empty()
		            self.forward_packet(queue.get(), iface)
            # Join any processes that may have terminated
            for process in processes:
                process.join(None)
		            
		
