# This file will simulate a switch.
import pcapy
from scapy.all import *
from threading import Thread, RLock, Semaphore
from Queue import Queue
import sys, traceback, logging, time

logging.getLogger("scapy").setLevel(logging.ERROR)

class Interface(object):
    incoming = None
    outgoing = None
    name = None
    process = None
    
    def __init__(self, name):
        self.incoming = Queue()
        self.outgoing = Queue()
        self.name = name
        self.process = Thread(target=self.run)
        self.has_data = Semaphore(0)
        self.writing = Semaphore(0)

    def activate(self):
        self.process.start()

    #~ def deactivate(self):
        #~ try:
            #~ self.process.terminate()
            #~ self.process.join()
        #~ except:
            #~ print "Problem deactivating interface:"
            #~ traceback.print_exc(file=sys.stdout)
            
    def send(self, pkt):
        self.outgoing.put(str(pkt))
        self.has_data.release()

    def _write_packet(self, pkt):
        # Wait for interface to be free, then lock it to write
        #print "%s queue size %d" %(self.name, self.outgoing.qsize())
        #sys.stdout.flush()
        print ""
        self._iface_lock.acquire(blocking=1)
        sendp(pkt, iface=self.name, verbose=False)
        self._iface_lock.release()
        self.writing.release()

    def _handle_packet(self, hdr, frame):
        # If not writing, then put frame in queue, otherwise drop it
        if self._iface_lock.acquire(blocking=0):
            self.incoming.put(str(frame))
            self._iface_lock.release()

    def run(self):
        try:
            sniffer = pcapy.open_live(self.name, 2500, True, 100)
            self._listener = Thread(target=sniffer.loop, args=(-1, self._handle_packet))
            self._iface_lock = RLock()
            self._listener.start()
            # TODO: send outgoing packets waiting in queue
            while True:
                self.has_data.acquire()
                if not self.outgoing.empty():
                    self._write_packet(Ether(self.outgoing.get()))
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
        return interface
    
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
                #print "%s -> %s on %s -> %s" %(eth_header.src, eth_header.dst, iface, dst_iface)
                dst_iface.send(pkt)
                dst_iface.writing.acquire()
                # This process is now done with this packet
                return
            except KeyError:
                pass
        # Otherwise, broadcast to all interfaces except the one the frame
        # was received on
        for dst_iface in self.interfaces:
            if dst_iface != iface:
                #print "%s -> %s (bcast) on %s -> %s" %(eth_header.src, eth_header.dst, iface, dst_iface)
                dst_iface.send(pkt)
                dst_iface.writing.acquire()
    
    def switch_forever(self):
        # Start up interface
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
                #~ for iface in self.interfaces:
                    #~ iface.deactivate()
                sys.exit(0)
            except:
                print "Unexpected error:"
                traceback.print_exc(file=sys.stdout)
