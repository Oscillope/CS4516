# This file will simulate a switch.
import pcapy
from scapy.all import *
import threading
from killable_thread import Thread
from Queue import Queue
import sys, traceback, logging, time
from datetime import datetime
from stopwatch import Stopwatch

logging.getLogger("scapy").setLevel(logging.ERROR)

class Interface(object):
    incoming = None
    name = None
    process = None
    
    def __init__(self, name):
        self.incoming = Queue(maxsize=1000)
        self.name = name
        self.has_data = threading.Semaphore(0)

    def activate(self):
        self.run()
            
    def deactivate(self):
        self._listener.terminate()
            
    def send(self, pkt):
        self._write_packet(str(pkt))
        self.has_data.release()

    def _write_packet(self, pkt):
        # Wait for interface to be free, then lock it to write
        self._iface_lock.acquire(blocking=1)
        sendp(pkt, iface=self.name, verbose=False)
        self._iface_lock.release()

    def _handle_packet(self, hdr, frame):
        # If not writing, then put frame in queue, otherwise drop it
        if self._iface_lock.acquire(blocking=0):
            self.incoming.put(str(frame))
            self._iface_lock.release()

    def _listen(self, sniffer):
        try:
            sniffer.loop(-1, self._handle_packet)
        except (KeyboardInterrupt, SystemExit):
            thread.interrupt_main()
            print "%s listener terminating..."%(self.name)
            thread.exit()

    def run(self):
        try:
            sniffer = pcapy.open_live(self.name, 2500, True, 100)
            self._iface_lock = threading.RLock()
            self._listener = Thread(target=self._listen, args=(sniffer,))
            self._listener.start()
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
    # For metric purposes
    watch = Stopwatch()
    # Moving average of broadcast traffic
    average = None
    # Moving average weight for new packets
    NEW_PACKET_WEIGHT = 0.1
    

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
        
    def _process_packet(self, pkt, iface):
        # Map source port to interface
        if not pkt.src in self.hosts:
            self.hosts[pkt.src] = iface
            print "Found host %s on interface %s " %(pkt.src, iface)
        # Check dictionary (if not a broadcast MAC) for mapping between destination and interface
        if pkt.dst != "ff:ff:ff:ff:ff:ff":
            try:
                dst_iface = self.hosts[pkt.dst]
                if iface == dst_iface:
                    return []
                # If mapping is found, forward frame on interface
                #print "%s -> %s on %s -> %s" %(pkt.src, pkt.dst, iface, dst_iface)
                # This process is now done with this packet
                return [dst_iface]
            except KeyError:
                pass
        # Otherwise, broadcast to all interfaces except the one the frame
        # was received on
        # print "%s -> %s on %s (bcast)" %(pkt.src, pkt.dst, iface)
        return filter(lambda x: x != iface, self.interfaces)
                
    
    def _forward_packet(self, pkt, ifaces):
        for dst_iface in ifaces:
            dst_iface.send(pkt)
    
    def switch_forever(self):
        logfile = open('broadcast_percent_%s.dat' %(str(datetime.now())), 'w')
        # Start up interface
        for iface in self.interfaces:
            iface.activate()
        # Switch forever
        try:
            while True:
                # For each interface, send a frame off the queue
                for iface in self.interfaces:
                    queue = iface.incoming
                    # Send one frame off each non-empty queue
                    if not queue.empty():
                        pkt = Ether(queue.get())
                        dst_ifaces = self._process_packet(pkt, iface)
                        if len(dst_ifaces) == 1:
                            if self.average is None:
                                self.average = 0
                                self.watch.start()
                            else:
                                self.average *= 1 - self.NEW_PACKET_WEIGHT
                        elif len(dst_ifaces) > 1:
                            if self.average is None:
                                self.average = 1
                                self.watch.start()
                            else:
                                self.average *= 1 - self.NEW_PACKET_WEIGHT
                                self.average += self.NEW_PACKET_WEIGHT
                        curtime = self.watch.gettime()
                        logfile.write("%d %f\n" %(curtime, self.average))
                        self._forward_packet(pkt, dst_ifaces)
        except IndexError:
            pass
        except KeyboardInterrupt:
            print "Keyboard interrupt detected!"
            logfile.close()
            print "Closed logfile."
            for iface in self.interfaces:
                iface.deactivate()
            print "Exiting..."
            sys.exit(0)
        except:
            print "Unexpected error:"
            traceback.print_exc(file=sys.stdout)
