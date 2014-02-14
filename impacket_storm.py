# Bring everything together.

from impacket import ImpactDecoder, ImpactPacket

## Import various python built in modules needed to process text, open
## sockets, search through text with regexp,  and run system commands.
import socket, impacket, string, sys, commands, re, os
from struct import *

def makepacket():
	ethernet = ImpactPacket.Ethernet()
	ethernet.set_ether_dhost([0xFF,0xFF,0xFF,0xFF,0xFF,0xFF])
	ethernet.set_ether_shost([0x00,0x00,0x00,0x00,0x00,0x00])
	ethernet.set_ether_type(0x01FF)
	
	return ethernet.get_packet()

packet = makepacket()
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("eth0", 0x01FF))

while True:
	s.send(packet)
