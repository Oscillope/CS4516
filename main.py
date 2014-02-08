# Bring everything together.


import socket, string, sys, re, os
from impacket import ImpactDecoder, ImpactPacket

from struct import *

def makepacket():
	ethernet = ImpactPacket.Ethernet()
	ethernet.set_ether_dhost([0xFF,0xFF,0xFF,0xFF,0xFF,0xFF])
	ethernet.set_ether_shost([0x00,0x00,0x00,0x00,0x00,0x00])
	ethernet.set_ether_type(0x01FF)
	ethernet.contains("Hello, world!")
	return ethernet.get_packet()

packet = makepacket()
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("eth0", 0x01FF))

while True:
	s.send(packet)
