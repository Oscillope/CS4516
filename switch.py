# This file will simulate a switch.

from scapy.all import *

class Switch:
	def start_switching(self):
		sniff(filter="ether", prn=self.forward_packet)
		
	def forward_packet(self):
		pass
