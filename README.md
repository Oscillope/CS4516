CS 4516 Term Project
====================

Layer 2 Routing
---------------

The code in this project is used for the simulation of network topologies under various conditions. Our goal is to
design and test a "smart" switch that would allow redundant links using bandwidth sharing and be auto-configuring.
The implementation of a regular "dumb" switch can be found in switch.py. This implementation is used as a control
and is also extentended by fancy_switch.py (to be renamed later), the implementation of our device for simulation
purposes.

The code for generation and measurement of network traffic will also eventually be included.

To run our simulations, one must create a great deal of virtual machines, some of which will function as switches, and others of which will serve as the hosts.
The virtual machines that serve as switches do not need IP addresses, because they are functioning on raw ethernet data, however the host virtual machines will need some way of getting an IP, the easiest of which is probably to just assign static IPs.
The Switch VMs will need one virtual interface per connection to another machine, each of which will be point to point and shared only with one other VM.

The switches are run by running "main.py [switch type] [interface 1] [interface 2] ..." where there are at least two network interfaces specified, but there is no hard limit beyond the limits imposed by the machine being used.

Dependencies
	
	* Python2.7
    * pip (used to install dependencies from requirements.txt)
    * For all other dependencies, see requirements.txt
