#!/usr/bin/env python

from switch import Switch
from fancy_switch import FancySwitch

import sys

dev_string = ["eth1", "eth2", "eth3"]
#dev_string = ["eth0", "eth1", "eth2", "eth3"]

if len(sys.argv) == 1:
    s = Switch(dev_string)
else:
    if sys.argv[1] == 'std':
        s = Switch(dev_string)
    elif sys.argv[1] == 'adv':
        s = FancySwitch(dev_string)
    else:
        print('usage: \nstd: launch a stadard switch\nadv: launch one of our fancy switches')
        exit(1);
s.switch_forever()
