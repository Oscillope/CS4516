#!/usr/bin/env python2

from switch import Switch

s = Switch(["eth0", "eth1"])

s.switch_forever()
