#!/usr/bin/env python2

from switch import Switch

s = Switch(["eth0", "wlan0"])

s.switch_forever()
