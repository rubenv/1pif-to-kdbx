#!/usr/bin/env python

from pykeepass import PyKeePass

kp = PyKeePass("out.kdbx", password="test")
kp.dump_xml("out.xml")
