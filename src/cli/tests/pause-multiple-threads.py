#!/usr/bin/env python3

import sys
from util import proctal_cli, spit_back_mt

guinea = spit_back_mt.run()

if not guinea.ping():
    sys.stderr.write("Failed to communicate with guinea pig.\n")
    guinea.stop()
    exit(1)

pauser = proctal_cli.pause(guinea.pid())

if guinea.ping():
    sys.stderr.write("Was not supposed to be able to communicate with guinea pig.\n")
    pauser.stop()
    guinea.stop()
    exit(1)

pauser.stop()
guinea.stop()
