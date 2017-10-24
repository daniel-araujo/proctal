#!/usr/bin/env python3

import sys
from util import proctal_cli, spit_back_mt

guinea = spit_back_mt.run()

if not guinea.ping():
    sys.stderr.write("Failed to communicate with guinea pig.\n")
    guinea.stop()
    exit(1)

freezer = proctal_cli.freeze(guinea.pid())

if guinea.ping():
    sys.stderr.write("Was not supposed to be able to communicate with guinea pig.\n")
    freezer.stop()
    guinea.stop()
    exit(1)

freezer.stop()
guinea.stop()
