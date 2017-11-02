#!/usr/bin/env python3

import sys
from util import proctal_cli, read_mem

try:
    guinea = read_mem.run()

    watch_address = guinea.address()

    watcher = proctal_cli.watch(guinea.pid(), watch_address, watch="rw", unique=True)

    try:
        if not watcher.wait_match(100):
            sys.stderr.write("Was supposed to have at least 1 match.\n")
            exit(1)
    finally:
        watcher.stop()

    # If a trap was not caught, the program will stop.
    guinea.wait_stop(100)

    if guinea.stopped():
        sys.stderr.write("Program died.\n")
        exit(1)
finally:
    guinea.stop()
