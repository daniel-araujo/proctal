#!/usr/bin/env python3

import sys
import time
from util import proctal_cli, read_mem

try:
    guinea = read_mem.run()

    watch_address = guinea.address()

    watcher = proctal_cli.watch(guinea.pid(), watch_address, watch="rw", unique=True)

    try:
        if not watcher.wait_match(100):
            sys.stderr.write("Was supposed to have at least 1 match.\n")
            exit(1)

        watcher.next_match()

        if watcher.wait_match(100):
            sys.stderr.write("Was not supposed to get more than 1 match.\n")
            exit(1)
    finally:
        watcher.stop()
finally:
    guinea.stop()
