#!/usr/bin/env python3

import sys
from util import proctal_cli, read_mem_mt

guinea = read_mem_mt.run()

try:
    watcher = proctal_cli.watch(guinea.pid(), guinea.address(), "rw")

    try:
        if not watcher.wait_match(100):
            sys.stderr.write("Was unable to watch for reads in a thread that is not the main one.\n")
            exit(1)
    finally:
        watcher.stop()
finally:
    guinea.stop()
