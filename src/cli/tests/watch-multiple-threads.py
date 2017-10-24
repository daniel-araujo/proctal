#!/usr/bin/env python3

import sys
from util import proctal_cli, read_mem_mt

guinea = read_mem_mt.run()
watcher = proctal_cli.watch(guinea.pid(), guinea.address(), "rw")

if watcher == None:
    guinea.stop()
    exit(1)

if not watcher.has_match():
    sys.stderr.write("Was unable to watch for reads in a thread that is not the main one.\n")
    watcher.stop()
    guinea.stop()
    exit(1)

watcher.stop()
guinea.stop()
