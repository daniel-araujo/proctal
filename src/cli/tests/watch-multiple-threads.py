#!/usr/bin/env python3

import subprocess
import sys
import os
import select
import time

test_program = "./tests/cli/program/read-mem-mt"

guinea = subprocess.Popen([test_program], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

address = guinea.stdout.readline()
address = str(address).strip()

watcher = subprocess.Popen(["./proctal", "watch", "--pid=" + str(guinea.pid), "--address=" + address, "-rw"], stdout=subprocess.PIPE)

poll = select.poll()
poll.register(watcher.stdout, select.POLLIN)

if not poll.poll(33):
    sys.stderr.write("Was unable to watch for memory read access in a thread other than the main one.\n")
    watcher.kill()
    guinea.kill()
    exit(1)

watcher.kill()
guinea.kill()
