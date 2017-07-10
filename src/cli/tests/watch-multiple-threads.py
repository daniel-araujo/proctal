#!/usr/bin/env python3

import subprocess
import sys
import os
import select
import time

test_program = "./tests/cli/program/read-mem-mt"

guinea = subprocess.Popen([test_program], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
address = guinea.stdout.readline().strip().decode("utf-8")

watcher = subprocess.Popen(["./proctal", "watch", "--pid=" + str(guinea.pid), "--address=" + address, "-rw"], stdout=subprocess.PIPE)

# Waiting for the watch command to perform.
# TODO: Find a reliable way to detect when the watcher has started.
time.sleep(0.033)

watcher.poll()

if watcher.returncode != None:
    # With no output detected, we expect that an error message was printed
    # instead.
    guinea.kill()
    guinea.wait()
    exit(1)

poll = select.poll()
poll.register(watcher.stdout, select.POLLIN)

if not poll.poll(100):
    sys.stderr.write("Was unable to watch for reads in a thread that is not the main one.\n")
    watcher.kill()
    watcher.wait()
    guinea.kill()
    guinea.wait()
    exit(1)

watcher.kill()
watcher.wait()
guinea.kill()
guinea.wait()
