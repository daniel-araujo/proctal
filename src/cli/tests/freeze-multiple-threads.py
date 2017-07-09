#!/usr/bin/env python3

import subprocess
import sys
import os
import select
import time

def make_freeze_cmd(pid):
    return ["./proctal", "freeze", "--pid=" + str(pid)]

def ping(process):
    expected_response = "ping\n".encode()

    process.stdin.write(expected_response)
    process.stdin.flush()

    poll = select.poll()
    poll.register(process.stdout, select.POLLIN)

    if poll.poll(33):
        response = process.stdout.read(len(expected_response))
        return response == expected_response
    else:
        return False


test_program = "./tests/cli/program/spit-back-mt"

guinea = subprocess.Popen([test_program], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

if not ping(guinea):
    sys.stderr.write("Failed to communicate with guinea pig.\n")
    guinea.kill()
    exit(1)

freezer = subprocess.Popen(make_freeze_cmd(guinea.pid))

# Waiting for the freeze command to perform. We should probably figure out a
# reliable way for it to tell us in some way when it has frozen the program
# instead of guessing when.
time.sleep(0.033)

if ping(guinea):
    sys.stderr.write("Was not supposed to be able to communicate with guinea pig.\n")
    freezer.kill()
    guinea.kill()
    exit(1)

freezer.kill()
guinea.kill()
