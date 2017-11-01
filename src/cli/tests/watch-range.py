#!/usr/bin/env python3

import sys
from util import proctal_cli, read_mem

class Error(Exception):
    pass

class ExpectedMatch(Error):
    def __init__(self):
        super().__init__("Expected a match.")

class UnepectedMatch(Error):
    def __init__(self):
        super().__init__("Did not expect a match.")

guinea = read_mem.run()

try:
    watch_address = guinea.address()

    try:
        watcher = proctal_cli.watch(guinea.pid(), watch_address, watch="rw")

        if not watcher.wait_match(100):
            sys.stderr.write("Was unable to watch for reads.\n")
            exit(1)

        instruction_address = watcher.next_match().address;
    finally:
        watcher.stop()

    def make_smallest_range():
        """Smallest range of addresses."""
        start_address = instruction_address.clone()
        stop_address = instruction_address.clone()
        stop_address.add_address_offset(1)

        return [start_address, stop_address, True]

    tests = [
        make_smallest_range(),
    ]

    def run(start_address, stop_address, expect_match):
        watcher = proctal_cli.watch(
            guinea.pid(),
            watch_address,
            address_start=start_address,
            address_stop=stop_address,
            watch="rw")

        try:
            if watcher.wait_match(100):
                if not expect_match:
                    raise UnexpectedMatch() 
            else:
                if expect_match:
                    raise ExpectedMatch() 
        finally:
            watcher.stop()

    for test in tests:
            run(test[0], test[1], test[2])
finally:
    guinea.stop()
