#!/usr/bin/env python3

import sys
from util import proctal_cli, sleeper

class TestCase:
    def __init__(self, type, value, length):
        self.type = type
        self.value = value
        self.length = length
        pass

class Error(Exception):
    pass

class UnexpectedMatchAddress(Error):
    def __init__(self, start, end, found):
        self.start = start
        self.end = end
        self.found = found

        message = "Expected to matches between {start} and {end} but got {found}.".format(
            start=str(self.start),
            end=str(self.end),
            found=str(self.found))

        super().__init__(message)

class UnexpectedMatchValue(Error):
    def __init__(self, expected, found):
        self.expected = expected
        self.found = found

        message = "Expected to match {expected} but got {found}.".format(
            expected=str(self.expected),
            found=str(self.found))

        super().__init__(message)

class UnexpectedTotalMatches(Error):
    def __init__(self, expected, found):
        self.expected = expected
        self.found = found

        message = "Expected {expected} matches but found {found}.".format(
            expected=self.expected,
            found=self.found)

        super().__init__(message)

def start(test):
    guinea = sleeper.run()

    total_size = int(test.value.size() * test.length)

    address = proctal_cli.allocate(guinea.pid(), str(total_size))

    proctal_cli.write(guinea.pid(), address, test.type, test.value, array=test.length)

    searcher = proctal_cli.search(guinea.pid(), test.type, eq=test.value)

    start_address = address
    end_address = start_address.clone()
    end_address.add_address_offset(total_size)
    found = 0

    for match in searcher.match_iterator():
        if test.value.cmp(match.value) != 0:
            guinea.stop()
            searcher.stop()
            raise UnexpectedMatchValue(test.value, match.value)

        if not (start_address.cmp(match.address) <= 0 and end_address.cmp(match.address) > 0):
            guinea.stop()
            searcher.stop()
            raise UnexpectedMatchAddress(start_address, end_address, match.address)

        found += 1

    searcher.stop()
    guinea.stop()

    if test.length != found:
        raise UnexpectedTotalMatches(test.length, found)

int32 = proctal_cli.TypeInteger(32);
int32_test_val = proctal_cli.ValueInteger(int32)
int32_test_val.parse(0x0ACC23AA)

tests = [
    TestCase(int32, int32_test_val, 4 // 4), # A single value.
    TestCase(int32, int32_test_val, 1000 // 4), # A kilobyte.
    TestCase(int32, int32_test_val, 1000000 // 4), # A megabyte.
]

for test in tests:
    start(test)
