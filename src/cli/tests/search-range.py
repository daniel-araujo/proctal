#!/usr/bin/env python3

import sys
from util import proctal_cli, sleeper

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

class LengthTest:
    def __init__(self, type, value, length, offset=0):
        self.type = type
        self.value = value
        self.length = length
        self.offset = offset
        pass

    def run(self):
        guinea = sleeper.run()

        total_length = self.length * self.value.size() 
        total_offset = self.offset * self.value.size()

        address = proctal_cli.allocate(guinea.pid(), total_offset + total_length)

        proctal_cli.write(guinea.pid(), address, self.type, self.value, array=self.offset + self.length)

        start_address = address
        start_address.add_address_offset(total_offset)
        stop_address = start_address.clone()
        stop_address.add_address_offset(total_length)

        searcher = proctal_cli.search(
            guinea.pid(),
            self.type,
            address_start=start_address,
            address_stop=stop_address,
            eq=test.value)

        found = 0

        for match in searcher.match_iterator():
            if self.value.cmp(match.value) != 0:
                guinea.stop()
                searcher.stop()
                raise UnexpectedMatchValue(match.value, self.value)

            if not (start_address.cmp(match.address) <= 0 and stop_address.cmp(match.address) > 0):
                guinea.stop()
                searcher.stop()
                raise UnexpectedMatchAddress(start_address, stop_address, match.address)

            found += 1

        searcher.stop()
        guinea.stop()

        if self.length != found:
            raise UnexpectedTotalMatches(self.length, found)

int32 = proctal_cli.TypeInteger(32);
int32_test_val = proctal_cli.ValueInteger(int32)
int32_test_val.parse(0x0ACC23AA)

tests = [
    LengthTest(int32, int32_test_val, 1),
    LengthTest(int32, int32_test_val, 2),
    LengthTest(int32, int32_test_val, 3),
    LengthTest(int32, int32_test_val, 4),
    LengthTest(int32, int32_test_val, 5),
    LengthTest(int32, int32_test_val, 5, offset=1),
    LengthTest(int32, int32_test_val, 100001),
]

for test in tests:
    test.run()
