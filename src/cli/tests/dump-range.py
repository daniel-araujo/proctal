#!/usr/bin/env python3

import sys
from util import proctal_cli, sleeper

class Error(Exception):
    pass

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
    def __init__(self, length, offset=0):
        self.length = length
        self.offset = offset
        pass

    def run(self):
        byte_type = proctal_cli.TypeByte();
        value = proctal_cli.ValueByte(byte_type)
        value.parse_binary(b'\x42')

        guinea = sleeper.run()

        address = proctal_cli.allocate(guinea.pid(), self.offset + self.length)
        address.add_address_offset(self.offset)

        proctal_cli.write(guinea.pid(), address, byte_type, value, array=self.length)

        start_address = address
        stop_address = start_address.clone()
        stop_address.add_address_offset(self.length)

        dumper = proctal_cli.dump(
            guinea.pid(),
            address_start=start_address,
            address_stop=stop_address)

        found = 0

        for match in dumper.byte_iterator():
            byte = proctal_cli.ValueByte(byte_type)
            byte.parse_binary(match)

            if value.cmp(byte) != 0:
                guinea.stop()
                dumper.stop()
                raise UnexpectedMatchValue(value, byte)

            found += 1

        dumper.stop()

        if self.length != found:
            guinea.stop()
            raise UnexpectedTotalMatches(self.length, found)

        guinea.stop()

tests = [
    LengthTest(1),
    LengthTest(2),
    LengthTest(3),
    LengthTest(4),
    LengthTest(5),
    LengthTest(5, offset=1),
    LengthTest(100001),
]

for test in tests:
    test.run()
