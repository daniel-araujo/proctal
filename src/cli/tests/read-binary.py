#!/usr/bin/env python3

import sys
from util import proctal_cli, sleeper

class Error(Exception):
    pass

class TestSingleValue:
    def __init__(self, type, value):
        self.type = type
        self.value = value
        pass

    def run(self, guinea):
        address = proctal_cli.allocate(guinea.pid(), self.value.size())

        try:
            proctal_cli.write(guinea.pid(), address, self.type, self.value)
            reader = proctal_cli.read(guinea.pid(), address, self.type, binary=True)

            try:
                value = reader.next_value()

                if self.value.cmp(value) != 0:
                    raise Error("Expected {expected} but got {found}.".format(expected=self.value, found=value))
            finally:
                reader.stop()
        finally:
            proctal_cli.deallocate(guinea.pid(), address)

int32 = proctal_cli.TypeInteger(32);
int32_test_val = proctal_cli.ValueInteger(int32)
int32_test_val.parse(0x0ACC23AA)

tests = [
    TestSingleValue(int32, int32_test_val)
]

guinea = sleeper.run()

try:
    for test in tests:
        test.run(guinea)
finally:
    guinea.stop()
