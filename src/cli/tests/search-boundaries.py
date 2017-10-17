#!/usr/bin/env python3

import subprocess
import sys

proctal = "./proctal"
test_program = "./tests/cli/program/sleeper"

class TestCase:
    def __init__(self, value, length):
        self.value = value
        self.length = length
        pass

class IntValue:
    def __init__(self, value, bits=32):
        self.bits = bits
        self.value = value

    def type_options(self):
        return ["--type=integer", "--integer-bits=" + str(self.bits)]

    def parse(self, str):
        self.value = int(str)

    def __str__(self):
        return str(self.value)

    def copy(self):
        return IntValue(self.value, self.bits)

    def size(self):
        return self.bits / 8

    def cmp(self, other):
        if not self.bits == other.bits:
            raise ValueError("Not the same type.")

        if self.value > other.value:
            return 1
        elif self.value < other.value:
            return -1
        else: 
            return 0

class SearchMatch:
    def __init__(self, address, value):
        self.address = address
        self.value = value

def parse_address(s):
    return int(s, 16)

def format_address(s):
    return hex(int(s))[2:].upper()

def parse_matches(output, value):
    for line in output.decode("utf-8").splitlines():
        first_break = line.index(" ")

        address = line[:first_break]

        value = value.copy()
        value.parse(line[first_break + 1:])

        yield SearchMatch(parse_address(address), value)

class Error(Exception):
    pass

class UnexpectedMatchAddress(Error):
    def __init__(self, start, end, found):
        self.start = start
        self.end = end
        self.found = found

        message = "Expected to matches between {start} and {end} but got {found}.".format(
            start=format_address(self.start),
            end=format_address(self.end),
            found=format_address(self.found))

        super(Error, self).__init__(message)

class UnexpectedMatchValue(Error):
    def __init__(self, expected, found):
        self.expected = expected
        self.found = found

        message = "Expected to match {expected} but got {found}.".format(
            expected=str(self.expected),
            found=str(self.found))

        super(Error, self).__init__(message)

class UnexpectedTotalMatches(Error):
    def __init__(self, expected, found):
        self.expected = expected
        self.found = found

        message = "Expected {expected} matches but found {found}.".format(
            expected=self.expected,
            found=self.found)

        super(Error, self).__init__(message)

def start(test):
    guinea = subprocess.Popen([test_program], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    total_size = int(test.value.size() * test.length)

    address = subprocess.check_output([
        proctal,
        "allocate",
        "--pid=" + str(guinea.pid),
        str(total_size)
    ])
    address = address.strip().decode("utf-8")

    subprocess.call([
        proctal,
        "write",
        "--pid=" + str(guinea.pid),
        "--address=" + address,
        "--array=" + str(test.length),
    ] + test.value.type_options() + [str(test.value)])

    matches = subprocess.check_output([
            proctal,
            "search",
            "--pid=" + str(guinea.pid),
        ]
        + test.value.type_options()
        + [
            "--eq=" + str(test.value),
        ])

    start_address = parse_address(address)
    end_address = start_address + total_size
    found = 0

    for match in parse_matches(matches, test.value):
        if test.value.cmp(match.value) != 0:
            raise UnexpectedMatchValue(test.value, match.value)

        if not start_address <= match.address < end_address:
            raise UnexpectedMatchAddress(start_address, end_address, match.address)

        found += 1

    if test.length != found:
        raise UnexpectedTotalMatches(test.length, found)

    guinea.kill()

tests = [
    TestCase(IntValue(0x0ACC23AA), 4 / 4), # A byte.
    TestCase(IntValue(0x0ACC23AA), 1000 / 4), # A kilobyte.
    TestCase(IntValue(0x0ACC23AA), 1000000 / 4), # A megabyte.
]

for test in tests:
    start(test)
