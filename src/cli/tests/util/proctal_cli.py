import subprocess
import select
import time
import sys

"""Provides wrapper functions that run cli commands and wrapper classes to
communicate with them.

Error messages are piped to stderr.
"""

proctal_exe = "./proctal"

class Type:
    """Base class that all types must inherit."""

    def type_options(self):
        return ["--type=" + self._type_name()] + self._type_options()

    def create_value(self):
        return self._create_value()

    def _type_name(self):
        raise NotImplementedError("Must return the name of the type.")

    def _create_value(self):
        raise NotImplementedError("Must create a new value.")

    def _type_options(self):
        return []

class TypeByte(Type):
    """Represents byte type."""

    def _type_name(self):
        return "byte"

    def _create_value(self):
        return ValueByte(self)

class TypeAddress(Type):
    """Represents address type."""

    def _type_name(self):
        return "address"

    def _create_value(self):
        return ValueAddress(self)

class TypeInteger(Type):
    """Represents integer type."""

    def __init__(self, bits=8):
        self._bits = bits

    def bits(self):
        return self._bits

    def _type_name(self):
        return "integer"

    def _type_options(self):
        return ["--integer-bits=" + str(self._bits)]

    def _create_value(self):
        return ValueInteger(self)

class Value:
    """Represents a value."""

    def format(self):
        raise NotImplementedError("Must format this value into a string.")

    def parse(self, s):
        raise NotImplementedError("Must parse a string.")

    def clone(self):
        raise NotImplementedError("Must create a copy of this value.")

    def size(self):
        raise NotImplementedError("Must return size of value in bytes.")

    def cmp(self, other):
        raise NotImplementedError("Must compare this value against another.")

    def __str__(self):
        return self.format()

class ValueAddress(Value):
    """Represents an address value."""

    def __init__(self, type):
        self._type = type
        self._value = 0

    def type(self):
        return self._type

    def parse(self, s):
        self._value = int(s, 16)

    def format(self):
        return hex(int(self._value))[2:].upper()

    def clone(self):
        other = ValueAddress(self._type)
        other._value = self._value
        return other

    def size(self):
        if sys.maxsize > 2**32:
            return 8
        else:
            return 4

    def cmp(self, other):
        if self._value > other._value:
            return 1
        elif self._value < other._value:
            return -1
        else:
            return 0

    def add_address_offset(self, offset):
        self._value = self._value + offset

class ValueInteger(Value):
    """Represents an integer value."""

    def __init__(self, type):
        self._type = type
        self._value = 0

    def type(self):
        return self._type

    def parse(self, s):
        self._value = int(s)

    def format(self):
        return str(self._value)

    def clone(self):
        other = ValueInteger(self.type)
        other._value = self._value
        return other

    def size(self):
        return self._type.bits() // 8

    def cmp(self, other):
        if not self._type.bits() == other._type.bits():
            raise ValueError("Not the same type.")

        if self._value > other._value:
            return 1
        elif self._value < other._value:
            return -1
        else:
            return 0

class FreezeProcess:
    """Controls the freeze command."""

    def __init__(self, process):
        self.process = process

    def stop(self):
        """Stops the freeze command."""
        self.process.kill()

def freeze(pid):
    """Runs the freeze command and returns an object that can control it."""
    cmd = [proctal_exe, "freeze", "--pid=" + str(pid)]

    process = subprocess.Popen(cmd)

    # Waiting for the freeze command to perform. We should probably figure out
    # a reliable way for it to tell us in some way when it has frozen the
    # program instead of guessing when. This will be the culprit of
    # false-positives.
    time.sleep(0.033)

    return FreezeProcess(process)

class WatchProcess:
    """Controls the watch command."""

    def __init__(self, process):
        self.process = process

    def has_match(self):
        """Checks whether the watch process has found a match."""
        poll = select.poll()
        poll.register(self.process.stdout, select.POLLIN)

        return poll.poll(100)

    def stop(self):
        """Stops the watch command."""
        self.process.kill()
        self.process.wait()

def watch(pid, address, permission="rw"):
    """Runs the watch command."""
    cmd = [
        proctal_exe,
        "watch",
        "--pid=" + str(pid),
        "--address=" + address,
        "-" + permission
    ]

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    # Waiting for the watch command to perform.
    # TODO: Find a reliable way to detect when the watcher has started.
    time.sleep(0.033)

    process.poll()

    if process.returncode != None:
        return None

    return WatchProcess(process)

class SearchMatch:
    """Represents a search match."""

    def __init__(self, address, value):
        self.address = address
        self.value = value

class SearchProcess:
    """Controls the search command."""

    def __init__(self, process, type):
        self.process = process
        self._type = type

    def match_iterator(self):
        address_type = TypeAddress()

        while True:
            line = self.process.stdout.readline().decode("utf-8")

            if line == '':
                # No more lines to read.
                break

            first_break = line.index(" ")

            address = ValueAddress(address_type)
            address.parse(line[:first_break])

            value = self._type.create_value()
            value.parse(line[first_break + 1:])

            yield SearchMatch(address, value)

    def stop(self):
        """Stops the command."""
        self.process.kill()
        self.process.wait()

def search(pid, type=TypeByte, eq=None, permission=None):
    """Runs the search command."""
    cmd = [
        proctal_exe,
        "search",
        "--pid=" + str(pid),
    ]
    cmd = cmd + type.type_options()

    if eq != None:
        cmd.append("--eq=" + str(eq))

    if permission != None:
        cmd.append("-" + str(permission))

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    process.poll()

    if process.returncode != None:
        return None

    return SearchProcess(process, type)

def allocate(pid, size, permission=None):
    """Runs the allocate command and returns the address."""

    cmd = [
        proctal_exe,
        "allocate",
        "--pid=" + str(pid),
        str(size)
    ]

    if permission != None:
        cmd.append("-" + str(permission))

    address = subprocess.check_output(cmd)
    address = address.strip().decode("utf-8")

    if not address:
        return None

    v = ValueAddress(TypeAddress())
    v.parse(address)

    return v

def write(pid, address, type, value, array=None):
    """Runs the write command."""

    cmd = [
        proctal_exe,
        "write",
        "--pid=" + str(pid),
        "--address=" + str(address),
    ]
    cmd = cmd + type.type_options()

    if isinstance(value, list):
        cmd = cmd + list(map(lambda v: str(v), value))
    else:
        cmd.append(str(value))

    if array != None:
        cmd.append("--array=" + str(array))

    code = subprocess.call(cmd)

    if code == 0:
        return True
    else:
        return False

def execute(pid, code):
    """Runs the execute command."""

    cmd = [
        proctal_exe,
        "execute",
        "--pid=" + str(pid),
    ]

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    process.communicate(input=code.encode())

    if process.returncode == 0:
        return True
    else:
        return False

class ReadProcess:
    """Controls the read command."""

    def __init__(self, process, type):
        self.process = process
        self._type = type

    def next_value(self):
        line = self.process.stdout.readline().decode("utf-8")

        if line == '':
            return None

        value = self._type.create_value()
        value.parse(line[:-1])

        return value

    def stop(self):
        """Stops the command."""
        self.process.kill()
        self.process.wait()

def read(pid, address, type, array=None):
    """Runs the read command."""

    cmd = [
        proctal_exe,
        "read",
        "--pid=" + str(pid),
        "--address=" + str(address),
    ]
    cmd = cmd + type.type_options()

    if array != None:
        cmd.append("--array=" + str(array))

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    return ReadProcess(process, type)
