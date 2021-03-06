import subprocess
import select
import time
import sys

"""Provides wrapper functions that run cli commands and wrapper classes to
communicate with them.

Error messages are piped to stderr.
"""

proctal_exe = "../proctal"

class Error(Exception):
    pass

class StopError(Error):
    """Raised when the process is not running but was expected to be."""

    def __init__(self):
        super().__init__("Proctal is not running.")

class ParseError(Error):
    """Raised when failing to parse a value."""

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

    def data(self):
        raise NotImplementedError("Must return an array of bytes that represents the value in binary.")

    def parse(self, s):
        raise NotImplementedError("Must parse a string.")

    def parse_binary(self, s):
        raise NotImplementedError("Must parse a sequence of bytes.")

    def clone(self):
        raise NotImplementedError("Must create a copy of this value.")

    def size(self):
        raise NotImplementedError("Must return size of value in bytes.")

    def cmp(self, other):
        raise NotImplementedError("Must compare this value against another.")

    def __str__(self):
        return self.format()

class ValueByte(Value):
    """Represents a byte value."""

    def __init__(self, type):
        self._type = type
        self._value = 0

    def type(self):
        return self._type

    def parse(self, s):
        self._value = int(s, 16)

    def parse_binary(self, s):
        self._value = s[0]

    def format(self):
        return hex(int(self._value))[2:].upper()

    def data(self):
        return self._value.to_bytes(self.size(), byteorder='little', signed=False)

    def clone(self):
        other = ValueAddress(self._type)
        other._value = self._value
        return other

    def size(self):
        return 1

    def cmp(self, other):
        if self._value > other._value:
            return 1
        elif self._value < other._value:
            return -1
        else:
            return 0

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

    def data(self):
        return self._value.to_bytes(self.size(), byteorder='little', signed=False)

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

    def parse_binary(self, s):
        size = self.size()

        if len(s) < size:
            raise ParseError("Expecting at least {expected} bytes.".format(expected=size))

        data = s[:size]
        del s[:size]

        self._value = int.from_bytes(data, byteorder='little', signed=True)

    def data(self):
        return self._value.to_bytes(self.size(), byteorder='little', signed=False)

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

class Process:
    def __init__(self, process):
        self._process = process

    def _assert_running(self):
        """Asserts that the process is still running."""
        self._process.poll()

        if self._process.returncode != None:
            raise StopError()

    def stop(self):
        """Stops the command."""
        self._process.terminate()
        self._process.wait()

    def exit_code(self):
        """Returns the exit code if the process has quit.
        If the process is still running it will return None."""
        return self._process.returncode

    def has_stopped(self):
        """Returns True if the process has stopped, False otherwise."""
        return self.exit_code() != None

class PauseProcess(Process):
    """Controls the pause command."""

    def __init__(self, process):
        super().__init__(process)

class WatchProcess(Process):
    """Controls the watch command."""

    def __init__(self, process):
        super().__init__(process)
        self.poll = select.poll()
        self.poll.register(self._process.stdout, select.POLLIN)

    def wait_match(self, timeout):
        """Waits for the watch process to report a match."""
        self._assert_running()

        r = self.poll.poll(timeout)

        if not r:
            return False

        return any([i[1] == select.POLLIN for i in r])

    def next_match(self):
        """Reads the next available match."""
        self._assert_running()

        address_type = TypeAddress()

        line = self._process.stdout.readline().decode("utf-8")

        if line == '':
            # No more lines to read.
            return None

        address = ValueAddress(address_type)
        address.parse(line[:-1])

        return SearchMatch(address, None)

class SearchMatch:
    """Represents a search match."""

    def __init__(self, address, value):
        self.address = address
        self.value = value

class SearchProcess(Process):
    """Controls the search command."""

    def __init__(self, process, type):
        super().__init__(process)
        self._type = type

    def match_iterator(self):
        """An iterator that goes through all the matches that are currently
        available."""
        self._assert_running()

        address_type = TypeAddress()

        while True:
            line = self._process.stdout.readline().decode("utf-8")

            if line == '':
                # No more lines to read.
                break

            first_break = line.index(" ")

            address = ValueAddress(address_type)
            address.parse(line[:first_break])

            value = self._type.create_value()
            value.parse(line[first_break + 1:])

            yield SearchMatch(address, value)

class PatternProcess(Process):
    """Controls the pattern command."""

    def __init__(self, process):
        super().__init__(process)

    def match_iterator(self):
        """An iterator that goes through all the matches that are currently
        available."""
        self._assert_running()

        address_type = TypeAddress()

        while True:
            line = self._process.stdout.readline().decode("utf-8")

            if line == '':
                # No more lines to read.
                break

            address = ValueAddress(address_type)
            address.parse(line[:-1])

            yield SearchMatch(address, None)

class ReadProcess(Process):
    """Controls the read command."""

    def __init__(self, process, type):
        super().__init__(process)
        self._type = type

    def next_value(self):
        """Gets the next available value."""
        self._assert_running()

        line = self._process.stdout.readline().decode("utf-8")

        if line == '':
            return None

        value = self._type.create_value()
        value.parse(line[:-1])

        return value

class ReadBinaryProcess(Process):
    """Controls the read command with the binary option."""

    def __init__(self, process, type):
        super().__init__(process)
        self._type = type
        self._buffer = bytearray()

    def next_value(self):
        """Gets the next available value."""
        self._assert_running()

        self._buffer.extend(self._process.stdout.read(16));

        value = self._type.create_value()
        value.parse_binary(self._buffer)

        return value

class DumpProcess(Process):
    """Controls the dump command."""

    def __init__(self, process):
        super().__init__(process)

    def byte_iterator(self):
        """Iterates over every byte that is being dumped."""
        self._assert_running()

        poll = select.poll()
        poll.register(self._process.stdout, select.POLLIN)

        while True:
            if not poll.poll(33):
                break

            byte = self._process.stdout.read(1)

            if len(byte) == 0:
                break

            yield byte

class WriteBinaryProcess(Process):
    """Controls the write command with the binary option."""

    def __init__(self, process):
        super().__init__(process)
        self._buffer = bytearray()

    def write_value(self, value):
        """Sends a value to be written."""
        self._buffer.extend(value.data());

    def stop(self):
        """Flushes the output and stops the command."""
        if not self.has_stopped():
            self._process.communicate(input=self._buffer)

        super().stop()

def pause(pid):
    """Runs the pause command and returns an object that can control it."""
    cmd = [proctal_exe, "pause", "--pid=" + str(pid)]

    process = subprocess.Popen(cmd)

    # Waiting for the pause command to perform. We should probably figure out
    # a reliable way for it to tell us in some way when it has paused the
    # program instead of guessing when. This will be the culprit of
    # false-positives.
    time.sleep(0.033)

    return PauseProcess(process)

def watch(pid, address, watch=None, address_start=None, address_stop=None, unique=None):
    """Runs the watch command."""
    cmd = [
        proctal_exe,
        "watch",
        "--pid=" + str(pid),
        str(address),
    ]

    if watch != None:
        cmd.append("-" + str(watch))

    if address_start != None:
        cmd.append("--address-start=" + str(address_start))

    if address_stop != None:
        cmd.append("--address-stop=" + str(address_stop))

    if unique:
        cmd.append("--unique")

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    process.poll()

    if process.returncode != None:
        return None

    return WatchProcess(process)

def search(pid, type=TypeByte, eq=None, permission=None, address_start=None, address_stop=None, review=None):
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

    if address_start != None:
        cmd.append("--address-start=" + str(address_start))

    if address_stop != None:
        cmd.append("--address-stop=" + str(address_stop))

    if review != None:
        cmd.append("--review")

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    if review != None:
        for match in review:
            match_line = match.address.format() + " " + match.value.format() + "\n"
            process.stdin.write(match_line.encode())
        process.stdin.close()

    process.poll()

    if process.returncode != None:
        return None

    return SearchProcess(process, type)

def pattern(pid, pattern, permission=None, address_start=None, address_stop=None):
    """Runs the pattern command."""
    cmd = [
        proctal_exe,
        "pattern",
        "--pid=" + str(pid),
        pattern
    ]

    if permission != None:
        cmd.append("-" + str(permission))

    if address_start != None:
        cmd.append("--address-start=" + str(address_start))

    if address_stop != None:
        cmd.append("--address-stop=" + str(address_stop))

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    process.poll()

    if process.returncode != None:
        return None

    return PatternProcess(process)

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

def deallocate(pid, address):
    """Runs the deallocate command."""

    cmd = [
        proctal_exe,
        "deallocate",
        "--pid=" + str(pid),
        str(address)
    ]

    code = subprocess.call(cmd)

    if code == 0:
        return True
    else:
        return False

def write(pid, address, type, value=None, array=None, binary=False):
    """Runs the write command."""

    cmd = [
        proctal_exe,
        "write",
        "--pid=" + str(pid),
        "--address=" + str(address),
    ]
    cmd = cmd + type.type_options()

    if binary:
        cmd.append("--binary")

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE)

        process.poll()

        if process.returncode != None:
            return False

        return WriteBinaryProcess(process)
    else:
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

def read(pid, address, type, array=None, binary=False):
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

    if binary:
        cmd.append("--binary")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        return ReadBinaryProcess(process, type)
    else:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        return ReadProcess(process, type)

def dump(pid, permission=None, address_start=None, address_stop=None):
    """Runs the dump command."""
    cmd = [
        proctal_exe,
        "dump",
        "--pid=" + str(pid),
    ]

    if address_start != None:
        cmd.append("--address-start=" + str(address_start))

    if address_stop != None:
        cmd.append("--address-stop=" + str(address_stop))

    if permission != None:
        cmd.append("-" + str(permission))

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    process.poll()

    if process.returncode != None:
        return None

    return DumpProcess(process)
