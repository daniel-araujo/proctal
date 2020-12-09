from util import proctal_cli, sleeper

class Error(Exception):
    pass

class UnexpectedMatchAddress(Error):
    def __init__(self, start, end, found):
        self.start = start
        self.end = end
        self.found = found

        message = "Expected matches between {start} and {end} but got {found}.".format(
            start=str(self.start),
            end=str(self.end),
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

test_type = proctal_cli.TypeInteger(32);
test_value = proctal_cli.ValueInteger(test_type)
test_value.parse(0x7FDDCCAA)
test_pattern = "AA CC DD 7F"

with sleeper.run() as guinea:
    length = 10
    byte_length = length * test_value.size() 

    address = proctal_cli.allocate(guinea.pid(), byte_length)

    proctal_cli.write(guinea.pid(), address, test_type, test_value, array=length)

    start_address = address
    stop_address = start_address.clone()
    stop_address.add_address_offset(byte_length)

    def make_test_full_range():
        """Search entire range of addresses."""
        start = start_address.clone()
        end = stop_address.clone()

        return [start, end, length]

    def make_test_skip_first_value():
        """Start from the second value."""
        start = start_address.clone()
        start.add_address_offset(test_value.size())
        end = stop_address.clone()

        return [start, end, length - 1]

    def make_test_skip_last_value():
        """End on the second to last value."""
        start = start_address.clone()
        end = stop_address.clone()
        end.add_address_offset(-test_value.size())

        return [start, end, length - 1]

    def make_test_skip_first_and_last_values():
        """Start from the second value and end on the second to last value."""
        start = start_address.clone()
        start.add_address_offset(test_value.size())
        end = stop_address.clone()
        end.add_address_offset(-test_value.size())

        return [start, end, length - 2]

    def make_test_skip_first_value_half():
        """Start in the middle of the first value."""
        start = start_address.clone()
        start.add_address_offset(test_value.size() // 2)
        end = stop_address.clone()

        return [start, end, length - 1]

    def make_test_skip_last_value_half():
        """End in the middle of the last value."""
        start = start_address.clone()
        end = stop_address.clone()
        end.add_address_offset(-test_value.size() // 2)

        return [start, end, length - 1]

    tests = [
        make_test_full_range(),
        make_test_skip_first_value(),
        make_test_skip_last_value(),
        make_test_skip_first_and_last_values(),
        make_test_skip_first_value_half(),
        make_test_skip_last_value_half(),
    ]

    def run(start_address, stop_address, length):
        searcher = proctal_cli.pattern(
            guinea.pid(),
            test_pattern,
            address_start=start_address,
            address_stop=stop_address)

        found = 0

        for match in searcher.match_iterator():
            if not (start_address.cmp(match.address) <= 0 and stop_address.cmp(match.address) > 0):
                searcher.stop()
                raise UnexpectedMatchAddress(start_address, stop_address, match.address)

            found += 1

        searcher.stop()

        if length != found:
            raise UnexpectedTotalMatches(length, found)

    for test in tests:
        run(test[0], test[1], test[2])
