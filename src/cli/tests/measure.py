from util import proctal_cli

class Error(Exception):
    pass

class MeasureTest:
    def __init__(self, label, type, values, expected, array=None):
        self.label = label
        self.type = type
        self.values = values
        self.expected = expected
        self.array = array

    def run(self):
        found = proctal_cli.measure(self.type, self.values, array=self.array)

        if found != self.expected:
            raise Error("{label}: expected size {expected} but got {found}.".format(
                label=self.label,
                expected=self.expected,
                found=found))

byte_type = proctal_cli.TypeByte()
int32_type = proctal_cli.TypeInteger(32)
int64_type = proctal_cli.TypeInteger(64)

tests = [
    MeasureTest("single byte", byte_type, ["AA"], 1),
    MeasureTest("single 32-bit integer", int32_type, ["1"], 4),
    MeasureTest("single 64-bit integer", int64_type, ["1"], 8),
    MeasureTest("multiple values without array", int32_type, ["1", "2", "3"], 12),
    MeasureTest("array larger than values cycles through them", int32_type, ["1"], 20, array=5),
    MeasureTest("array larger than values cycles through multiple", int32_type, ["1", "2"], 12, array=3),
    MeasureTest("array smaller than values", int32_type, ["1", "2", "3"], 8, array=2),
]

for test in tests:
    test.run()
