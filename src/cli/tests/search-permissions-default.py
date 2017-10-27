#!/usr/bin/env python3

import sys
from util import proctal_cli, sleeper

guinea = sleeper.run()

active_flags = "r"
inactive_flags = "wx"

int32 = proctal_cli.TypeInteger(32)
test_value = proctal_cli.ValueInteger(int32)
test_value.parse(0xFFAAFFAA)

for flag in active_flags:
    address = proctal_cli.allocate(guinea.pid(), test_value.size(), permission=flag)

    proctal_cli.write(guinea.pid(), address, int32, test_value)

    searcher = proctal_cli.search(guinea.pid(), int32, eq=test_value)

    found = False

    for match in searcher.match_iterator():
        if match.address.cmp(address) == 0:
            found = True

    if not found:
        sys.stderr.write("Default search permissions is missing the {flag} flag.\n".format(flag=flag))
        searcher.stop()
        guinea.stop()
        exit(1)

for flag in inactive_flags:
    address = proctal_cli.allocate(guinea.pid(), test_value.size(), permission=flag)

    proctal_cli.write(guinea.pid(), address, int32, test_value)

    searcher = proctal_cli.search(guinea.pid(), int32, eq=test_value)

    for match in searcher.match_iterator():
        if match.address.cmp(address) == 0:
            sys.stderr.write("Default search permissions should not have the {flag} flag.\n".format(flag=flag))
            searcher.stop()
            guinea.stop()
            exit(1)

searcher.stop()
guinea.stop()
