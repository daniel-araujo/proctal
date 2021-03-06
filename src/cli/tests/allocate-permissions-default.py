from util import proctal_cli, sleeper, algorithms

with sleeper.run() as guinea:
    default_flags = "rwx"

    int32 = proctal_cli.TypeInteger(32)
    test_value = proctal_cli.ValueInteger(int32)
    test_value.parse(0xFFAAFFAA)

    address = proctal_cli.allocate(guinea.pid(), test_value.size())

    proctal_cli.write(guinea.pid(), address, int32, test_value)

    for flag in default_flags:
        searcher = proctal_cli.search(guinea.pid(), int32, eq=test_value, permission=flag)

        found = False

        for match in searcher.match_iterator():
            if match.address.cmp(address) == 0:
                found = True
                break

        searcher.stop()

        if not found:
            exit("Default allocate permissions is missing the {flag} flag.".format(flag=flag))
