from util import proctal_cli, sleeper, algorithms

permission_flags = ["r", "w", "x"]

# All possible combinations.
possible_permissions = algorithms.all_combinations(permission_flags)
possible_permissions = map(lambda x: ''.join(x), possible_permissions)

with sleeper.run() as guinea:
    for flags in possible_permissions:
        int32 = proctal_cli.TypeInteger(32)
        test_value = proctal_cli.ValueInteger(int32)
        test_value.parse(0xFFAAFFAA)

        address = proctal_cli.allocate(guinea.pid(), test_value.size(), permission=flags)

        proctal_cli.write(guinea.pid(), address, int32, test_value)

        searcher = proctal_cli.search(guinea.pid(), int32, eq=test_value, permission=flags)

        found = False

        for match in searcher.match_iterator():
            if match.address.cmp(address) == 0:
                found = True
                break

        searcher.stop()

        if not found:
            exit("Could not allocate memory with the following permission flags: {flags}.".format(flags=flags))
