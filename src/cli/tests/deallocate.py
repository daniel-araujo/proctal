from util import proctal_cli, sleeper

with sleeper.run() as guinea:
    int32 = proctal_cli.TypeInteger(32)
    test_value = proctal_cli.ValueInteger(int32)
    test_value.parse(0xFFAAFFAA)

    address = proctal_cli.allocate(guinea.pid(), test_value.size())

    proctal_cli.write(guinea.pid(), address, int32, test_value)

    proctal_cli.deallocate(guinea.pid(), address)

    searcher = proctal_cli.search(guinea.pid(), int32, eq=test_value)

    for match in searcher.match_iterator():
        if match.address.cmp(address) == 0:
            searcher.stop()
            exit("Memory block still seems accessible.")
            break

    searcher.stop()
