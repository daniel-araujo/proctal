from util import proctal_cli, sleeper

with sleeper.run() as guinea:
    address = proctal_cli.ValueAddress(proctal_cli.TypeAddress())
    address.parse("1")

    if proctal_cli.deallocate(guinea.pid(), address):
        exit("Deallocating an address that was never allocated should have failed.")
