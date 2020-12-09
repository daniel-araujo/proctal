from util import proctal_cli, spit_back_mt

with spit_back_mt.run() as guinea:
    if not guinea.ping():
        exit("Failed to communicate with guinea pig.")

    pauser = proctal_cli.pause(guinea.pid())

    if guinea.ping():
        pauser.stop()
        exit("Was not supposed to be able to communicate with guinea pig.")

    pauser.stop()
