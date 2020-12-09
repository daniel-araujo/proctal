from util import proctal_cli, read_mem

with read_mem.run() as guinea:
    watch_address = guinea.address()

    watcher = proctal_cli.watch(guinea.pid(), watch_address, watch="rw", unique=True)

    try:
        if not watcher.wait_match(100):
            exit("Was supposed to have at least 1 match.")
    finally:
        watcher.stop()

    # If a trap was not caught, the program will stop.
    guinea.wait_stop(200)

    if guinea.stopped():
        exit("Program died.")
