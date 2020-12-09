from util import proctal_cli, read_mem

with read_mem.run() as guinea:
    watch_address = guinea.address()

    watcher = proctal_cli.watch(guinea.pid(), watch_address, watch="rw", unique=True)

    try:
        if not watcher.wait_match(100):
            exit("Was supposed to have at least 1 match.")

        watcher.next_match()

        if watcher.wait_match(100):
            exit("Was not supposed to get more than 1 match.")
    finally:
        watcher.stop()
