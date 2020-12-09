from util import proctal_cli, read_mem_mt

with read_mem_mt.run() as guinea:
    watcher = proctal_cli.watch(guinea.pid(), guinea.address(), "rw")

    try:
        if not watcher.wait_match(100):
            exit("Was unable to watch for reads in a thread that is not the main one.")
    finally:
        watcher.stop()
