import subprocess
import select
import time

proctal_exe = "./proctal"

class FreezeProcess:
    """Controls the freeze command."""

    def __init__(self, process):
        self.process = process

    def stop(self):
        """Stops the freeze command."""
        self.process.kill()

def freeze(pid):
    """Runs the freeze command and returns an object that can control it."""
    cmd = [proctal_exe, "freeze", "--pid=" + str(pid)]

    process = subprocess.Popen(cmd)

    # Waiting for the freeze command to perform. We should probably figure out
    # a reliable way for it to tell us in some way when it has frozen the
    # program instead of guessing when. This will be the culprit of
    # false-positives.
    time.sleep(0.033)

    return FreezeProcess(process)

class WatchProcess:
    """Controls the watch command."""

    def __init__(self, process):
        self.process = process

    def has_match(self):
        """Checks whether the watch process has found a match."""
        poll = select.poll()
        poll.register(self.process.stdout, select.POLLIN)

        return poll.poll(100)

    def stop(self):
        """Stops the watch command."""
        self.process.kill()
        self.process.wait()

def watch(pid, address, permission="rw"):
    """Runs the watch command."""
    cmd = [
        proctal_exe,
        "watch",
        "--pid=" + str(pid),
        "--address=" + address,
        "-" + permission
    ]

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    # Waiting for the watch command to perform.
    # TODO: Find a reliable way to detect when the watcher has started.
    time.sleep(0.033)

    process.poll()

    if process.returncode != None:
        return None

    return WatchProcess(process)
