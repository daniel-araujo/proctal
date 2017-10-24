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
