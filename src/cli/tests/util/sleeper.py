import subprocess
import select

exe = "./tests/cli/program/sleeper"

class Proc:
    """Controls the program."""

    def __init__(self, process):
        self.process = process

    def stop(self):
        """Stops the program."""
        self.process.kill()
        self.process.wait()

    def pid(self):
        """Returns the process id (PID) of the program."""
        return self.process.pid

def run():
    """Runs the program and returns an object that can communicate with it."""
    process = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    return Proc(process)
