import subprocess
import select

exe = "./util/read-mem"

class Proc:
    """Controls the program."""

    def __init__(self, process):
        self.process = process
        self._address = self.process.stdout.readline().strip().decode("utf-8")

    def stop(self):
        """Stops the program."""
        self.process.terminate()
        self.process.wait()

    def stopped(self):
        """Stops whether the program has stopped."""
        self.process.poll()
        return self.process.returncode != None

    def wait_stop(self, timeout):
        """Waits for the program to stop."""
        try:
            self.process.wait(timeout / 1000)
        except subprocess.TimeoutExpired:
            return

    def address(self):
        """Returns the address of the variable that is being read."""
        return self._address

    def pid(self):
        """Returns the process id (PID) of the program."""
        return self.process.pid

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

def run():
    """Runs the program and returns an object that can communicate with it."""
    process = subprocess.Popen([exe], stdout=subprocess.PIPE)
    return Proc(process)
