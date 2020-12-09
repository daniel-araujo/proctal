import subprocess
import select

exe = "./util/spit-back-mt"

class Proc:
    """Controls the program."""
    def __init__(self, process):
        self.process = process

    def stop(self):
        """Stops the program."""
        self.process.terminate()
        self.process.wait()

    def ping(self):
        """Checks whether the program is responsive."""
        expected_response = "ping\n".encode()

        self.process.stdin.write(expected_response)
        self.process.stdin.flush()

        poll = select.poll()
        poll.register(self.process.stdout, select.POLLIN)

        if poll.poll(33):
            response = self.process.stdout.read(len(expected_response))
            return response == expected_response
        else:
            return False

    def pid(self):
        """Returns the process id (PID) of the program."""
        return self.process.pid

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

def run():
    """Runs the program and returns an object that can communicate with it."""
    process = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    return Proc(process)
