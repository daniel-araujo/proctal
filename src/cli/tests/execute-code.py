#!/usr/bin/env python3

import sys
from util import proctal_cli, sleeper

codes = {
    "x86-64": """
        mov rax, 0x{address}
        mov DWORD PTR [rax], {value}
    """
}

guinea = sleeper.run()
address = proctal_cli.allocate(guinea.pid(), 14)

type = proctal_cli.TypeInteger(bits=32)
value = proctal_cli.ValueInteger(type)
value.parse(0)

proctal_cli.write(guinea.pid(), address, type, value)

proctal_cli.execute(guinea.pid(), codes["x86-64"].format(address=str(address), value=1))

reader = proctal_cli.read(guinea.pid(), address, type)
read = reader.next_value()
reader.stop()

if read.cmp(value) == 0:
    sys.stderr.write("Value was not overwritten.\n")
    guinea.stop()
    exit(1)

guinea.stop()
