from util import proctal_cli, sleeper

codes = {
    "x86-64": """
        mov rax, 0x{address}
        mov DWORD PTR [rax], {value}
    """
}

with sleeper.run() as guinea:
    address = proctal_cli.allocate(guinea.pid(), 14)

    type = proctal_cli.TypeInteger(bits=32)
    value = proctal_cli.ValueInteger(type)
    value.parse(0)

    proctal_cli.write(guinea.pid(), address, type, value)

    if not proctal_cli.execute(guinea.pid(), codes["x86-64"].format(address=str(address), value=1)):
        exit("Execute command failed.")

    with proctal_cli.read(guinea.pid(), address, type) as reader:
        read = reader.next_value()

    if read.cmp(value) == 0:
        exit("Value was not overwritten.")
