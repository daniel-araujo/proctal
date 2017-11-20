#!/usr/bin/env python3

import subprocess
import sys

proctal = "./proctal"

common_base_commands = [
    [proctal, "read", "--pid=1", "--address=1"],
    [proctal, "write", "--pid=1", "--address=1", "1"],
    [proctal, "search", "--pid=1"],
    [proctal, "measure", "--address=1", "1"],
]

common_tests = [
    {
        "command_args": ["--type=unknown"],
        "expected_output": "Invalid type.",
    },
    {
        "command_args": ["--type=integer", "--integer-endianness=litle"],
        "expected_output": "Invalid integer endianness.",
    },
    {
        "command_args": ["--type=integer", "--integer-bits=1"],
        "expected_output": "Invalid integer size.",
    },
    {
        "command_args": ["--type=integer", "--integer-sign=2scompl"],
        "expected_output": "Invalid integer sign.",
    },
    {
        "command_args": ["--type=ieee754", "--ieee754-precision=4"],
        "expected_output": "Invalid ieee754 precision.",
    },
    {
        "command_args": ["--type=text", "--text-encoding=utf8"],
        "expected_output": "Invalid text encoding.",
    },
    {
        "command_args": ["--type=x86", "--x86-mode=8"],
        "expected_output": "Invalid x86 mode.",
    },
    {
        "command_args": ["--type=x86", "--x86-syntax=attt"],
        "expected_output": "Invalid x86 syntax.",
    },
]

tests = [
    {
        "command": [proctal, "execute", "--pid=1", "--format=english"],
        "expected_output": "Invalid input format.",
    },
]

for common_base_command in common_base_commands:
    for common_test in common_tests:
        tests.append({
            "command": common_base_command + common_test["command_args"],
            "expected_output": common_test["expected_output"],
        })

for test in tests:
    try:
        output = subprocess.check_output(test["command"], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        output = e.output

    output = output.decode("utf-8")

    if not test["expected_output"] in output:
        sys.stderr.write("Command '" + ' '.join(test["command"]) + "' output was:\n")
        sys.stderr.write(output)
        sys.stderr.write("\n")
        sys.stderr.write("But was expecting:\n")
        sys.stderr.write(test["expected_output"])
        sys.stderr.write("\n")
        exit(1)
