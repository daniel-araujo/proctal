# Proctal 0.0.0

Proctal provides a command line interface and a C library to manipulate the
address space of a running program on Linux.

Currently only tested on x86-64 Linux.

> **Note**
>
> This is work in progress and as such the API is unstable and the
> documentation is done as an afterthought. This will change as the project
> matures.

Features:
- Reading and writing values in memory
- Searching for values with a vast combination of filters
- Writing a value to memory repeatedly fast, essentially freezing it
- Temporarily freezing execution of a program's main thread
- Read, write and execution watch points on the main thread
- Disassembling instructions from any memory location
- Assembling instructions to write to any memory location
- Allocating and deallocating readable/writable/executable memory locations
- Arbitrary instruction execution

Planned:
- Byte pattern search
- Freezing all threads of execution
- Watch points on all threads of execution


## Example

Forces a program — whose Process ID (PID) is 15433 in this example — to print
Hello, world!

### CLI

```sh
# Allocates memory to store Hello, world!
$ proctal alloc --pid=15433 -rw 14
7f78fda9c000

# Writes Hello, world! to memory.
$ proctal write --pid=15433 --address=7f78fda9c000 --type=text H e l l o , ' ' w o r l d '!' $'\n'

# Executes code that will print Hello, world! to standard output.
$ proctal execute --pid=15433
	mov	rax, 1
	mov	rdi, 1
	mov	rsi, 0x7f78fda9c000
	mov	rdx, 14
	syscall

# Deallocates memory that was used to store Hello, world!
$ proctal dealloc --pid=15433 7f78fda9c000
```


### C library

```C
#include <stdlib.h>
#include <stdio.h>

#include <proctal.h>

int main (int argc, char **argv)
{
	const char output[] = "Hello, world!\n";
	char code[] = { 0x48, 0xbe, 0xDE, 0xAD, 0xBE, 0xFF, 0xDE, 0xAD, 0xBE, 0xFF, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc2, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05 };

	proctal p = proctal_create();

	if (proctal_error(p)) {
		proctal_destroy(p);
		fprintf(stderr, "Failed to create an instance of Proctal.\n");
		return EXIT_FAILURE;
	}

	proctal_set_pid(p, 15433);

	void *allocated_memory = proctal_alloc(p, sizeof output, PROCTAL_ALLOC_PERM_READ);

	if (proctal_error(p)) {
		proctal_destroy(p);
		fprintf(stderr, "Failed to allocate memory.\n");
		return EXIT_FAILURE;
	}

	proctal_write(p, allocated_memory, output, sizeof output);

	if (proctal_error(p)) {
		proctal_dealloc(p, allocated_memory);
		proctal_destroy(p);
		fprintf(stderr, "Failed to write to memory.\n");
		return EXIT_FAILURE;
	}

	code[2] = ((unsigned long long) allocated_memory >> 0x8 * 0) & 0xFF;
	code[3] = ((unsigned long long) allocated_memory >> 0x8 * 1) & 0xFF;
	code[4] = ((unsigned long long) allocated_memory >> 0x8 * 2) & 0xFF;
	code[5] = ((unsigned long long) allocated_memory >> 0x8 * 3) & 0xFF;
	code[6] = ((unsigned long long) allocated_memory >> 0x8 * 4) & 0xFF;
	code[7] = ((unsigned long long) allocated_memory >> 0x8 * 5) & 0xFF;
	code[8] = ((unsigned long long) allocated_memory >> 0x8 * 6) & 0xFF;
	code[9] = ((unsigned long long) allocated_memory >> 0x8 * 7) & 0xFF;

	proctal_execute(p, code, sizeof code);

	if (proctal_error(p)) {
		proctal_dealloc(p, allocated_memory);
		proctal_destroy(p);
		fprintf(stderr, "Failed to execute code.\n");
		return EXIT_FAILURE;
	}

	proctal_dealloc(p, allocated_memory);
	proctal_destroy(p);

	return EXIT_SUCCESS;
}
```


## Usage

### CLI

The command line interface can be used in the following ways:

	proctal read [--type=<type>] --pid=<pid> --address=<address>

	proctal write [--type=<type>] --pid=<pid> --address=<address> <value>

	proctal search [--type=<type>] [--eq=<val>] [--gt=<val>] [--gte=<val>]
		[--lt=<val>] [--lte=<val>] [--inc=<val>] [--dec=<val>]
		[--changed] [--unchanged] [--increased] [--decreased]
		[--input] --pid=<pid> --address=<address>

	proctal watch [--read] [--write] [--execute] --pid=<pid>
		--address=<address>

	proctal freeze [--input] --pid=<pid>

	proctal execute [--format=<format>]--pid=<pid>

	proctal alloc [--read] [--write] [--execute] --pid=<pid> <size>

	proctal dealloc --pid=<pid> <address>

For more details run `proctal -h` or read the man page:

	man 1 proctal


### C library

Can be used by linking to `libproctal` and including `proctal.h`

Functions, types and macros are documented in the header file.


## Installation

> **Note**
>
> If you have a clean state of the source repository you will need to
> prepare the build tools before you can start the installation process by
> running the following command:
>
> $ autoreconf -i

Proctal provides a 3 step installation process employed by many C/C++ programs
on Linux:

	$ ./configure

	$ make

	$ make install

The configure script allows you to define how you want Proctal to be compiled
and installed. For more information type `./configure -h`.


## Development

Proctal uses the autotools to generate build systems for UNIX like operating
systems. I will provide instructions on how to quickly create a development
build to tinker with the source code.

First you need to run `autoreconf` with the `-i` option in the project:

	$ autoreconf -i

You will notice that now there are new files and directories. These were
generated by `autoreconf` and can be ignored.

You can now generate a build. I recommend using different build directories for
different purposes. Here's how you can create a build that suppresses
optimizations and adds debugging symbols:

	$ mkdir -p build/debug

	$ cd build/debug

	$ ../../configure 'CFLAGS=-g -O0'

You can now start compiling by running the `make` command:

	$ make

If you modify a source file and run `make` again it should detect the change
and recompile again.

For more details on what you can do with the autotools read the manuals over at
gnu.org [[1]].


## Contributing

Found a bug or want to contribute code? Feel free to create an issue or send a
pull request on GitHub [[2]].


## License

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

[1]: https://www.gnu.org/software/
[2]: https://github.com/daniel-araujo/proctal
