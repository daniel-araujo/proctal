# Proctal 0.0.0

Proctal gives you access to the address space of a program on Linux with a
command line tool and a C API.

Features:
- Reading and writing values in memory
- Searching for values in memory
- Repeatedly writing a value to memory fast so as to make it seem like it's never changing
- Temporarily freezing main thread execution
- Detecting reads, writes and execution of memory addresses in main thread
- Disassembling instructions from any memory location
- Assembling instructions to write to any memory location
- Allocating and deallocating readable/writable/executable memory locations
- Stopping the normal flow of execution to run your own instructions
- Measure size of assembly instructions and values
- Byte pattern search
- Memory dump

Planned:
- Freezing all threads
- Watch points on all threads

> **Note**
>
> This is work in progress and as such the API is unstable and the
> documentation is done as an afterthought. This will change as the project
> matures.
>
> It's currently only tested on x86-64 Linux.


## Content

- [Example](#example)
- [Usage](#usage)
- [Installation](#installation)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)


## Example

Forces a program — whose Process ID (PID) is 15433 in this example — to print
Hello, world!

> **Note**
>
> Accessing sensitive parts of other processes most likely requires you to have
> higher privileges. Try running as root.

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
		fprintf(stderr, "Failed to create a Proctal handle.\n");
		return EXIT_FAILURE;
	}

	proctal_set_pid(p, 15433);

	void *allocated_memory = proctal_alloc(p, sizeof output, PROCTAL_ALLOC_PERM_READ);

	if (proctal_error(p)) {
		proctal_destroy(p);
		fprintf(stderr, "Failed to allocate memory in process %d.\n", proctal_pid(p));
		return EXIT_FAILURE;
	}

	proctal_write(p, allocated_memory, output, sizeof output);

	if (proctal_error(p)) {
		proctal_dealloc(p, allocated_memory);
		proctal_destroy(p);
		fprintf(stderr, "Failed to write to memory in process %d.\n", proctal_pid(p));
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
		fprintf(stderr, "Failed to execute code in process %d.\n", proctal_pid(p));
		return EXIT_FAILURE;
	}

	proctal_dealloc(p, allocated_memory);
	proctal_destroy(p);

	return EXIT_SUCCESS;
}
```


## Usage

### CLI

The command line interface consists of a group of commands that are passed to
the `proctal` program, like so:

	proctal COMMAND

If you execute `proctal` without a command, or pass it the `-h` option, it will
print help information which includes a list of all available commands.

Commands can also take options. Every command recognizes the `-h` option, which
will make it print help information related to it and then exit without doing
anything else.

For a complete overview of the functionality provided by the tool, you can read
the man page by running the following command:

	man 1 proctal


### C library

Can be used by linking to `libproctal` and including `proctal.h`

Functions, types and macros are documented in the header file.


## Installation

> **Note**
>
> If you have a clean state of the source repository you will need to follow
> some instructions given in the Development section.

Dependencies:

- GCC [[9]]
- libtool [[10]]
- capstone [[3]]
- keystone [[4]]

Proctal provides a 3 step installation process employed by many C/C++ programs
on Linux:

	$ ./configure

	$ make

	$ make install

The configure script checks whether your system meets the minimum necessary
requirements and allows you to define how you want Proctal to be compiled and
installed. For more information type `./configure -h`.

Read the INSTALL file for more details.


## Development

Besides requiring the same dependencies found in the Installation section, you
will also need:

- yuck [[5]]
- php [[6]]
- python [[11]]
- autoconf [[7]]
- automake [[8]]

Proctal uses the autotools to generate build systems for UNIX like operating
systems. This section will not go into too much detail but will show you how
you can create a development build to tinker with the source code.

First we need certain files and directories for the tools to work. Those can be
created by running the `autoreconf` command with the `-i` option in the root
directory of the project:

	$ autoreconf -i

You can now create a build. At this point you can follow the instructions in
the Installation section but as a developer you will most likely want to have
everything working from the project directory. You might even be interested in
working with different build settings, like having a release or a debug build.
This is actually possible. Here's how you would create and compile a build that
suppresses optimizations and adds debugging symbols.

	$ mkdir -p build/debug

	$ cd build/debug

	$ ../../configure 'CFLAGS=-g -O0'

	$ make

If you modify a source file and run `make` again it should detect the change
and compile again.

For more details on what else you can do with the autotools go read the manuals
over at gnu.org [[1]]


## Contributing

Found a bug or want to contribute code? Feel free to create an issue or send a
pull request on GitHub [[2]].

You can also report bugs privately to bugs@proctal.io.


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
[3]: http://www.capstone-engine.org/
[4]: http://www.keystone-engine.org/
[5]: http://www.fresse.org/yuck/
[6]: http://php.net/
[7]: https://www.gnu.org/software/autoconf/autoconf.html
[8]: https://www.gnu.org/software/automake/
[9]: https://gcc.gnu.org/
[10]: https://www.gnu.org/software/libtool/libtool.html
[11]: https://www.python.org/
