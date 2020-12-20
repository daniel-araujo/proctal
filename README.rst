=========
 Proctal
=========

https://proctal.io

A tool for modding programs on Linux at runtime. Provides a CLI and a C library.

**Features:**

- Reading and writing to memory

- Searching for values and byte patterns

- Pausing program execution

- Watching for accesses to memory locations

- Allocating and deallocating memory blocks

- Assembling and disassembling instructions

- Running your own code in the context of the program

- Dumping contents in memory

..

	**Note**

	This is work in progress. It's currently only tested on x86-64 Linux.


.. contents::


Example
=======

This example forces a program — whose Process ID (PID) is 15433 — to print
Hello, world!

	**Note**

	Accessing sensitive parts of other processes most likely requires you
	to have higher privileges. Try running as root.

**CLI**

.. code :: sh

	# Allocates memory to store Hello, world!
	$ proctal allocate --pid=15433 -rw 14
	7F78FDA9C000

	# Writes Hello, world! to memory.
	$ proctal write --pid=15433 --address=7F78FDA9C000 --type=text 'Hello, world!' $'\n'

	# Executes code that will print Hello, world! to standard output.
	$ proctal execute --pid=15433
		mov	rsi, 0x7F78FDA9C000
		mov	rdx, 14
		mov	rdi, 1
		mov	rax, 1
		syscall

	# Deallocates memory that was used to store Hello, world!
	$ proctal deallocate --pid=15433 7F78FDA9C000

**API**

.. code :: C

	#include <stdlib.h>
	#include <stdint.h>
	#include <stdio.h>

	#include <proctal.h>

	int main (int argc, char **argv)
	{
		const char output[] = "Hello, world!\n";
		char code[] = {
			// mov rsi, <address>
			0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// mov rax, 1
			0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
			// mov rdx, 14
			0x48, 0xc7, 0xc2, 0x0e, 0x00, 0x00, 0x00,
			// mov rdi, 1
			0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
			// syscall
			0x0f, 0x05
		};

		proctal_t proctal = proctal_open();

		if (proctal_error(proctal)) {
			fprintf(stderr, "Failed to open Proctal.\n");
			proctal_close(proctal);
			return EXIT_FAILURE;
		}

		proctal_pid_set(proctal, 15433);

		void *allocated_memory = proctal_allocate(proctal, sizeof output);

		if (proctal_error(proctal)) {
			fprintf(stderr, "Failed to allocate memory in process %d.\n", proctal_pid(proctal));
			proctal_close(proctal);
			return EXIT_FAILURE;
		}

		proctal_write(proctal, allocated_memory, output, sizeof output);

		if (proctal_error(proctal)) {
			fprintf(stderr, "Failed to write to memory in process %d.\n", proctal_pid(proctal));
			proctal_deallocate(proctal, allocated_memory);
			proctal_close(proctal);
			return EXIT_FAILURE;
		}

		code[2] = (char) ((uintptr_t) allocated_memory >> 8 * 0 & 0xFF);
		code[3] = (char) ((uintptr_t) allocated_memory >> 8 * 1 & 0xFF);
		code[4] = (char) ((uintptr_t) allocated_memory >> 8 * 2 & 0xFF);
		code[5] = (char) ((uintptr_t) allocated_memory >> 8 * 3 & 0xFF);
		code[6] = (char) ((uintptr_t) allocated_memory >> 8 * 4 & 0xFF);
		code[7] = (char) ((uintptr_t) allocated_memory >> 8 * 5 & 0xFF);
		code[8] = (char) ((uintptr_t) allocated_memory >> 8 * 6 & 0xFF);
		code[9] = (char) ((uintptr_t) allocated_memory >> 8 * 7 & 0xFF);

		proctal_execute(proctal, code, sizeof code);

		if (proctal_error(proctal)) {
			fprintf(stderr, "Failed to execute code in process %d.\n", proctal_pid(proctal));
			proctal_deallocate(proctal, allocated_memory);
			proctal_close(proctal);
			return EXIT_FAILURE;
		}

		proctal_deallocate(proctal, allocated_memory);
		proctal_close(proctal);
		return EXIT_SUCCESS;
	}


Installation
============

You need to have the following programs installed on your system:

- GCC_
- CMake_
- sed_
- m4_
- php_

Optionally:

- Capstone_ - For disassembling instructions.
- Keystone_ - For assembling instructions.

Then run:

.. code :: sh

	$ mkdir build

	$ cmake -DCMAKE_BUILD_TYPE=Release ..

	$ make

	$ make install


Usage
=====

**CLI**

The command line tool is a program called ``proctal`` that takes commands, like
so:

.. code :: sh

	$ proctal COMMAND

If you execute ``proctal`` without a command, or pass it the ``-h`` option, it
will print help information which includes a list of all available commands.

Commands can also take options. Every command recognizes the ``-h`` option,
which will make it print help information related to it and then exit without
doing anything else.

For a complete overview of the functionality provided by the tool, you can read
the man page by running the following command:

.. code :: sh

	$ man 1 proctal

**API**

The C library can be used by linking to ``libproctal.so`` or ``libproctal.a``
and including ``proctal.h``.

The header file contains comments that explain how functions and macros are
meant to be used.


Documentation
=============

You will find a complete guide with examples and tutorials at `proctal.io
<Documentation_>`_. 


Development
===========

Proctal uses CMake_ to generate a suitable build system for your operating
system. This section will not go into too much detail about that but will show
you what you need to get started.

You must have the following programs installed on your system:

- Git_
- GCC_
- CMake_
- sed_
- m4_
- php_
- Python_

Here's how you create a debug build of the latest version:

.. code :: sh

	$ git clone https://github.com/daniel-araujo/proctal

	$ cd proctal

	$ mkdir -p build

	$ cd build

	$ cmake -DCMAKE_BUILD_TYPE=Debug ..

	$ make

If you modify a source file and run ``make`` again it will detect the change and
compile again.

Libraries are automatically downloaded and installed locally in the project.

You can also run the test suite with ``ctest``.

.. code :: sh

	$ ctest

Beware that some test cases require higher privileges, which means that you will
most likely have to run that command as root in order for all tests to pass.


Contributing
============

Found a bug or want to contribute code? Feel free to create an issue or send a
pull request on GitHub_.

By submitting code as an individual you agree to the Individual Contributor
License Agreement. By submitting code as an entity you agree to the Entity
Contributor License Agreement. Read the CONTRIBUTING file for more details.

You can also report bugs to bugs@proctal.io.


Copying
=======

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

A copy of the GNU General Public License is distributed in a file named
COPYING. If not, see `GNU licenses`_.


.. References

.. _Documentation: https://proctal.io/documentation
.. _Download: https://proctal.io/download
.. _`GNU software`: https://www.gnu.org/software/
.. _`GNU licenses`: http://www.gnu.org/licenses/
.. _GitHub: https://github.com/daniel-araujo/proctal
.. _Capstone: http://www.capstone-engine.org/
.. _Keystone: http://www.keystone-engine.org/
.. _PHP: http://php.net/
.. _CMake: https://cmake.org/cmake/help/v3.14/
.. _GCC: https://gcc.gnu.org/
.. _sed: https://www.gnu.org/software/sed/
.. _m4: https://www.gnu.org/software/m4/
.. _Python: https://www.python.org/
.. _Git: https://git-scm.com/
