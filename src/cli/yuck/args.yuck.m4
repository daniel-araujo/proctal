define(`PID_ARGUMENT', `
  -p, --pid=PID         Process ID (PID) of a program.
')dnl
define(`TYPE_OPTIONS', `
  -t, --type=TYPE
                        Type of value. If omitted, TYPE is implicitly byte.
                        TYPE can be:
                        byte
                        integer
                        ieee754
                        text
                        address
                        instruction
  --integer-endianness=ENDIANNESS
                        If type is integer, this determines the order of bytes.
                        By default ENDIANNESS is the same as the host.
                        ENDIANNESS can be:
                        little
                        big
  --integer-size=SIZE
                        If type is integer, this determines the number of bits
                        stored in memory. By default SIZE is 8.
                        SIZE can be:
                        8
                        16
                        32
                        64
  --integer-sign=SIGN
                        If type is integer, this determines what signing
                        notation is used to distinguish negative from positive
                        numbers. By default SIGN is twos-complement.
                        SIGN can be:
                        unsigned
                        twos-complement
  --text-charset=CHARSET
                        If type is text, this determines the character encoding.
                        By default CHARSET is ascii.
                        CHARSET can be:
                        ascii
  --ieee754-precision=PRECISION
                        If type is ieee754, this determines the precision of
                        the floating point number. By default PRECISION is
                        single.
                        PRECISION can be:
                        single
                        double
                        extended
  --instruction-arch=ARCH
                        If type is instruction, this determines the
                        architecture.
                        By default ARCH is the same architecture that the tool
                        was compiled in.
                        ARCH can be:
                        x86
                        x86-64
                        arm
                        aarch64
  --instruction-syntax=SYNTAX
                        If type is architecture, this determines the syntax
                        used for assembly.
                        By default SYNTAX is intel.
                        SYNTAX can be:
                        att
                        intel
')dnl
Usage: proctal
Gives you access to the address space of a program.


  -h, --help            Display help information and exit. If a command is
                        given, also show command specific options.
  -V, --version         Output version information and exit.



Usage: proctal read
Reads values.

Will output the value found at the given address.

If the --array option is given, it will read values that come after the given
address.

You can optionally prefix the values with their respective addresses by passing
the --show-address option.

Examples:
  Reading single byte
        proctal read --pid=12345 --address=1c09346

  Reading multiple bytes
        proctal read --pid=12345 --address=1c09346 --array=12

  Reading IEEE754 floating point number
        proctal read --pid=12345 --address=1c09346 --type=ieee754


  PID_ARGUMENT
  -a, --address=ADDR    Start address of values to read.
  --freeze              Whether to keep the program frozen while reading.
  --array=SIZE          Makes the command read SIZE values in adjacent memory
                        addresses. By default SIZE is equal to 1.
  TYPE_OPTIONS
  --show-address        Additionally prints the address before the value.
                        As a side effect, all values will be separated by new
                        lines.
  --show-instruction-bytecode
                        If type is instruction, additionally prints the
                        bytecode of the instruction in hexadecimal.



Usage: proctal write VALUES...
Writes values.

Will write the given values starting at the given address.

Examples:
  Writing 99 to address 1c09346
        proctal write --pid=12345 --address=1c09346 99

  Writing 99 to address 1c09346 and 1c09347
        proctal write --pid=12345 --address=1c09346 --array=2 99

  Writing 99 to address 1c09346 and 98 to 1c09347
        proctal write --pid=12345 --address=1c09346 99 98

  Repeatedly writing 99 to address 1c09346
        proctal write --pid=12345 --address=1c09346 --repeat 99

  Writing floating point number
        proctal write --pid=12345 --address=1c09346 --type=ieee754 99.999999


  PID_ARGUMENT
  -a, --address=ADDR    Start address where to begin writing values.
  --freeze              Whether to keep the program frozen while writing.
  --array=SIZE          Makes the command write SIZE values in adjacent
                        addresses. If less than SIZE values are provided, then
                        when in need of more values it will cycle back through
                        the provided values. This behavior allows you to
                        specify a single value and have it repeatedly written
                        SIZE times. If SIZE is not provided, it will be set to
                        the number of given values.
  --repeat              Whether to repeatedly write the same values to the
                        address until the command is interrupted by the SIGINT
                        signal.
  --repeat-delay=DELAY  If the repeat option is passed, this sets the delay
                        in milliseconds between each write. A delay value of 0
                        essentially removes the delay and will let the program
                        use every CPU cycle it gets to overwrite the value. By
                        default, DELAY is set to 5.
  TYPE_OPTIONS



Usage: proctal search
Searches for values in memory.

Outputs a list of addresses and their current values that match the given
filters.

You can additionally filter against the results of a previous search by passing
the --input option which expects the output of the previous command to be
streamed to the standard input stream.

Examples:
  Searching for all bytes that equal 12
        proctal search --pid=12345 --eq 12

  Searching for all bytes that are greater than 12 but less than or equal to 16
        proctal search --pid=12345 --gt 12 --lte 16

  Searching for all floating point values in memory
        proctal search --pid=12345 --type=ieee754

  Filtering against the search results of a previous search
        proctal search --pid=12345 --eq 12 > previous-search-results
        proctal search --pid=12345 --increased < previous-search-results

  Searching in executable memory only
        proctal search --pid=12345 -x --eq 12


  PID_ARGUMENT
  -i, --input           Reads the output of a previous scan of the same type
                        from standard input.
  --freeze              Whether to keep the program frozen while searching.
  TYPE_OPTIONS
  -r, --read            Readable memory.
  -w, --write           Writable memory.
  -x, --execute         Executable memory.
  --eq=VAL              Equal to VAL
  --ne=VAL              Not equal to VAL
  --gt=VAL              Greater than VAL
  --gte=VAL             Greater than or equal to VAL
  --lt=VAL              Less than VAL
  --lte=VAL             Less than or equal to VAL
  --inc=VAL             Incremented by VAL
  --inc-up-to=VAL       Incremented up to and including VAL
  --dec=VAL             Decremented by VAL
  --dec-up-to=VAL       Decremented up to and including VAL
  --changed             Value from previous search changed
  --unchanged           Value from previous search did not change
  --increased           Value from previous search increased
  --decreased           Value from previous search decreased



Usage: proctal pattern PATTERN
Searches for patterns in memory.

Outputs the starting address of each match.

The following patterns are available:

 00 to FF - Exact byte value

   Matches exactly the value of a byte. You must express the value in
   hexadecimal notation and always with 2 digits.

 ?? - Any byte value

   Matches any byte value.

Examples:
  Searching for exact sequence of bytes
        proctal pattern --pid=12345 -x "48 83 C0 01"

  Searching for sequence with any value between E8 and 48 followed by 83 C0 01
        proctal pattern --pid=12345 -x "E8 ?? ?? ?? ??  48 83 C0 01"

  Searching for patterns in program code
        proctal pattern --pid=12345 --program-code "48 83 C0 01"


  PID_ARGUMENT
  --freeze              Whether to keep the program frozen while searching.
  -r, --read            Readable memory.
  -w, --write           Writable memory.
  -x, --execute         Executable memory.
  --program-code        Program code in memory.



Usage: proctal freeze
Freezes program execution.

The program will be frozen as long as the command is executing. The command can
be stopped by sending it the SIGINT signal.

Examples:
  Pause program execution
        proctal freeze --pid=12345


  PID_ARGUMENT
  -i, --input           Additionally to quitting when receiving SIGINT, will
                        read from standard input and quit when no more input is
                        available, whichever happens first.



Usage: proctal watch
Detects when a memory address is accessed.

A way to get the value of the instruction pointer the moment after a memory
address is read, written or executed.

Note that the instruction pointer may not actually be pointing at the
instruction that actually accessed the memory address.

Examples:
  Watching for any instruction reading or writing to 1c09346
        proctal watch --pid=12345 --address=1c09346 -rw

  Watching for 1c09346 being executed as an instruction
        proctal watch --pid=12345 --address=1c09346 -x


  PID_ARGUMENT
  -a, --address=ADDR    Address to watch.
  -r, --read            Read access.
  -w, --write           Write access.
  -x, --execute         Execute instruction.
  --unique              Print an address only once.



Usage: proctal execute
Executes arbitrary code.

The given instructions will be embedded at some place in memory and executed in
a new stack frame in the context of the main thread. The other threads will be
paused. Your code is free to modify any registers because they will be restored
to their original values. Control will be given back to the program after the
last instruction is executed.

The instructions are expected to be passed through standard input and cannot
rely on where they will be placed in memory.

Examples:
  Executing instructions from an assembly file
        proctal execute --pid=12345 < code.asm

  Executing instructions from a file containing bytecode
        proctal execute --pid=12345 --format=bytecode < code.bin


  PID_ARGUMENT
  --format=FORMAT       Input format. By default FORMAT is assembly.
                        FORMAT can be:
                        assembly
                        bytecode
  --assembly-arch=ARCH
                        If type is instruction, this determines the
                        architecture.
                        By default ARCH is the same architecture that the tool
                        was compiled in.
                        ARCH can be:
                        x86
                        x86-64
                        arm
                        aarch64
  --assembly-syntax=SYNTAX
                        If type is architecture, this determines the syntax
                        used for assembly.
                        By default SYNTAX is intel.
                        SYNTAX can be:
                        att
                        intel



Usage: proctal allocate SIZE
Allocates memory.

Will output the start address of an allocated chunk of memory with at least
SIZE bytes.

When you no longer need it, you should deallocate it with the deallocate
command.

Examples:
  Allocating 8 bytes
        proctal allocate --pid=12345 8

  Allocating 8 bytes in readable and executable memory
        proctal allocate --pid=12345 -rx 8


  PID_ARGUMENT
  -r, --read            Read permission.
  -w, --write           Write permission.
  -x, --execute         Execute permission.



Usage: proctal deallocate ADDRESS
Deallocates memory.

Should only be used to deallocate memory allocated by the allocate command.

Examples:
  Deallocating memory starting at 7fbf7b6b2000
        proctal deallocate --pid=12345 7fbf7b6b2000


  PID_ARGUMENT



Usage: proctal measure VALUES...
Measure size of values.

If you don't know how much space the values you want to write would take, you
can use this command to measure them.

Examples:
  Measuring how many bytes a call instruction would take
        proctal measure --address=1c09346 --type=instruction "call 0x5"


  -a, --address=ADDR    Address where the first value would reside in memory.
  --array=SIZE          Emulates the same behavior described in the write
                        command.
  TYPE_OPTIONS



Usage: proctal dump
Dumps memory.

Will output contents in memory.

Examples:
  Dumping everything in memory to a file
        proctal dump --pid=12345 > dump

  Dumping program code in memory to a file
	proctal dump --pid=12345 --program-code > dump

  Dumping memory marked as executable to a file
	proctal dump --pid=12345 -x > dump


  PID_ARGUMENT
  --freeze              Whether to keep the program frozen while dumping.
  -r, --read            Readable memory.
  -w, --write           Writable memory.
  -x, --execute         Executable memory.
  --program-code        Program code in memory.
