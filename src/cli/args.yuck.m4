define(`PID_ARGUMENT', `
  -p, --pid=PID         Process ID (PID) of a running program.
')dnl
define(`TYPE_ARGUMENTS', `
  -t, --type=TYPE
                        Type of value. If omitted, TYPE is implicitly byte.
                        TYPE can be:
                        byte
                        integer
                        ieee754
                        text
                        address
                        instruction
  --endianness=ENDIANNESS
                        By default ENDIANNESS is little.
                        ENDIANNESS can be:
                        little
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
                        numbers. By default SIGN is 2scmpl.
                        SIGN can be:
                        unsigned
                        2scmpl
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
')dnl
Usage: proctal
Accesses the address space of a running program.

  -h, --help            Display help information and exit. If a command is
                        given, also show command specific options.
  -V, --version         Output version information and exit.

Usage: proctal read
Reads values.

Example:
        proctal read --pid=12345 --address=1c09346

  PID_ARGUMENT
  -a, --address=ADDR    Start address of values to read.
  --array=SIZE          Makes the command read SIZE values in adjacent memory
                        addresses. By default SIZE is equal to 1.
  TYPE_ARGUMENTS
  --show-instruction-address
                        If type is instruction, additionally prints the
                        instruction address.
  --show-instruction-byte-code
                        If type is instruction, additionally prints the
                        byte code of the instruction in hexadecimal.

Usage: proctal write VALUES...
Writes values.

The first value will be written to the given address, then the next one will be
written to the memory address coming after it, and so on.

Example:
        proctal write --pid=12345 --address=1c09346 99

  PID_ARGUMENT
  -a, --address=ADDR    Start address where to begin writing values.
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
  --repeat-delay=DELAY  If the repeat option is passed, this sets the delay in
                        milliseconds between each write. A delay value of 0
                        essentially removes the delay and will let the program
                        use every CPU cycle it gets to overwrite the value. By
                        default, DELAY is set to 5.
  TYPE_ARGUMENTS

Usage: proctal search
Searches for values in memory.

Example:
        proctal search --type=integer --pid=12345 --address=1c09346 --eq 12

  PID_ARGUMENT
  -i, --input           Reads the output of a previous scan of the same type
                        from standard input.
  TYPE_ARGUMENTS
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
  --changed             Value changed from previous scan
  --unchanged           Value did not change from previous scan
  --increased           Value increased from previous scan
  --decreased           Value decreased from previous scan

Usage: proctal pattern PATTERN
Searches for patterns in memory.

Prints the starting address of each match.

The following patterns are available:

 00 to FF - Exact byte value

   Matches exactly the value of a byte. You must express the value in
   hexadecimal notation and always with 2 digits.

   Examples:
     00
     01
     7A
     FF

 ?? - Any byte value

   Matches any byte value.

Example:
        proctal pattern --pid=12345 -x "E8 ?? ?? ?? ??"

  PID_ARGUMENT
  -r, --read            Readable memory.
  -w, --write           Writable memory.
  -x, --execute         Executable memory.
  --program-code        Program code in memory.

Usage: proctal freeze
Freezes main thread of execution.

The running program will be frozen as long as the command is executing. It will
stop executing when it receives the SIGINT signal.

Example:
        proctal freeze --pid=12345

  PID_ARGUMENT
  -i, --input           Additionally to quitting when receiving SIGINT, will
                        read from standard input and quit when no more input is
                        available, whichever happens first.

Usage: proctal watch
Watches for memory accesses in main thread of execution.

It's important to note that this may not report the actual instruction that
accessed the address.

Example:
        proctal watch --pid=12345 --address=1c09346 -rw

  PID_ARGUMENT
  -a, --address=ADDR    Address to watch.
  -r, --read            Read access.
  -w, --write           Write access.
  -x, --execute         Execute instruction.
  --unique              Print an address only once.

Usage: proctal execute
Executes arbitrary code.

The given instructions will be embedded at some place in memory and executed in
a new stack frame in the context of the main thread. Your code is free to
modify any registers because they will be restored to their original values on
return. You can either use the ret instruction to explicitly return or let the
processor continue executing instructions after the last instruction you gave.

Example:
        proctal execute --pid=12345

  PID_ARGUMENT
  --format=FORMAT       Input format. By default FORMAT is assembly.
                        FORMAT can be:
                        assembly
                        bytecode

Usage: proctal alloc SIZE
Allocates memory.

Will output the start address of an allocated chunk of memory with at least
SIZE bytes.

When you no longer need the space, you should deallocate it with the dealloc
command.

Example:
        proctal alloc --pid=12345 8

  PID_ARGUMENT
  -r, --read            Read permission.
  -w, --write           Write permission.
  -x, --execute         Execute permission.

Usage: proctal dealloc ADDRESS
Deallocates memory.

Should only be used to deallocate memory allocated by the alloc command.

Example:
        proctal dealloc --pid=12345 7fbf7b6b2000

  PID_ARGUMENT

Usage: proctal measure VALUES...
Measure size of values.

If you're in doubt how much space the values you want to write will take you
can use this command to figure out.

Example:
        proctal measure --address=1c09346 --type=instruction "call 0x5"

  -a, --address=ADDR    Address where the first value would reside in memory.
  --array=SIZE          Emulates the same behavior described in the write
                        command.
  TYPE_ARGUMENTS
