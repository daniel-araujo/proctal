define(`PID_OPTION', `
  --pid=PID             Process ID (PID) of a program.
')dnl
define(`REGION_OPTION', `
  --region=REGION       Memory region. REGION can be:
                        stack
                        heap
                        program-code
')dnl
define(`ADDRESS_RANGE_OPTIONS', `
  --address-start=ADDRESS
                        Where to start in memory.
  --address-stop=ADDRESS
                        Where to stop in memory.
')dnl
define(`TYPE_OPTIONS', `
  --type=TYPE
                        Type of value. By default TYPE is byte.
                        TYPE can be:
                        byte
                        integer
                        ieee754
                        text
                        address
                        x86
                        arm
                        sparc
                        powerpc
                        mips
  --integer-endianness=ENDIANNESS
                        If type is integer, determines the byte order in
                        memory. By default ENDIANNESS is the same that the
                        system uses.
                        ENDIANNESS can be:
                        little
                        big
  --integer-bits=SIZE
                        If type is integer, determines the number of bits
                        stored in memory. By default SIZE is 8.
                        SIZE can be:
                        8
                        16
                        32
                        64
  --integer-sign=SIGN
                        If type is integer, determines what signing notation is
                        used to distinguish negative from positive numbers. By
                        default SIGN is twos-complement.
                        SIGN can be:
                        unsigned
                        twos-complement
  --text-encoding=ENCODING
                        If type is text, determines the encoding. By default
                        ENCODING is ascii.
                        ENCODING can be:
                        ascii
  --ieee754-precision=PRECISION
                        If type is ieee754, determines the precision of the
                        floating point number. By default PRECISION is single.
                        PRECISION can be:
                        single
                        double
                        extended
  --x86-syntax=SYNTAX
                        Determines the syntax for x86 instructions. By default
                        SYNTAX is intel.
                        SYNTAX can be:
                        att
                        intel
  --x86-mode=MODE
                        In what mode to operate. By default MODE is 64.
                        MODE can be:
                        16
                        32
                        64
  --arm-mode=MODE
                        Sets ARM mode. By default MODE is a64.
                        MODE can be:
                        a32
                        t32
                        a64
  --arm-endianness=ENDIANNESS
                        By default ENDIANNESS is the same that the system uses.
                        ENDIANNESS can be:
                        little
                        big
  --sparc-mode=MODE
                        Sets SPARC mode. By default MODE is 64.
                        MODE can be:
                        32
                        64
  --sparc-endianness=ENDIANNESS
                        By default ENDIANNESS is the same that the system uses.
                        ENDIANNESS can be:
                        little
                        big
  --powerpc-mode=MODE
                        Sets PowerPC mode. By default MODE is 64.
                        MODE can be:
                        32
                        64
  --powerpc-endianness=ENDIANNESS
                        By default ENDIANNESS is the same that the system uses.
                        ENDIANNESS can be:
                        little
                        big
  --mips-mode=MODE
                        Sets MIPS mode. By default MODE is 64.
                        MODE can be:
                        32
                        64
  --mips-endianness=ENDIANNESS
                        By default ENDIANNESS is the same that the system uses.
                        ENDIANNESS can be:
                        little
                        big
')dnl
Usage: proctal

A tool for modding programs at runtime. Visit https://proctal.io for extensive
documentation.


  -h, --help            Display help information and exit. If a command is
                        given, also show command specific options.
  -V, --version         Output version information and exit.



Usage: proctal read
Reads values from memory.

The --array option makes the command read values in consecutive addresses.
With the --show-address option, the command will additionally print the
respective address of a value.

Examples:
  Reading 1 byte
        proctal read --pid=12345 --address=1c09346

  Reading 12 bytes
        proctal read --pid=12345 --address=1c09346 --array=12

  Reading IEEE754 floating point number
        proctal read --pid=12345 --address=1c09346 --type=ieee754


  PID_OPTION
  --address=ADDRESS     Address to read from.
  --binary              Whether to print in binary.
  --pause               Whether to keep the program paused while reading.
  --array=SIZE          Read SIZE values in consecutive addresses. By default
                        SIZE is 1.
  TYPE_OPTIONS
  --show-address        Additionally prints the respective address of a value.
                        As a side effect, all values will be separated by new
                        lines. Is ignored when printing in binary.
  --show-bytes          Additionally prints a sequence of numbers in
                        hexadecimal that represent the bytes of the value in
                        memory, from the smallest to the largest address. Is
                        ignored when printing in binary.



Usage: proctal write VALUES...
Writes values to memory.

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


  PID_OPTION
  --address=ADDRESS     Address to write to.
  --binary              Whether to parse values in binary.
  --pause               Whether to keep the program paused while writing.
  --array=SIZE          Write SIZE values in consecutive addresses. If less
                        than SIZE values are provided, then when in need of
                        more values the command will cycle through the provided
                        values. This behavior allows you to specify a single
                        value and have it repeatedly written SIZE times. By
                        default SIZE is set to the number of given values.
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

Prints the address and the current value of every match that passes the given
filters.

By passing the --review option the command will read the output of a previous
run and allow you to use filters that compare against the previous values. Both
runs must use the same type options.

Options that compare against values in memory:
  --eq
  --ne
  --gt
  --gte
  --lt
  --lte

Options that compare against values from the previous run:
  --inc
  --inc-up-to
  --dec
  --dec-up-to
  --changed
  --unchanged
  --increased
  --decreased

Examples:
  Searching for all bytes that equal 12
        proctal search --pid=12345 --eq=12

  Searching for all bytes that are greater than 12 but less than or equal to 16
        proctal search --pid=12345 --gt=12 --lte=16

  Searching for all floating point values in memory
        proctal search --pid=12345 --type=ieee754

  Searching for values that changed from the results of a previous search
        proctal search --pid=12345 --eq=12 --review > previous-search-results
        proctal search --pid=12345 --changed --review < previous-search-results

  Searching in executable memory only
        proctal search --pid=12345 -x --eq=12

  Searching from address DCA0 to DCAF
	proctal search --pid=12345 --address-start=DCA0 --address-stop=DCAF


  PID_OPTION
  ADDRESS_RANGE_OPTIONS
  REGION_OPTION
  --review              Matches against the output of a previous run.
  --pause               Whether to keep the program paused while searching.
  TYPE_OPTIONS
  -r, --read            Readable memory.
  -w, --write           Writable memory.
  -x, --execute         Executable memory.
  --eq=VALUE            Equal to VALUE.
  --ne=VALUE            Not equal to VALUE.
  --gt=VALUE            Greater than VALUE.
  --gte=VALUE           Greater than or equal to VALUE.
  --lt=VALUE            Less than VALUE.
  --lte=VALUE           Less than or equal to VALUE.
  --inc=VALUE           Incremented by VALUE.
  --inc-up-to=VALUE     Incremented up to and including VALUE.
  --dec=VALUE           Decremented by VALUE.
  --dec-up-to=VALUE     Decremented up to and including VALUE.
  --changed             Value changed.
  --unchanged           Value did not change.
  --increased           Value increased.
  --decreased           Value decreased.



Usage: proctal pattern PATTERN
Searches for patterns in memory.

Prints the address of each match.

Available patterns:

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
        proctal pattern --pid=12345 --region=program-code "48 83 C0 01"

  Searching from address DCA0 to DCAF
	proctal pattern --pid=12345 --address-start=DCA0 --address-stop=DCAF 42


  PID_OPTION
  ADDRESS_RANGE_OPTIONS
  REGION_OPTION
  --pause               Whether to keep the program paused while searching.
  -r, --read            Readable memory.
  -w, --write           Writable memory.
  -x, --execute         Executable memory.



Usage: proctal pause
Pauses program execution.

The program will be paused for as long as the command is running.

Examples:
  Pause program execution
        proctal pause --pid=12345


  PID_OPTION



Usage: proctal watch ADDRESS
Detects accesses to a memory address.

Prints the value of the instruction pointer after detecting that the given
memory address was accessed. Note that the instruction pointer may not actually
be pointing to the instruction that accessed the memory address.

Examples:
  Watching for any instruction reading or writing to 1c09346
        proctal watch --pid=12345 --read --write 1c09346

  Watching for 1c09346 being executed
        proctal watch --pid=12345 --execute 1c09346


  PID_OPTION
  ADDRESS_RANGE_OPTIONS
  -r, --read            Read access.
  -w, --write           Write access.
  -x, --execute         Execute instruction.
  --unique              Print an address only once.



Usage: proctal execute
Executes arbitrary code.

The given instructions will be embedded at some place in memory and executed in
a new stack frame in the context of the main thread. The other threads will be
paused. Control will be given back to the program after the last instruction is
executed. The stack frame will be destroyed and the CPU registers will be
restored.

The instructions cannot rely on where they will be placed in memory.

Examples:
  Executing instructions from an assembly file
        proctal execute --pid=12345 < code.asm

  Executing instructions from a file containing bytecode
        proctal execute --pid=12345 --format=bytecode < code.bin


  PID_OPTION
  --format=FORMAT       Input format. By default FORMAT is assembly.
                        FORMAT can be:
                        assembly
                        bytecode
  --architecture=ARCHITECTURE
                        This defines which assembly language to use based on
                        the given architecture. By default ARCHITECTURE is set
                        to be the native architecture of the system if
                        supported.
                        ARCHITECTURE can be:
                        x86
                        arm
                        sparc
                        powerpc
                        mips
  --endianness=ENDIANNESS
                        Sets the endianness of the architecture. By default
                        ENDIANNESS is set to be the same that the system is
                        using if it's supported.
                        ENDIANNESS can be:
                        little
                        big
  --x86-mode=MODE
                        Sets x86 mode. By default, mode is set to be the native
                        mode of the system if supported.
                        MODE can be:
                        16
                        32
                        64
  --x86-syntax=SYNTAX
                        Sets the syntax for x86 assembly. By default SYNTAX is
                        intel.
                        SYNTAX can be:
                        att
                        intel
  --arm-mode=MODE
                        Sets ARM mode. By default, mode is set to be the native
                        mode of the system if supported.
                        MODE can be:
                        a32
                        t32
                        a64
  --sparc-mode=MODE
                        Sets SPARC mode. By default, mode is set to be the native
                        mode of the system if supported.
                        MODE can be:
                        32
                        64
  --powerpc-mode=MODE
                        Sets PowerPC mode. By default, mode is set to be the native
                        mode of the system if supported.
                        MODE can be:
                        32
                        64
  --mips-mode=MODE
                        Sets MIPS mode. By default, mode is set to be the native
                        mode of the system if supported.
                        MODE can be:
                        32
                        64



Usage: proctal allocate SIZE
Allocates memory.

Will print the address of a newly allocated block of memory with the capacity
to store at least SIZE bytes.

Deallocate the block with the deallocate command.

Examples:
  Allocating 8 bytes
        proctal allocate --pid=12345 8

  Allocating 8 bytes in readable and executable memory
        proctal allocate --pid=12345 -rx 8


  PID_OPTION
  -r, --read            Read permission.
  -w, --write           Write permission.
  -x, --execute         Execute permission.



Usage: proctal deallocate ADDRESS
Deallocates memory.

Takes the address of a block of memory allocated by the allocate command and
deallocates it.

Examples:
  Deallocating memory starting at 7fbf7b6b2000
        proctal deallocate --pid=12345 7fbf7b6b2000


  PID_OPTION



Usage: proctal measure VALUES...
Measure size of values.

Let's you measure how many bytes a value, or multiple values, would take up in
memory.

Examples:
  Measuring how many bytes a call instruction on x86 would take
        proctal measure --address=1c09346 --type=x86 "call 0x5"


  --address=ADDRESS     Address where the values would be in memory.
  --array=SIZE          Simulates the same behavior described for the --array
                        option for the write command.
  TYPE_OPTIONS



Usage: proctal dump
Dumps memory.

Will print byte for byte what's in memory.

Examples:
  Dumping everything in memory to a file
        proctal dump --pid=12345 > dump

  Dumping program code in memory to a file
	proctal dump --pid=12345 --region=program-code > dump

  Dumping memory marked as executable to a file
	proctal dump --pid=12345 -x > dump

  Dumping memory from address DCA0 to DCAF
	proctal dump --pid=123 --address-start=DCA0 --address-stop=DCAF > dump


  PID_OPTION
  ADDRESS_RANGE_OPTIONS
  REGION_OPTION
  --pause               Whether to keep the program paused while dumping.
  -r, --read            Readable memory.
  -w, --write           Writable memory.
  -x, --execute         Executable memory.
