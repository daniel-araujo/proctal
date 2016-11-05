define(`TYPE_ARGUMENTS', `
  -t, --type=TYPE
                        Type of value. If omitted, TYPE is implicitly byte.
                        TYPE can be one of:
                        byte
                        integer
                        ieee754
                        text
                        address
  --integer-size=SIZE
                        If type is integer, this determines the number of bits
                        stored in memory. By default SIZE is 8.
                        SIZE can be one of:
                        8
                        16
                        32
                        64
  --integer-sign=SIGN
                        If type is integer, this determines what signing
                        notation is used to distinguish negative from positive
                        numbers. By default SIGN is 2scmpl.
                        SIGN can be one of:
                        unsigned
                        2scmpl
  --text-charset=CHARSET
                        If type is text, this determines the character encoding.
                        By default CHARSET is ascii.
                        CHARSET can be one of:
                        ascii
  --ieee754-precision=PRECISION
                        If type is ieee754, this determines the precision of
                        the floating point number. By default PRECISION is
                        single.
                        PRECISION can be one of:
                        single
                        double
                        extended
')dnl
Usage: proctal
Accesses the address space of a running program.

  -h, --help            Display this help and exit.
  -V, --version         Output version information and exit.

Usage: proctal read
Reads values from the address space of a running program.

Example:
        proctal read --pid=12345 --address=1c09346

  -p, --pid=PID         Process ID of a running program.
  -a, --address=ADDR    Start address of value to read.
  TYPE_ARGUMENTS


Usage: proctal write VALUE
Writes values to the address space of a running program.

Example:
        proctal write --pid=12345 --address=1c09346 99

  -p, --pid=pid         process id of a running program.
  -a, --address=ADDR    Start address where value will be written.
  TYPE_ARGUMENTS

Usage: proctal search
Searches for values in the address space of a running program.

Example:
        proctal search -type=int --pid=12345 --address=1c09346 --eq 12
        d32428          12
        d4ccc4          12
        d80984          12
        dc234c          12
        [...]

  -p, --pid=pid         process id of a running program.
  -i, --input           reads addresses and values from a previous scan of the
                        same type from standard input.
  TYPE_ARGUMENTS
  --eq=VAL              Equal VAL
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
