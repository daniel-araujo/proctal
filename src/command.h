#ifndef COMMAND_H
#define COMMAND_H

enum proctal_command_value_type {
        PROCTAL_COMMAND_VALUE_TYPE_UNKNOWN,
        PROCTAL_COMMAND_VALUE_TYPE_CHAR,
        PROCTAL_COMMAND_VALUE_TYPE_UCHAR,
        PROCTAL_COMMAND_VALUE_TYPE_SCHAR,
        PROCTAL_COMMAND_VALUE_TYPE_SHORT,
        PROCTAL_COMMAND_VALUE_TYPE_USHORT,
        PROCTAL_COMMAND_VALUE_TYPE_INT,
        PROCTAL_COMMAND_VALUE_TYPE_UINT,
        PROCTAL_COMMAND_VALUE_TYPE_LONG,
        PROCTAL_COMMAND_VALUE_TYPE_ULONG,
        PROCTAL_COMMAND_VALUE_TYPE_LONGLONG,
        PROCTAL_COMMAND_VALUE_TYPE_ULONGLONG,
        PROCTAL_COMMAND_VALUE_TYPE_FLOAT,
        PROCTAL_COMMAND_VALUE_TYPE_DOUBLE,
        PROCTAL_COMMAND_VALUE_TYPE_LONGDOUBLE,
};

struct proctal_command_read_arg {
	int pid;
	void *address;
	enum proctal_command_value_type type;
};
struct proctal_command_write_arg {
	int pid;
	void *address;
	int value;
	enum proctal_command_value_type type;
};

void proctal_command_read(struct proctal_command_read_arg *arg);

void proctal_command_write(struct proctal_command_write_arg *arg);

#endif /* COMMAND_H */
