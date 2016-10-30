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

	enum proctal_command_value_type type;

	void *address;
};

struct proctal_command_write_arg {
	int pid;

	enum proctal_command_value_type type;

	void *address;
	void* value;
};

struct proctal_command_search_arg {
	int pid;

	enum proctal_command_value_type type;

	// Whether to check these addresses.
	struct {
		void *address;
		void *value;
	} *scan;

	// Whether to perform an equality check.
	int eq;
	void* eq_value;

	// Whether to perform a not equals check.
	int ne;
	void* ne_value;

	// Whether to perform greather than.
	int gt;
	void* gt_value;

	// Whether to perform greather than equals.
	int gte;
	void* gte_value;

	// Whether to perform less than.
	int lt;
	void* lt_value;

	// Whether to perform less than equals.
	int lte;
	void* lte_value;

	// Whether to check if it was incremented.
	int inc;
	void* inc_value;

	// Whether to check if it was decremented.
	int dec;
	void* dec_value;

	// Whether to check if it was changed.
	int changed;

	// Whether to check if it was unchanged.
	int unchanged;

	// Whether to check if it was increased.
	int increased;

	// Whether to check if it was decreased.
	int decreased;
};

void proctal_command_read(struct proctal_command_read_arg *arg);

void proctal_command_write(struct proctal_command_write_arg *arg);

void proctal_command_search(struct proctal_command_search_arg *arg);

#endif /* COMMAND_H */
