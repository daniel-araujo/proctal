#ifndef COMMAND_H
#define COMMAND_H

struct proctal_command_read_arg {
	int pid;
	void *address;
};
struct proctal_command_write_arg {
	int pid;
	void *address;
	int value;
};

void proctal_command_read(struct proctal_command_read_arg *arg);

void proctal_command_write(struct proctal_command_write_arg *arg);

#endif /* COMMAND_H */
