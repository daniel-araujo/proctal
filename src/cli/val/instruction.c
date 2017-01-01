#include "instruction.h"

void cli_val_instruction_attr_init(struct cli_val_instruction_attr *a);

void cli_val_instruction_attr_set_arch(
	struct cli_val_instruction_attr *a,
	enum cli_val_instruction_arch arch);

void cli_val_instruction_attr_deinit(struct cli_val_instruction_attr *a);

struct cli_val_instruction *cli_val_instruction_create(struct cli_val_instruction_attr *a);

void cli_val_instruction_destroy(struct cli_val_instruction *v);

void cli_val_instruction_set_address(struct cli_val_instruction *v, void *addr);

void *cli_val_instruction_raw(struct cli_val_instruction *v);

size_t cli_val_instruction_sizeof(struct cli_val_instruction *v);

int cli_val_instruction_print(struct cli_val_instruction *v, FILE *f);

struct cli_val_instruction *cli_val_instruction_create_clone(struct cli_val_instruction *other_v);

int cli_val_instruction_parse_bin(struct cli_val_instruction *v, const char *s, size_t length)
{
	if (v->insn) {
		cs_free(v->insn, 1);
		v->insn = NULL;
	}

	csh handle;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		return 0;
	}

	int count = cs_disasm(handle, (const unsigned char *) s, length, (unsigned long int) v->addr, 1, &v->insn);

	cs_close(&handle);

	if (count == 0) {
		return 0;
	}

	return v->insn->size;
}

int cli_val_instruction_parse(struct cli_val_instruction *v, const char *s)
{
	if (v->insn) {
		cs_free(v->insn, 1);
		v->insn = NULL;
	}

	// The value structure was programmed to hold a reference to a capstone
	// disassembled instruction because it conveniently provides all the
	// information we care about. To remain compatible with existing code,
	// we're going to assemble the code with keystone and then disassemble
	// the result with capstone so as to keep the remaining code as is.
	// Also, it ensures we only parse the first instruction that shows up
	// and ignore the rest.

	ks_engine *ks;

	size_t count;
	unsigned char *encode;
	size_t size;

	if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK) {
		return 0;
	}

	if (ks_asm(ks, s, 0, &encode, &size, &count) != KS_ERR_OK) {
		ks_close(ks);
		return 0;
	}

	int parse_bin = cli_val_instruction_parse_bin(v, (const char *) encode, size);

	ks_free(encode);
	ks_close(ks);

	return parse_bin ? 1 : 0;
}
