#include <x86/dr.h>

static inline int is_address_register(int r)
{
	switch (r) {
	case PROCTAL_X86_DR_0:
	case PROCTAL_X86_DR_1:
	case PROCTAL_X86_DR_2:
	case PROCTAL_X86_DR_3:
		return 1;

	default:
		return 0;
	}
}

static inline int get_rw_offset(int r)
{
	switch (r) {
	case PROCTAL_X86_DR_0:
		return 16;

	case PROCTAL_X86_DR_1:
		return 20;

	case PROCTAL_X86_DR_2:
		return 24;

	case PROCTAL_X86_DR_3:
		return 28;

	default:
		return -1;
	}
}

static inline int get_len_offset(int r)
{
	switch (r) {
	case PROCTAL_X86_DR_0:
		return 18;

	case PROCTAL_X86_DR_1:
		return 22;

	case PROCTAL_X86_DR_2:
		return 26;

	case PROCTAL_X86_DR_3:
		return 30;

	default:
		return -1;
	}
}

static inline int get_l_offset(int r)
{
	switch (r) {
	case PROCTAL_X86_DR_0:
		return 0;

	case PROCTAL_X86_DR_1:
		return 2;

	case PROCTAL_X86_DR_2:
		return 4;

	case PROCTAL_X86_DR_3:
		return 6;

	default:
		return -1;
	}
}

void proctal_x86_dr_set_rw(unsigned long long *dr7, int r, unsigned int state)
{
	int offset = get_rw_offset(r);

	if (offset == -1) {
		return;
	}

	unsigned int mask = 0x3u << offset;

	state <<= offset;
	state &= mask;
	*dr7 &= ~(mask);
	*dr7 |= state;
}

unsigned int proctal_x86_dr_rw(unsigned long long dr7, int r)
{
	int offset = get_rw_offset(r);

	if (offset == -1) {
		return 0;
	}

	unsigned int mask = 0x3u << offset;

	return (dr7 & mask) >> offset;
}

void proctal_x86_dr_set_len(unsigned long long *dr7, int r, unsigned int state)
{
	int offset = get_len_offset(r);

	if (offset == -1) {
		return;
	}

	unsigned int mask = 0x3u << offset;

	state <<= offset;
	state &= mask;
	*dr7 &= ~(mask);
	*dr7 |= state;
}

unsigned int proctal_x86_dr_len(unsigned long long dr7, int r)
{
	int offset = get_len_offset(r);

	if (offset == -1) {
		return 0;
	}

	unsigned int mask = 0x3u << offset;

	return (dr7 & mask) >> offset;
}

void proctal_x86_dr_enable_l(unsigned long long *dr7, int r, int enable)
{
	int offset = get_l_offset(r);

	if (offset == -1) {
		return;
	}

	unsigned int mask = 1u << offset;

	int state = enable ? 1u : 0u;
	state <<= offset;
	*dr7 &= ~(mask);
	*dr7 |= state;
}

int proctal_x86_dr_is_l_enabled(unsigned long long dr7, int r)
{
	int offset = get_l_offset(r);

	if (offset == -1) {
		return 0;
	}

	unsigned int mask = 1u << offset;

	return (dr7 & mask) >> offset;
}
