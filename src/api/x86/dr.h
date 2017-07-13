#ifndef API_X86_DR_H
#define API_X86_DR_H

/*
 * From what I understood reading AMD64 Architecture Programmer's Manual, there
 * are 8 registers dedicated for debugging: DR0, DR1, DR2, DR3, DR4, DR5, DR6
 * and DR7.
 *
 * DR0, DR1, DR2 and DR3 each set the location of a breakpoint.
 *
 * DR4 and DR5 are not meant to be used and should just be ignored.
 *
 * DR6 will contain information when a breakpoint is hit.
 * Bits 1, 2, 3 and 4 are called B0, B1, B2 and B3 and will tell you whether a
 * breakpoint was hit by DR0, DR1, DR2 or DR3, respectively.
 * Bits 5 to 13 are reserved.
 * Bit 14 is called BD and is set to 1 when an access to a debug register was
 * detected while the general-detect condition is enabled.
 * Bit 15 is called BS and is set to 1 if the breakpoint occurs due to
 * single-step mode.
 * Bit 16 is called BT and is set to 1 if the breakpoint occurs as a result of
 * a task switch.
 * Bits 17 to 64 are reserved.
 *
 * DR7 is used to configure breakpoints from DR0, DR1, DR2 and DR3.
 * Bits 1, 3, 5 and 7 are called L0, L1, L2 and L3, respectively and activate
 * DR0, DR1, DR2 and DR3, respectively. These bits are cleared on hardware task
 * switches, which don't happen on Linux but the kernel will make sure they are
 * thread specific.
 * Bits 2, 4, 6 and 8 are called G0, G1, G2 and G3, respectively and activate
 * DR0, DR1, DR2 and DR3 respectively. Unlike L0, L1, L2 and L3, these bits are
 * not cleared on hardware task switches, but Linux doesn't use hardware task
 * switches and for our purposes we won't need them for now.
 * Bits 9 and 10 are ignored on X86-64.
 * Bits 17-18, 21-22, 25-26 and 29-30 are called R/W0, R/W1, R/W2 and R/W3
 * respectively, have the following meaning for DR0, DR1, DR2 and DR3,
 * respectively:
 *
 *     00 - Break on instruction execution
 *     01 - Break on data write
 *     10 - Break on I/O (a bit more elaborated than that)
 *     11 - Break on data read or write
 *
 * Bits 19-20, 23-24, 27-28 and 31-32 are called LEN0, LEN1, LEN2 and LEN3,
 * respectively and specify how many bits from DR0, DR1, DR2 and DR3
 * respectively, are masked in.
 *
 *     00 - 1 byte.
 *     01 - 2 bytes. must be aligned on word boundary.
 *     10 - 8 bytes. must be aligned on quadword boundary.
 *     11 - 4 bytes. must be aligned on doubleword boundary.
 *
 * If breaking on instruction execution is set, however, LEN must be set to 00
 * otherwise the behavior is left undefined.
 */

#define PROCTAL_X86_DR_0 0
#define PROCTAL_X86_DR_1 1
#define PROCTAL_X86_DR_2 2
#define PROCTAL_X86_DR_3 3
#define PROCTAL_X86_DR_4 4
#define PROCTAL_X86_DR_5 5
#define PROCTAL_X86_DR_6 6
#define PROCTAL_X86_DR_7 7

#define PROCTAL_X86_DR_RW_X 0
#define PROCTAL_X86_DR_RW_W 1
#define PROCTAL_X86_DR_RW_RW 3

#define PROCTAL_X86_DR_LEN_1B 0
#define PROCTAL_X86_DR_LEN_2B 1
#define PROCTAL_X86_DR_LEN_4B 3
#define PROCTAL_X86_DR_LEN_8B 2

/*
 * Sets and gets the RW portion.
 */
void proctal_x86_dr_rw_set(unsigned long long *dr7, int r, unsigned int state);
unsigned int proctal_x86_dr_rw(unsigned long long dr7, int r);

/*
 * Sets and gets the LEN portion.
 */
void proctal_x86_dr_len_set(unsigned long long *dr7, int r, unsigned int state);
unsigned int proctal_x86_dr_len(unsigned long long dr7, int r);

/*
 * Enables and disables local breakpoints.
 *
 * If enable is set to 0, breakpoint will be disabled, if set to 1 it will be
 * enabled.
 */
void proctal_x86_dr_l_set(unsigned long long *dr7, int r, int enable);
/*
 * Checks whether a local breakpoint is enabled.
 *
 * If the return value is 0 it's disabled, if 1 it's enabled.
 */
int proctal_x86_dr_l(unsigned long long dr7, int r);

#endif /* API_X86_DR_H */
