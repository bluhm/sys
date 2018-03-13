#ifndef _MACHINE_CPU_FULL_H_
#define _MACHINE_CPU_FULL_H_

#include <sys/param.h>		/* offsetof, PAGE_SIZE */
#include <machine/segments.h>
#include <machine/tss.h>

struct cpu_info_full {
	/* page mapped kRO in u-k */
	union {
		struct i386tss		u_tss; /* followed by gdt */
		char			u_align[PAGE_SIZE];
	} cif_TSS_RO;
#define cif_tss cif_TSS_RO.u_tss

	/* start of page mapped kRW in u-k */
	uint32_t cif_tramp_stack[(PAGE_SIZE
	    - offsetof(struct cpu_info, ci_PAGEALIGN)) / sizeof(uint32_t)];

	/*
	 * Beginning of this hangs over into the kRW page; rest is
	 * unmapped in u-k
	 */
	struct cpu_info cif_cpu;
} __aligned(PAGE_SIZE);

/* tss, align shim, and gdt must fit in a page */
CTASSERT(_ALIGN(sizeof(struct i386tss)) +
	sizeof(struct segment_descriptor) * NGDT < PAGE_SIZE);

/* verify expected alignment */
CTASSERT(offsetof(struct cpu_info_full, cif_cpu.ci_PAGEALIGN) % PAGE_SIZE == 0);

/* verify total size is multiple of page size */
CTASSERT(sizeof(struct cpu_info_full) % PAGE_SIZE == 0);

extern struct cpu_info_full cpu_info_full_primary;

/* Now make sure the cpu_info_primary macro is correct */
CTASSERT(&cpu_info_primary == &cpu_info_full_primary.cif_cpu);

#endif	/* _MACHINE_CPU_FULL_H_ */
#ifndef _MACHINE_CPU_FULL_H_
#define _MACHINE_CPU_FULL_H_

#include <sys/param.h>		/* offsetof, PAGE_SIZE */
#include <machine/segments.h>
#include <machine/tss.h>

struct cpu_info_full {
	/* page mapped kRO in u-k */
	union {
		struct i386tss		u_tss; /* followed by gdt */
		char			u_align[PAGE_SIZE];
	} cif_TSS_RO;
#define cif_tss cif_TSS_RO.u_tss

	/* start of page mapped kRW in u-k */
	uint32_t cif_tramp_stack[(PAGE_SIZE
	    - offsetof(struct cpu_info, ci_PAGEALIGN)) / sizeof(uint32_t)];

	/*
	 * Beginning of this hangs over into the kRW page; rest is
	 * unmapped in u-k
	 */
	struct cpu_info cif_cpu;
} __aligned(PAGE_SIZE);

/* idt and align shim must fit exactly in a page */
CTASSERT(_ALIGN(sizeof(struct gate_descriptor) * NIDT) <= PAGE_SIZE);

/* tss, align shim, and gdt must fit in a page */
CTASSERT(_ALIGN(sizeof(struct i386tss)) +
	sizeof(struct segment_descriptor) * NGDT < PAGE_SIZE);

/* verify expected alignment */
CTASSERT(offsetof(struct cpu_info_full, cif_cpu.ci_PAGEALIGN) % PAGE_SIZE == 0);

/* verify total size is multiple of page size */
CTASSERT(sizeof(struct cpu_info_full) % PAGE_SIZE == 0);

extern struct cpu_info_full cpu_info_full_primary;

/* Now make sure the cpu_info_primary macro is correct */
CTASSERT(&cpu_info_primary == &cpu_info_full_primary.cif_cpu);

#endif	/* _MACHINE_CPU_FULL_H_ */
