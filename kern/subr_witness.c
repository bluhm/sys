/*	$OpenBSD: subr_witness.c,v 1.12 2018/05/07 15:54:03 visa Exp $	*/

/*-
 * Copyright (c) 2008 Isilon Systems, Inc.
 * Copyright (c) 2008 Ilya Maykov <ivmaykov@gmail.com>
 * Copyright (c) 1998 Berkeley Software Design, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Berkeley Software Design Inc's name may not be used to endorse or
 *    promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY BERKELEY SOFTWARE DESIGN INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL BERKELEY SOFTWARE DESIGN INC BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from BSDI Id: mutex_witness.c,v 1.1.2.20 2000/04/27 03:10:27 cp Exp
 *	and BSDI Id: synch_machdep.c,v 2.3.2.39 2000/04/27 03:10:25 cp Exp
 */

/*
 * Implementation of the `witness' lock verifier.  Originally implemented for
 * mutexes in BSD/OS.  Extended to handle generic lock objects and lock
 * classes in FreeBSD.
 */

/*
 *	Main Entry: witness
 *	Pronunciation: 'wit-n&s
 *	Function: noun
 *	Etymology: Middle English witnesse, from Old English witnes knowledge,
 *	    testimony, witness, from 2wit
 *	Date: before 12th century
 *	1 : attestation of a fact or event : TESTIMONY
 *	2 : one that gives evidence; specifically : one who testifies in
 *	    a cause or before a judicial tribunal
 *	3 : one asked to be present at a transaction so as to be able to
 *	    testify to its having taken place
 *	4 : one who has personal knowledge of something
 *	5 a : something serving as evidence or proof : SIGN
 *	  b : public affirmation by word or example of usually
 *	      religious faith or conviction <the heroic witness to divine
 *	      life -- Pilot>
 *	6 capitalized : a member of the Jehovah's Witnesses
 */

/*
 * Special rules concerning Giant and lock orders:
 *
 * 1) Giant must be acquired before any other mutexes.  Stated another way,
 *    no other mutex may be held when Giant is acquired.
 *
 * 2) Giant must be released when blocking on a sleepable lock.
 *
 * This rule is less obvious, but is a result of Giant providing the same
 * semantics as spl().  Basically, when a thread sleeps, it must release
 * Giant.  When a thread blocks on a sleepable lock, it sleeps.  Hence rule
 * 2).
 *
 * 3) Giant may be acquired before or after sleepable locks.
 *
 * This rule is also not quite as obvious.  Giant may be acquired after
 * a sleepable lock because it is a non-sleepable lock and non-sleepable
 * locks may always be acquired while holding a sleepable lock.  The second
 * case, Giant before a sleepable lock, follows from rule 2) above.  Suppose
 * you have two threads T1 and T2 and a sleepable lock X.  Suppose that T1
 * acquires X and blocks on Giant.  Then suppose that T2 acquires Giant and
 * blocks on X.  When T2 blocks on X, T2 will release Giant allowing T1 to
 * execute.  Thus, acquiring Giant both before and after a sleepable lock
 * will not result in a lock order reversal.
 */

#if 0
__FBSDID("$FreeBSD: head/sys/kern/subr_witness.c 313261 2017-02-05 02:27:04Z markj $");
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mplock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/stdint.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/witness.h>

#include <machine/cpu.h>

#include <uvm/uvm.h>	/* uvm_pageboot_alloc */

#ifndef DDB
#error "DDB is required for WITNESS"
#endif

#include <machine/db_machdep.h>

#include <ddb/db_access.h>
#include <ddb/db_var.h>
#include <ddb/db_output.h>

#define	LI_RECURSEMASK	0x0000ffff	/* Recursion depth of lock instance. */
#define	LI_EXCLUSIVE	0x00010000	/* Exclusive lock instance. */
#define	LI_NORELEASE	0x00020000	/* Lock not allowed to be released. */

#ifndef WITNESS_COUNT
#define	WITNESS_COUNT		1536
#endif
#define	WITNESS_HASH_SIZE	251	/* Prime, gives load factor < 2 */
#define	WITNESS_PENDLIST	(1024 + MAXCPUS)

/* Allocate 256 KB of stack data space */
#define	WITNESS_LO_DATA_COUNT	2048

/* Prime, gives load factor of ~2 at full load */
#define	WITNESS_LO_HASH_SIZE	1021

/*
 * XXX: This is somewhat bogus, as we assume here that at most 2048 threads
 * will hold LOCK_NCHILDREN locks.  We handle failure ok, and we should
 * probably be safe for the most part, but it's still a SWAG.
 */
#define	LOCK_NCHILDREN	5
#define	LOCK_CHILDCOUNT	2048

#define	FULLGRAPH_SBUF_SIZE	512

/*
 * These flags go in the witness relationship matrix and describe the
 * relationship between any two struct witness objects.
 */
#define	WITNESS_UNRELATED        0x00    /* No lock order relation. */
#define	WITNESS_PARENT           0x01    /* Parent, aka direct ancestor. */
#define	WITNESS_ANCESTOR         0x02    /* Direct or indirect ancestor. */
#define	WITNESS_CHILD            0x04    /* Child, aka direct descendant. */
#define	WITNESS_DESCENDANT       0x08    /* Direct or indirect descendant. */
#define	WITNESS_ANCESTOR_MASK    (WITNESS_PARENT | WITNESS_ANCESTOR)
#define	WITNESS_DESCENDANT_MASK  (WITNESS_CHILD | WITNESS_DESCENDANT)
#define	WITNESS_RELATED_MASK						\
	(WITNESS_ANCESTOR_MASK | WITNESS_DESCENDANT_MASK)
#define	WITNESS_REVERSAL         0x10    /* A lock order reversal has been
					  * observed. */
#define	WITNESS_RESERVED1        0x20    /* Unused flag, reserved. */
#define	WITNESS_RESERVED2        0x40    /* Unused flag, reserved. */
#define	WITNESS_LOCK_ORDER_KNOWN 0x80    /* This lock order is known. */

/* Descendant to ancestor flags */
#define	WITNESS_DTOA(x)	(((x) & WITNESS_RELATED_MASK) >> 2)

/* Ancestor to descendant flags */
#define	WITNESS_ATOD(x)	(((x) & WITNESS_RELATED_MASK) << 2)

#define	WITNESS_INDEX_ASSERT(i)						\
	KASSERT((i) > 0 && (i) <= w_max_used_index && (i) < witness_count)

/*
 * Lock classes.  Each lock has a class which describes characteristics
 * common to all types of locks of a given class.
 *
 * Spin locks in general must always protect against preemption, as it is
 * an error to perform any type of context switch while holding a spin lock.
 * Also, for an individual lock to be recursable, its class must allow
 * recursion and the lock itself must explicitly allow recursion.
 */

struct lock_class {
	const		char *lc_name;
	u_int		lc_flags;
};

#define	LC_SLEEPLOCK	0x00000001	/* Sleep lock. */
#define	LC_SPINLOCK	0x00000002	/* Spin lock. */
#define	LC_SLEEPABLE	0x00000004	/* Sleeping allowed with this lock. */
#define	LC_RECURSABLE	0x00000008	/* Locks of this type may recurse. */
#define	LC_UPGRADABLE	0x00000010	/* Upgrades and downgrades permitted. */

/*
 * Lock instances.  A lock instance is the data associated with a lock while
 * it is held by witness.  For example, a lock instance will hold the
 * recursion count of a lock.  Lock instances are held in lists.  Spin locks
 * are held in a per-cpu list while sleep locks are held in per-thread list.
 */
struct lock_instance {
	struct lock_object	*li_lock;
	const char		*li_file;
	int			li_line;
	u_int			li_flags;
};

/*
 * A simple list type used to build the list of locks held by a thread
 * or CPU.  We can't simply embed the list in struct lock_object since a
 * lock may be held by more than one thread if it is a shared lock.  Locks
 * are added to the head of the list, so we fill up each list entry from
 * "the back" logically.  To ease some of the arithmetic, we actually fill
 * in each list entry the normal way (children[0] then children[1], etc.) but
 * when we traverse the list we read children[count-1] as the first entry
 * down to children[0] as the final entry.
 */
struct lock_list_entry {
	struct lock_list_entry	*ll_next;
	struct lock_instance	ll_children[LOCK_NCHILDREN];
	int			ll_count;
};

/*
 * The main witness structure. One of these per named lock type in the system
 * (for example, "vnode interlock").
 */
struct witness {
	struct lock_type	*w_type;
	const char		*w_subtype;
	uint32_t		w_index;  /* Index in the relationship matrix */
	struct lock_class	*w_class;
	SIMPLEQ_ENTRY(witness)	w_list;		/* List of all witnesses. */
	SIMPLEQ_ENTRY(witness)	w_typelist;	/* Witnesses of a type. */
	struct witness		*w_hash_next; /* Linked list in hash buckets. */
	const char		*w_file; /* File where last acquired */
	uint32_t		w_line; /* Line where last acquired */
	uint16_t		w_num_ancestors; /* direct/indirect
						  * ancestor count */
	uint16_t		w_num_descendants; /* direct/indirect
						    * descendant count */
	int16_t			w_ddb_level;
	unsigned		w_displayed:1;
	unsigned		w_reversed:1;
};

SIMPLEQ_HEAD(witness_list, witness);

/*
 * The witness hash table. Keys are witness names (const char *), elements are
 * witness objects (struct witness *).
 */
struct witness_hash {
	struct witness	*wh_array[WITNESS_HASH_SIZE];
	uint32_t	wh_size;
	uint32_t	wh_count;
};

/*
 * Key type for the lock order data hash table.
 */
struct witness_lock_order_key {
	uint16_t	from;
	uint16_t	to;
};

struct witness_lock_order_data {
	struct db_stack_trace		wlod_stack;
	struct witness_lock_order_key	wlod_key;
	struct witness_lock_order_data	*wlod_next;
};

/*
 * The witness lock order data hash table. Keys are witness index tuples
 * (struct witness_lock_order_key), elements are lock order data objects
 * (struct witness_lock_order_data).
 */
struct witness_lock_order_hash {
	struct witness_lock_order_data	*wloh_array[WITNESS_LO_HASH_SIZE];
	u_int	wloh_size;
	u_int	wloh_count;
};

struct witness_pendhelp {
	struct lock_type	*wh_type;
	struct lock_object	*wh_lock;
};

struct witness_cpu {
	struct lock_list_entry	*wc_spinlocks;
};

struct witness_cpu witness_cpu[MAXCPUS];

/*
 * Returns 0 if one of the locks is a spin lock and the other is not.
 * Returns 1 otherwise.
 */
static __inline int
witness_lock_type_equal(struct witness *w1, struct witness *w2)
{

	return ((w1->w_class->lc_flags & (LC_SLEEPLOCK | LC_SPINLOCK)) ==
		(w2->w_class->lc_flags & (LC_SLEEPLOCK | LC_SPINLOCK)));
}

static __inline int
witness_lock_order_key_equal(const struct witness_lock_order_key *a,
    const struct witness_lock_order_key *b)
{

	return (a->from == b->from && a->to == b->to);
}

static int	_isitmyx(struct witness *w1, struct witness *w2, int rmask,
		    const char *fname);
static void	adopt(struct witness *parent, struct witness *child);
static struct witness	*enroll(struct lock_type *, const char *,
			    struct lock_class *);
static struct lock_instance	*find_instance(struct lock_list_entry *list,
				    const struct lock_object *lock);
static int	isitmychild(struct witness *parent, struct witness *child);
static int	isitmydescendant(struct witness *parent, struct witness *child);
static void	itismychild(struct witness *parent, struct witness *child);
#ifdef DDB
static void	db_witness_add_fullgraph(struct witness *parent);
static void	witness_ddb_compute_levels(void);
static void	witness_ddb_display(int(*)(const char *fmt, ...));
static void	witness_ddb_display_descendants(int(*)(const char *fmt, ...),
		    struct witness *, int indent);
static void	witness_ddb_display_list(int(*prnt)(const char *fmt, ...),
		    struct witness_list *list);
static void	witness_ddb_level_descendants(struct witness *parent, int l);
static void	witness_ddb_list(struct proc *td);
#endif
static void	witness_debugger(int cond, const char *msg);
static void	witness_free(struct witness *m);
static struct witness	*witness_get(void);
static uint32_t	witness_hash_djb2(const uint8_t *key, uint32_t size);
static struct witness	*witness_hash_get(struct lock_type *, const char *);
static void	witness_hash_put(struct witness *w);
static void	witness_init_hash_tables(void);
static void	witness_increment_graph_generation(void);
static int	witness_list_locks(struct lock_list_entry **,
		    int (*)(const char *, ...));
static void	witness_lock_list_free(struct lock_list_entry *lle);
static struct lock_list_entry	*witness_lock_list_get(void);
static int	witness_lock_order_add(struct witness *parent,
		    struct witness *child);
static int	witness_lock_order_check(struct witness *parent,
		    struct witness *child);
static struct witness_lock_order_data	*witness_lock_order_get(
					    struct witness *parent,
					    struct witness *child);
static void	witness_list_lock(struct lock_instance *instance,
		    int (*prnt)(const char *fmt, ...));
static int	witness_output(const char *fmt, ...)
		    __attribute__((__format__(__kprintf__, 1, 2)));
static int	witness_voutput(const char *fmt, va_list ap)
		    __attribute__((__format__(__kprintf__, 1, 0)));
static void	witness_setflag(struct lock_object *lock, int flag, int set);

/*
 * If set to 0, lock order checking is disabled.  If set to -1,
 * witness is completely disabled.  Otherwise witness performs full
 * lock order checking for all locks.  At runtime, lock order checking
 * may be toggled.  However, witness cannot be reenabled once it is
 * completely disabled.
 */
static int witness_watch = 1;

#ifdef WITNESS_SKIPSPIN
int	witness_skipspin = 1;
#else
int	witness_skipspin = 0;
#endif

int witness_count = WITNESS_COUNT;

/*
 * Output channel for witness messages.  By default we print to the console.
 */
enum witness_channel {
	WITNESS_CONSOLE,
	WITNESS_LOG,
	WITNESS_NONE,
};

static enum witness_channel witness_channel = WITNESS_CONSOLE;

static struct mutex w_mtx;

/* w_list */
static struct witness_list w_free = SIMPLEQ_HEAD_INITIALIZER(w_free);
static struct witness_list w_all = SIMPLEQ_HEAD_INITIALIZER(w_all);

/* w_typelist */
static struct witness_list w_spin = SIMPLEQ_HEAD_INITIALIZER(w_spin);
static struct witness_list w_sleep = SIMPLEQ_HEAD_INITIALIZER(w_sleep);

/* lock list */
static struct lock_list_entry *w_lock_list_free = NULL;
static struct witness_pendhelp pending_locks[WITNESS_PENDLIST];
static u_int pending_cnt;

static int w_free_cnt, w_spin_cnt, w_sleep_cnt;

static struct witness *w_data;
static uint8_t **w_rmatrix;
static struct lock_list_entry w_locklistdata[LOCK_CHILDCOUNT];
static struct witness_hash w_hash;	/* The witness hash table. */

/* The lock order data hash */
static struct witness_lock_order_data w_lodata[WITNESS_LO_DATA_COUNT];
static struct witness_lock_order_data *w_lofree = NULL;
static struct witness_lock_order_hash w_lohash;
static int w_max_used_index = 0;
static unsigned int w_generation = 0;

static struct lock_class lock_class_kernel_lock = {
	.lc_name = "kernel_lock",
	.lc_flags = LC_SLEEPLOCK | LC_RECURSABLE | LC_SLEEPABLE
};

static struct lock_class lock_class_sched_lock = {
	.lc_name = "sched_lock",
	.lc_flags = LC_SPINLOCK | LC_RECURSABLE
};

static struct lock_class lock_class_mutex = {
	.lc_name = "mutex",
	.lc_flags = LC_SPINLOCK
};

static struct lock_class lock_class_rwlock = {
	.lc_name = "rwlock",
	.lc_flags = LC_SLEEPLOCK | LC_SLEEPABLE | LC_UPGRADABLE
};

static struct lock_class lock_class_rrwlock = {
	.lc_name = "rrwlock",
	.lc_flags = LC_SLEEPLOCK | LC_RECURSABLE | LC_SLEEPABLE |
	    LC_UPGRADABLE
};

static struct lock_class *lock_classes[] = {
	&lock_class_kernel_lock,
	&lock_class_sched_lock,
	&lock_class_mutex,
	&lock_class_rwlock,
	&lock_class_rrwlock,
};

/*
 * This global is set to 0 once it becomes safe to use the witness code.
 */
static int witness_cold = 1;

/*
 * This global is set to 1 once the static lock orders have been enrolled
 * so that a warning can be issued for any spin locks enrolled later.
 */
static int witness_spin_warn = 0;

/* Trim useless garbage from filenames. */
static const char *
fixup_filename(const char *file)
{

	if (file == NULL)
		return (NULL);
	while (strncmp(file, "../", 3) == 0)
		file += 3;
	return (file);
}

/*
 * The WITNESS-enabled diagnostic code.  Note that the witness code does
 * assume that the early boot is single-threaded at least until after this
 * routine is completed.
 */
void
witness_initialize(void)
{
	struct lock_object *lock;
	struct witness *w;
	int i;

	w_data = (void *)uvm_pageboot_alloc(sizeof(struct witness) *
	    witness_count);
	memset(w_data, 0, sizeof(struct witness) * witness_count);

	w_rmatrix = (void *)uvm_pageboot_alloc(sizeof(*w_rmatrix) *
	    (witness_count + 1));

	for (i = 0; i < witness_count + 1; i++) {
		w_rmatrix[i] = (void *)uvm_pageboot_alloc(
		    sizeof(*w_rmatrix[i]) * (witness_count + 1));
		memset(w_rmatrix[i], 0, sizeof(*w_rmatrix[i]) *
		    (witness_count + 1));
	}

	mtx_init_flags(&w_mtx, IPL_HIGH, "witness lock", MTX_NOWITNESS);
	for (i = witness_count - 1; i >= 0; i--) {
		w = &w_data[i];
		memset(w, 0, sizeof(*w));
		w_data[i].w_index = i;	/* Witness index never changes. */
		witness_free(w);
	}
	KASSERTMSG(SIMPLEQ_FIRST(&w_free)->w_index == 0,
	    "%s: Invalid list of free witness objects", __func__);

	/* Witness with index 0 is not used to aid in debugging. */
	SIMPLEQ_REMOVE_HEAD(&w_free, w_list);
	w_free_cnt--;

	for (i = 0; i < witness_count; i++) {
		memset(w_rmatrix[i], 0, sizeof(*w_rmatrix[i]) *
		    (witness_count + 1));
	}

	for (i = 0; i < LOCK_CHILDCOUNT; i++)
		witness_lock_list_free(&w_locklistdata[i]);
	witness_init_hash_tables();
	witness_spin_warn = 1;

	/* Iterate through all locks and add them to witness. */
	for (i = 0; pending_locks[i].wh_lock != NULL; i++) {
		lock = pending_locks[i].wh_lock;
		KASSERTMSG(lock->lo_flags & LO_WITNESS,
		    "%s: lock %s is on pending list but not LO_WITNESS",
		    __func__, lock->lo_name);
		lock->lo_witness = enroll(pending_locks[i].wh_type,
		    lock->lo_name, LOCK_CLASS(lock));
	}

	/* Mark the witness code as being ready for use. */
	witness_cold = 0;
}

void
witness_init(struct lock_object *lock, struct lock_type *type)
{
	struct lock_class *class;

	/* Various sanity checks. */
	class = LOCK_CLASS(lock);
	if ((lock->lo_flags & LO_RECURSABLE) != 0 &&
	    (class->lc_flags & LC_RECURSABLE) == 0)
		panic("%s: lock (%s) %s can not be recursable",
		    __func__, class->lc_name, lock->lo_name);
	if ((lock->lo_flags & LO_SLEEPABLE) != 0 &&
	    (class->lc_flags & LC_SLEEPABLE) == 0)
		panic("%s: lock (%s) %s can not be sleepable",
		    __func__, class->lc_name, lock->lo_name);
	if ((lock->lo_flags & LO_UPGRADABLE) != 0 &&
	    (class->lc_flags & LC_UPGRADABLE) == 0)
		panic("%s: lock (%s) %s can not be upgradable",
		    __func__, class->lc_name, lock->lo_name);

	/*
	 * If we shouldn't watch this lock, then just clear lo_witness.
	 * Record the type in case the lock becomes watched later.
	 * Otherwise, if witness_cold is set, then it is too early to
	 * enroll this lock, so defer it to witness_initialize() by adding
	 * it to the pending_locks list.  If it is not too early, then enroll
	 * the lock now.
	 */
	if (witness_watch < 1 || panicstr != NULL || db_active ||
	    (lock->lo_flags & LO_WITNESS) == 0) {
		lock->lo_witness = NULL;
		lock->lo_type = type;
	} else if (witness_cold) {
		pending_locks[pending_cnt].wh_lock = lock;
		pending_locks[pending_cnt++].wh_type = type;
		if (pending_cnt > WITNESS_PENDLIST)
			panic("%s: pending locks list is too small, "
			    "increase WITNESS_PENDLIST\n",
			    __func__);
	} else
		lock->lo_witness = enroll(type, lock->lo_name, class);
}

#ifdef DDB
static void
witness_ddb_compute_levels(void)
{
	struct witness *w;

	/*
	 * First clear all levels.
	 */
	SIMPLEQ_FOREACH(w, &w_all, w_list)
		w->w_ddb_level = -1;

	/*
	 * Look for locks with no parents and level all their descendants.
	 */
	SIMPLEQ_FOREACH(w, &w_all, w_list) {

		/* If the witness has ancestors (is not a root), skip it. */
		if (w->w_num_ancestors > 0)
			continue;
		witness_ddb_level_descendants(w, 0);
	}
}

static void
witness_ddb_level_descendants(struct witness *w, int l)
{
	int i;

	if (w->w_ddb_level >= l)
		return;

	w->w_ddb_level = l;
	l++;

	for (i = 1; i <= w_max_used_index; i++) {
		if (w_rmatrix[w->w_index][i] & WITNESS_PARENT)
			witness_ddb_level_descendants(&w_data[i], l);
	}
}

static void
witness_ddb_display_descendants(int(*prnt)(const char *fmt, ...),
    struct witness *w, int indent)
{
	int i;

	for (i = 0; i < indent; i++)
		prnt(" ");
	prnt("%s (type: %s, depth: %d)",
	     w->w_type->lt_name, w->w_class->lc_name, w->w_ddb_level);
	if (w->w_displayed) {
		prnt(" -- (already displayed)\n");
		return;
	}
	w->w_displayed = 1;
	if (w->w_file != NULL && w->w_line != 0)
		prnt(" -- last acquired @ %s:%d\n", fixup_filename(w->w_file),
		    w->w_line);
	else
		prnt(" -- never acquired\n");
	indent++;
	WITNESS_INDEX_ASSERT(w->w_index);
	for (i = 1; i <= w_max_used_index; i++) {
		if (w_rmatrix[w->w_index][i] & WITNESS_PARENT)
			witness_ddb_display_descendants(prnt, &w_data[i],
			    indent);
	}
}

static void
witness_ddb_display_list(int(*prnt)(const char *fmt, ...),
    struct witness_list *list)
{
	struct witness *w;

	SIMPLEQ_FOREACH(w, list, w_typelist) {
		if (w->w_file == NULL || w->w_ddb_level > 0)
			continue;

		/* This lock has no anscestors - display its descendants. */
		witness_ddb_display_descendants(prnt, w, 0);
	}
}

static void
witness_ddb_display(int(*prnt)(const char *fmt, ...))
{
	struct witness *w;

	KASSERTMSG(witness_cold == 0, "%s: witness_cold", __func__);
	witness_ddb_compute_levels();

	/* Clear all the displayed flags. */
	SIMPLEQ_FOREACH(w, &w_all, w_list)
		w->w_displayed = 0;

	/*
	 * First, handle sleep locks which have been acquired at least
	 * once.
	 */
	prnt("Sleep locks:\n");
	witness_ddb_display_list(prnt, &w_sleep);

	/*
	 * Now do spin locks which have been acquired at least once.
	 */
	prnt("\nSpin locks:\n");
	witness_ddb_display_list(prnt, &w_spin);

	/*
	 * Finally, any locks which have not been acquired yet.
	 */
	prnt("\nLocks which were never acquired:\n");
	SIMPLEQ_FOREACH(w, &w_all, w_list) {
		if (w->w_file != NULL)
			continue;
		prnt("%s (type: %s, depth: %d)\n", w->w_type->lt_name,
		    w->w_class->lc_name, w->w_ddb_level);
	}
}
#endif /* DDB */

int
witness_defineorder(struct lock_object *lock1, struct lock_object *lock2)
{

	if (witness_watch < 0 || panicstr != NULL || db_active)
		return (0);

	/* Require locks that witness knows about. */
	if (lock1 == NULL || lock1->lo_witness == NULL || lock2 == NULL ||
	    lock2->lo_witness == NULL)
		return (EINVAL);

	MUTEX_ASSERT_UNLOCKED(&w_mtx);
	mtx_enter(&w_mtx);

	/*
	 * If we already have either an explicit or implied lock order that
	 * is the other way around, then return an error.
	 */
	if (witness_watch &&
	    isitmydescendant(lock2->lo_witness, lock1->lo_witness)) {
		mtx_leave(&w_mtx);
		return (EINVAL);
	}

	/* Try to add the new order. */
	itismychild(lock1->lo_witness, lock2->lo_witness);
	mtx_leave(&w_mtx);
	return (0);
}

void
witness_checkorder(struct lock_object *lock, int flags, const char *file,
    int line, struct lock_object *interlock)
{
	struct lock_list_entry *lock_list, *lle;
	struct lock_instance *lock1, *lock2, *plock;
	struct lock_class *class, *iclass;
	struct proc *p;
	struct witness *w, *w1;
	int i, j, s;

	if (witness_cold || witness_watch < 1 || panicstr != NULL ||
	    db_active || (lock->lo_flags & LO_WITNESS) == 0)
		return;

	w = lock->lo_witness;
	class = LOCK_CLASS(lock);

	if (w == NULL)
		w = lock->lo_witness =
		    enroll(lock->lo_type, lock->lo_name, class);

	p = curproc;

	if (class->lc_flags & LC_SLEEPLOCK) {
		/*
		 * Since spin locks include a critical section, this check
		 * implicitly enforces a lock order of all sleep locks before
		 * all spin locks.
		 */
		lock_list = witness_cpu[cpu_number()].wc_spinlocks;
		if (lock_list != NULL && lock_list->ll_count > 0) {
			panic("acquiring blockable sleep lock with "
			    "spinlock or critical section held (%s) %s @ %s:%d",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
		}

		/*
		 * If this is the first lock acquired then just return as
		 * no order checking is needed.
		 */
		lock_list = p->p_sleeplocks;
		if (lock_list == NULL || lock_list->ll_count == 0)
			return;
	} else {

		/*
		 * If this is the first lock, just return as no order
		 * checking is needed.
		 */
		lock_list = witness_cpu[cpu_number()].wc_spinlocks;
		if (lock_list == NULL || lock_list->ll_count == 0)
			return;
	}

	s = splhigh();

	/*
	 * Check to see if we are recursing on a lock we already own.  If
	 * so, make sure that we don't mismatch exclusive and shared lock
	 * acquires.
	 */
	lock1 = find_instance(lock_list, lock);
	if (lock1 != NULL) {
		if ((lock1->li_flags & LI_EXCLUSIVE) != 0 &&
		    (flags & LOP_EXCLUSIVE) == 0) {
			witness_output("shared lock of (%s) %s @ %s:%d\n",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
			witness_output("while exclusively locked from %s:%d\n",
			    fixup_filename(lock1->li_file), lock1->li_line);
			panic("excl->share");
		}
		if ((lock1->li_flags & LI_EXCLUSIVE) == 0 &&
		    (flags & LOP_EXCLUSIVE) != 0) {
			witness_output("exclusive lock of (%s) %s @ %s:%d\n",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
			witness_output("while share locked from %s:%d\n",
			    fixup_filename(lock1->li_file), lock1->li_line);
			panic("share->excl");
		}
		goto out_splx;
	}

	/* Warn if the interlock is not locked exactly once. */
	if (interlock != NULL) {
		iclass = LOCK_CLASS(interlock);
		lock1 = find_instance(lock_list, interlock);
		if (lock1 == NULL)
			panic("interlock (%s) %s not locked @ %s:%d",
			    iclass->lc_name, interlock->lo_name,
			    fixup_filename(file), line);
		else if ((lock1->li_flags & LI_RECURSEMASK) != 0)
			panic("interlock (%s) %s recursed @ %s:%d",
			    iclass->lc_name, interlock->lo_name,
			    fixup_filename(file), line);
	}

	/*
	 * Find the previously acquired lock, but ignore interlocks.
	 */
	plock = &lock_list->ll_children[lock_list->ll_count - 1];
	if (interlock != NULL && plock->li_lock == interlock) {
		if (lock_list->ll_count > 1)
			plock =
			    &lock_list->ll_children[lock_list->ll_count - 2];
		else {
			lle = lock_list->ll_next;

			/*
			 * The interlock is the only lock we hold, so
			 * simply return.
			 */
			if (lle == NULL)
				goto out_splx;
			plock = &lle->ll_children[lle->ll_count - 1];
		}
	}

	/*
	 * Try to perform most checks without a lock.  If this succeeds we
	 * can skip acquiring the lock and return success.  Otherwise we redo
	 * the check with the lock held to handle races with concurrent updates.
	 */
	w1 = plock->li_lock->lo_witness;
	if (witness_lock_order_check(w1, w))
		goto out_splx;

	mtx_enter(&w_mtx);
	if (witness_lock_order_check(w1, w))
		goto out;

	witness_lock_order_add(w1, w);

	/*
	 * Check for duplicate locks of the same type.  Note that we only
	 * have to check for this on the last lock we just acquired.  Any
	 * other cases will be caught as lock order violations.
	 */
	if (w1 == w) {
		i = w->w_index;
		if (!(lock->lo_flags & LO_DUPOK) && !(flags & LOP_DUPOK) &&
		    !(w_rmatrix[i][i] & WITNESS_REVERSAL)) {
		    w_rmatrix[i][i] |= WITNESS_REVERSAL;
			w->w_reversed = 1;
			mtx_leave(&w_mtx);
			witness_output(
			    "acquiring duplicate lock of same type: \"%s\"\n",
			    w->w_type->lt_name);
			witness_output(" 1st %s @ %s:%d\n", plock->li_lock->lo_name,
			    fixup_filename(plock->li_file), plock->li_line);
			witness_output(" 2nd %s @ %s:%d\n", lock->lo_name,
			    fixup_filename(file), line);
			witness_debugger(1, __func__);
		} else
			mtx_leave(&w_mtx);
		goto out_splx;
	}
	MUTEX_ASSERT_LOCKED(&w_mtx);

	/*
	 * If we know that the lock we are acquiring comes after
	 * the lock we most recently acquired in the lock order tree,
	 * then there is no need for any further checks.
	 */
	if (isitmychild(w1, w))
		goto out;

	for (j = 0, lle = lock_list; lle != NULL; lle = lle->ll_next) {
		for (i = lle->ll_count - 1; i >= 0; i--, j++) {

			KASSERT(j < LOCK_CHILDCOUNT * LOCK_NCHILDREN);
			lock1 = &lle->ll_children[i];

			/*
			 * Ignore the interlock.
			 */
			if (interlock == lock1->li_lock)
				continue;

			/*
			 * If this lock doesn't undergo witness checking,
			 * then skip it.
			 */
			w1 = lock1->li_lock->lo_witness;
			if (w1 == NULL) {
				KASSERTMSG((lock1->li_lock->lo_flags &
				    LO_WITNESS) == 0,
				    "lock missing witness structure");
				continue;
			}

			/*
			 * If we are locking Giant and this is a sleepable
			 * lock, then skip it.
			 */
			if ((lock1->li_lock->lo_flags & LO_SLEEPABLE) != 0 &&
			    lock == &kernel_lock.mpl_lock_obj)
				continue;

			/*
			 * If we are locking a sleepable lock and this lock
			 * is Giant, then skip it.
			 */
			if ((lock->lo_flags & LO_SLEEPABLE) != 0 &&
			    lock1->li_lock == &kernel_lock.mpl_lock_obj)
				continue;

			/*
			 * If we are locking a sleepable lock and this lock
			 * isn't sleepable, we want to treat it as a lock
			 * order violation to enfore a general lock order of
			 * sleepable locks before non-sleepable locks.
			 */
			if (((lock->lo_flags & LO_SLEEPABLE) != 0 &&
			    (lock1->li_lock->lo_flags & LO_SLEEPABLE) == 0))
				goto reversal;

			/*
			 * If we are locking Giant and this is a non-sleepable
			 * lock, then treat it as a reversal.
			 */
			if ((lock1->li_lock->lo_flags & LO_SLEEPABLE) == 0 &&
			    lock == &kernel_lock.mpl_lock_obj)
				goto reversal;

			/*
			 * Check the lock order hierarchy for a reveresal.
			 */
			if (!isitmydescendant(w, w1))
				continue;
		reversal:

			/*
			 * We have a lock order violation, check to see if it
			 * is allowed or has already been yelled about.
			 */

			/* Bail if this violation is known */
			if (w_rmatrix[w1->w_index][w->w_index] & WITNESS_REVERSAL)
				goto out;

			/* Record this as a violation */
			w_rmatrix[w1->w_index][w->w_index] |= WITNESS_REVERSAL;
			w_rmatrix[w->w_index][w1->w_index] |= WITNESS_REVERSAL;
			w->w_reversed = w1->w_reversed = 1;
			witness_increment_graph_generation();
			mtx_leave(&w_mtx);

			/*
			 * There are known LORs between VNODE locks. They are
			 * not an indication of a bug. VNODE locks are flagged
			 * as such (LO_IS_VNODE) and we don't yell if the LOR
			 * is between 2 VNODE locks.
			 */
			if ((lock->lo_flags & LO_IS_VNODE) != 0 &&
			    (lock1->li_lock->lo_flags & LO_IS_VNODE) != 0)
				goto out_splx;

			/*
			 * Ok, yell about it.
			 */
			if (((lock->lo_flags & LO_SLEEPABLE) != 0 &&
			    (lock1->li_lock->lo_flags & LO_SLEEPABLE) == 0))
				witness_output(
		"lock order reversal: (sleepable after non-sleepable)\n");
			else if ((lock1->li_lock->lo_flags & LO_SLEEPABLE) == 0
			    && lock == &kernel_lock.mpl_lock_obj)
				witness_output(
		"lock order reversal: (Giant after non-sleepable)\n");
			else
				witness_output("lock order reversal:\n");

			/*
			 * Try to locate an earlier lock with
			 * witness w in our list.
			 */
			do {
				lock2 = &lle->ll_children[i];
				KASSERT(lock2->li_lock != NULL);
				if (lock2->li_lock->lo_witness == w)
					break;
				if (i == 0 && lle->ll_next != NULL) {
					lle = lle->ll_next;
					i = lle->ll_count - 1;
					KASSERT(i >= 0 && i < LOCK_NCHILDREN);
				} else
					i--;
			} while (i >= 0);
			if (i < 0) {
				witness_output(" 1st %p %s (%s) @ %s:%d\n",
				    lock1->li_lock, lock1->li_lock->lo_name,
				    w1->w_type->lt_name,
				    fixup_filename(lock1->li_file),
				    lock1->li_line);
				witness_output(" 2nd %p %s (%s) @ %s:%d\n",
				    lock, lock->lo_name, w->w_type->lt_name,
				    fixup_filename(file), line);
			} else {
				witness_output(" 1st %p %s (%s) @ %s:%d\n",
				    lock2->li_lock, lock2->li_lock->lo_name,
				    lock2->li_lock->lo_witness->w_type->lt_name,
				    fixup_filename(lock2->li_file),
				    lock2->li_line);
				witness_output(" 2nd %p %s (%s) @ %s:%d\n",
				    lock1->li_lock, lock1->li_lock->lo_name,
				    w1->w_type->lt_name,
				    fixup_filename(lock1->li_file),
				    lock1->li_line);
				witness_output(" 3rd %p %s (%s) @ %s:%d\n", lock,
				    lock->lo_name, w->w_type->lt_name,
				    fixup_filename(file), line);
			}
			witness_debugger(1, __func__);
			goto out_splx;
		}
	}

	/*
	 * If requested, build a new lock order.  However, don't build a new
	 * relationship between a sleepable lock and Giant if it is in the
	 * wrong direction.  The correct lock order is that sleepable locks
	 * always come before Giant.
	 */
	if (flags & LOP_NEWORDER &&
	    !(plock->li_lock == &kernel_lock.mpl_lock_obj &&
	    (lock->lo_flags & LO_SLEEPABLE) != 0))
		itismychild(plock->li_lock->lo_witness, w);
out:
	mtx_leave(&w_mtx);
out_splx:
	splx(s);
}

void
witness_lock(struct lock_object *lock, int flags, const char *file, int line)
{
	struct lock_list_entry **lock_list, *lle;
	struct lock_instance *instance;
	struct proc *p;
	struct witness *w;
	int s;

	if (witness_cold || witness_watch < 0 || panicstr != NULL ||
	    db_active || (lock->lo_flags & LO_WITNESS) == 0)
		return;

	w = lock->lo_witness;
	if (w == NULL)
		w = lock->lo_witness =
		    enroll(lock->lo_type, lock->lo_name, LOCK_CLASS(lock));

	p = curproc;

	/* Determine lock list for this lock. */
	if (LOCK_CLASS(lock)->lc_flags & LC_SLEEPLOCK)
		lock_list = &p->p_sleeplocks;
	else
		lock_list = &witness_cpu[cpu_number()].wc_spinlocks;

	s = splhigh();

	/* Check to see if we are recursing on a lock we already own. */
	instance = find_instance(*lock_list, lock);
	if (instance != NULL) {
		instance->li_flags++;
		instance->li_file = file;
		instance->li_line = line;
		goto out;
	}

	/* Update per-witness last file and line acquire. */
	w->w_file = file;
	w->w_line = line;

	/* Find the next open lock instance in the list and fill it. */
	lle = *lock_list;
	if (lle == NULL || lle->ll_count == LOCK_NCHILDREN) {
		lle = witness_lock_list_get();
		if (lle == NULL)
			goto out;
		lle->ll_next = *lock_list;
		*lock_list = lle;
	}
	instance = &lle->ll_children[lle->ll_count++];
	instance->li_lock = lock;
	instance->li_line = line;
	instance->li_file = file;
	if ((flags & LOP_EXCLUSIVE) != 0)
		instance->li_flags = LI_EXCLUSIVE;
	else
		instance->li_flags = 0;
out:
	splx(s);
}

void
witness_upgrade(struct lock_object *lock, int flags, const char *file, int line)
{
	struct lock_instance *instance;
	struct lock_class *class;
	int s;

	KASSERTMSG(witness_cold == 0, "%s: witness_cold", __func__);
	if (lock->lo_witness == NULL || witness_watch < 0 ||
	    panicstr != NULL || db_active)
		return;
	class = LOCK_CLASS(lock);
	if (witness_watch) {
		if ((lock->lo_flags & LO_UPGRADABLE) == 0)
			panic("upgrade of non-upgradable lock (%s) %s @ %s:%d",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
		if ((class->lc_flags & LC_SLEEPLOCK) == 0)
			panic("upgrade of non-sleep lock (%s) %s @ %s:%d",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
	}
	s = splhigh();
	instance = find_instance(curproc->p_sleeplocks, lock);
	if (instance == NULL) {
		panic("upgrade of unlocked lock (%s) %s @ %s:%d",
		    class->lc_name, lock->lo_name,
		    fixup_filename(file), line);
		goto out;
	}
	if (witness_watch) {
		if ((instance->li_flags & LI_EXCLUSIVE) != 0)
			panic("upgrade of exclusive lock (%s) %s @ %s:%d",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
		if ((instance->li_flags & LI_RECURSEMASK) != 0)
			panic("upgrade of recursed lock (%s) %s r=%d @ %s:%d",
			    class->lc_name, lock->lo_name,
			    instance->li_flags & LI_RECURSEMASK,
			    fixup_filename(file), line);
	}
	instance->li_flags |= LI_EXCLUSIVE;
out:
	splx(s);
}

void
witness_downgrade(struct lock_object *lock, int flags, const char *file,
    int line)
{
	struct lock_instance *instance;
	struct lock_class *class;
	int s;

	KASSERTMSG(witness_cold == 0, "%s: witness_cold", __func__);
	if (lock->lo_witness == NULL || witness_watch < 0 ||
	    panicstr != NULL || db_active)
		return;
	class = LOCK_CLASS(lock);
	if (witness_watch) {
		if ((lock->lo_flags & LO_UPGRADABLE) == 0)
			panic(
			    "downgrade of non-upgradable lock (%s) %s @ %s:%d",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
		if ((class->lc_flags & LC_SLEEPLOCK) == 0)
			panic("downgrade of non-sleep lock (%s) %s @ %s:%d",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
	}
	s = splhigh();
	instance = find_instance(curproc->p_sleeplocks, lock);
	if (instance == NULL) {
		panic("downgrade of unlocked lock (%s) %s @ %s:%d",
		    class->lc_name, lock->lo_name,
		    fixup_filename(file), line);
		goto out;
	}
	if (witness_watch) {
		if ((instance->li_flags & LI_EXCLUSIVE) == 0)
			panic("downgrade of shared lock (%s) %s @ %s:%d",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
		if ((instance->li_flags & LI_RECURSEMASK) != 0)
			panic("downgrade of recursed lock (%s) %s r=%d @ %s:%d",
			    class->lc_name, lock->lo_name,
			    instance->li_flags & LI_RECURSEMASK,
			    fixup_filename(file), line);
	}
	instance->li_flags &= ~LI_EXCLUSIVE;
out:
	splx(s);
}

void
witness_unlock(struct lock_object *lock, int flags, const char *file, int line)
{
	struct lock_list_entry **lock_list, *lle;
	struct lock_instance *instance;
	struct lock_class *class;
	struct proc *p;
	int i, j;
	int s;

	if (witness_cold || lock->lo_witness == NULL ||
	    panicstr != NULL || db_active)
		return;
	p = curproc;
	class = LOCK_CLASS(lock);

	/* Find lock instance associated with this lock. */
	if (class->lc_flags & LC_SLEEPLOCK)
		lock_list = &p->p_sleeplocks;
	else
		lock_list = &witness_cpu[cpu_number()].wc_spinlocks;

	s = splhigh();

	lle = *lock_list;
	for (; *lock_list != NULL; lock_list = &(*lock_list)->ll_next)
		for (i = 0; i < (*lock_list)->ll_count; i++) {
			instance = &(*lock_list)->ll_children[i];
			if (instance->li_lock == lock)
				goto found;
		}

	/*
	 * When disabling WITNESS through witness_watch we could end up in
	 * having registered locks in the p_sleeplocks queue.
	 * We have to make sure we flush these queues, so just search for
	 * eventual register locks and remove them.
	 */
	if (witness_watch > 0) {
		panic("lock (%s) %s not locked @ %s:%d", class->lc_name,
		    lock->lo_name, fixup_filename(file), line);
	}
	goto out;

found:

	/* First, check for shared/exclusive mismatches. */
	if ((instance->li_flags & LI_EXCLUSIVE) != 0 && witness_watch > 0 &&
	    (flags & LOP_EXCLUSIVE) == 0) {
		witness_output("shared unlock of (%s) %s @ %s:%d\n",
		    class->lc_name, lock->lo_name, fixup_filename(file), line);
		witness_output("while exclusively locked from %s:%d\n",
		    fixup_filename(instance->li_file), instance->li_line);
		panic("excl->ushare");
	}
	if ((instance->li_flags & LI_EXCLUSIVE) == 0 && witness_watch > 0 &&
	    (flags & LOP_EXCLUSIVE) != 0) {
		witness_output("exclusive unlock of (%s) %s @ %s:%d\n",
		    class->lc_name, lock->lo_name, fixup_filename(file), line);
		witness_output("while share locked from %s:%d\n",
		    fixup_filename(instance->li_file),
		    instance->li_line);
		panic("share->uexcl");
	}
	/* If we are recursed, unrecurse. */
	if ((instance->li_flags & LI_RECURSEMASK) > 0) {
		instance->li_flags--;
		goto out;
	}
	/* The lock is now being dropped, check for NORELEASE flag */
	if ((instance->li_flags & LI_NORELEASE) != 0 && witness_watch > 0) {
		witness_output("forbidden unlock of (%s) %s @ %s:%d\n",
		    class->lc_name, lock->lo_name, fixup_filename(file), line);
		panic("lock marked norelease");
	}

	/* Otherwise, remove this item from the list. */
	for (j = i; j < (*lock_list)->ll_count - 1; j++)
		(*lock_list)->ll_children[j] =
		    (*lock_list)->ll_children[j + 1];
	(*lock_list)->ll_count--;

	/*
	 * In order to reduce contention on w_mtx, we want to keep always an
	 * head object into lists so that frequent allocation from the
	 * free witness pool (and subsequent locking) is avoided.
	 * In order to maintain the current code simple, when the head
	 * object is totally unloaded it means also that we do not have
	 * further objects in the list, so the list ownership needs to be
	 * hand over to another object if the current head needs to be freed.
	 */
	if ((*lock_list)->ll_count == 0) {
		if (*lock_list == lle) {
			if (lle->ll_next == NULL)
				goto out;
		} else
			lle = *lock_list;
		*lock_list = lle->ll_next;
		witness_lock_list_free(lle);
	}
out:
	splx(s);
}

void
witness_thread_exit(struct proc *p)
{
	struct lock_list_entry *lle;
	int i, n;

	lle = p->p_sleeplocks;
	if (lle == NULL || panicstr != NULL || db_active)
		return;
	if (lle->ll_count != 0) {
		for (n = 0; lle != NULL; lle = lle->ll_next)
			for (i = lle->ll_count - 1; i >= 0; i--) {
				if (n == 0)
					witness_output("Thread %p exiting with "
					    "the following locks held:\n", p);
				n++;
				witness_list_lock(&lle->ll_children[i],
				    witness_output);
			}
		panic("Thread %p cannot exit while holding sleeplocks\n", p);
	}
	KASSERT(lle->ll_next == NULL);
	witness_lock_list_free(lle);
}

/*
 * Warn if any locks other than 'lock' are held.  Flags can be passed in to
 * exempt Giant and sleepable locks from the checks as well.  If any
 * non-exempt locks are held, then a supplied message is printed to the
 * output channel along with a list of the offending locks.  If indicated in the
 * flags then a failure results in a panic as well.
 */
int
witness_warn(int flags, struct lock_object *lock, const char *fmt, ...)
{
	struct lock_list_entry *lock_list, *lle;
	struct lock_instance *lock1;
	struct proc *p;
	va_list ap;
	int i, n;

	if (witness_cold || witness_watch < 1 || panicstr != NULL || db_active)
		return (0);
	n = 0;
	p = curproc;
	for (lle = p->p_sleeplocks; lle != NULL; lle = lle->ll_next)
		for (i = lle->ll_count - 1; i >= 0; i--) {
			lock1 = &lle->ll_children[i];
			if (lock1->li_lock == lock)
				continue;
			if (flags & WARN_KERNELOK &&
			    lock1->li_lock == &kernel_lock.mpl_lock_obj)
				continue;
			if (flags & WARN_SLEEPOK &&
			    (lock1->li_lock->lo_flags & LO_SLEEPABLE) != 0)
				continue;
			if (n == 0) {
				va_start(ap, fmt);
				vprintf(fmt, ap);
				va_end(ap);
				printf(" with the following %slocks held:\n",
				    (flags & WARN_SLEEPOK) != 0 ?
				    "non-sleepable " : "");
			}
			n++;
			witness_list_lock(lock1, printf);
		}

	lock_list = witness_cpu[cpu_number()].wc_spinlocks;
	if (lock_list != NULL && lock_list->ll_count != 0) {
		/*
		 * We should only have one spinlock and as long as
		 * the flags cannot match for this locks class,
		 * check if the first spinlock is the one curproc
		 * should hold.
		 */
		lock1 = &lock_list->ll_children[lock_list->ll_count - 1];
		if (lock_list->ll_count == 1 && lock_list->ll_next == NULL &&
		    lock1->li_lock == lock && n == 0)
			return (0);

		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
		printf(" with the following %slocks held:\n",
		    (flags & WARN_SLEEPOK) != 0 ?  "non-sleepable " : "");
		n += witness_list_locks(&lock_list, printf);
	}
	if (flags & WARN_PANIC && n)
		panic("%s", __func__);
	else
		witness_debugger(n, __func__);
	return (n);
}

const char *
witness_file(struct lock_object *lock)
{
	struct witness *w;

	if (witness_cold || witness_watch < 1 || lock->lo_witness == NULL)
		return ("?");
	w = lock->lo_witness;
	return (w->w_file);
}

int
witness_line(struct lock_object *lock)
{
	struct witness *w;

	if (witness_cold || witness_watch < 1 || lock->lo_witness == NULL)
		return (0);
	w = lock->lo_witness;
	return (w->w_line);
}

static struct witness *
enroll(struct lock_type *type, const char *subtype,
    struct lock_class *lock_class)
{
	struct witness *w;
	struct witness_list *typelist;

	KASSERT(type != NULL);

	if (witness_watch < 0 || panicstr != NULL || db_active)
		return (NULL);
	if ((lock_class->lc_flags & LC_SPINLOCK)) {
		if (witness_skipspin)
			return (NULL);
		else
			typelist = &w_spin;
	} else if ((lock_class->lc_flags & LC_SLEEPLOCK)) {
		typelist = &w_sleep;
	} else {
		panic("lock class %s is not sleep or spin",
		    lock_class->lc_name);
		return (NULL);
	}

	mtx_enter(&w_mtx);
	w = witness_hash_get(type, subtype);
	if (w)
		goto found;
	if ((w = witness_get()) == NULL)
		return (NULL);
	w->w_type = type;
	w->w_subtype = subtype;
	w->w_class = lock_class;
	SIMPLEQ_INSERT_HEAD(&w_all, w, w_list);
	if (lock_class->lc_flags & LC_SPINLOCK) {
		SIMPLEQ_INSERT_HEAD(&w_spin, w, w_typelist);
		w_spin_cnt++;
	} else if (lock_class->lc_flags & LC_SLEEPLOCK) {
		SIMPLEQ_INSERT_HEAD(&w_sleep, w, w_typelist);
		w_sleep_cnt++;
	}

	/* Insert new witness into the hash */
	witness_hash_put(w);
	witness_increment_graph_generation();
	mtx_leave(&w_mtx);
	return (w);
found:
	mtx_leave(&w_mtx);
	if (lock_class != w->w_class)
		panic("lock (%s) %s does not match earlier (%s) lock",
		    type->lt_name, lock_class->lc_name, w->w_class->lc_name);
	return (w);
}

static void
adopt(struct witness *parent, struct witness *child)
{
	int pi, ci, i, j;

	if (witness_cold == 0)
		MUTEX_ASSERT_LOCKED(&w_mtx);

	/* If the relationship is already known, there's no work to be done. */
	if (isitmychild(parent, child))
		return;

	/* When the structure of the graph changes, bump up the generation. */
	witness_increment_graph_generation();

	/*
	 * The hard part ... create the direct relationship, then propagate all
	 * indirect relationships.
	 */
	pi = parent->w_index;
	ci = child->w_index;
	WITNESS_INDEX_ASSERT(pi);
	WITNESS_INDEX_ASSERT(ci);
	KASSERT(pi != ci);
	w_rmatrix[pi][ci] |= WITNESS_PARENT;
	w_rmatrix[ci][pi] |= WITNESS_CHILD;

	/*
	 * If parent was not already an ancestor of child,
	 * then we increment the descendant and ancestor counters.
	 */
	if ((w_rmatrix[pi][ci] & WITNESS_ANCESTOR) == 0) {
		parent->w_num_descendants++;
		child->w_num_ancestors++;
	}

	/*
	 * Find each ancestor of 'pi'. Note that 'pi' itself is counted as
	 * an ancestor of 'pi' during this loop.
	 */
	for (i = 1; i <= w_max_used_index; i++) {
		if ((w_rmatrix[i][pi] & WITNESS_ANCESTOR_MASK) == 0 &&
		    (i != pi))
			continue;

		/* Find each descendant of 'i' and mark it as a descendant. */
		for (j = 1; j <= w_max_used_index; j++) {

			/*
			 * Skip children that are already marked as
			 * descendants of 'i'.
			 */
			if (w_rmatrix[i][j] & WITNESS_ANCESTOR_MASK)
				continue;

			/*
			 * We are only interested in descendants of 'ci'. Note
			 * that 'ci' itself is counted as a descendant of 'ci'.
			 */
			if ((w_rmatrix[ci][j] & WITNESS_ANCESTOR_MASK) == 0 &&
			    (j != ci))
				continue;
			w_rmatrix[i][j] |= WITNESS_ANCESTOR;
			w_rmatrix[j][i] |= WITNESS_DESCENDANT;
			w_data[i].w_num_descendants++;
			w_data[j].w_num_ancestors++;

			/*
			 * Make sure we aren't marking a node as both an
			 * ancestor and descendant. We should have caught
			 * this as a lock order reversal earlier.
			 */
			if ((w_rmatrix[i][j] & WITNESS_ANCESTOR_MASK) &&
			    (w_rmatrix[i][j] & WITNESS_DESCENDANT_MASK)) {
				printf("witness rmatrix paradox! [%d][%d]=%d "
				    "both ancestor and descendant\n",
				    i, j, w_rmatrix[i][j]);
#ifdef DDB
				db_stack_dump();
#endif
				printf("Witness disabled.\n");
				witness_watch = -1;
			}
			if ((w_rmatrix[j][i] & WITNESS_ANCESTOR_MASK) &&
			    (w_rmatrix[j][i] & WITNESS_DESCENDANT_MASK)) {
				printf("witness rmatrix paradox! [%d][%d]=%d "
				    "both ancestor and descendant\n",
				    j, i, w_rmatrix[j][i]);
#ifdef DDB
				db_stack_dump();
#endif
				printf("Witness disabled.\n");
				witness_watch = -1;
			}
		}
	}
}

static void
itismychild(struct witness *parent, struct witness *child)
{
	int unlocked;

	KASSERT(child != NULL && parent != NULL);
	if (witness_cold == 0)
		MUTEX_ASSERT_LOCKED(&w_mtx);

	if (!witness_lock_type_equal(parent, child)) {
		if (witness_cold == 0) {
			unlocked = 1;
			mtx_leave(&w_mtx);
		} else {
			unlocked = 0;
		}
		panic(
		    "%s: parent \"%s\" (%s) and child \"%s\" (%s) are not "
		    "the same lock type", __func__, parent->w_type->lt_name,
		    parent->w_class->lc_name, child->w_type->lt_name,
		    child->w_class->lc_name);
		if (unlocked)
			mtx_enter(&w_mtx);
	}
	adopt(parent, child);
}

/*
 * Generic code for the isitmy*() functions. The rmask parameter is the
 * expected relationship of w1 to w2.
 */
static int
_isitmyx(struct witness *w1, struct witness *w2, int rmask, const char *fname)
{
	unsigned char r1, r2;
	int i1, i2;

	i1 = w1->w_index;
	i2 = w2->w_index;
	WITNESS_INDEX_ASSERT(i1);
	WITNESS_INDEX_ASSERT(i2);
	r1 = w_rmatrix[i1][i2] & WITNESS_RELATED_MASK;
	r2 = w_rmatrix[i2][i1] & WITNESS_RELATED_MASK;

	/* The flags on one better be the inverse of the flags on the other */
	if (!((WITNESS_ATOD(r1) == r2 && WITNESS_DTOA(r2) == r1) ||
	    (WITNESS_DTOA(r1) == r2 && WITNESS_ATOD(r2) == r1))) {
		/* Don't squawk if we're potentially racing with an update. */
		if (w_mtx.mtx_owner != curcpu())
			return (0);
		printf("%s: rmatrix mismatch between %s (index %d) and %s "
		    "(index %d): w_rmatrix[%d][%d] == %x but "
		    "w_rmatrix[%d][%d] == %x\n",
		    fname, w1->w_type->lt_name, i1, w2->w_type->lt_name,
		    i2, i1, i2, r1,
		    i2, i1, r2);
#ifdef DDB
		db_stack_dump();
#endif
		printf("Witness disabled.\n");
		witness_watch = -1;
	}
	return (r1 & rmask);
}

/*
 * Checks if @child is a direct child of @parent.
 */
static int
isitmychild(struct witness *parent, struct witness *child)
{

	return (_isitmyx(parent, child, WITNESS_PARENT, __func__));
}

/*
 * Checks if @descendant is a direct or inderect descendant of @ancestor.
 */
static int
isitmydescendant(struct witness *ancestor, struct witness *descendant)
{

	return (_isitmyx(ancestor, descendant, WITNESS_ANCESTOR_MASK,
	    __func__));
}

static struct witness *
witness_get(void)
{
	struct witness *w;
	int index;

	if (witness_cold == 0)
		MUTEX_ASSERT_LOCKED(&w_mtx);

	if (witness_watch < 0) {
		mtx_leave(&w_mtx);
		return (NULL);
	}
	if (SIMPLEQ_EMPTY(&w_free)) {
		witness_watch = -1;
		mtx_leave(&w_mtx);
		printf("WITNESS: unable to allocate a new witness object\n");
		return (NULL);
	}
	w = SIMPLEQ_FIRST(&w_free);
	SIMPLEQ_REMOVE_HEAD(&w_free, w_list);
	w_free_cnt--;
	index = w->w_index;
	KASSERT(index > 0 && index == w_max_used_index + 1 &&
	    index < witness_count);
	bzero(w, sizeof(*w));
	w->w_index = index;
	if (index > w_max_used_index)
		w_max_used_index = index;
	return (w);
}

static void
witness_free(struct witness *w)
{

	SIMPLEQ_INSERT_HEAD(&w_free, w, w_list);
	w_free_cnt++;
}

static struct lock_list_entry *
witness_lock_list_get(void)
{
	struct lock_list_entry *lle;

	if (witness_watch < 0)
		return (NULL);
	mtx_enter(&w_mtx);
	lle = w_lock_list_free;
	if (lle == NULL) {
		witness_watch = -1;
		mtx_leave(&w_mtx);
		printf("%s: witness exhausted\n", __func__);
		return (NULL);
	}
	w_lock_list_free = lle->ll_next;
	mtx_leave(&w_mtx);
	bzero(lle, sizeof(*lle));
	return (lle);
}

static void
witness_lock_list_free(struct lock_list_entry *lle)
{
	mtx_enter(&w_mtx);
	lle->ll_next = w_lock_list_free;
	w_lock_list_free = lle;
	mtx_leave(&w_mtx);
}

static struct lock_instance *
find_instance(struct lock_list_entry *list, const struct lock_object *lock)
{
	struct lock_list_entry *lle;
	struct lock_instance *instance;
	int i;

	for (lle = list; lle != NULL; lle = lle->ll_next) {
		for (i = lle->ll_count - 1; i >= 0; i--) {
			instance = &lle->ll_children[i];
			if (instance->li_lock == lock)
				return (instance);
		}
	}
	return (NULL);
}

static void
witness_list_lock(struct lock_instance *instance,
    int (*prnt)(const char *fmt, ...))
{
	struct lock_object *lock;

	lock = instance->li_lock;
	prnt("%s %s %s", (instance->li_flags & LI_EXCLUSIVE) != 0 ?
	    "exclusive" : "shared", LOCK_CLASS(lock)->lc_name, lock->lo_name);
	prnt(" r = %d (%p) locked @ %s:%d\n",
	    instance->li_flags & LI_RECURSEMASK, lock,
	    fixup_filename(instance->li_file), instance->li_line);
}

static int
witness_output(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = witness_voutput(fmt, ap);
	va_end(ap);
	return (ret);
}

static int
witness_voutput(const char *fmt, va_list ap)
{
	int ret;

	ret = 0;
	switch (witness_channel) {
	case WITNESS_CONSOLE:
		ret = db_vprintf(fmt, ap);
		break;
	case WITNESS_LOG:
		log(LOG_NOTICE, fmt, ap);
		break;
	case WITNESS_NONE:
		break;
	}
	return (ret);
}

#ifdef DDB
static int
witness_thread_has_locks(struct proc *p)
{

	if (p->p_sleeplocks == NULL)
		return (0);
	return (p->p_sleeplocks->ll_count != 0);
}

static int
witness_process_has_locks(struct process *pr)
{
	struct proc *p;

	TAILQ_FOREACH(p, &pr->ps_threads, p_thr_link) {
		if (witness_thread_has_locks(p))
			return (1);
	}
	return (0);
}
#endif

int
witness_list_locks(struct lock_list_entry **lock_list,
    int (*prnt)(const char *fmt, ...))
{
	struct lock_list_entry *lle;
	int i, nheld;

	nheld = 0;
	for (lle = *lock_list; lle != NULL; lle = lle->ll_next)
		for (i = lle->ll_count - 1; i >= 0; i--) {
			witness_list_lock(&lle->ll_children[i], prnt);
			nheld++;
		}
	return (nheld);
}

/*
 * This is a bit risky at best.  We call this function when we have timed
 * out acquiring a spin lock, and we assume that the other CPU is stuck
 * with this lock held.  So, we go groveling around in the other CPU's
 * per-cpu data to try to find the lock instance for this spin lock to
 * see when it was last acquired.
 */
void
witness_display_spinlock(struct lock_object *lock, struct proc *owner,
    int (*prnt)(const char *fmt, ...))
{
	struct lock_instance *instance;

	if (owner->p_stat != SONPROC)
		return;
	instance = find_instance(
	    witness_cpu[owner->p_cpu->ci_cpuid].wc_spinlocks, lock);
	if (instance != NULL)
		witness_list_lock(instance, prnt);
}

void
witness_save(struct lock_object *lock, const char **filep, int *linep)
{
	struct lock_list_entry *lock_list;
	struct lock_instance *instance;
	struct lock_class *class;

	KASSERTMSG(witness_cold == 0, "%s: witness_cold", __func__);
	if (lock->lo_witness == NULL || witness_watch < 0 ||
	    panicstr != NULL || db_active)
		return;
	class = LOCK_CLASS(lock);
	if (class->lc_flags & LC_SLEEPLOCK)
		lock_list = curproc->p_sleeplocks;
	else {
		if (witness_skipspin)
			return;
		lock_list = witness_cpu[cpu_number()].wc_spinlocks;
	}
	instance = find_instance(lock_list, lock);
	if (instance == NULL) {
		panic("%s: lock (%s) %s not locked", __func__,
		    class->lc_name, lock->lo_name);
		return;
	}
	*filep = instance->li_file;
	*linep = instance->li_line;
}

void
witness_restore(struct lock_object *lock, const char *file, int line)
{
	struct lock_list_entry *lock_list;
	struct lock_instance *instance;
	struct lock_class *class;

	KASSERTMSG(witness_cold == 0, "%s: witness_cold", __func__);
	if (lock->lo_witness == NULL || witness_watch < 0 ||
	    panicstr != NULL || db_active)
		return;
	class = LOCK_CLASS(lock);
	if (class->lc_flags & LC_SLEEPLOCK)
		lock_list = curproc->p_sleeplocks;
	else {
		if (witness_skipspin)
			return;
		lock_list = witness_cpu[cpu_number()].wc_spinlocks;
	}
	instance = find_instance(lock_list, lock);
	if (instance == NULL)
		panic("%s: lock (%s) %s not locked", __func__,
		    class->lc_name, lock->lo_name);
	lock->lo_witness->w_file = file;
	lock->lo_witness->w_line = line;
	if (instance == NULL)
		return;
	instance->li_file = file;
	instance->li_line = line;
}

void
witness_assert(const struct lock_object *lock, int flags, const char *file,
    int line)
{
#ifdef INVARIANT_SUPPORT
	struct lock_instance *instance;
	struct lock_class *class;

	if (lock->lo_witness == NULL || witness_watch < 1 ||
	    panicstr != NULL || db_active)
		return;
	class = LOCK_CLASS(lock);
	if ((class->lc_flags & LC_SLEEPLOCK) != 0)
		instance = find_instance(curproc->p_sleeplocks, lock);
	else if ((class->lc_flags & LC_SPINLOCK) != 0)
		instance = find_instance(
		    witness_cpu[cpu_number()].wc_spinlocks, lock);
	else {
		panic("Lock (%s) %s is not sleep or spin!",
		    class->lc_name, lock->lo_name);
		return;
	}
	switch (flags) {
	case LA_UNLOCKED:
		if (instance != NULL)
			panic("Lock (%s) %s locked @ %s:%d.",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
		break;
	case LA_LOCKED:
	case LA_LOCKED | LA_RECURSED:
	case LA_LOCKED | LA_NOTRECURSED:
	case LA_SLOCKED:
	case LA_SLOCKED | LA_RECURSED:
	case LA_SLOCKED | LA_NOTRECURSED:
	case LA_XLOCKED:
	case LA_XLOCKED | LA_RECURSED:
	case LA_XLOCKED | LA_NOTRECURSED:
		if (instance == NULL) {
			panic("Lock (%s) %s not locked @ %s:%d.",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
			break;
		}
		if ((flags & LA_XLOCKED) != 0 &&
		    (instance->li_flags & LI_EXCLUSIVE) == 0)
			panic(
			    "Lock (%s) %s not exclusively locked @ %s:%d.",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
		if ((flags & LA_SLOCKED) != 0 &&
		    (instance->li_flags & LI_EXCLUSIVE) != 0)
			panic(
			    "Lock (%s) %s exclusively locked @ %s:%d.",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
		if ((flags & LA_RECURSED) != 0 &&
		    (instance->li_flags & LI_RECURSEMASK) == 0)
			panic("Lock (%s) %s not recursed @ %s:%d.",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
		if ((flags & LA_NOTRECURSED) != 0 &&
		    (instance->li_flags & LI_RECURSEMASK) != 0)
			panic("Lock (%s) %s recursed @ %s:%d.",
			    class->lc_name, lock->lo_name,
			    fixup_filename(file), line);
		break;
	default:
		panic("Invalid lock assertion at %s:%d.",
		    fixup_filename(file), line);

	}
#endif	/* INVARIANT_SUPPORT */
}

static void
witness_setflag(struct lock_object *lock, int flag, int set)
{
	struct lock_list_entry *lock_list;
	struct lock_instance *instance;
	struct lock_class *class;

	if (lock->lo_witness == NULL || witness_watch < 0 ||
	    panicstr != NULL || db_active)
		return;
	class = LOCK_CLASS(lock);
	if (class->lc_flags & LC_SLEEPLOCK)
		lock_list = curproc->p_sleeplocks;
	else {
		if (witness_skipspin)
			return;
		lock_list = witness_cpu[cpu_number()].wc_spinlocks;
	}
	instance = find_instance(lock_list, lock);
	if (instance == NULL) {
		panic("%s: lock (%s) %s not locked", __func__,
		    class->lc_name, lock->lo_name);
		return;
	}

	if (set)
		instance->li_flags |= flag;
	else
		instance->li_flags &= ~flag;
}

void
witness_norelease(struct lock_object *lock)
{

	witness_setflag(lock, LI_NORELEASE, 1);
}

void
witness_releaseok(struct lock_object *lock)
{

	witness_setflag(lock, LI_NORELEASE, 0);
}

#ifdef DDB
static void
witness_ddb_list(struct proc *p)
{
	struct witness_cpu *wc = &witness_cpu[cpu_number()];

	KASSERTMSG(witness_cold == 0, "%s: witness_cold", __func__);
	KASSERTMSG(db_is_active, "%s: not in the debugger", __func__);

	if (witness_watch < 1)
		return;

	witness_list_locks(&p->p_sleeplocks, db_printf);

	/*
	 * We only handle spinlocks if td == curproc.  This is somewhat broken
	 * if td is currently executing on some other CPU and holds spin locks
	 * as we won't display those locks.  If we had a MI way of getting
	 * the per-cpu data for a given cpu then we could use
	 * td->td_oncpu to get the list of spinlocks for this thread
	 * and "fix" this.
	 *
	 * That still wouldn't really fix this unless we locked the scheduler
	 * lock or stopped the other CPU to make sure it wasn't changing the
	 * list out from under us.  It is probably best to just not try to
	 * handle threads on other CPU's for now.
	 */
	if (p == curproc && wc->wc_spinlocks != NULL)
		witness_list_locks(&wc->wc_spinlocks, db_printf);
}

void
db_witness_list(db_expr_t addr, int have_addr, db_expr_t count, char *modif)
{
	struct proc *p;

	if (have_addr)
		p = (struct proc *)addr;
	else
		p = curproc;
	witness_ddb_list(p);
}

void
db_witness_list_all(db_expr_t addr, int have_addr, db_expr_t count, char *modif)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;
	struct lock_list_entry *lock_list;
	struct process *pr;
	struct proc *p;

	CPU_INFO_FOREACH(cii, ci) {
		lock_list = witness_cpu[CPU_INFO_UNIT(ci)].wc_spinlocks;
		if (lock_list == NULL || lock_list->ll_count == 0)
			continue;
		db_printf("CPU %d:\n", CPU_INFO_UNIT(ci));
		witness_list_locks(&lock_list, db_printf);
	}

	/*
	 * It would be nice to list only threads and processes that actually
	 * held sleep locks, but that information is currently not exported
	 * by WITNESS.
	 */
	LIST_FOREACH(pr, &allprocess, ps_list) {
		if (!witness_process_has_locks(pr))
			continue;
		TAILQ_FOREACH(p, &pr->ps_threads, p_thr_link) {
			if (!witness_thread_has_locks(p))
				continue;
			db_printf("Process %d (%s) thread %p (%d)\n",
			    pr->ps_pid, pr->ps_comm, p, p->p_tid);
			witness_ddb_list(p);
		}
	}
}

void
witness_print_badstacks(void)
{
	static struct witness tmp_w1, tmp_w2;
	static struct witness_lock_order_data tmp_data1, tmp_data2;
	struct witness_lock_order_data *data1, *data2;
	struct witness *w1, *w2;
	int error, generation, i, j;

	if (witness_watch < 1) {
		db_printf("witness watch is disabled\n");
		return;
	}
	if (witness_cold) {
		db_printf("witness is cold\n");
		return;
	}
	error = 0;

	memset(&tmp_w1, 0, sizeof(tmp_w1));
	memset(&tmp_w2, 0, sizeof(tmp_w2));
	memset(&tmp_data1, 0, sizeof(tmp_data1));
	memset(&tmp_data2, 0, sizeof(tmp_data2));

restart:
	mtx_enter(&w_mtx);
	generation = w_generation;
	mtx_leave(&w_mtx);
	db_printf("Number of known direct relationships is %d\n",
	    w_lohash.wloh_count);
	for (i = 1; i < w_max_used_index; i++) {
		mtx_enter(&w_mtx);
		if (generation != w_generation) {
			mtx_leave(&w_mtx);

			/* The graph has changed, try again. */
			db_printf("Lock graph changed, restarting trace.\n");
			goto restart;
		}

		w1 = &w_data[i];
		if (w1->w_reversed == 0) {
			mtx_leave(&w_mtx);
			continue;
		}

		/* Copy w1 locally so we can release the spin lock. */
		tmp_w1 = *w1;
		mtx_leave(&w_mtx);

		if (tmp_w1.w_reversed == 0)
			continue;
		for (j = 1; j < w_max_used_index; j++) {
			if ((w_rmatrix[i][j] & WITNESS_REVERSAL) == 0 || i > j)
				continue;

			mtx_enter(&w_mtx);
			if (generation != w_generation) {
				mtx_leave(&w_mtx);

				/* The graph has changed, try again. */
				db_printf("Lock graph changed, "
				    "restarting trace.\n");
				goto restart;
			}

			w2 = &w_data[j];
			data1 = witness_lock_order_get(w1, w2);
			data2 = witness_lock_order_get(w2, w1);

			/*
			 * Copy information locally so we can release the
			 * spin lock.
			 */
			tmp_w2 = *w2;

			if (data1)
				tmp_data1.wlod_stack = data1->wlod_stack;
			if (data2 && data2 != data1)
				tmp_data2.wlod_stack = data2->wlod_stack;
			mtx_leave(&w_mtx);

			db_printf("\nLock order reversal between \"%s\"(%s) "
			    "and \"%s\"(%s)!\n",
			    tmp_w1.w_type->lt_name, tmp_w1.w_class->lc_name,
			    tmp_w2.w_type->lt_name, tmp_w2.w_class->lc_name);
			if (data1) {
				db_printf("Lock order \"%s\"(%s) -> \"%s\"(%s) "
				    "first seen at:\n",
				    tmp_w1.w_type->lt_name,
				    tmp_w1.w_class->lc_name,
				    tmp_w2.w_type->lt_name,
				    tmp_w2.w_class->lc_name);
				db_print_stack_trace(&tmp_data1.wlod_stack,
				    db_printf);
				db_printf("\n");
			}
			if (data2 && data2 != data1) {
				db_printf("Lock order \"%s\"(%s) -> \"%s\"(%s) "
				    "first seen at:\n",
				    tmp_w2.w_type->lt_name,
				    tmp_w2.w_class->lc_name,
				    tmp_w1.w_type->lt_name,
				    tmp_w1.w_class->lc_name);
				db_print_stack_trace(&tmp_data2.wlod_stack,
				    db_printf);
				db_printf("\n");
			}
		}
	}
	mtx_enter(&w_mtx);
	if (generation != w_generation) {
		mtx_leave(&w_mtx);

		/*
		 * The graph changed while we were printing stack data,
		 * try again.
		 */
		db_printf("Lock graph changed, restarting trace.\n");
		goto restart;
	}
	mtx_leave(&w_mtx);
}

void
db_witness_display(db_expr_t addr, int have_addr, db_expr_t count, char *modif)
{
	switch (modif[0]) {
	case 'b':
		witness_print_badstacks();
		break;
	default:
		witness_ddb_display(db_printf);
		break;
	}
}
#endif

void
db_witness_print_fullgraph(void)
{
	struct witness *w;
	int error;

	if (witness_watch < 1) {
		db_printf("witness watch is disabled\n");
		return;
	}
	if (witness_cold) {
		db_printf("witness is cold\n");
		return;
	}
	error = 0;

	mtx_enter(&w_mtx);
	SIMPLEQ_FOREACH(w, &w_all, w_list)
		w->w_displayed = 0;
	SIMPLEQ_FOREACH(w, &w_all, w_list)
		db_witness_add_fullgraph(w);
	mtx_leave(&w_mtx);
}

static void
db_witness_add_fullgraph(struct witness *w)
{
	int i;

	if (w->w_displayed != 0 || (w->w_file == NULL && w->w_line == 0))
		return;
	w->w_displayed = 1;

	WITNESS_INDEX_ASSERT(w->w_index);
	for (i = 1; i <= w_max_used_index; i++) {
		if (w_rmatrix[w->w_index][i] & WITNESS_PARENT) {
			db_printf("\"%s\",\"%s\"\n", w->w_type->lt_name,
			    w_data[i].w_type->lt_name);
			db_witness_add_fullgraph(&w_data[i]);
		}
	}
}

/*
 * A simple hash function. Takes a key pointer and a key size. If size == 0,
 * interprets the key as a string and reads until the null
 * terminator. Otherwise, reads the first size bytes. Returns an unsigned 32-bit
 * hash value computed from the key.
 */
static uint32_t
witness_hash_djb2(const uint8_t *key, uint32_t size)
{
	unsigned int hash = 5381;
	int i;

	/* hash = hash * 33 + key[i] */
	if (size)
		for (i = 0; i < size; i++)
			hash = ((hash << 5) + hash) + (unsigned int)key[i];
	else
		for (i = 0; key[i] != 0; i++)
			hash = ((hash << 5) + hash) + (unsigned int)key[i];

	return (hash);
}


/*
 * Initializes the two witness hash tables. Called exactly once from
 * witness_initialize().
 */
static void
witness_init_hash_tables(void)
{
	int i;

	KASSERT(witness_cold);

	/* Initialize the hash tables. */
	for (i = 0; i < WITNESS_HASH_SIZE; i++)
		w_hash.wh_array[i] = NULL;

	w_hash.wh_size = WITNESS_HASH_SIZE;
	w_hash.wh_count = 0;

	/* Initialize the lock order data hash. */
	w_lofree = NULL;
	for (i = 0; i < WITNESS_LO_DATA_COUNT; i++) {
		memset(&w_lodata[i], 0, sizeof(w_lodata[i]));
		w_lodata[i].wlod_next = w_lofree;
		w_lofree = &w_lodata[i];
	}
	w_lohash.wloh_size = WITNESS_LO_HASH_SIZE;
	w_lohash.wloh_count = 0;
	for (i = 0; i < WITNESS_LO_HASH_SIZE; i++)
		w_lohash.wloh_array[i] = NULL;
}

static struct witness *
witness_hash_get(struct lock_type *type, const char *subtype)
{
	struct witness *w;
	uint32_t hash;

	KASSERT(type != NULL);
	if (witness_cold == 0)
		MUTEX_ASSERT_LOCKED(&w_mtx);
	hash = (uint32_t)((uintptr_t)type ^ (uintptr_t)subtype) %
	    w_hash.wh_size;
	w = w_hash.wh_array[hash];
	while (w != NULL) {
		if (w->w_type == type && w->w_subtype == subtype)
			goto out;
		w = w->w_hash_next;
	}

out:
	return (w);
}

static void
witness_hash_put(struct witness *w)
{
	uint32_t hash;

	KASSERT(w != NULL);
	KASSERT(w->w_type != NULL);
	if (witness_cold == 0)
		MUTEX_ASSERT_LOCKED(&w_mtx);
	KASSERTMSG(witness_hash_get(w->w_type, w->w_subtype) == NULL,
	    "%s: trying to add a hash entry that already exists!", __func__);
	KASSERTMSG(w->w_hash_next == NULL,
	    "%s: w->w_hash_next != NULL", __func__);

	hash = (uint32_t)((uintptr_t)w->w_type ^ (uintptr_t)w->w_subtype) %
	    w_hash.wh_size;
	w->w_hash_next = w_hash.wh_array[hash];
	w_hash.wh_array[hash] = w;
	w_hash.wh_count++;
}


static struct witness_lock_order_data *
witness_lock_order_get(struct witness *parent, struct witness *child)
{
	struct witness_lock_order_data *data = NULL;
	struct witness_lock_order_key key;
	unsigned int hash;

	KASSERT(parent != NULL && child != NULL);
	key.from = parent->w_index;
	key.to = child->w_index;
	WITNESS_INDEX_ASSERT(key.from);
	WITNESS_INDEX_ASSERT(key.to);
	if ((w_rmatrix[parent->w_index][child->w_index]
	    & WITNESS_LOCK_ORDER_KNOWN) == 0)
		goto out;

	hash = witness_hash_djb2((const char*)&key,
	    sizeof(key)) % w_lohash.wloh_size;
	data = w_lohash.wloh_array[hash];
	while (data != NULL) {
		if (witness_lock_order_key_equal(&data->wlod_key, &key))
			break;
		data = data->wlod_next;
	}

out:
	return (data);
}

/*
 * Verify that parent and child have a known relationship, are not the same,
 * and child is actually a child of parent.  This is done without w_mtx
 * to avoid contention in the common case.
 */
static int
witness_lock_order_check(struct witness *parent, struct witness *child)
{

	if (parent != child &&
	    w_rmatrix[parent->w_index][child->w_index]
	    & WITNESS_LOCK_ORDER_KNOWN &&
	    isitmychild(parent, child))
		return (1);

	return (0);
}

static int
witness_lock_order_add(struct witness *parent, struct witness *child)
{
	struct witness_lock_order_data *data = NULL;
	struct witness_lock_order_key key;
	unsigned int hash;

	KASSERT(parent != NULL && child != NULL);
	key.from = parent->w_index;
	key.to = child->w_index;
	WITNESS_INDEX_ASSERT(key.from);
	WITNESS_INDEX_ASSERT(key.to);
	if (w_rmatrix[parent->w_index][child->w_index]
	    & WITNESS_LOCK_ORDER_KNOWN)
		return (1);

	hash = witness_hash_djb2((const char*)&key,
	    sizeof(key)) % w_lohash.wloh_size;
	w_rmatrix[parent->w_index][child->w_index] |= WITNESS_LOCK_ORDER_KNOWN;
	data = w_lofree;
	if (data == NULL)
		return (0);
	w_lofree = data->wlod_next;
	data->wlod_next = w_lohash.wloh_array[hash];
	data->wlod_key = key;
	w_lohash.wloh_array[hash] = data;
	w_lohash.wloh_count++;
	db_save_stack_trace(&data->wlod_stack);
	return (1);
}

/* Call this whenever the structure of the witness graph changes. */
static void
witness_increment_graph_generation(void)
{

	if (witness_cold == 0)
		MUTEX_ASSERT_LOCKED(&w_mtx);
	w_generation++;
}

static void
witness_debugger(int cond, const char *msg)
{
	if (!cond)
		return;

	db_enter();
}
