/*	$OpenBSD: kern_sched.c,v 1.43 2016/06/03 15:21:23 kettenis Exp $	*/
/*
 * Copyright (c) 2007, 2008 Artur Grabowski <art@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>

#include <sys/sched.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/systm.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/mutex.h>
#include <sys/task.h>

TAILQ_HEAD(, proc)		sched_qs[SCHED_NQS];
volatile uint32_t		sched_whichqs;

#ifdef MULTIPROCESSOR
struct taskq *sbartq;
#endif

struct proc *sched_select(struct cpu_info *);
void sched_kthreads_create(void *);

void
sched_init(void)
{
	struct cpu_info *ci = curcpu();
	int i;

	for (i = 0; i < SCHED_NQS; i++)
		TAILQ_INIT(&sched_qs[i]);
	sched_whichqs = 0;

#ifdef MULTIPROCESSOR
	sbartq = taskq_create("sbar", 1, IPL_NONE,
	    TASKQ_MPSAFE | TASKQ_CANTSLEEP);
	if (sbartq == NULL)
		panic("unable to create sbar taskq");
#endif

	ci->ci_randseed = (arc4random() & 0x7fffffff) + 1;
	sched_init_cpu(ci);
}

/*
 * A few notes about cpu_switchto that is implemented in MD code.
 *
 * cpu_switchto takes two arguments, the old proc and the proc
 * it should switch to. The new proc will never be NULL, so we always have
 * a saved state that we need to switch to. The old proc however can
 * be NULL if the process is exiting. NULL for the old proc simply
 * means "don't bother saving old state".
 *
 * cpu_switchto is supposed to atomically load the new state of the process
 * including the pcb, pmap and setting curproc, the p_cpu pointer in the
 * proc and p_stat to SONPROC. Atomically with respect to interrupts, other
 * cpus in the system must not depend on this state being consistent.
 * Therefore no locking is necessary in cpu_switchto other than blocking
 * interrupts during the context switch.
 */

/*
 * sched_init_cpu is called from sched_init() for the boot cpu, then
 * it's the responsibility of the MD code to call it for all other cpus.
 */
void
sched_init_cpu(struct cpu_info *ci)
{
	struct schedstate_percpu *spc = &ci->ci_schedstate;

	spc->spc_idleproc = NULL;
	LIST_INIT(&spc->spc_deadproc);

	kthread_create_deferred(sched_kthreads_create, ci);
}

void
sched_kthreads_create(void *v)
{
	struct cpu_info *ci = v;
	struct schedstate_percpu *spc = &ci->ci_schedstate;
	static int num;

	if (fork1(&proc0, FORK_SHAREVM|FORK_SHAREFILES|FORK_NOZOMBIE|
	    FORK_SYSTEM|FORK_SIGHAND|FORK_IDLE, NULL, 0, sched_idle, ci, NULL,
	    &spc->spc_idleproc))
		panic("fork idle");

	/* Name it as specified. */
	snprintf(spc->spc_idleproc->p_comm, sizeof(spc->spc_idleproc->p_comm),
	    "idle%d", num);
	/* Always triggers a reschedule when an idle thread is running. */
	spc->spc_idleproc->p_usrpri = MAXPRI;

	num++;
}

/*
 * Returns 1 if a CPU can idle, 0 otherwise.
 */
static inline int
can_idle(struct cpu_info *ci)
{
#ifdef MULTIPROCESSOR
	struct schedstate_percpu *spc = &ci->ci_schedstate;
#endif /* MULTIPROCESSOR */

	/*
	 * As soon as a wakeup() or roundrobin() called need_resched()
	 * for this CPU, it has to go through mi_switch() to clear the
	 * resched flag.
	 *
	 * Yes, it is racy as the thread that triggered the reschedule
	 * might already be executing on another CPU.  In this case,
	 * if there's nothing else on the runqueue, this CPU will come
	 * back in its idle loop.
	 */
	if (want_resched(ci))
		return (0);

	if (sched_qs_empty(ci))
		return (1);

#ifdef MULTIPROCESSOR
	if ((spc->spc_schedflags & SPCF_SHOULDHALT) && (spc->spc_npeg == 0))
		return (1);
#endif /* MULTIPROCESSOR */

	return (0);
}

void
sched_idle(void *v)
{
	struct schedstate_percpu *spc;
	struct proc *p = curproc;
	struct cpu_info *ci = v;
	int s;

	KERNEL_UNLOCK();

	spc = &ci->ci_schedstate;

	/*
	 * First time we enter here, we're not supposed to idle,
	 * just go away for a while.
	 */
	SCHED_LOCK(s);
	p->p_stat = SSLEEP;
	p->p_cpu = ci;
	atomic_setbits_int(&p->p_flag, P_CPUPEG);
	mi_switch();
	SCHED_UNLOCK(s);

	KASSERT(ci == curcpu());
	KASSERT(curproc == spc->spc_idleproc);

	while (1) {
		while (!can_idle(ci)) {
			struct proc *dead;

			SCHED_LOCK(s);
			p->p_stat = SSLEEP;
			mi_switch();
			SCHED_UNLOCK(s);

			while ((dead = LIST_FIRST(&spc->spc_deadproc))) {
				LIST_REMOVE(dead, p_hash);
				exit2(dead);
			}
		}

		splassert(IPL_NONE);

		cpu_idle_enter();
		while (!want_resched(ci)) {
#ifdef MULTIPROCESSOR
			if (spc->spc_schedflags & SPCF_SHOULDHALT &&
			    (spc->spc_schedflags & SPCF_HALTED) == 0) {
				KASSERT(spc->spc_npeg == 0);
				atomic_setbits_int(&spc->spc_schedflags,
				    SPCF_HALTED);
				wakeup(spc);
			}
#endif /* MULTIPROCESSOR */
			cpu_idle_cycle();
		}
		cpu_idle_leave();
	}
}

/*
 * To free our address space we have to jump through a few hoops.
 * The freeing is done by the reaper, but until we have one reaper
 * per cpu, we have no way of putting this proc on the deadproc list
 * and waking up the reaper without risking having our address space and
 * stack torn from under us before we manage to switch to another proc.
 * Therefore we have a per-cpu list of dead processes where we put this
 * proc and have idle clean up that list and move it to the reaper list.
 * All this will be unnecessary once we can bind the reaper this cpu
 * and not risk having it switch to another in case it sleeps.
 */
void
sched_exit(struct proc *p)
{
	struct schedstate_percpu *spc = &curcpu()->ci_schedstate;
	struct timespec ts;
	struct proc *idle;
	int s;

	nanouptime(&ts);
	timespecsub(&ts, &spc->spc_runtime, &ts);
	timespecadd(&p->p_rtime, &ts, &p->p_rtime);

	LIST_INSERT_HEAD(&spc->spc_deadproc, p, p_hash);

	/* This process no longer needs to hold the kernel lock. */
	KERNEL_UNLOCK();

	SCHED_LOCK(s);
	idle = spc->spc_idleproc;
	idle->p_stat = SRUN;
	idle->p_cpu = curcpu();
	cpu_switchto(NULL, idle);
	panic("cpu_switchto returned");
}

void
setrunqueue(struct proc *p)
{
	int queue = p->p_priority >> 2;

	SCHED_ASSERT_LOCKED();

	TAILQ_INSERT_TAIL(&sched_qs[queue], p, p_runq);
	sched_whichqs |= (1 << queue);

	if (p->p_flag & P_CPUPEG)
		p->p_cpu->ci_schedstate.spc_npeg++;
}

void
remrunqueue(struct proc *p)
{
	int queue = p->p_priority >> 2;

	SCHED_ASSERT_LOCKED();

	TAILQ_REMOVE(&sched_qs[queue], p, p_runq);
	if (TAILQ_EMPTY(&sched_qs[queue]))
		sched_whichqs &= ~(1 << queue);

	if (p->p_flag & P_CPUPEG)
		p->p_cpu->ci_schedstate.spc_npeg--;
}

/*
 * Select the first thread that can run on cpu ``ci'' from the runqueue.
 *
 * This is O(1) when there's no pegged thread in the runqueue.
 */
struct proc *
sched_select(struct cpu_info *ci)
{
#ifdef MULTIPROCESSOR
	struct schedstate_percpu *spc = &ci->ci_schedstate;
#endif /* MULTIPROCESSOR */
	struct proc *p;
	int queue;

	if (sched_qs_empty(ci))
		return (NULL);

	for (queue = 0; queue < SCHED_NQS; queue++) {
		TAILQ_FOREACH(p, &sched_qs[queue], p_runq) {
#ifdef MULTIPROCESSOR
			/* Never run a thread pegged to another CPU. */
			if ((p->p_flag & P_CPUPEG) && p->p_cpu != ci)
				continue;

			/* If it should halt, only run pegged threads. */
			if ((spc->spc_schedflags & SPCF_SHOULDHALT) &&
			    (p->p_flag & P_CPUPEG) == 0)
				continue;
#endif /* MULTIPROCESSOR */

			return (p);
		}
	}

	return (NULL);
}

struct proc *
sched_chooseproc(void)
{
	struct cpu_info *ci = curcpu();
	struct proc *p = NULL;

	SCHED_ASSERT_LOCKED();

again:
	p = sched_select(ci);

	if (p != NULL) {
		remrunqueue(p);
		KASSERT(p->p_stat == SRUN);
	} else {
		struct schedstate_percpu *spc = &ci->ci_schedstate;

		p = spc->spc_idleproc;
		if (p == NULL) {
                        int s;
			/*
			 * We get here if someone decides to switch during
			 * boot before forking kthreads, bleh.
			 * This is kind of like a stupid idle loop.
			 */
#ifdef MULTIPROCESSOR
			__mp_unlock(&sched_lock);
#endif
			spl0();
			delay(10);
			SCHED_LOCK(s);
			goto again;
                }
		KASSERT(p);
		p->p_stat = SRUN;
	}

	KASSERT(p->p_wchan == NULL);
	p->p_cpu = ci;
	return (p);
}

/*
 * Peg a proc to a cpu.
 */
void
sched_peg_curproc(struct cpu_info *ci)
{
	struct proc *p = curproc;
	int s;

	SCHED_LOCK(s);
	p->p_priority = p->p_usrpri;
	p->p_stat = SRUN;
	p->p_cpu = ci;
	atomic_setbits_int(&p->p_flag, P_CPUPEG);
	setrunqueue(p);
	p->p_ru.ru_nvcsw++;
	mi_switch();
	SCHED_UNLOCK(s);
}

#ifdef MULTIPROCESSOR

void
sched_start_secondary_cpus(void)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;

	CPU_INFO_FOREACH(cii, ci) {
		struct schedstate_percpu *spc = &ci->ci_schedstate;

		if (CPU_IS_PRIMARY(ci))
			continue;
		atomic_clearbits_int(&spc->spc_schedflags,
		    SPCF_SHOULDHALT | SPCF_HALTED);
	}
}

void
sched_stop_secondary_cpus(void)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;

	/*
	 * Make sure we stop the secondary CPUs.
	 */
	CPU_INFO_FOREACH(cii, ci) {
		struct schedstate_percpu *spc = &ci->ci_schedstate;

		if (CPU_IS_PRIMARY(ci))
			continue;
		atomic_setbits_int(&spc->spc_schedflags, SPCF_SHOULDHALT);
	}
	CPU_INFO_FOREACH(cii, ci) {
		struct schedstate_percpu *spc = &ci->ci_schedstate;
		struct sleep_state sls;

		if (CPU_IS_PRIMARY(ci))
			continue;
		while ((spc->spc_schedflags & SPCF_HALTED) == 0) {
			sleep_setup(&sls, spc, PZERO, "schedstate");
			sleep_finish(&sls,
			    (spc->spc_schedflags & SPCF_HALTED) == 0);
		}
	}
}

void
sched_barrier_task(void *arg)
{
	struct cpu_info *ci = arg;

	sched_peg_curproc(ci);
	ci->ci_schedstate.spc_barrier = 1;
	wakeup(&ci->ci_schedstate.spc_barrier);
	atomic_clearbits_int(&curproc->p_flag, P_CPUPEG);
}

void
sched_barrier(struct cpu_info *ci)
{
	struct sleep_state sls;
	struct task task;
	CPU_INFO_ITERATOR cii;
	struct schedstate_percpu *spc;

	if (ci == NULL) {
		CPU_INFO_FOREACH(cii, ci) {
			if (CPU_IS_PRIMARY(ci))
				break;
		}
	}
	KASSERT(ci != NULL);

	if (ci == curcpu())
		return;

	task_set(&task, sched_barrier_task, ci);
	spc = &ci->ci_schedstate;
	spc->spc_barrier = 0;
	task_add(sbartq, &task);
	while (!spc->spc_barrier) {
		sleep_setup(&sls, &spc->spc_barrier, PWAIT, "sbar");
		sleep_finish(&sls, !spc->spc_barrier);
	}
}

#else /* MULTIPROCESSOR */

void
sched_barrier(struct cpu_info *ci)
{
}

#endif /* MULTIPROCESSOR */

/*
 * Functions to manipulate cpu sets.
 */
struct cpu_info *cpuset_infos[MAXCPUS];
static struct cpuset cpuset_all;

void
cpuset_init_cpu(struct cpu_info *ci)
{
	cpuset_add(&cpuset_all, ci);
	cpuset_infos[CPU_INFO_UNIT(ci)] = ci;
}

void
cpuset_clear(struct cpuset *cs)
{
	memset(cs, 0, sizeof(*cs));
}

void
cpuset_add(struct cpuset *cs, struct cpu_info *ci)
{
	unsigned int num = CPU_INFO_UNIT(ci);
	atomic_setbits_int(&cs->cs_set[num/32], (1 << (num % 32)));
}

void
cpuset_del(struct cpuset *cs, struct cpu_info *ci)
{
	unsigned int num = CPU_INFO_UNIT(ci);
	atomic_clearbits_int(&cs->cs_set[num/32], (1 << (num % 32)));
}

int
cpuset_isset(struct cpuset *cs, struct cpu_info *ci)
{
	unsigned int num = CPU_INFO_UNIT(ci);
	return (cs->cs_set[num/32] & (1 << (num % 32)));
}

void
cpuset_add_all(struct cpuset *cs)
{
	cpuset_copy(cs, &cpuset_all);
}

void
cpuset_copy(struct cpuset *to, struct cpuset *from)
{
	memcpy(to, from, sizeof(*to));
}

struct cpu_info *
cpuset_first(struct cpuset *cs)
{
	int i;

	for (i = 0; i < CPUSET_ASIZE(ncpus); i++)
		if (cs->cs_set[i])
			return (cpuset_infos[i * 32 + ffs(cs->cs_set[i]) - 1]);

	return (NULL);
}

void
cpuset_union(struct cpuset *to, struct cpuset *a, struct cpuset *b)
{
	int i;

	for (i = 0; i < CPUSET_ASIZE(ncpus); i++)
		to->cs_set[i] = a->cs_set[i] | b->cs_set[i];
}

void
cpuset_intersection(struct cpuset *to, struct cpuset *a, struct cpuset *b)
{
	int i;

	for (i = 0; i < CPUSET_ASIZE(ncpus); i++)
		to->cs_set[i] = a->cs_set[i] & b->cs_set[i];
}

void
cpuset_complement(struct cpuset *to, struct cpuset *a, struct cpuset *b)
{
	int i;

	for (i = 0; i < CPUSET_ASIZE(ncpus); i++)
		to->cs_set[i] = b->cs_set[i] & ~a->cs_set[i];
}
