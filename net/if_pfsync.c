/*	$OpenBSD: if_pfsync.c,v 1.278 2020/08/24 15:30:58 kn Exp $	*/

/*
 * Copyright (c) 2002 Michael Shalayeff
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR OR HIS RELATIVES BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF MIND, USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 2009 David Gwynne <dlg@openbsd.org>
 * Copyright (c) 2017 Christiano Haesbaert <christiano_haesbaert@genua.de>
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
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/timeout.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/pool.h>
#include <sys/syslog.h>
#include <sys/task.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/netisr.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/ip_ipsp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_fsm.h>
#include <netinet/udp.h>

#ifdef INET6
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#endif /* INET6 */

#include "carp.h"
#if NCARP > 0
#include <netinet/ip_carp.h>
#endif

#define PF_DEBUGNAME	"pfsync: "
#include <net/pfvar.h>
#include <net/pfvar_priv.h>
#include <net/if_pfsync.h>

#include "bpfilter.h"
#include "pfsync.h"

struct pfsync_softc;

#define PFSYNC_MINPKT ( \
	sizeof(struct ip) + \
	sizeof(struct pfsync_header))

int	pfsync_upd_tcp(struct pf_state *, struct pfsync_state_peer *,
	    struct pfsync_state_peer *);

int	pfsync_in_clr(caddr_t, int, int, int);
int	pfsync_in_iack(caddr_t, int, int, int);
int	pfsync_in_upd_c(caddr_t, int, int, int);
int	pfsync_in_ureq(caddr_t, int, int, int);
int	pfsync_in_del(caddr_t, int, int, int);
int	pfsync_in_del_c(caddr_t, int, int, int);
int	pfsync_in_bus(caddr_t, int, int, int);
int	pfsync_in_tdb(caddr_t, int, int, int);
int	pfsync_in_ins(caddr_t, int, int, int);
int	pfsync_in_upd(caddr_t, int, int, int);
int	pfsync_in_eof(caddr_t, int, int, int);

int	pfsync_in_error(caddr_t, int, int, int);

int	pfsync_in_ureq_bus(struct pfsync_softc *);

struct {
	int	(*in)(caddr_t, int, int, int);
	size_t	len;
} pfsync_acts[] = {
	/* PFSYNC_ACT_CLR */
	{ pfsync_in_clr,	sizeof(struct pfsync_clr) },
	 /* PFSYNC_ACT_OINS */
	{ pfsync_in_error,	0 },
	/* PFSYNC_ACT_INS_ACK */
	{ pfsync_in_iack,	sizeof(struct pfsync_ins_ack) },
	/* PFSYNC_ACT_OUPD */
	{ pfsync_in_error,	0 },
	/* PFSYNC_ACT_UPD_C */
	{ pfsync_in_upd_c,	sizeof(struct pfsync_upd_c) },
	/* PFSYNC_ACT_UPD_REQ */
	{ pfsync_in_ureq,	sizeof(struct pfsync_upd_req) },
	/* PFSYNC_ACT_DEL */
	{ pfsync_in_del,	sizeof(struct pfsync_state) },
	/* PFSYNC_ACT_DEL_C */
	{ pfsync_in_del_c,	sizeof(struct pfsync_del_c) },
	/* PFSYNC_ACT_INS_F */
	{ pfsync_in_error,	0 },
	/* PFSYNC_ACT_DEL_F */
	{ pfsync_in_error,	0 },
	/* PFSYNC_ACT_BUS */
	{ pfsync_in_bus,	sizeof(struct pfsync_bus) },
	/* PFSYNC_ACT_OTDB */
	{ pfsync_in_error,	0 },
	/* PFSYNC_ACT_EOF */
	{ pfsync_in_error,	0 },
	/* PFSYNC_ACT_INS */
	{ pfsync_in_ins,	sizeof(struct pfsync_state) },
	/* PFSYNC_ACT_UPD */
	{ pfsync_in_upd,	sizeof(struct pfsync_state) },
	/* PFSYNC_ACT_TDB */
	{ pfsync_in_tdb,	sizeof(struct pfsync_tdb) },
};

struct pfsync_q {
	void		(*write)(struct pf_state *, void *);
	size_t		len;
	u_int8_t	action;
};

/* we have one of these for every PFSYNC_S_ */
void	pfsync_out_state(struct pf_state *, void *);
void	pfsync_out_iack(struct pf_state *, void *);
void	pfsync_out_upd_c(struct pf_state *, void *);
void	pfsync_out_del(struct pf_state *, void *);
/* tdbs only sync the whole tdb state, no special messages */
void	pfsync_out_tdb(struct tdb *, void *);

struct pfsync_q pfsync_qs[] = {
	{ pfsync_out_iack,  sizeof(struct pfsync_ins_ack), PFSYNC_ACT_INS_ACK },
	{ pfsync_out_upd_c, sizeof(struct pfsync_upd_c),   PFSYNC_ACT_UPD_C },
	{ pfsync_out_del,   sizeof(struct pfsync_del_c),   PFSYNC_ACT_DEL_C },
	{ pfsync_out_state, sizeof(struct pfsync_state),   PFSYNC_ACT_INS },
	{ pfsync_out_state, sizeof(struct pfsync_state),   PFSYNC_ACT_UPD }
};

void	pfsync_q_ins(struct pf_state *, int);

struct pfsync_msg_storage {
	struct pfsync_msg msg;	/* must be first */
	union {
		struct pfsync_bus	bus;
		struct pfsync_clr	clr;
		struct pfsync_upd_req	ureq;
		struct pfsync_tdb	ptdb;
	} store;
};

TAILQ_HEAD(pfsync_msg_queue, pfsync_msg);

struct pfsync_local {
	struct task		 lo_task;
	int			 lo_denywork;
	int			 lo_lastrun;
#define PFSYNC_LO_BUSY_MAX 10
	int			 lo_busy;
	struct pfsync_msg_queue	 lo_msg_queue;
};

#define pfsync_local_enter(_sc)		cpumem_enter((_sc)->sc_local)
#define pfsync_local_leave(_sc, _lo)	cpumem_leave((_sc)->sc_local, _lo)

struct pfsync_softc {
	struct ifnet		 sc_if;
	unsigned int		 sc_sync_ifidx;

	struct pool		 sc_msg_pool;

	struct ip_moptions	 sc_imo;

	struct in_addr		 sc_sync_peer;

	struct ip		 sc_template;

	int			 sc_initial_bulk;
	int			 sc_link_demoted;

	u_int32_t		 sc_ureq_sent;
	int			 sc_bulk_tries;
	struct timeout		 sc_bulkfail_tmo;

	u_int32_t		 sc_ureq_received; /* bulk request received */

	struct task		 sc_ltask;
	struct task		 sc_dtask;

	struct cpumem		*sc_local;
};

struct timeout		 pfsync_tick_tmo;
struct pfsync_softc	*pfsyncif = NULL;
struct cpumem		*pfsynccounters;

void	pfsyncattach(int);
int	pfsync_clone_create(struct if_clone *, int);
int	pfsync_clone_destroy(struct ifnet *);
int	pfsync_alloc_scrub_memory(struct pfsync_state_peer *,
	    struct pf_state_peer *);
void	pfsync_update_net_tdb(struct pfsync_tdb *);
int	pfsyncoutput(struct ifnet *, struct mbuf *, struct sockaddr *,
	    struct rtentry *);
int	pfsyncioctl(struct ifnet *, u_long, caddr_t);
void	pfsyncstart(struct ifqueue *);
void	pfsync_syncdev_state(void *);
void	pfsync_ifdetach(void *);

void	pfsync_cancel_full_update(struct pfsync_softc *);
void	pfsync_request_full_update(struct pfsync_softc *);
void	pfsync_request_update(u_int32_t, u_int64_t);
void	pfsync_update_state_req(struct pf_state *);

void	pfsync_drop(struct pfsync_softc *);
void	pfsync_sendout_bpf(struct pf_state *, int);
void	pfsync_tdb_timeout(void *);

void	pfsync_bulk_fail(void *);

void		 pfsync_local(void);
void		 pfsync_local_task(void *);
struct mbuf *	 pfsync_mbuf_to_send(struct pfsync_softc *);
int		 pfsync_send_queue(struct pfsync_softc *, struct pfsync_local *);
int		 pfsync_send_mbuf(struct pfsync_softc *, struct mbuf *);
void		 pfsync_allow_work(struct pfsync_softc *);
void		 pfsync_deny_work(struct pfsync_softc *);
struct pfsync_msg *pfsync_msg_alloc(struct pfsync_softc *, enum pfsync_msg_type);
void		 pfsync_msg_free(struct pfsync_softc *, struct pfsync_msg *);
void		 pfsync_release_msg(struct pfsync_msg *, int);
void		 pfsync_sched_local(struct pfsync_softc *, int);
void		 pfsync_tick(void *);

#define PFSYNC_BLK_MIN_DELTA	 2
#define PFSYNC_MAX_BULKTRIES	12
#define PFSYNC_TIMEOUT_OFF	2
int	pfsync_sync_ok;

struct if_clone	pfsync_cloner =
    IF_CLONE_INITIALIZER("pfsync", pfsync_clone_create, pfsync_clone_destroy);

void
pfsyncattach(int npfsync)
{
	if_clone_attach(&pfsync_cloner);
	pfsynccounters = counters_alloc(pfsyncs_ncounters);
}

int
pfsync_clone_create(struct if_clone *ifc, int unit)
{
	struct pfsync_softc *sc;
	struct pfsync_local *lo;
	struct ifnet *ifp;
	struct cpumem_iter i;

	if (unit != 0)
		return (EINVAL);

	pfsync_sync_ok = 1;	/* shouldn't this be last ? */

	sc = malloc(sizeof(*pfsyncif), M_DEVBUF, M_WAITOK|M_ZERO);

	pool_init(&sc->sc_msg_pool, sizeof(struct pfsync_msg_storage),
	    0, IPL_NET, 0, "pfsync_msg", NULL);

	task_set(&sc->sc_ltask, pfsync_syncdev_state, sc);
	task_set(&sc->sc_dtask, pfsync_ifdetach, sc);

	sc->sc_imo.imo_membership = mallocarray(IP_MIN_MEMBERSHIPS,
	    sizeof(struct in_multi *), M_IPMOPTS, M_WAITOK|M_ZERO);
	sc->sc_imo.imo_max_memberships = IP_MIN_MEMBERSHIPS;

	ifp = &sc->sc_if;
	snprintf(ifp->if_xname, sizeof ifp->if_xname, "pfsync%d", unit);
	ifp->if_softc = sc;
	ifp->if_ioctl = pfsyncioctl;
	ifp->if_output = pfsyncoutput;
	ifp->if_qstart = pfsyncstart;
	ifp->if_type = IFT_PFSYNC;
	ifp->if_hdrlen = sizeof(struct pfsync_header);
	ifp->if_mtu = ETHERMTU;
	ifp->if_xflags = IFXF_CLONED | IFXF_MPSAFE;
	timeout_set_proc(&sc->sc_bulkfail_tmo, pfsync_bulk_fail, sc);
	timeout_set(&pfsync_tick_tmo, pfsync_tick, sc);

	sc->sc_local = cpumem_malloc(sizeof(struct pfsync_local), M_DEVBUF);

	CPUMEM_FOREACH(lo, &i, sc->sc_local) {
		task_set(&lo->lo_task, pfsync_local_task, sc);
		TAILQ_INIT(&lo->lo_msg_queue);
	}

	if_attach(ifp);
	if_alloc_sadl(ifp);

#if NCARP > 0
	if_addgroup(ifp, "carp");
#endif

#if NBPFILTER > 0
	bpfattach(&sc->sc_if.if_bpf, ifp, DLT_PFSYNC, PFSYNC_HDRLEN);
#endif

	pfsyncif = sc;

	timeout_add(&pfsync_tick_tmo, 1);

	return (0);
}

int
pfsync_clone_destroy(struct ifnet *ifp)
{
	struct pfsync_softc *sc = ifp->if_softc;
	int s;
	struct ifnet *ifp0;

#ifndef GENUOS
	NET_LOCK();
#endif

	/* XXX this is racy against timeouts */
	timeout_del(&sc->sc_bulkfail_tmo);
	s = splsoftclock();
	timeout_del(&pfsync_tick_tmo);
	splx(s);
#if NCARP > 0
	if (!pfsync_sync_ok)
		carp_group_demote_adj(&sc->sc_if, -1, "pfsync destroy");
	if (sc->sc_link_demoted)
		carp_group_demote_adj(&sc->sc_if, -1, "pfsync destroy");
	if (sc->sc_initial_bulk)
		carp_group_demote_adj(&sc->sc_if, -32, "pfsync destroy");
#endif
	if ((ifp0 = if_get(sc->sc_sync_ifidx)) != NULL) {
		if_linkstatehook_del(ifp0, &sc->sc_ltask);
		if_detachhook_del(ifp0, &sc->sc_dtask);
	}
	if_put(ifp0);

#ifndef GENUOS
	/* XXXSMP breaks atomicity */
	NET_UNLOCK();
#endif
	if_detach(ifp);

	pfsync_drop(sc);

	pool_destroy(&sc->sc_msg_pool);
	free(sc->sc_imo.imo_membership, M_IPMOPTS,
	    sc->sc_imo.imo_max_memberships * sizeof(struct in_multi *));
	free(sc, M_DEVBUF, sizeof(*sc));

	pfsyncif = NULL;

	return (0);
}

/*
 * Start output on the pfsync interface.
 */
void
pfsyncstart(struct ifqueue *ifq)
{
	ifq_purge(ifq);
}

void
pfsync_syncdev_state(void *arg)
{
	struct pfsync_softc *sc = arg;
	struct ifnet *ifp;

	NET_ASSERT_LOCKED();

	if ((sc->sc_if.if_flags & IFF_UP) == 0)
		return;
	if ((ifp = if_get(sc->sc_sync_ifidx)) == NULL)
		return;

	if (ifp->if_link_state == LINK_STATE_DOWN ||
	   !(ifp->if_flags & IFF_UP)) {
		sc->sc_if.if_flags &= ~IFF_RUNNING;
		if (!sc->sc_link_demoted) {
#if NCARP > 0
			carp_group_demote_adj(&sc->sc_if, 1,
			    "pfsync link state down");
#endif
			sc->sc_link_demoted = 1;
		}

		/* drop everything */
		/* XXX membar to make sure if_flags is propagated */
		pfsync_drop(sc);

		pfsync_cancel_full_update(sc);
	} else if (sc->sc_link_demoted) {
		sc->sc_if.if_flags |= IFF_RUNNING;

		pfsync_request_full_update(sc);

		/* after pfsync_request_full_update demotes */
		carp_group_demote_adj(&sc->sc_if, -1,
		    "pfsync link state up");
		sc->sc_link_demoted = 0;
	}

	if_put(ifp);
}

void
pfsync_ifdetach(void *arg)
{
	struct pfsync_softc *sc = arg;
	struct ifnet *ifp;

	if ((ifp = if_get(sc->sc_sync_ifidx)) != NULL) {
		if_linkstatehook_del(ifp, &sc->sc_ltask);
		if_detachhook_del(ifp, &sc->sc_dtask);
	}
	if_put(ifp);

	sc->sc_sync_ifidx = 0;
}

struct pfsync_msg *
pfsync_msg_alloc(struct pfsync_softc *sc, enum pfsync_msg_type type)
{
	struct pfsync_msg *msg;

	msg = pool_get(&sc->sc_msg_pool, PR_NOWAIT | PR_ZERO);
	if (msg == NULL)
		return (NULL);
	msg->msg_data = msg + 1;
	msg->msg_type = type;

	return (msg);
}

void
pfsync_msg_free(struct pfsync_softc *sc, struct pfsync_msg *msg)
{
	KASSERT(msg->msg_type != PFSYNC_MSG_STATE &&
	    msg->msg_type != PFSYNC_MSG_TDB);
	pool_put(&sc->sc_msg_pool, msg);
}

static inline void
pfsync_insert_msg(struct pfsync_local *lo, struct pfsync_msg *msg)
{
	TAILQ_INSERT_TAIL(&lo->lo_msg_queue, msg, msg_entry);
}

static inline void
pfsync_insert_state_msg(struct pfsync_local *lo, struct pf_state *st)
{
	struct pfsync_msg *msg = &st->sync_msg;

	msg->msg_type = PFSYNC_MSG_STATE;
	msg->msg_data = st;

	pfsync_insert_msg(lo, msg);
}

static inline void
pfsync_insert_tdb_msg(struct pfsync_local *lo, struct tdb *tdb)
{
	struct pfsync_msg *msg = &tdb->tdb_sync_msg;

	msg->msg_type = PFSYNC_MSG_TDB;
	msg->msg_data = tdb;
	TAILQ_INSERT_TAIL(&lo->lo_msg_queue, msg, msg_entry);
}

struct pfsync_msg *
pfsync_bus_msg(struct pfsync_softc *sc, uint8_t status)
{
	struct pfsync_msg *msg;
	struct pfsync_bus *bus;

	if ((msg = pfsync_msg_alloc(sc, PFSYNC_MSG_BUS)) == NULL)
		return (NULL);

	bus = msg->msg_data;
	bus->creatorid = pf_status.hostid;
	bus->endtime = htonl(getuptime() - sc->sc_ureq_received);
	bus->status = status;

	return (msg);
}

int
pfsync_alloc_scrub_memory(struct pfsync_state_peer *s,
    struct pf_state_peer *d)
{
	if (s->scrub.scrub_flag && d->scrub == NULL) {
		d->scrub = pool_get(&pf_state_scrub_pl, PR_NOWAIT | PR_ZERO);
		if (d->scrub == NULL)
			return (ENOMEM);
	}

	return (0);
}

void
pfsync_state_export(struct pfsync_state *sp, struct pf_state *st)
{
	pf_state_export(sp, st);
}

int
pfsync_state_import(struct pfsync_state *sp, int flags)
{
	struct pf_state	*st = NULL;
	struct pf_state_key *skw = NULL, *sks = NULL;
	struct pf_rule *r = NULL;
	struct pfi_kif	*kif;
	int pool_flags;
	int error = ENOMEM;
	int n = 0;

	PF_ASSERT_UNLOCKED();

	/* skip expired or purging states */
	if (sp->timeout >= PFTM_MAX || (sp->expire == 0))
		return (0);

	if (sp->creatorid == 0) {
		DPFPRINTF(LOG_NOTICE, "pfsync_state_import: "
		    "invalid creator id: %08x", ntohl(sp->creatorid));
		return (EINVAL);
	}

	if ((kif = pfi_kif_get(sp->ifname, NULL)) == NULL) {
		DPFPRINTF(LOG_NOTICE, "pfsync_state_import: "
		    "unknown interface: %s", sp->ifname);
		if (flags & PFSYNC_SI_IOCTL)
			return (EINVAL);
		return (0);	/* skip this state */
	}

	if (sp->af == 0)
		return (0);	/* skip this state */

	/*
	 * If the ruleset checksums match or the state is coming from the ioctl,
	 * it's safe to associate the state with the rule of that number.
	 */
	if (sp->rule != htonl(-1) && sp->anchor == htonl(-1) &&
	    (flags & (PFSYNC_SI_IOCTL | PFSYNC_SI_CKSUM)) && ntohl(sp->rule) <
	    pf_main_ruleset.rules.active.rcount) {
		TAILQ_FOREACH(r, pf_main_ruleset.rules.active.ptr, entries)
			if (ntohl(sp->rule) == n++)
				break;
	} else
		r = &pf_default_rule;

	if ((r->max_states && r->states_cur >= r->max_states))
		goto cleanup;
#ifndef GENUOS
	if (flags & PFSYNC_SI_IOCTL)
		pool_flags = PR_WAITOK | PR_LIMITFAIL | PR_ZERO;
	else
#endif
		pool_flags = PR_NOWAIT | PR_LIMITFAIL | PR_ZERO;

	if ((st = pool_get(&pf_state_pl, pool_flags)) == NULL)
		goto cleanup;

	if ((skw = pf_alloc_state_key(pool_flags)) == NULL)
		goto cleanup;

	if ((sp->key[PF_SK_WIRE].af &&
	    (sp->key[PF_SK_WIRE].af != sp->key[PF_SK_STACK].af)) ||
	    PF_ANEQ(&sp->key[PF_SK_WIRE].addr[0],
	    &sp->key[PF_SK_STACK].addr[0], sp->af) ||
	    PF_ANEQ(&sp->key[PF_SK_WIRE].addr[1],
	    &sp->key[PF_SK_STACK].addr[1], sp->af) ||
	    sp->key[PF_SK_WIRE].port[0] != sp->key[PF_SK_STACK].port[0] ||
	    sp->key[PF_SK_WIRE].port[1] != sp->key[PF_SK_STACK].port[1] ||
	    sp->key[PF_SK_WIRE].rdomain != sp->key[PF_SK_STACK].rdomain) {
		if ((sks = pf_alloc_state_key(pool_flags)) == NULL)
			goto cleanup;
	} else
		sks = skw;

	/* allocate memory for scrub info */
	if (pfsync_alloc_scrub_memory(&sp->src, &st->src) ||
	    pfsync_alloc_scrub_memory(&sp->dst, &st->dst))
		goto cleanup;

	/* copy to state key(s) */
	skw->addr[0] = sp->key[PF_SK_WIRE].addr[0];
	skw->addr[1] = sp->key[PF_SK_WIRE].addr[1];
	skw->port[0] = sp->key[PF_SK_WIRE].port[0];
	skw->port[1] = sp->key[PF_SK_WIRE].port[1];
	skw->rdomain = ntohs(sp->key[PF_SK_WIRE].rdomain);
	PF_REF_INIT(skw->refcnt);
	skw->removed = 0;
	skw->proto = sp->proto;
	if (!(skw->af = sp->key[PF_SK_WIRE].af))
		skw->af = sp->af;
	if (sks != skw) {
		sks->addr[0] = sp->key[PF_SK_STACK].addr[0];
		sks->addr[1] = sp->key[PF_SK_STACK].addr[1];
		sks->port[0] = sp->key[PF_SK_STACK].port[0];
		sks->port[1] = sp->key[PF_SK_STACK].port[1];
		sks->rdomain = ntohs(sp->key[PF_SK_STACK].rdomain);
		PF_REF_INIT(sks->refcnt);
		sks->removed = 0;
		if (!(sks->af = sp->key[PF_SK_STACK].af))
			sks->af = sp->af;
		if (sks->af != skw->af) {
			switch (sp->proto) {
			case IPPROTO_ICMP:
				sks->proto = IPPROTO_ICMPV6;
				break;
			case IPPROTO_ICMPV6:
				sks->proto = IPPROTO_ICMP;
				break;
			default:
				sks->proto = sp->proto;
			}
		} else
			sks->proto = sp->proto;

		if (((sks->af != AF_INET) && (sks->af != AF_INET6)) ||
		    ((skw->af != AF_INET) && (skw->af != AF_INET6))) {
			error = EINVAL;
			goto cleanup;
		}

	} else if ((sks->af != AF_INET) && (sks->af != AF_INET6)) {
		error = EINVAL;
		goto cleanup;
	}
	st->rtableid[PF_SK_WIRE] = ntohl(sp->rtableid[PF_SK_WIRE]);
	st->rtableid[PF_SK_STACK] = ntohl(sp->rtableid[PF_SK_STACK]);

	/* copy to state */
	bcopy(&sp->rt_addr, &st->rt_addr, sizeof(st->rt_addr));
	st->creation = getuptime() - ntohl(sp->creation);
	st->expire = sp->expire;
	st->direction = sp->direction;
	st->log = sp->log;
	st->timeout = sp->timeout;
	st->state_flags = ntohs(sp->state_flags);
	st->max_mss = ntohs(sp->max_mss);
	st->min_ttl = sp->min_ttl;
	st->set_tos = sp->set_tos;
	st->set_prio[0] = sp->set_prio[0];
	st->set_prio[1] = sp->set_prio[1];

	st->id = sp->id;
	st->creatorid = sp->creatorid;
	pf_state_peer_ntoh(&sp->src, &st->src);
	pf_state_peer_ntoh(&sp->dst, &st->dst);

	st->rule.ptr = r;
	st->anchor.ptr = NULL;

	st->pfsync_time = getuptime();
	st->sync_state = PFSYNC_S_NONE;

	if (!ISSET(flags, PFSYNC_SI_IOCTL))
		SET(st->state_flags, PFSTATE_NOSYNC);

#ifdef GENUOS
	if (r != &pf_default_rule && r->rt) {
		extern void pf_set_rt_ifp(struct pf_state *, struct pf_addr *,
		    sa_family_t, struct pf_src_node **);
		struct pf_src_node *sns[PF_SN_MAX];
		struct pf_addr zero;
		memset(sns, 0, sizeof(sns));
		memset(&zero, 0, sizeof(zero));
		pf_set_rt_ifp(st, &zero, skw->af, sns);
	} else {
		st->kif = NULL;
		st->natrule.ptr = NULL;
	}
#endif

	/* XXX same locking strategy as pf_create_state() */
	/* XXX why no pf_detach_state() in the error case? */
	KASSERT(SLIST_EMPTY(&st->match_rules));
	if (pf_state_insert(kif, &skw, &sks, st) != 0) {
		error = EEXIST;
		goto cleanup_state;
	}

	PF_STATE_ASSERT_LOCKED();

	if (!ISSET(flags, PFSYNC_SI_IOCTL)) {
		CLR(st->state_flags, PFSTATE_NOSYNC);
		if (ISSET(st->state_flags, PFSTATE_ACK))
			printf("%s: PFSYNC_S_IACK unimplemented\n", __func__);
	}
	CLR(st->state_flags, PFSTATE_ACK);
//	st->ready = 1;
//	pf_state_update_timeout_off(st, st->timeout, PFSYNC_TIMEOUT_OFF);
	PF_STATE_EXIT_WRITE();

	return (0);

 cleanup:
	if (skw == sks)
		sks = NULL;
	if (skw != NULL)
		pf_state_key_free_unlinked(skw);
	if (sks != NULL)
		pf_state_key_free_unlinked(sks);

 cleanup_state:	/* pf_state_insert frees the state keys */
	if (st) {
		if (st->dst.scrub)
			pool_put(&pf_state_scrub_pl, st->dst.scrub);
		if (st->src.scrub)
			pool_put(&pf_state_scrub_pl, st->src.scrub);
		pool_put(&pf_state_pl, st);
	}
	return (error);
}

int
pfsync_input(struct mbuf **mp, int *offp, int proto, int af)
{
	struct mbuf *n, *m = *mp;
	struct pfsync_softc *sc = pfsyncif;
	struct ip *ip = mtod(m, struct ip *);
	struct pfsync_header *ph;
	struct pfsync_subheader subh;
	int offset, noff, len, count, mlen, flags = 0;
	int e;

	pfsyncstat_inc(pfsyncs_ipackets);

	/* verify that we have a sync interface configured */
	if (sc == NULL || !ISSET(sc->sc_if.if_flags, IFF_RUNNING) ||
	    sc->sc_sync_ifidx == 0 || !pf_status.running)
		goto done;

	/* verify that the packet came in on the right interface */
	if (sc->sc_sync_ifidx != m->m_pkthdr.ph_ifidx) {
		pfsyncstat_inc(pfsyncs_badif);
		goto done;
	}

	ifc_inc_ipackets(&sc->sc_if);
	ifc_add_ibytes(&sc->sc_if, m->m_pkthdr.len);

	/* verify that the IP TTL is 255. */
	if (ip->ip_ttl != PFSYNC_DFLTTL) {
		pfsyncstat_inc(pfsyncs_badttl);
		goto done;
	}

	offset = ip->ip_hl << 2;
	n = m_pulldown(m, offset, sizeof(*ph), &noff);
	if (n == NULL) {
		pfsyncstat_inc(pfsyncs_hdrops);
		return IPPROTO_DONE;
	}
	ph = (struct pfsync_header *)(n->m_data + noff);

	/* verify the version */
	if (ph->version != PFSYNC_VERSION) {
		pfsyncstat_inc(pfsyncs_badver);
		goto done;
	}
	len = ntohs(ph->len) + offset;
	if (m->m_pkthdr.len < len) {
		pfsyncstat_inc(pfsyncs_badlen);
		goto done;
	}

	if (!bcmp(&ph->pfcksum, &pf_status.pf_chksum, PF_MD5_DIGEST_LENGTH))
		flags = PFSYNC_SI_CKSUM;

	offset += sizeof(*ph);
	while (offset <= len - sizeof(subh)) {
		m_copydata(m, offset, sizeof(subh), (caddr_t)&subh);
		offset += sizeof(subh);

		mlen = subh.len << 2;
		count = ntohs(subh.count);

		if (subh.action >= PFSYNC_ACT_MAX ||
		    subh.action >= nitems(pfsync_acts) ||
		    mlen < pfsync_acts[subh.action].len) {
			/*
			 * subheaders are always followed by at least one
			 * message, so if the peer is new
			 * enough to tell us how big its messages are then we
			 * know enough to skip them.
			 */
			if (count > 0 && mlen > 0) {
				offset += count * mlen;
				continue;
			}
			pfsyncstat_inc(pfsyncs_badact);
			goto done;
		}

		n = m_pulldown(m, offset, mlen * count, &noff);
		if (n == NULL) {
			pfsyncstat_inc(pfsyncs_badlen);
			return IPPROTO_DONE;
		}

		e = pfsync_acts[subh.action].in(n->m_data + noff, mlen, count,
		    flags);
		if (e != 0)
			goto done;

		offset += mlen * count;
	}

done:
	m_freem(m);
	return IPPROTO_DONE;
}

int
pfsync_in_clr(caddr_t buf, int len, int count, int flags)
{
	struct pfsync_clr *clr;
	struct pf_state *st, *nexts;
	struct pfi_kif *kif;
	u_int32_t creatorid;
	int i;

	for (i = 0; i < count; i++) {
		clr = (struct pfsync_clr *)buf + len * i;
		kif = NULL;
		creatorid = clr->creatorid;
		if (strlen(clr->ifname) &&
		    (kif = pfi_kif_find(clr->ifname)) == NULL)
			continue;

		rcu_list_foreach_safe(st, &state_list, entry_list, nexts) {
			if (pf_state_isvalid(st) &&
			    st->creatorid == creatorid &&
			    ((kif && st->kif == kif) || !kif)) {
				pf_state_lock(st);
				if (pf_state_isvalid(st) &&
				    st->creatorid == creatorid &&
				    ((kif && st->kif == kif) || !kif)) {
					SET(st->state_flags, PFSTATE_NOSYNC);
					pf_state_unlock(st);
					pf_remove_state(st);
				} else
					pf_state_unlock(st);
			}
		}
	}

	return (0);
}

int
pfsync_in_ins(caddr_t buf, int len, int count, int flags)
{
	struct pfsync_state *sp;
	sa_family_t af1, af2;
	int i;

	for (i = 0; i < count; i++) {
		sp = (struct pfsync_state *)(buf + len * i);
		af1 = sp->key[0].af;
		af2 = sp->key[1].af;

		/* check for invalid values */
		if (sp->timeout >= PFTM_MAX ||
		    sp->src.state > PF_TCPS_PROXY_DST ||
		    sp->dst.state > PF_TCPS_PROXY_DST ||
		    sp->direction > PF_OUT ||
		    (((af1 || af2) &&
		     ((af1 != AF_INET && af1 != AF_INET6) ||
		      (af2 != AF_INET && af2 != AF_INET6))) ||
		    (sp->af != AF_INET && sp->af != AF_INET6))) {
			DPFPRINTF(LOG_NOTICE,
			    "pfsync_input: PFSYNC5_ACT_INS: invalid value");
			pfsyncstat_inc(pfsyncs_badval);
			continue;
		}

		if (pfsync_state_import(sp, flags) == ENOMEM) {
			/* drop out, but process the rest of the actions */
			break;
		}
	}

	return (0);
}

int
pfsync_in_iack(caddr_t buf, int len, int count, int flags)
{
	struct pfsync_ins_ack *ia;
	struct pf_state *st;
	int i;

	for (i = 0; i < count; i++) {
		ia = (struct pfsync_ins_ack *)(buf + len * i);

		st = pf_find_state_byid(ia->id, ia->creatorid);
		if (st == NULL)
			continue;
		PF_STATE_ASSERT_LOCKED();
		pf_state_unlock(st);
	}

	return (0);
}

int
pfsync_upd_tcp(struct pf_state *st, struct pfsync_state_peer *src,
    struct pfsync_state_peer *dst)
{
	int sync = 0;

	/*
	 * The state should never go backwards except
	 * for syn-proxy states.  Neither should the
	 * sequence window slide backwards.
	 */
	if ((st->src.state > src->state &&
	    (st->src.state < PF_TCPS_PROXY_SRC ||
	    src->state >= PF_TCPS_PROXY_SRC)) ||

	    (st->src.state == src->state &&
	    SEQ_GT(st->src.seqlo, ntohl(src->seqlo))))
		sync++;
	else
		pf_state_peer_ntoh(src, &st->src);

	if ((st->dst.state > dst->state) ||

	    (st->dst.state >= TCPS_SYN_SENT &&
	    SEQ_GT(st->dst.seqlo, ntohl(dst->seqlo))))
		sync++;
	else
		pf_state_peer_ntoh(dst, &st->dst);

	return (sync);
}

int
pfsync_in_upd(caddr_t buf, int len, int count, int flags)
{
	struct pfsync_state *sp;
	struct pf_state *st;
	int sync;

	int i;

	for (i = 0; i < count; i++) {
		sp = (struct pfsync_state *)(buf + len * i);

		/* check for invalid values */
		if (sp->timeout >= PFTM_MAX ||
		    sp->src.state > PF_TCPS_PROXY_DST ||
		    sp->dst.state > PF_TCPS_PROXY_DST) {
			DPFPRINTF(LOG_NOTICE,
			    "pfsync_input: PFSYNC_ACT_UPD: invalid value");
			pfsyncstat_inc(pfsyncs_badval);
			continue;
		}

		st = pf_find_state_byid(sp->id, sp->creatorid);
		if (st == NULL) {
			/* insert the update */
			if (pfsync_state_import(sp, flags))
				pfsyncstat_inc(pfsyncs_badstate);
			continue;
		}
		PF_STATE_ASSERT_LOCKED();

		if (st->key[PF_SK_WIRE]->proto == IPPROTO_TCP)
			sync = pfsync_upd_tcp(st, &sp->src, &sp->dst);
		else {
			sync = 0;

			/*
			 * Non-TCP protocol state machine always go
			 * forwards
			 */
			if (st->src.state > sp->src.state)
				sync++;
			else
				pf_state_peer_ntoh(&sp->src, &st->src);

			if (st->dst.state > sp->dst.state)
				sync++;
			else
				pf_state_peer_ntoh(&sp->dst, &st->dst);
		}

		if (sync < 2) {
			pfsync_alloc_scrub_memory(&sp->dst, &st->dst);
			pf_state_peer_ntoh(&sp->dst, &st->dst);
			st->expire = getuptime();
			st->timeout = sp->timeout;
		}
		st->pfsync_time = getuptime();

		if (sync) {
			pfsyncstat_inc(pfsyncs_stale);

			pfsync_update_state(st);
		}
		pf_state_unlock(st);
	}

	return (0);
}

int
pfsync_in_upd_c(caddr_t buf, int len, int count, int flags)
{
	struct pfsync_upd_c *up;
	struct pf_state *st;

	int sync;

	int i;

	for (i = 0; i < count; i++) {
		up = (struct pfsync_upd_c *)(buf + len * i);

		/* check for invalid values */
		if (up->timeout >= PFTM_MAX ||
		    up->src.state > PF_TCPS_PROXY_DST ||
		    up->dst.state > PF_TCPS_PROXY_DST) {
			DPFPRINTF(LOG_NOTICE,
			    "pfsync_input: PFSYNC_ACT_UPD_C: invalid value");
			pfsyncstat_inc(pfsyncs_badval);
			continue;
		}

		st = pf_find_state_byid(up->id, up->creatorid);
		if (st == NULL) {
			/* We don't have this state. Ask for it. */
			pfsync_request_update(up->creatorid, up->id);
			continue;
		}
		PF_STATE_ASSERT_LOCKED();

		if (st->key[PF_SK_WIRE]->proto == IPPROTO_TCP)
			sync = pfsync_upd_tcp(st, &up->src, &up->dst);
		else {
			sync = 0;
			/*
			 * Non-TCP protocol state machine always go
			 * forwards
			 */
			if (st->src.state > up->src.state)
				sync++;
			else
				pf_state_peer_ntoh(&up->src, &st->src);

			if (st->dst.state > up->dst.state)
				sync++;
			else
				pf_state_peer_ntoh(&up->dst, &st->dst);
		}
		if (sync < 2) {
			/* XXX review this */
			pfsync_alloc_scrub_memory(&up->dst, &st->dst);
			pf_state_peer_ntoh(&up->dst, &st->dst);

			/*
			 * XXX Other side never fills in up->expire, if it did
			 * we could get a more accurate timeout. Consider
			 * KASSERTing it.
			 */
//			KASSERT(up->expire == 0);
			pf_state_update_timeout_off(st, up->timeout, PFSYNC_TIMEOUT_OFF);
		}
		st->pfsync_time = getuptime();

		if (sync) {
			pfsyncstat_inc(pfsyncs_stale);

			pfsync_update_state(st);
		}
		pf_state_unlock(st);
	}

	return (0);
}

int
pfsync_in_ureq(caddr_t buf, int len, int count, int flags)
{
	struct pfsync_softc *sc = pfsyncif;
	struct pfsync_upd_req *ur;
	struct pfsync_local *lo;
	int i;
	struct pf_state *st;

	lo = pfsync_local_enter(sc);

	for (i = 0; i < count; i++) {
		ur = (struct pfsync_upd_req *)(buf + len * i);

		if (ur->id == 0 && ur->creatorid == 0) {
			KERNEL_LOCK();
			pfsync_in_ureq_bus(sc);
			KERNEL_UNLOCK();
		} else {
			st = pf_find_state_byid(ur->id, ur->creatorid);
			if (st == NULL) {
				pfsyncstat_inc(pfsyncs_badstate);
				continue;
			}
			PF_STATE_ASSERT_LOCKED();
			pfsync_update_state_req(st);
			pf_state_unlock(st);
		}
	}
	pfsync_local_leave(sc, lo);

	return (0);
}

int
pfsync_in_del(caddr_t buf, int len, int count, int flags)
{
	struct pfsync_state *sp;
	struct pf_state *st;
	int i;

	for (i = 0; i < count; i++) {
		sp = (struct pfsync_state *)(buf + len * i);

		st = pf_find_state_byid(sp->id, sp->creatorid);
		if (st == NULL) {
			pfsyncstat_inc(pfsyncs_badstate);
			continue;
		}
		PF_STATE_ASSERT_LOCKED();
		SET(st->state_flags, PFSTATE_NOSYNC);
		pf_state_unlock(st);

		pf_remove_state(st);
	}

	return (0);
}

int
pfsync_in_del_c(caddr_t buf, int len, int count, int flags)
{
	struct pfsync_del_c *sp;
	struct pf_state *st;
	int i;

	for (i = 0; i < count; i++) {
		sp = (struct pfsync_del_c *)(buf + len * i);

		st = pf_find_state_byid(sp->id, sp->creatorid);
		if (st == NULL) {
			pfsyncstat_inc(pfsyncs_badstate);
			continue;
		}
		PF_STATE_ASSERT_LOCKED();
		SET(st->state_flags, PFSTATE_NOSYNC);
		pf_state_unlock(st);

		pf_remove_state(st);
	}

	return (0);
}

/*
 * This is a control message, it means we're receiving the markers of a bulk
 * update. Since we have to set timers and manipulate control data in
 * pfsync_softc we have to lock, KERNEL_LOCK is a appropriate since it's a rare
 * message.
 */
int
pfsync_in_bus(caddr_t buf, int len, int count, int flags)
{
	struct pfsync_softc *sc = pfsyncif;
	struct pfsync_bus *bus;


	KERNEL_LOCK();

	/* If we're not waiting for a bulk update, who cares. */
	if (sc->sc_ureq_sent == 0) {
		KERNEL_UNLOCK();
		return (0);
	}

	bus = (struct pfsync_bus *)buf;

	switch (bus->status) {
	case PFSYNC_BUS_START:
		timeout_add_sec(&sc->sc_bulkfail_tmo, 60);
		DPFPRINTF(LOG_INFO, "received bulk update start");
		break;

	case PFSYNC_BUS_END:
		if (getuptime() + PFSYNC_BLK_MIN_DELTA - ntohl(bus->endtime) >=
		    sc->sc_ureq_sent) {
			/* that's it, we're happy */
			sc->sc_ureq_sent = 0;
			sc->sc_bulk_tries = 0;
			timeout_del(&sc->sc_bulkfail_tmo);
#if NCARP > 0
			if (sc->sc_initial_bulk) {
				carp_group_demote_adj(&sc->sc_if, -32,
				    "pfsync init");
				sc->sc_initial_bulk = 0;
			}
			if (!pfsync_sync_ok)
				carp_group_demote_adj(&sc->sc_if, -1,
				    "pfsync bulk done");
#endif
			pfsync_sync_ok = 1;
			DPFPRINTF(LOG_INFO, "received valid bulk update end");
		} else {
			DPFPRINTF(LOG_WARNING, "received invalid "
			    "bulk update end: bad timestamp");
		}
		break;
	}

	KERNEL_UNLOCK();

	return (0);
}

int
pfsync_in_tdb(caddr_t buf, int len, int count, int flags)
{
#if defined(IPSEC)
	struct pfsync_tdb *tp;
	int i;

	for (i = 0; i < count; i++) {
		tp = (struct pfsync_tdb *)(buf + len * i);
		/* XXX racy ?? */
		pfsync_update_net_tdb(tp);
	}
#endif

	return (0);
}

#if defined(IPSEC)
/* Update an in-kernel tdb. Silently fail if no tdb is found. */
void
pfsync_update_net_tdb(struct pfsync_tdb *pt)
{
	struct tdb		*tdb;

	GENUOS_NET_ASSERT_LOCKED_OK();

	/* check for invalid values */
	if (ntohl(pt->spi) <= SPI_RESERVED_MAX ||
	    (pt->dst.sa.sa_family != AF_INET &&
	     pt->dst.sa.sa_family != AF_INET6))
		goto bad;

	tdb = gettdb(ntohs(pt->rdomain), pt->spi,
	    (union sockaddr_union *)&pt->dst, pt->sproto);
	if (tdb) {
		pt->rpl = betoh64(pt->rpl);
		pt->cur_bytes = betoh64(pt->cur_bytes);

		/* Neither replay nor byte counter should ever decrease. */
		if (pt->rpl < tdb->tdb_rpl ||
		    pt->cur_bytes < tdb->tdb_cur_bytes) {
			tdb_unref(tdb);
			goto bad;
		}

		tdb->tdb_rpl = pt->rpl;
		tdb->tdb_cur_bytes = pt->cur_bytes;
		tdb_unref(tdb);
	}
	return;

 bad:
	DPFPRINTF(LOG_WARNING, "pfsync_insert: PFSYNC_ACT_TDB_UPD: "
	    "invalid value");
	pfsyncstat_inc(pfsyncs_badstate);
	return;
}
#endif


int
pfsync_in_eof(caddr_t buf, int len, int count, int flags)
{
	if (len > 0 || count > 0)
		pfsyncstat_inc(pfsyncs_badact);

	/* we're done. let the caller return */
	return (1);
}

int
pfsync_in_error(caddr_t buf, int len, int count, int flags)
{
	pfsyncstat_inc(pfsyncs_badact);
	return (-1);
}

int
pfsyncoutput(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
	struct rtentry *rt)
{
	m_freem(m);	/* drop packet */
	return (EAFNOSUPPORT);
}

int
pfsyncioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct proc *p = curproc;
	struct pfsync_softc *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *)data;
	struct ip_moptions *imo = &sc->sc_imo;
	struct pfsyncreq pfsyncr;
	struct ifnet *ifp0, *sifp;
	struct ip *ip;
	int error;

	switch (cmd) {
	case SIOCSIFFLAGS:
		if ((ifp->if_flags & IFF_RUNNING) == 0 &&
		    (ifp->if_flags & IFF_UP)) {
			ifp->if_flags |= IFF_RUNNING;

#if NCARP > 0
			/* Do not demote for concurrent bulk updates. */
			if (sc->sc_initial_bulk == 0) {
				sc->sc_initial_bulk = 1;
				carp_group_demote_adj(&sc->sc_if, 32,
				    "pfsync init");
			} else
				DPFPRINTF(LOG_INFO,
				    "already demoted for initial bulk");
#endif

			pfsync_request_full_update(sc);
		}
		if ((ifp->if_flags & IFF_RUNNING) &&
		    (ifp->if_flags & IFF_UP) == 0) {
			ifp->if_flags &= ~IFF_RUNNING;

			/* XXX membar to make sure if_flags is propagated */
			/* drop everything */
			pfsync_drop(sc);

			pfsync_cancel_full_update(sc);
		}
		break;
	case SIOCSIFMTU:
		if ((ifp0 = if_get(sc->sc_sync_ifidx)) == NULL)
			return (EINVAL);
		error = 0;
		if (ifr->ifr_mtu <= PFSYNC_MINPKT ||
		    ifr->ifr_mtu > ifp0->if_mtu) {
			error = EINVAL;
		}
		if_put(ifp0);
		if (error)
			return error;
#ifndef GENUOS
		if (ifr->ifr_mtu < ifp->if_mtu)
			pfsync_sendout();
#endif
		ifp->if_mtu = ifr->ifr_mtu;
		break;
	case SIOCGETPFSYNC:
		bzero(&pfsyncr, sizeof(pfsyncr));
		if ((ifp0 = if_get(sc->sc_sync_ifidx)) != NULL) {
			strlcpy(pfsyncr.pfsyncr_syncdev,
			    ifp0->if_xname, IFNAMSIZ);
		}
		if_put(ifp0);
		pfsyncr.pfsyncr_syncpeer = sc->sc_sync_peer;
		pfsyncr.pfsyncr_maxupdates = 0;
		pfsyncr.pfsyncr_defer = 0;
		return (copyout(&pfsyncr, ifr->ifr_data, sizeof(pfsyncr)));

	case SIOCSETPFSYNC:
		if ((error = suser(p)) != 0)
			return (error);
		if ((error = copyin(ifr->ifr_data, &pfsyncr, sizeof(pfsyncr))))
			return (error);

		if (pfsyncr.pfsyncr_syncpeer.s_addr == 0)
			sc->sc_sync_peer.s_addr = INADDR_PFSYNC_GROUP;
		else
			sc->sc_sync_peer.s_addr =
			    pfsyncr.pfsyncr_syncpeer.s_addr;

		if (pfsyncr.pfsyncr_maxupdates > 255)
			return (EINVAL);

		if (pfsyncr.pfsyncr_syncdev[0] == 0) {
			if ((ifp0 = if_get(sc->sc_sync_ifidx)) != NULL) {
				if_linkstatehook_del(ifp0, &sc->sc_ltask);
				if_detachhook_del(ifp0, &sc->sc_dtask);
			}
			if_put(ifp0);
			sc->sc_sync_ifidx = 0;
			if (imo->imo_num_memberships > 0) {
				in_delmulti(imo->imo_membership[
				    --imo->imo_num_memberships]);
				imo->imo_ifidx = 0;
			}
			break;
		}

		if ((sifp = if_unit(pfsyncr.pfsyncr_syncdev)) == NULL)
			return (EINVAL);

		ifp0 = if_get(sc->sc_sync_ifidx);

#ifndef GENUOS
		if (sifp->if_mtu < sc->sc_if.if_mtu || (ifp0 != NULL &&
		    sifp->if_mtu < ifp0->if_mtu) ||
		    sifp->if_mtu < MCLBYTES - sizeof(struct ip))
			pfsync_sendout();
#endif

		if (ifp0) {
			if_linkstatehook_del(ifp0, &sc->sc_ltask);
			if_detachhook_del(ifp0, &sc->sc_dtask);
		}
		if_put(ifp0);
		sc->sc_sync_ifidx = sifp->if_index;

		if (imo->imo_num_memberships > 0) {
			in_delmulti(imo->imo_membership[--imo->imo_num_memberships]);
			imo->imo_ifidx = 0;
		}

		if (sc->sc_sync_peer.s_addr == INADDR_PFSYNC_GROUP) {
			struct in_addr addr;

			if (!(sifp->if_flags & IFF_MULTICAST)) {
				sc->sc_sync_ifidx = 0;
				if_put(sifp);
				return (EADDRNOTAVAIL);
			}

			addr.s_addr = INADDR_PFSYNC_GROUP;

			if ((imo->imo_membership[0] =
			    in_addmulti(&addr, sifp)) == NULL) {
				sc->sc_sync_ifidx = 0;
				if_put(sifp);
				return (ENOBUFS);
			}
			imo->imo_num_memberships++;
			imo->imo_ifidx = sc->sc_sync_ifidx;
			imo->imo_ttl = PFSYNC_DFLTTL;
			imo->imo_loop = 0;
		}

		ip = &sc->sc_template;
		bzero(ip, sizeof(*ip));
		ip->ip_v = IPVERSION;
		ip->ip_hl = sizeof(sc->sc_template) >> 2;
		ip->ip_tos = IPTOS_LOWDELAY;
		/* len and id are set later */
		ip->ip_off = htons(IP_DF);
		ip->ip_ttl = PFSYNC_DFLTTL;
		ip->ip_p = IPPROTO_PFSYNC;
		ip->ip_src.s_addr = INADDR_ANY;
		ip->ip_dst.s_addr = sc->sc_sync_peer.s_addr;

		if_linkstatehook_add(sifp, &sc->sc_ltask);
		if_detachhook_add(sifp, &sc->sc_dtask);
		if_put(sifp);

		/* Deal with situations, where the syncdev is not up, yet. */
		pfsync_syncdev_state(sc);

		pfsync_request_full_update(sc);

		break;

	default:
		return (ENOTTY);
	}

	return (0);
}

void
pfsync_out_state(struct pf_state *st, void *buf)
{
	struct pfsync_state *sp = buf;

	pfsync_state_export(sp, st);
}

void
pfsync_out_iack(struct pf_state *st, void *buf)
{
	struct pfsync_ins_ack *iack = buf;

	iack->id = st->id;
	iack->creatorid = st->creatorid;
}

void
pfsync_out_upd_c(struct pf_state *st, void *buf)
{
	struct pfsync_upd_c *up = buf;

	bzero(up, sizeof(*up));
	up->id = st->id;
	pf_state_peer_hton(&st->src, &up->src);
	pf_state_peer_hton(&st->dst, &up->dst);
	up->creatorid = st->creatorid;
	up->timeout = st->timeout;
	/*
	 * Historically expire was never used. We should consider changing this
	 * so we can get better timeout synchronization.
	 */
//	up->expire = time_uptime - st->expire;
}

void
pfsync_out_del(struct pf_state *st, void *buf)
{
	struct pfsync_del_c *dp = buf;

	dp->id = st->id;
	dp->creatorid = st->creatorid;
}

/*
 * Might be called with interface not IFF_RUNNING and/or not IFF_UP
 */
void
pfsync_drop(struct pfsync_softc *sc)
{
	struct every_cpu_iter i;
	struct pfsync_local *lo;
	struct pfsync_msg *msg;
	u_int dropped;

	ON_EVERY_CPU(&i) {
		lo = pfsync_local_enter(sc);
		dropped = 0;
		while ((msg = TAILQ_FIRST(&lo->lo_msg_queue)) != NULL) {
			pfsync_release_msg(msg, 1);
			dropped++;
		}
		DPFPRINTF(LOG_DEBUG, "pfsync_drop: cpu %d dropped %d msgs",
		    (int)curcpu()->ci_cpuid, dropped);
		pfsync_local_leave(sc, lo);
	}
}

void
pfsync_insert_state(struct pf_state *st)
{
	struct pfsync_softc *sc = pfsyncif;

	PF_STATE_ASSERT_LOCKED();

	KASSERT(st->sync_state == PFSYNC_S_NONE);

	/*
	 * This should be done in PF, we should not modify state_flags in
	 * pfsync.
	 */
	if (ISSET(st->rule.ptr->rule_flag, PFRULE_NOSYNC) ||
	    st->key[PF_SK_WIRE]->proto == IPPROTO_PFSYNC) {
		SET(st->state_flags, PFSTATE_NOSYNC);
		return;
	}

	if (sc == NULL || !ISSET(sc->sc_if.if_flags, IFF_RUNNING) ||
	    ISSET(st->state_flags, PFSTATE_NOSYNC))
		return;

	pfsync_q_ins(st, PFSYNC_S_INS);

#if NBPFILTER > 0		/* XXX bpf here is horrible ! */
#ifdef GENUOS
	pfsync_sendout_bpf(st, PFSYNC_ACT_INS_LBL);
#else
	pfsync_sendout_bpf(st, PFSYNC_ACT_INS);
#endif
#endif
}

void
pfsync_update_state(struct pf_state *st)
{
	struct pfsync_softc *sc = pfsyncif;

	PF_STATE_ASSERT_LOCKED();

	if (sc == NULL || !ISSET(sc->sc_if.if_flags, IFF_RUNNING) ||
	    ISSET(st->state_flags, PFSTATE_NOSYNC))
		return;

	switch (st->sync_state) {
	case PFSYNC_S_UPD_C:
	case PFSYNC_S_UPD:
	case PFSYNC_S_INS:
	case PFSYNC_S_DEL:
		break;
	case PFSYNC_S_IACK:
		printf("%s: PFSYNC_S_IACK unimplemented\n", __func__);
		break;
	case PFSYNC_S_NONE:
		pfsync_q_ins(st, PFSYNC_S_UPD_C);
		break;
	default:
		panic("pfsync_update_state: unexpected sync state %d",
		    st->sync_state);
	}
}

void
pfsync_cancel_full_update(struct pfsync_softc *sc)
{
	KERNEL_ASSERT_LOCKED();

	/* XXX removed timeout_pending(&sc->sc_bulk_tmo) as talked with hans */
	if (timeout_pending(&sc->sc_bulkfail_tmo)) {
#if NCARP > 0
		if (sc->sc_initial_bulk) {
			carp_group_demote_adj(&sc->sc_if, -32,
			    "pfsync init");
			sc->sc_initial_bulk = 0;
		}
		if (!pfsync_sync_ok)
			carp_group_demote_adj(&sc->sc_if, -1,
			    "pfsync bulk cancelled");
#endif
		pfsync_sync_ok = 1;
		DPFPRINTF(LOG_INFO, "cancelling bulk update");
	}
	timeout_del(&sc->sc_bulkfail_tmo);
	sc->sc_ureq_sent = 0;
	sc->sc_bulk_tries = 0;
}

void
pfsync_request_full_update(struct pfsync_softc *sc)
{
	if (!pfsync_sync_ok)
		return;

	if (sc->sc_sync_ifidx && ISSET(sc->sc_if.if_flags, IFF_RUNNING)) {
		/* Request a full state table update. */
		sc->sc_ureq_sent = getuptime();
#if NCARP > 0
		carp_group_demote_adj(&sc->sc_if, 1,
		    "pfsync bulk start");
#endif
		pfsync_sync_ok = 0;
		timeout_add_sec(&sc->sc_bulkfail_tmo, 60);
		pfsync_request_update(0, 0);
	}
}

void
pfsync_request_update(u_int32_t creatorid, u_int64_t id)
{
	struct pfsync_softc *sc = pfsyncif;
	struct pfsync_local *lo;
	struct pfsync_msg *msg;
	struct pfsync_upd_req *ur;

	/*
	 * this code does nothing to prevent multiple update requests for the
	 * same state being generated.
	 */
	msg = pfsync_msg_alloc(sc, PFSYNC_MSG_UPD_REQ);
	if (msg == NULL) {
		/* XXX stats */
		return;
	}
	ur = msg->msg_data;

	ur->id = id;
	ur->creatorid = creatorid;

	lo = pfsync_local_enter(sc);
	pfsync_insert_msg(lo, msg);
	pfsync_local_leave(sc, lo);
}

void
pfsync_update_state_req(struct pf_state *st)
{
	struct pfsync_softc *sc = pfsyncif;

	PF_STATE_ASSERT_LOCKED();

	if (sc == NULL)
		panic("pfsync_update_state_req: nonexistant instance");

	if (ISSET(st->state_flags, PFSTATE_NOSYNC))
		return;

	switch (st->sync_state) {
	case PFSYNC_S_UPD_C:
		st->sync_updc2upd = 1;
		break;
	case PFSYNC_S_IACK:
		printf("%s: PFSYNC_S_IACK unimplemented\n", __func__);
		break;
	case PFSYNC_S_NONE:
		pfsync_q_ins(st, PFSYNC_S_UPD);
		return;

	case PFSYNC_S_INS:
	case PFSYNC_S_UPD:
	case PFSYNC_S_DEL:
		/* we're already handling it */
		return;

	default:
		panic("pfsync_update_state_req: unexpected sync state %d",
		    st->sync_state);
	}
}

/*
 * Returns true if pfsync made no claims on st, meaning the caller can free it.
 * Otherwise pfsync will resume freeing the state once it's done with it.
 */
int
pfsync_delete_state(struct pf_state *st)
{
	PF_STATE_ASSERT_LOCKED();

	if (st->sync_state == PFSYNC_S_NONE)
		pfsync_q_ins(st, PFSYNC_S_DEL);

	return (st->sync_state == PFSYNC_S_NONE);
}

void
pfsync_clear_states(u_int32_t creatorid, const char *ifname)
{
	struct pfsync_softc *sc = pfsyncif;
	struct pfsync_msg *msg;
	struct pfsync_clr *clr;
	struct pfsync_local *lo;

#ifndef GENUOS
	    NET_ASSERT_LOCKED();
#endif

	if (sc == NULL || !ISSET(sc->sc_if.if_flags, IFF_RUNNING))
		return;

	if ((msg = pfsync_msg_alloc(sc, PFSYNC_MSG_CLR)) == NULL) {
		DPFPRINTF(LOG_WARNING, "pfsync_clear_states: no memory for "
		    "sending clear states message");
		return;
	}

	clr = msg->msg_data;
	strlcpy(clr->ifname, ifname, sizeof(clr->ifname));
	clr->creatorid = creatorid;

	lo = pfsync_local_enter(sc);
	pfsync_insert_msg(lo, msg);
	pfsync_local_leave(sc, lo);
}

void
pfsync_q_ins(struct pf_state *st, int q)
{
	struct pfsync_softc *sc = pfsyncif;
	struct pfsync_local *lo;

	PF_STATE_ASSERT_LOCKED();

	KASSERT(st->sync_state == PFSYNC_S_NONE);

	if (sc == NULL || !ISSET(sc->sc_if.if_flags, IFF_RUNNING) ||
	    st->state_flags & PFSTATE_NOSYNC)
		return;

	lo = pfsync_local_enter(sc);

	if (lo->lo_denywork) {
		pfsync_local_leave(sc, lo);
		return;
	}
	st->sync_state = q;
	pfsync_insert_state_msg(lo, st);
	if (q == PFSYNC_S_DEL)
		SET(st->state_flags, PFSTATE_NOSYNC);

	pfsync_local_leave(sc, lo);
}

void
pfsync_update_tdb(struct tdb *tdb, int output)
{
	struct pfsync_softc *sc = pfsyncif;
	struct pfsync_local *lo;

	if (sc == NULL || !ISSET(sc->sc_if.if_flags, IFF_RUNNING))
		return;

	/*
	 * Acquire pfsync, tdb_sync must be volatile.
	 */
	if (tdb->tdb_sync ||
	    atomic_cas_uint(&tdb->tdb_sync, 0, 1) != 0)
		return;

	lo = pfsync_local_enter(sc);
	pfsync_insert_tdb_msg(lo, tdb);
#if 0
	/* Do we want tdb_updates ?? */
	tdb->tdb_updates = 0; /* XXX SHOULD WE ?  ??? */
	if (++tdb->tdb_updates >= sc->sc_maxupdates)
		;
#endif
	pfsync_local_leave(sc, lo);

#ifndef GENUOS
	if (output)
		SET(tdb->tdb_flags, TDBF_PFSYNC_RPL);
	else
		CLR(tdb->tdb_flags, TDBF_PFSYNC_RPL);
#endif
}

int
pfsync_delete_tdb(struct tdb *t)
{
	struct pfsync_softc *sc = pfsyncif;

	/*
	 * If pfsync is up, tdb_sync will never be cleared, assert this.
	 */
	if (sc == NULL || !ISSET(sc->sc_if.if_flags, IFF_RUNNING))
		KASSERT(t->tdb_sync == 0);

	if (t->tdb_sync)
		return (EAGAIN);
	else
		return (0);
}

void
pfsync_out_tdb(struct tdb *t, void *buf)
{
	struct pfsync_tdb *ut = buf;

	bzero(ut, sizeof(*ut));
	ut->spi = t->tdb_spi;
	bcopy(&t->tdb_dst, &ut->dst, sizeof(ut->dst));
	ut->rpl = htobe64(t->tdb_rpl);
	ut->cur_bytes = htobe64(t->tdb_cur_bytes);
	ut->sproto = t->tdb_sproto;
	ut->rdomain = htons(t->tdb_rdomain);
}

void
pfsync_bulk_fail(void *arg)
{
	struct pfsync_softc *sc = arg;

#ifndef GENUOS
	NET_LOCK();
#endif
	KERNEL_ASSERT_LOCKED();
	/* XXX should it be WRITE ? */
	netisr_conf_enter_read();

	if (sc->sc_bulk_tries++ < PFSYNC_MAX_BULKTRIES) {
		/* Try again */
		timeout_add_sec(&sc->sc_bulkfail_tmo, 5);
		pfsync_request_update(0, 0);
	} else {
		/* Pretend like the transfer was ok */
		sc->sc_ureq_sent = 0;
		sc->sc_bulk_tries = 0;
#if NCARP > 0
		if (sc->sc_initial_bulk) {
			carp_group_demote_adj(&sc->sc_if, -32,
			    "pfsync init");
			sc->sc_initial_bulk = 0;
		}
		if (!pfsync_sync_ok)
			carp_group_demote_adj(&sc->sc_if, -1,
			    "pfsync bulk fail");
#endif
		pfsync_sync_ok = 1;
		DPFPRINTF(LOG_ERR, "failed to receive bulk update");
	}

	netisr_conf_exit_read();
}

int
pfsync_sysctl_pfsyncstat(void *oldp, size_t *oldlenp, void *newp)
{
	struct pfsyncstats pfsyncstat;

	CTASSERT(sizeof(pfsyncstat) == (pfsyncs_ncounters * sizeof(uint64_t)));
	memset(&pfsyncstat, 0, sizeof pfsyncstat);
	counters_read(pfsynccounters, (uint64_t *)&pfsyncstat,
	    pfsyncs_ncounters);
	return (sysctl_rdstruct(oldp, oldlenp, newp,
	    &pfsyncstat, sizeof(pfsyncstat)));
}

int
pfsync_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp,
    size_t newlen)
{
	/* All sysctl names at this level are terminal. */
	if (namelen != 1)
		return (ENOTDIR);

	switch (name[0]) {
	case PFSYNCCTL_STATS:
		return (pfsync_sysctl_pfsyncstat(oldp, oldlenp, newp));
	default:
		return (ENOPROTOOPT);
	}
}

#if NBPFILTER > 0
void
pfsync_sendout_bpf(struct pf_state *st, int act)
{
	struct pfsync_softc *sc = pfsyncif;
	struct ifnet *ifp = &sc->sc_if;
	struct mbuf *m;
	struct pfsync_header *ph;
	struct pfsync_subheader *subh;
	int offset;
	int totlen = sizeof(*ph) + sizeof(*subh) +
#ifdef GENUOS
	    sizeof(struct pfsync_state_lbl);
	struct pfsync_state_lbl *spl;
#else
	    sizeof(struct pfsync_state);
#endif

	PF_STATE_ASSERT_LOCKED();

	if (!ISSET(sc->sc_if.if_flags, IFF_RUNNING) ||
	    (ifp->if_bpf == NULL))
		return;

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL) {
		ifc_inc_oerrors(&sc->sc_if);
		pfsyncstat_inc(pfsyncs_onomem);
		return;
	}

	if (max_linkhdr + totlen > MHLEN) {
		MCLGETL(m, M_DONTWAIT, max_linkhdr + totlen);
		if (!ISSET(m->m_flags, M_EXT)) {
			m_free(m);
			ifc_inc_oerrors(&sc->sc_if);
			pfsyncstat_inc(pfsyncs_onomem);
			return;
		}
	}
	m->m_data += max_linkhdr;
	m->m_len = m->m_pkthdr.len = totlen;

	/* build the pfsync header */
	ph = mtod(m, struct pfsync_header *);
	bzero(ph, sizeof(*ph));
	offset = sizeof(*ph);
	ph->version = PFSYNC_VERSION;
	ph->len = htons(totlen);
	/* skip ph->pf_checksum. does not matter on bpf */

	subh = (struct pfsync_subheader *)(m->m_data + offset);
	bzero(subh, sizeof(*subh));
	subh->action = act;
	subh->len = sizeof(struct pfsync_state) >> 2;
	subh->count = htons(1);
	offset += sizeof(*subh);

	pfsync_out_state(st, m->m_data + offset);
#ifdef GENUOS
	spl = (struct pfsync_state_lbl *)(m->m_data + offset);
	bzero(spl->label, sizeof(spl->label));
	if (st->rule.ptr->label[0])
		strlcpy(spl->label, st->rule.ptr->label, sizeof(spl->label));
#endif

	bpf_mtap(ifp->if_bpf, m, BPF_DIRECTION_OUT);
	m_freem(m);
}
#endif

int
pfsync_send_mbuf(struct pfsync_softc *sc, struct mbuf *m)
{
	int error, s;
	caddr_t	end;
	struct pfsync_header *ph;
	struct ip *ip;
	int bytes;

	end = m->m_data;
	m->m_data = m->m_ext.ext_buf + max_linkhdr;
	m->m_pkthdr.len = m->m_len = bytes = end - m->m_data;

	/* build the pfsync header */
	ph = (struct pfsync_header *) (m->m_data + sizeof(*ip));
	bzero(ph, sizeof(*ph));
	ph->len = htons(m->m_len - sizeof(struct ip));
	ph->version = PFSYNC_VERSION;
	bcopy(pf_status.pf_chksum, ph->pfcksum, PF_MD5_DIGEST_LENGTH);

	/* build the ip header */
	ip = mtod(m, struct ip *);
	bcopy(&sc->sc_template, ip, sizeof(*ip));
	ip->ip_id = htons(1);	/* XXX was randomid */
	ip->ip_len = htons(m->m_len);

	s = splsoftnet();
	error = ip_output(m, NULL, NULL, IP_RAWOUTPUT, &sc->sc_imo, NULL, 0,
	    NULL);
	splx(s);

	if (!error) {
		pfsyncstat_inc(pfsyncs_opackets);
		ifc_inc_opackets(&sc->sc_if);
		ifc_add_obytes(&sc->sc_if, bytes);
	} else
		pfsyncstat_inc(pfsyncs_oerrors);

	if (error == ENOBUFS)
		error = EBUSY;

	return (error);
}

struct mbuf *
pfsync_mbuf_to_send(struct pfsync_softc *sc)
{
	struct mbuf *m;

	m = MCLGETL(NULL, M_DONTWAIT, max_linkhdr + sc->sc_if.if_mtu);
	if (m == NULL) {
		ifc_inc_oerrors(&sc->sc_if);
		pfsyncstat_inc(pfsyncs_onomem);
		return (NULL);
	}
	KASSERT(m->m_data == m->m_ext.ext_buf);

	m->m_pkthdr.ph_rtableid = sc->sc_if.if_rdomain;
	m->m_data += max_linkhdr;
	m->m_len = m->m_pkthdr.len = 0;
	m->m_data += sizeof(struct pfsync_header) + sizeof(struct ip);

	return (m);
}

static inline int
pfsync_append_msg(struct mbuf *m, struct pfsync_msg *msg)
{
	struct pfsync_subheader *subh;
	struct pf_state *st = NULL;
	struct pfsync_bus *bus;
	struct tdb *tdb;
	size_t len, pktmax;
	u_int8_t act, ss = PFSYNC_S_NONE;

	switch (msg->msg_type) {
	case PFSYNC_MSG_STATE:
		st = msg->msg_data;
		if (st->sync_state == PFSYNC_S_UPD_C &&
		    st->sync_updc2upd) {
			st->sync_updc2upd = 0;
			st->sync_state = PFSYNC_S_UPD;
		}
		ss = st->sync_state;
		act = pfsync_qs[ss].action;
		len = pfsync_qs[ss].len;
		break;
	case PFSYNC_MSG_BUS:
		act = PFSYNC_ACT_BUS;
		len = sizeof(struct pfsync_bus);
		break;
	case PFSYNC_MSG_CLR:
		act = PFSYNC_ACT_CLR;
		len = sizeof(struct pfsync_clr);
		break;
	case PFSYNC_MSG_UPD_REQ:
		act = PFSYNC_ACT_UPD_REQ;
		len = sizeof(struct pfsync_upd_req);
		break;
	case PFSYNC_MSG_TDB:
		act = PFSYNC_ACT_TDB;
		len = sizeof(struct pfsync_tdb);
		break;
	default:
		panic("%s: unhandled msg_type %d\n", __func__, msg->msg_type);
	}

	pktmax = max_linkhdr + pfsyncif->sc_if.if_mtu;
	pktmax = MIN(pktmax, m->m_ext.ext_size);
	if (m->m_data + sizeof(*subh) + len >
	    m->m_ext.ext_buf + pktmax)
		return (-1);

	subh = (struct pfsync_subheader *) m->m_data;
	bzero(subh, sizeof(*subh));
	subh->action = act;
	subh->len = len >> 2;
	subh->count = htons(1);
	m->m_data += sizeof(*subh);

	switch (msg->msg_type) {
	case PFSYNC_MSG_STATE:
		KASSERT(ss == st->sync_state);
		pfsync_qs[ss].write(st, m->m_data);
		break;
	case PFSYNC_MSG_TDB:
		tdb = msg->msg_data;
		pfsync_out_tdb(tdb, m->m_data);
		break;
	case PFSYNC_MSG_BUS:
		/*
		 * We must patch endtime now, otherwise endtime will probably be
		 * 0, since time_uptime == sc->sc_ureq_received when this message
		 * was queued.
		 */
		bus = msg->msg_data;
		bus->endtime = htonl(getuptime() - pfsyncif->sc_ureq_received);
		/* FALLTHROUGH */
	case PFSYNC_MSG_CLR:
	case PFSYNC_MSG_UPD_REQ:
		bcopy(msg->msg_data, m->m_data, len);
		break;
	default:
		panic("%s: unhandled msg_type %d\n", __func__, msg->msg_type);
	}

	m->m_data += len;
	return (0);
}

void
pfsync_release_msg(struct pfsync_msg *msg, int drop)
{
	struct pf_state *st;
	struct tdb *tdb;
	struct pfsync_local *lo;
	int old_sync;

	lo = pfsync_local_enter(pfsyncif);

	TAILQ_REMOVE(&lo->lo_msg_queue, msg, msg_entry);

	switch (msg->msg_type) {
	case PFSYNC_MSG_STATE:
		st = msg->msg_data;

		/* sync_state can only change from local context.  */
		pf_state_lock(st);
		KASSERT(st->sync_state != PFSYNC_S_NONE);
		old_sync = st->sync_state;
		st->sync_state = PFSYNC_S_NONE;

		if (old_sync == PFSYNC_S_DEL)
			KASSERT(st->removed);

		if (st->removed) {
			/*
			 * With drop we don't care about sending a delete.
			 */
			if (drop) {
				rcu_call(&st->rcu, pf_free_state);
			/*
			 * We either sent S_DEL, in this case old_sync is
			 * S_DEL.
			 * Or pfsync_delete_state() made no claims.
			 */
			} else if (old_sync == PFSYNC_S_DEL ||
			    pfsync_delete_state(st)) {
				KASSERT(st->sync_state == PFSYNC_S_NONE);
				pfsync_sendout_bpf(st, PFSYNC_ACT_DEL_LBL);
				rcu_call(&st->rcu, pf_free_state);
			} else
				KASSERT(st->sync_state == PFSYNC_S_DEL);
		}
		pf_state_unlock(st);
		/* Don't free the message, it's allocated inside pf_state() */
		break;
	case PFSYNC_MSG_BUS:	/* FALLTHROUGH */
	case PFSYNC_MSG_CLR:	/* FALLTHROUGH */
	case PFSYNC_MSG_UPD_REQ:
		pfsync_msg_free(pfsyncif, msg);
		break;
	case PFSYNC_MSG_TDB:
		tdb = msg->msg_data;
		tdb->tdb_sync = 0;
		break;
	default:
		panic("pfsync_release_msg: unknown msg_type %d\n", msg->msg_type);
	}

	pfsync_local_leave(pfsyncif, lo);
}

static inline void
pfsync_release_queue(struct pfsync_msg_queue *msgq_tmp)
{
	struct pfsync_msg *msg;

	while ((msg = TAILQ_FIRST(msgq_tmp)) != NULL) {
		TAILQ_REMOVE(msgq_tmp, msg, msg_entry_tmp);
		pfsync_release_msg(msg, 0);
	}
}

int
pfsync_send_queue(struct pfsync_softc *sc, struct pfsync_local *lo)
{
	struct mbuf *m = NULL;
	struct pfsync_msg *msg;
	struct pfsync_msg_queue msgq_tmp = TAILQ_HEAD_INITIALIZER(msgq_tmp);

	msg = TAILQ_FIRST(&lo->lo_msg_queue);
	while (msg) {
		if (m == NULL)
			m = pfsync_mbuf_to_send(sc);
		if (m == NULL)
			return (ENOBUFS);
		/*
		 * Try to append message to mbuf and link it to msgq_tmp.
		 * When we succeed in sending this mbuf, release msg msgq_tmp.
		 */
		if (pfsync_append_msg(m, msg) != 0) {
			if (!TAILQ_EMPTY(&msgq_tmp)) {
				if (pfsync_send_mbuf(sc, m) == EBUSY) {
					if (lo->lo_busy++ < PFSYNC_LO_BUSY_MAX)
						return (EBUSY);
				}
				lo->lo_busy = 0;
				/* Release temporary queue */
				pfsync_release_queue(&msgq_tmp);
				/*
				 * This mbuf was either sent, or error != EBUSY.
				 * Drop it all since we can only expect to
				 * recover from EBUSY.
				 */
				m = NULL;
			}
			/* Retry this message */
		} else {
			/* Record we have appended this message */
			TAILQ_INSERT_TAIL(&msgq_tmp, msg, msg_entry_tmp);
			/* Advance to next message */
			msg = TAILQ_NEXT(msg, msg_entry);
		}
	}

	if (m) {
		if (!TAILQ_EMPTY(&msgq_tmp)) {
			if (pfsync_send_mbuf(sc, m) == EBUSY)
				return (EBUSY);
			pfsync_release_queue(&msgq_tmp);
		} else
			m_freem(m);
	}

	return (0);
}

int
pfsync_in_ureq_bus(struct pfsync_softc *sc)
{
	struct pf_state *st;
	int s, bulk_count = 0;
	struct pfsync_msg *bm_start, *bm_end;
	struct pfsync_local *lo;

	KERNEL_ASSERT_LOCKED();	/* only one handler always */

	DPFPRINTF(LOG_INFO, "received bulk update request");

	sc->sc_ureq_received = getuptime();

	/* Out of memory ? Too bad we just fail :/ */
	if ((bm_start = pfsync_bus_msg(sc, PFSYNC_BUS_START)) == NULL)
		return (ENOBUFS);
	if ((bm_end = pfsync_bus_msg(sc, PFSYNC_BUS_END)) == NULL) {
		pfsync_msg_free(sc, bm_start);
		return (ENOBUFS);
	}

	/*
	 * Make sure no pfsync local accepts any new messages to be sent.
	 */
	pfsync_deny_work(sc);

	/*
	 * Drop every msg we were about to send. XXX we could drop PF_STATE_MSG
	 * only, that's all we're interested.
	 */
	pfsync_drop(sc);

	lo = pfsync_local_enter(sc);
	/*
	 * We must be allowed to work.
	 */
	lo->lo_denywork = 0;

	/* We will send a bulk start */
	pfsync_insert_msg(lo, bm_start);

	s = splnet();
	rcu_list_foreach(st, &state_list, entry_list) {
		if (st->state_flags & PFSTATE_NOSYNC)
			continue;

		pf_state_lock(st);
		if (pf_state_isvalid(st) &&
		    st->sync_state == PFSYNC_S_NONE &&
		    st->timeout < PFTM_MAX &&
		    st->pfsync_time <= sc->sc_ureq_received) {
			pfsync_update_state_req(st);
			bulk_count++;
		}
		pf_state_unlock(st);
	}
	splx(s);

	/* Send BUS_END after all states have been sent */
	pfsync_insert_msg(lo, bm_end);

	pfsync_local_leave(sc, lo);

	/* Everyone can continue now */
	pfsync_allow_work(sc);

	return (0);
}

void
pfsync_local(void)
{
	struct pfsync_softc *sc = pfsyncif;
	struct pfsync_local *lo;

	if (sc == NULL)
		return;

	lo = pfsync_local_enter(sc);

	/*
	 * The card is too busy, only retry next tick.
	 */
	if (lo->lo_lastrun == ticks) {
		pfsync_local_leave(sc, lo);
		return;
	}
	/* Do the actual work, send everything we can. */
	pfsync_send_queue(sc, lo);

	lo->lo_lastrun = ticks;

	pfsync_local_leave(sc, lo);
}

void
pfsync_local_task(void *unused)
{
	netisr_conf_enter_read();
	pfsync_local();
	netisr_conf_exit_read();
}

void
pfsync_sched_local(struct pfsync_softc *sc, int cpuid)
{
	task_add(taskq_of_cpuid(cpuid), cpumem_of_id(sc->sc_local, cpuid));
}

void
pfsync_sched_locals(void)
{
	struct pfsync_softc *sc = pfsyncif; /* XXX */
	struct pfsync_local *lo;
	struct cpumem_iter i;

	/* XXX check running ? or not ? */
	if (sc == NULL)
		return;

	CPUMEM_FOREACH(lo, &i, sc->sc_local)
		task_add(taskq_of_cpuid(i.cpu), &lo->lo_task);
}

void
pfsync_deny_work(struct pfsync_softc *sc)
{
	struct pfsync_local *lo;
	struct cpumem_iter i;

	CPUMEM_FOREACH(lo, &i, sc->sc_local)
		lo->lo_denywork = 1;
}

void
pfsync_allow_work(struct pfsync_softc *sc)
{
	struct pfsync_local *lo;
	struct cpumem_iter i;

	CPUMEM_FOREACH(lo, &i, sc->sc_local)
		lo->lo_denywork = 0;
}

void
pfsync_tick(void *unused)
{
	struct pfsync_local *lo;
	struct cpumem_iter i;
	struct pfsync_softc *sc = pfsyncif;
	extern int hz;

	if (sc == NULL)
		return;

	CPUMEM_FOREACH(lo, &i, sc->sc_local) {
#if 0	/* XXX Enable me when happy */
		if (TAILQ_EMPTY(&lo->lo_msg_queue))
			continue;
#endif
		pfsync_sched_local(sc, i.cpu);
	}

	timeout_add(&pfsync_tick_tmo, hz / 25);
}
