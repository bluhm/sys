/* $OpenBSD: wsevent.c,v 1.28 2024/03/25 13:01:49 mvs Exp $ */
/* $NetBSD: wsevent.c,v 1.16 2003/08/07 16:31:29 agc Exp $ */

/*
 * Copyright (c) 1996, 1997 Christopher G. Demetriou.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Christopher G. Demetriou
 *	for the NetBSD Project.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
 *
 * All advertising materials mentioning features or use of this software
 * must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Lawrence Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)event.c	8.1 (Berkeley) 6/11/93
 */

/*
 * Internal "wscons_event" queue interface for the keyboard and mouse drivers.
 */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <dev/wscons/wsconsio.h>
#include <dev/wscons/wseventvar.h>

void	filt_wseventdetach(struct knote *);
int	filt_wseventread(struct knote *, long);

const struct filterops wsevent_filtops = {
	.f_flags	= FILTEROP_ISFD,
	.f_attach	= NULL,
	.f_detach	= filt_wseventdetach,
	.f_event	= filt_wseventread,
};

/*
 * Initialize a wscons_event queue.
 */
int
wsevent_init(struct wseventvar *ev)
{
	struct wscons_event *queue;

	if (ev->ws_q != NULL)
		return (0);

        queue = mallocarray(WSEVENT_QSIZE, sizeof(struct wscons_event),
	    M_DEVBUF, M_WAITOK | M_ZERO);
	if (ev->ws_q != NULL) {
		free(queue, M_DEVBUF,
		    WSEVENT_QSIZE * sizeof(struct wscons_event));
		return (1);
	}

	ev->ws_q = queue;
	ev->ws_get = ev->ws_put = 0;

	sigio_init(&ev->ws_sigio);

	return (0);
}

/*
 * Tear down a wscons_event queue.
 */
void
wsevent_fini(struct wseventvar *ev)
{
	if (ev->ws_q == NULL) {
#ifdef DIAGNOSTIC
		printf("wsevent_fini: already invoked\n");
#endif
		return;
	}
	free(ev->ws_q, M_DEVBUF, WSEVENT_QSIZE * sizeof(struct wscons_event));
	ev->ws_q = NULL;

	klist_invalidate(&ev->ws_sel.si_note);

	sigio_free(&ev->ws_sigio);
}

/*
 * User-level interface: read, kqueue.
 * (User cannot write an event queue.)
 */
int
wsevent_read(struct wseventvar *ev, struct uio *uio, int flags)
{
	int s, error;
	u_int cnt;
	size_t n;

	/*
	 * Make sure we can return at least 1.
	 */
	if (uio->uio_resid < sizeof(struct wscons_event))
		return (EMSGSIZE);	/* ??? */
	s = splwsevent();
	while (ev->ws_get == ev->ws_put) {
		if (flags & IO_NDELAY) {
			splx(s);
			return (EWOULDBLOCK);
		}
		ev->ws_wanted = 1;
		error = tsleep_nsec(ev, PWSEVENT | PCATCH,
		    "wsevent_read", INFSLP);
		if (error) {
			splx(s);
			return (error);
		}
	}
	/*
	 * Move wscons_event from tail end of queue (there is at least one
	 * there).
	 */
	if (ev->ws_put < ev->ws_get)
		cnt = WSEVENT_QSIZE - ev->ws_get; /* events in [get..QSIZE) */
	else
		cnt = ev->ws_put - ev->ws_get;    /* events in [get..put) */
	splx(s);
	n = howmany(uio->uio_resid, sizeof(struct wscons_event));
	if (cnt > n)
		cnt = n;
	error = uiomove((caddr_t)&ev->ws_q[ev->ws_get],
	    cnt * sizeof(struct wscons_event), uio);
	n -= cnt;
	/*
	 * If we do not wrap to 0, used up all our space, or had an error,
	 * stop.  Otherwise move from front of queue to put index, if there
	 * is anything there to move.
	 */
	if ((ev->ws_get = (ev->ws_get + cnt) % WSEVENT_QSIZE) != 0 ||
	    n == 0 || error || (cnt = ev->ws_put) == 0)
		return (error);
	if (cnt > n)
		cnt = n;
	error = uiomove((caddr_t)&ev->ws_q[0],
	    cnt * sizeof(struct wscons_event), uio);
	ev->ws_get = cnt;
	return (error);
}

int
wsevent_kqfilter(struct wseventvar *ev, struct knote *kn)
{
	struct klist *klist;
	int s;

	klist = &ev->ws_sel.si_note;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &wsevent_filtops;
		break;
	default:
		return (EINVAL);
	}

	kn->kn_hook = ev;

	s = splwsevent();
	klist_insert_locked(klist, kn);
	splx(s);

	return (0);
}

void
filt_wseventdetach(struct knote *kn)
{
	struct wseventvar *ev = kn->kn_hook;
	struct klist *klist = &ev->ws_sel.si_note;
	int s;

	s = splwsevent();
	klist_remove_locked(klist, kn);
	splx(s);
}

int
filt_wseventread(struct knote *kn, long hint)
{
	struct wseventvar *ev = kn->kn_hook;

	if (ev->ws_get == ev->ws_put)
		return (0);

	if (ev->ws_get < ev->ws_put)
		kn->kn_data = ev->ws_put - ev->ws_get;
	else
		kn->kn_data = (WSEVENT_QSIZE - ev->ws_get) + ev->ws_put;

	return (1);
}
