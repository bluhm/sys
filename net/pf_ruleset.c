/*	$OpenBSD: pf_ruleset.c,v 1.9 2014/07/22 11:06:10 mpi Exp $ */

/*
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002,2003 Henning Brauer
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 */

#include <sys/param.h>
#include <sys/socket.h>
#ifdef _KERNEL
# include <sys/systm.h>
# include <sys/mbuf.h>
#endif /* _KERNEL */
#include <sys/syslog.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <net/if.h>
#include <net/pfvar.h>

#ifdef INET6
#include <netinet/ip6.h>
#endif /* INET6 */


#ifdef _KERNEL
#define rs_malloc(x)		malloc(x, M_TEMP, M_WAITOK|M_CANFAIL|M_ZERO)
#define rs_free(x)		free(x, M_TEMP, 0)

#else
/* Userland equivalents so we can lend code to pfctl et al. */

# include <arpa/inet.h>
# include <errno.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# define rs_malloc(x)		 calloc(1, x)
# define rs_free(x)		 free(x)

# ifdef PFDEBUG
#  include <sys/stdarg.h>	/* for DPFPRINTF() */
# endif
#endif /* _KERNEL */


struct pf_anchor_global	 pf_anchors;
struct pf_anchor	 pf_main_anchor;

static __inline int pf_anchor_compare(struct pf_anchor *, struct pf_anchor *);

RB_GENERATE(pf_anchor_global, pf_anchor, entry_global, pf_anchor_compare);
RB_GENERATE(pf_anchor_node, pf_anchor, entry_node, pf_anchor_compare);

static __inline int
pf_anchor_compare(struct pf_anchor *a, struct pf_anchor *b)
{
	int c = strcmp(a->path, b->path);

	return (c ? (c < 0 ? -1 : 1) : 0);
}

void
pf_init_ruleset(struct pf_ruleset *ruleset)
{
	memset(ruleset, 0, sizeof(struct pf_ruleset));
	TAILQ_INIT(&ruleset->rules.queues[0]);
	TAILQ_INIT(&ruleset->rules.queues[1]);
	ruleset->rules.active.ptr = &ruleset->rules.queues[0];
	ruleset->rules.inactive.ptr = &ruleset->rules.queues[1];
}

struct pf_anchor *
pf_find_anchor(const char *path)
{
	struct pf_anchor	*key, *found;

	key = (struct pf_anchor *)rs_malloc(sizeof(*key));
	if (key == NULL)
		return (NULL);
	strlcpy(key->path, path, sizeof(key->path));
	found = RB_FIND(pf_anchor_global, &pf_anchors, key);
	rs_free(key);
	return (found);
}

struct pf_ruleset *
pf_find_ruleset(const char *path)
{
	struct pf_anchor	*anchor;

	while (*path == '/')
		path++;
	if (!*path)
		return (&pf_main_ruleset);
	anchor = pf_find_anchor(path);
	if (anchor == NULL)
		return (NULL);
	else
		return (&anchor->ruleset);
}

struct pf_ruleset *
pf_find_or_create_ruleset(const char *path)
{
	char			*p, *q, *r;
	struct pf_ruleset	*ruleset;
	struct pf_anchor	*anchor, *dup, *parent = NULL;

	if (path[0] == 0)
		return (&pf_main_ruleset);
	while (*path == '/')
		path++;
	ruleset = pf_find_ruleset(path);
	if (ruleset != NULL)
		return (ruleset);
	p = (char *)rs_malloc(MAXPATHLEN);
	if (p == NULL)
		return (NULL);
	strlcpy(p, path, MAXPATHLEN);
	while (parent == NULL && (q = strrchr(p, '/')) != NULL) {
		*q = 0;
		if ((ruleset = pf_find_ruleset(p)) != NULL) {
			parent = ruleset->anchor;
			break;
		}
	}
	if (q == NULL)
		q = p;
	else
		q++;
	strlcpy(p, path, MAXPATHLEN);
	if (!*q) {
		rs_free(p);
		return (NULL);
	}
	while ((r = strchr(q, '/')) != NULL || *q) {
		if (r != NULL)
			*r = 0;
		if (!*q || strlen(q) >= PF_ANCHOR_NAME_SIZE ||
		    (parent != NULL && strlen(parent->path) >=
		    MAXPATHLEN - PF_ANCHOR_NAME_SIZE - 1)) {
			rs_free(p);
			return (NULL);
		}
		anchor = (struct pf_anchor *)rs_malloc(sizeof(*anchor));
		if (anchor == NULL) {
			rs_free(p);
			return (NULL);
		}
		RB_INIT(&anchor->children);
		strlcpy(anchor->name, q, sizeof(anchor->name));
		if (parent != NULL) {
			strlcpy(anchor->path, parent->path,
			    sizeof(anchor->path));
			strlcat(anchor->path, "/", sizeof(anchor->path));
		}
		strlcat(anchor->path, anchor->name, sizeof(anchor->path));
		if ((dup = RB_INSERT(pf_anchor_global, &pf_anchors, anchor)) !=
		    NULL) {
			DPFPRINTF(LOG_NOTICE,
			    "pf_find_or_create_ruleset: RB_INSERT1 "
			    "'%s' '%s' collides with '%s' '%s'",
			    anchor->path, anchor->name, dup->path, dup->name);
			rs_free(anchor);
			rs_free(p);
			return (NULL);
		}
		if (parent != NULL) {
			anchor->parent = parent;
			if ((dup = RB_INSERT(pf_anchor_node, &parent->children,
			    anchor)) != NULL) {
				DPFPRINTF(LOG_NOTICE,
				    "pf_find_or_create_ruleset: "
				    "RB_INSERT2 '%s' '%s' collides with "
				    "'%s' '%s'", anchor->path, anchor->name,
				    dup->path, dup->name);
				RB_REMOVE(pf_anchor_global, &pf_anchors,
				    anchor);
				rs_free(anchor);
				rs_free(p);
				return (NULL);
			}
		}
		pf_init_ruleset(&anchor->ruleset);
		anchor->ruleset.anchor = anchor;
		parent = anchor;
		if (r != NULL)
			q = r + 1;
		else
			*q = 0;
	}
	rs_free(p);
	return (&anchor->ruleset);
}

void
pf_remove_if_empty_ruleset(struct pf_ruleset *ruleset)
{
	struct pf_anchor	*parent;

	while (ruleset != NULL) {
		if (ruleset == &pf_main_ruleset || ruleset->anchor == NULL ||
		    !RB_EMPTY(&ruleset->anchor->children) ||
		    ruleset->anchor->refcnt > 0 || ruleset->tables > 0 ||
		    ruleset->topen)
			return;
		if (!TAILQ_EMPTY(ruleset->rules.active.ptr) ||
		    !TAILQ_EMPTY(ruleset->rules.inactive.ptr) ||
		    ruleset->rules.inactive.open)
			return;
		RB_REMOVE(pf_anchor_global, &pf_anchors, ruleset->anchor);
		if ((parent = ruleset->anchor->parent) != NULL)
			RB_REMOVE(pf_anchor_node, &parent->children,
			    ruleset->anchor);
		rs_free(ruleset->anchor);
		if (parent == NULL)
			return;
		ruleset = &parent->ruleset;
	}
}

int
pf_anchor_setup(struct pf_rule *r, const struct pf_ruleset *s,
    const char *name)
{
	char			*p, *path;
	struct pf_ruleset	*ruleset;

	r->anchor = NULL;
	r->anchor_relative = 0;
	r->anchor_wildcard = 0;
	if (!name[0])
		return (0);
	path = (char *)rs_malloc(MAXPATHLEN);
	if (path == NULL)
		return (1);
	if (name[0] == '/')
		strlcpy(path, name + 1, MAXPATHLEN);
	else {
		/* relative path */
		r->anchor_relative = 1;
		if (s->anchor == NULL || !s->anchor->path[0])
			path[0] = 0;
		else
			strlcpy(path, s->anchor->path, MAXPATHLEN);
		while (name[0] == '.' && name[1] == '.' && name[2] == '/') {
			if (!path[0]) {
				DPFPRINTF(LOG_NOTICE,
				    "pf_anchor_setup: .. beyond root");
				rs_free(path);
				return (1);
			}
			if ((p = strrchr(path, '/')) != NULL)
				*p = 0;
			else
				path[0] = 0;
			r->anchor_relative++;
			name += 3;
		}
		if (path[0])
			strlcat(path, "/", MAXPATHLEN);
		strlcat(path, name, MAXPATHLEN);
	}
	if ((p = strrchr(path, '/')) != NULL && !strcmp(p, "/*")) {
		r->anchor_wildcard = 1;
		*p = 0;
	}
	ruleset = pf_find_or_create_ruleset(path);
	rs_free(path);
	if (ruleset == NULL || ruleset->anchor == NULL) {
		DPFPRINTF(LOG_NOTICE,
		    "pf_anchor_setup: ruleset");
		return (1);
	}
	r->anchor = ruleset->anchor;
	r->anchor->refcnt++;
	return (0);
}

int
pf_anchor_copyout(const struct pf_ruleset *rs, const struct pf_rule *r,
    struct pfioc_rule *pr)
{
	pr->anchor_call[0] = 0;
	if (r->anchor == NULL)
		return (0);
	if (!r->anchor_relative) {
		strlcpy(pr->anchor_call, "/", sizeof(pr->anchor_call));
		strlcat(pr->anchor_call, r->anchor->path,
		    sizeof(pr->anchor_call));
	} else {
		char	*a, *p;
		int	 i;

		a = (char *)rs_malloc(MAXPATHLEN);
		if (a == NULL)
			return (1);
		if (rs->anchor == NULL)
			a[0] = 0;
		else
			strlcpy(a, rs->anchor->path, MAXPATHLEN);
		for (i = 1; i < r->anchor_relative; ++i) {
			if ((p = strrchr(a, '/')) == NULL)
				p = a;
			*p = 0;
			strlcat(pr->anchor_call, "../",
			    sizeof(pr->anchor_call));
		}
		if (strncmp(a, r->anchor->path, strlen(a))) {
			DPFPRINTF(LOG_NOTICE,
			    "pf_anchor_copyout: '%s' '%s'", a,
			    r->anchor->path);
			rs_free(a);
			return (1);
		}
		if (strlen(r->anchor->path) > strlen(a))
			strlcat(pr->anchor_call, r->anchor->path + (a[0] ?
			    strlen(a) + 1 : 0), sizeof(pr->anchor_call));
		rs_free(a);
	}
	if (r->anchor_wildcard)
		strlcat(pr->anchor_call, pr->anchor_call[0] ? "/*" : "*",
		    sizeof(pr->anchor_call));
	return (0);
}

void
pf_anchor_remove(struct pf_rule *r)
{
	if (r->anchor == NULL)
		return;
	if (r->anchor->refcnt <= 0) {
		DPFPRINTF(LOG_NOTICE,
		    "pf_anchor_remove: broken refcount");
		r->anchor = NULL;
		return;
	}
	if (!--r->anchor->refcnt)
		pf_remove_if_empty_ruleset(&r->anchor->ruleset);
	r->anchor = NULL;
}
