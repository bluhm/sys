/*	$OpenBSD: in6.c,v 1.230 2019/02/13 23:47:43 dlg Exp $	*/
/*	$KAME: in6.c,v 1.372 2004/06/14 08:14:21 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)in.c	8.2 (Berkeley) 11/15/93
 */

#include "carp.h"

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/mld6_var.h>
#ifdef MROUTING
#include <netinet6/ip6_mroute.h>
#endif
#include <netinet6/in6_ifattach.h>
#if NCARP > 0
#include <netinet/ip_carp.h>
#endif

/*
 * Definitions of some constant IP6 addresses.
 */
const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;
const struct in6_addr in6addr_intfacelocal_allnodes =
	IN6ADDR_INTFACELOCAL_ALLNODES_INIT;
const struct in6_addr in6addr_linklocal_allnodes =
	IN6ADDR_LINKLOCAL_ALLNODES_INIT;
const struct in6_addr in6addr_linklocal_allrouters =
	IN6ADDR_LINKLOCAL_ALLROUTERS_INIT;

const struct in6_addr in6mask0 = IN6MASK0;
const struct in6_addr in6mask32 = IN6MASK32;
const struct in6_addr in6mask64 = IN6MASK64;
const struct in6_addr in6mask96 = IN6MASK96;
const struct in6_addr in6mask128 = IN6MASK128;

int in6_ioctl(u_long, caddr_t, struct ifnet *, int);
int in6_ioctl_change_ifaddr(u_long, caddr_t, struct ifnet *);
int in6_ioctl_get(u_long, caddr_t, struct ifnet *);
int in6_check_embed_scope(struct sockaddr_in6 *, unsigned int);
int in6_clear_scope_id(struct sockaddr_in6 *, unsigned int);
int in6_ifinit(struct ifnet *, struct in6_ifaddr *, int);
void in6_unlink_ifa(struct in6_ifaddr *, struct ifnet *);

const struct sockaddr_in6 sa6_any = {
	sizeof(sa6_any), AF_INET6, 0, 0, IN6ADDR_ANY_INIT, 0
};

int
in6_mask2len(struct in6_addr *mask, u_char *lim0)
{
	int x = 0, y;
	u_char *lim = lim0, *p;

	/* ignore the scope_id part */
	if (lim0 == NULL || lim0 - (u_char *)mask > sizeof(*mask))
		lim = (u_char *)mask + sizeof(*mask);
	for (p = (u_char *)mask; p < lim; x++, p++) {
		if (*p != 0xff)
			break;
	}
	y = 0;
	if (p < lim) {
		for (y = 0; y < 8; y++) {
			if ((*p & (0x80 >> y)) == 0)
				break;
		}
	}

	/*
	 * when the limit pointer is given, do a stricter check on the
	 * remaining bits.
	 */
	if (p < lim) {
		if (y != 0 && (*p & (0x00ff >> y)) != 0)
			return (-1);
		for (p = p + 1; p < lim; p++)
			if (*p != 0)
				return (-1);
	}

	return x * 8 + y;
}

int
in6_nam2sin6(const struct mbuf *nam, struct sockaddr_in6 **sin6)
{
	struct sockaddr *sa = mtod(nam, struct sockaddr *);

	if (nam->m_len < offsetof(struct sockaddr, sa_data))
		return EINVAL;
	if (sa->sa_family != AF_INET6)
		return EAFNOSUPPORT;
	if (sa->sa_len != nam->m_len)
		return EINVAL;
	if (sa->sa_len != sizeof(struct sockaddr_in6))
		return EINVAL;
	*sin6 = satosin6(sa);

	return 0;
}

int
in6_control(struct socket *so, u_long cmd, caddr_t data, struct ifnet *ifp)
{
	int privileged;
	int error;

	privileged = 0;
	if ((so->so_state & SS_PRIV) != 0)
		privileged++;

	switch (cmd) {
#ifdef MROUTING
	case SIOCGETSGCNT_IN6:
	case SIOCGETMIFCNT_IN6:
		error = mrt6_ioctl(so, cmd, data);
		break;
#endif /* MROUTING */
	default:
		error = in6_ioctl(cmd, data, ifp, privileged);
		break;
	}

	return error;
}

int
in6_ioctl(u_long cmd, caddr_t data, struct ifnet *ifp, int privileged)
{
	if (ifp == NULL)
		return (ENXIO);

	switch (cmd) {
	case SIOCGIFINFO_IN6:
	case SIOCGNBRINFO_IN6:
		return (nd6_ioctl(cmd, data, ifp));
	case SIOCGIFDSTADDR_IN6:
	case SIOCGIFNETMASK_IN6:
	case SIOCGIFAFLAG_IN6:
	case SIOCGIFALIFETIME_IN6:
		return (in6_ioctl_get(cmd, data, ifp));
	case SIOCAIFADDR_IN6:
	case SIOCDIFADDR_IN6:
		if (!privileged)
			return (EPERM);
		return (in6_ioctl_change_ifaddr(cmd, data, ifp));
	case SIOCSIFADDR:
	case SIOCSIFDSTADDR:
	case SIOCSIFBRDADDR:
	case SIOCSIFNETMASK:
		/*
		 * Do not pass those ioctl to driver handler since they are not
		 * properly set up. Instead just error out.
		 */
		return (EINVAL);
	default:
		return (EOPNOTSUPP);
	}
}

int
in6_ioctl_change_ifaddr(u_long cmd, caddr_t data, struct ifnet *ifp)
{
	struct	in6_ifreq *ifr = (struct in6_ifreq *)data;
	struct	in6_ifaddr *ia6 = NULL;
	struct	in6_aliasreq *ifra = (struct in6_aliasreq *)data;
	struct sockaddr_in6 *sa6;
	int	error = 0, newifaddr = 0, plen;

	/*
	 * Find address for this interface, if it exists.
	 *
	 * In netinet code, we have checked ifra_addr in SIOCSIF*ADDR operation
	 * only, and used the first interface address as the target of other
	 * operations (without checking ifra_addr).  This was because netinet
	 * code/API assumed at most 1 interface address per interface.
	 * Since IPv6 allows a node to assign multiple addresses
	 * on a single interface, we almost always look and check the
	 * presence of ifra_addr, and reject invalid ones here.
	 * It also decreases duplicated code among SIOC*_IN6 operations.
	 */
	switch (cmd) {
	case SIOCAIFADDR_IN6:
		sa6 = &ifra->ifra_addr;
		break;
	case SIOCDIFADDR_IN6:
		sa6 = &ifr->ifr_addr;
		break;
	default:
		panic("unknown ioctl %lu", cmd);
	}

	NET_LOCK();

	if (sa6 && sa6->sin6_family == AF_INET6) {
		error = in6_check_embed_scope(sa6, ifp->if_index);
		if (error)
			goto err;
		error = in6_clear_scope_id(sa6, ifp->if_index);
		if (error)
			goto err;
		ia6 = in6ifa_ifpwithaddr(ifp, &sa6->sin6_addr);
	}

	switch (cmd) {
	case SIOCDIFADDR_IN6:
		/*
		 * for IPv4, we look for existing in_ifaddr here to allow
		 * "ifconfig if0 delete" to remove the first IPv4 address on
		 * the interface.  For IPv6, as the spec allows multiple
		 * interface address from the day one, we consider "remove the
		 * first one" semantics to be not preferable.
		 */
		if (ia6 == NULL) {
			error = EADDRNOTAVAIL;
			break;
		}
		/*
		 * We always require users to specify a valid IPv6 address for
		 * the corresponding operation.
		 */
		if (ifra->ifra_addr.sin6_family != AF_INET6 ||
		    ifra->ifra_addr.sin6_len != sizeof(struct sockaddr_in6)) {
			error = EAFNOSUPPORT;
			break;
		}
		in6_purgeaddr(&ia6->ia_ifa);
		dohooks(ifp->if_addrhooks, 0);
		break;

	case SIOCAIFADDR_IN6:
		/*
		 * We always require users to specify a valid IPv6 address for
		 * the corresponding operation.
		 */
		if (ifra->ifra_addr.sin6_family != AF_INET6 ||
		    ifra->ifra_addr.sin6_len != sizeof(struct sockaddr_in6)) {
			error = EAFNOSUPPORT;
			break;
		}

		/* reject read-only flags */
		if ((ifra->ifra_flags & IN6_IFF_DUPLICATED) != 0 ||
		    (ifra->ifra_flags & IN6_IFF_DETACHED) != 0 ||
		    (ifra->ifra_flags & IN6_IFF_DEPRECATED) != 0) {
			error = EINVAL;
			break;
		}

		if (ia6 == NULL)
			newifaddr = 1;

		/*
		 * Make the address tentative before joining multicast
		 * addresses, so that corresponding MLD responses would
		 * not have a tentative source address.
		 */
		if (newifaddr && in6if_do_dad(ifp))
			ifra->ifra_flags |= IN6_IFF_TENTATIVE;

		/*
		 * first, make or update the interface address structure,
		 * and link it to the list. try to enable inet6 if there
		 * is no link-local yet.
		 */
		error = in6_ifattach(ifp);
		if (error != 0)
			break;
		error = in6_update_ifa(ifp, ifra, ia6);
		if (error != 0)
			break;

		ia6 = in6ifa_ifpwithaddr(ifp, &ifra->ifra_addr.sin6_addr);
		if (ia6 == NULL) {
			/*
			 * this can happen when the user specify the 0 valid
			 * lifetime.
			 */
			break;
		}

		/* Perform DAD, if needed. */
		if (ia6->ia6_flags & IN6_IFF_TENTATIVE)
			nd6_dad_start(&ia6->ia_ifa);

		if (!newifaddr) {
			dohooks(ifp->if_addrhooks, 0);
			break;
		}

		plen = in6_mask2len(&ia6->ia_prefixmask.sin6_addr, NULL);
		if ((ifp->if_flags & IFF_LOOPBACK) || plen == 128) {
			dohooks(ifp->if_addrhooks, 0);
			break;	/* No need to install a connected route. */
		}

		error = rt_ifa_add(&ia6->ia_ifa,
		    RTF_CLONING | RTF_CONNECTED | RTF_MPATH,
		    ia6->ia_ifa.ifa_addr, ifp->if_rdomain);
		if (error) {
			in6_purgeaddr(&ia6->ia_ifa);
			break;
		}
		dohooks(ifp->if_addrhooks, 0);
		break;
	}

err:
	NET_UNLOCK();
	return (error);
}

int
in6_ioctl_get(u_long cmd, caddr_t data, struct ifnet *ifp)
{
	struct	in6_ifreq *ifr = (struct in6_ifreq *)data;
	struct	in6_ifaddr *ia6 = NULL;
	struct sockaddr_in6 *sa6;
	int	error = 0;

	sa6 = &ifr->ifr_addr;

	NET_RLOCK();

	if (sa6 && sa6->sin6_family == AF_INET6) {
		error = in6_check_embed_scope(sa6, ifp->if_index);
		if (error)
			goto err;
		error = in6_clear_scope_id(sa6, ifp->if_index);
		if (error)
			goto err;
		ia6 = in6ifa_ifpwithaddr(ifp, &sa6->sin6_addr);
	}

	/* must think again about its semantics */
	if (ia6 == NULL) {
		error = EADDRNOTAVAIL;
		goto err;
	}

	switch (cmd) {
	case SIOCGIFDSTADDR_IN6:
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0) {
			error = EINVAL;
			break;
		}
		/*
		 * XXX: should we check if ifa_dstaddr is NULL and return
		 * an error?
		 */
		ifr->ifr_dstaddr = ia6->ia_dstaddr;
		break;

	case SIOCGIFNETMASK_IN6:
		ifr->ifr_addr = ia6->ia_prefixmask;
		break;

	case SIOCGIFAFLAG_IN6:
		ifr->ifr_ifru.ifru_flags6 = ia6->ia6_flags;
		break;

	case SIOCGIFALIFETIME_IN6:
		ifr->ifr_ifru.ifru_lifetime = ia6->ia6_lifetime;
		if (ia6->ia6_lifetime.ia6t_vltime != ND6_INFINITE_LIFETIME) {
			time_t expire, maxexpire;
			struct in6_addrlifetime *retlt =
			    &ifr->ifr_ifru.ifru_lifetime;

			/*
			 * XXX: adjust expiration time assuming time_t is
			 * signed.
			 */
			maxexpire =
			    (time_t)~(1ULL << ((sizeof(maxexpire) * 8) - 1));
			if (ia6->ia6_lifetime.ia6t_vltime <
			    maxexpire - ia6->ia6_updatetime) {
				expire = ia6->ia6_updatetime +
				    ia6->ia6_lifetime.ia6t_vltime;
				if (expire != 0) {
					expire -= time_uptime;
					expire += time_second;
				}
				retlt->ia6t_expire = expire;
			} else
				retlt->ia6t_expire = maxexpire;
		}
		if (ia6->ia6_lifetime.ia6t_pltime != ND6_INFINITE_LIFETIME) {
			time_t expire, maxexpire;
			struct in6_addrlifetime *retlt =
			    &ifr->ifr_ifru.ifru_lifetime;

			/*
			 * XXX: adjust expiration time assuming time_t is
			 * signed.
			 */
			maxexpire =
			    (time_t)~(1ULL << ((sizeof(maxexpire) * 8) - 1));
			if (ia6->ia6_lifetime.ia6t_pltime <
			    maxexpire - ia6->ia6_updatetime) {
				expire = ia6->ia6_updatetime +
				    ia6->ia6_lifetime.ia6t_pltime;
				if (expire != 0) {
					expire -= time_uptime;
					expire += time_second;
				}
				retlt->ia6t_preferred = expire;
			} else
				retlt->ia6t_preferred = maxexpire;
		}
		break;

	default:
		panic("invalid ioctl %lu", cmd);
	}

err:
	NET_RUNLOCK();
	return (error);
}

int
in6_check_embed_scope(struct sockaddr_in6 *sa6, unsigned int ifidx)
{
	if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)) {
		if (sa6->sin6_addr.s6_addr16[1] == 0) {
			/* link ID is not embedded by the user */
			sa6->sin6_addr.s6_addr16[1] = htons(ifidx);
		} else if (sa6->sin6_addr.s6_addr16[1] != htons(ifidx))
			return EINVAL;	/* link ID contradicts */
	}
	return 0;
}

int
in6_clear_scope_id(struct sockaddr_in6 *sa6, unsigned int ifidx)
{
	if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)) {
		if (sa6->sin6_scope_id) {
			if (sa6->sin6_scope_id != (u_int32_t)ifidx)
				return EINVAL;
			sa6->sin6_scope_id = 0; /* XXX: good way? */
		}
	}
	return 0;
}

/*
 * Update parameters of an IPv6 interface address.
 * If necessary, a new entry is created and linked into address chains.
 * This function is separated from in6_control().
 */
int
in6_update_ifa(struct ifnet *ifp, struct in6_aliasreq *ifra,
    struct in6_ifaddr *ia6)
{
	int error = 0, hostIsNew = 0, plen = -1;
	struct sockaddr_in6 dst6;
	struct in6_addrlifetime *lt;
	struct in6_multi_mship *imm;
	struct rtentry *rt;
	char addr[INET6_ADDRSTRLEN];

	NET_ASSERT_LOCKED();

	/* Validate parameters */
	if (ifp == NULL || ifra == NULL) /* this maybe redundant */
		return (EINVAL);

	/*
	 * The destination address for a p2p link must have a family
	 * of AF_UNSPEC or AF_INET6.
	 */
	if ((ifp->if_flags & IFF_POINTOPOINT) != 0 &&
	    ifra->ifra_dstaddr.sin6_family != AF_INET6 &&
	    ifra->ifra_dstaddr.sin6_family != AF_UNSPEC)
		return (EAFNOSUPPORT);

	/*
	 * validate ifra_prefixmask.  don't check sin6_family, netmask
	 * does not carry fields other than sin6_len.
	 */
	if (ifra->ifra_prefixmask.sin6_len > sizeof(struct sockaddr_in6))
		return (EINVAL);
	/*
	 * Because the IPv6 address architecture is classless, we require
	 * users to specify a (non 0) prefix length (mask) for a new address.
	 * We also require the prefix (when specified) mask is valid, and thus
	 * reject a non-consecutive mask.
	 */
	if (ia6 == NULL && ifra->ifra_prefixmask.sin6_len == 0)
		return (EINVAL);
	if (ifra->ifra_prefixmask.sin6_len != 0) {
		plen = in6_mask2len(&ifra->ifra_prefixmask.sin6_addr,
		    (u_char *)&ifra->ifra_prefixmask +
		    ifra->ifra_prefixmask.sin6_len);
		if (plen <= 0)
			return (EINVAL);
	} else {
		/*
		 * In this case, ia6 must not be NULL.  We just use its prefix
		 * length.
		 */
		plen = in6_mask2len(&ia6->ia_prefixmask.sin6_addr, NULL);
	}
	/*
	 * If the destination address on a p2p interface is specified,
	 * and the address is a scoped one, validate/set the scope
	 * zone identifier.
	 */
	dst6 = ifra->ifra_dstaddr;
	if ((ifp->if_flags & (IFF_POINTOPOINT|IFF_LOOPBACK)) != 0 &&
	    (dst6.sin6_family == AF_INET6)) {
		error = in6_check_embed_scope(&dst6, ifp->if_index);
		if (error)
			return error;
	}
	/*
	 * The destination address can be specified only for a p2p or a
	 * loopback interface.  If specified, the corresponding prefix length
	 * must be 128.
	 */
	if (ifra->ifra_dstaddr.sin6_family == AF_INET6) {
		if ((ifp->if_flags & (IFF_POINTOPOINT|IFF_LOOPBACK)) == 0)
			return (EINVAL);
		if (plen != 128)
			return (EINVAL);
	}
	/* lifetime consistency check */
	lt = &ifra->ifra_lifetime;
	if (lt->ia6t_pltime > lt->ia6t_vltime)
		return (EINVAL);
	if (lt->ia6t_vltime == 0) {
		/*
		 * the following log might be noisy, but this is a typical
		 * configuration mistake or a tool's bug.
		 */
		nd6log((LOG_INFO, "%s: valid lifetime is 0 for %s\n", __func__,
		    inet_ntop(AF_INET6, &ifra->ifra_addr.sin6_addr,
		    addr, sizeof(addr))));

		if (ia6 == NULL)
			return (0); /* there's nothing to do */
	}

	/*
	 * If this is a new address, allocate a new ifaddr and link it
	 * into chains.
	 */
	if (ia6 == NULL) {
		hostIsNew = 1;
		ia6 = malloc(sizeof(*ia6), M_IFADDR, M_WAITOK | M_ZERO);
		LIST_INIT(&ia6->ia6_memberships);
		/* Initialize the address and masks, and put time stamp */
		ia6->ia_ifa.ifa_addr = sin6tosa(&ia6->ia_addr);
		ia6->ia_addr.sin6_family = AF_INET6;
		ia6->ia_addr.sin6_len = sizeof(ia6->ia_addr);
		ia6->ia6_updatetime = time_uptime;
		if ((ifp->if_flags & (IFF_POINTOPOINT | IFF_LOOPBACK)) != 0) {
			/*
			 * XXX: some functions expect that ifa_dstaddr is not
			 * NULL for p2p interfaces.
			 */
			ia6->ia_ifa.ifa_dstaddr = sin6tosa(&ia6->ia_dstaddr);
		} else {
			ia6->ia_ifa.ifa_dstaddr = NULL;
		}
		ia6->ia_ifa.ifa_netmask = sin6tosa(&ia6->ia_prefixmask);

		ia6->ia_ifp = ifp;
		ia6->ia_addr = ifra->ifra_addr;
		ifa_add(ifp, &ia6->ia_ifa);
	}

	/* set prefix mask */
	if (ifra->ifra_prefixmask.sin6_len) {
		/*
		 * We prohibit changing the prefix length of an existing
		 * address, because
		 * + such an operation should be rare in IPv6, and
		 * + the operation would confuse prefix management.
		 */
		if (ia6->ia_prefixmask.sin6_len &&
		    in6_mask2len(&ia6->ia_prefixmask.sin6_addr, NULL) != plen) {
			error = EINVAL;
			goto unlink;
		}
		ia6->ia_prefixmask = ifra->ifra_prefixmask;
	}

	/*
	 * If a new destination address is specified, scrub the old one and
	 * install the new destination.  Note that the interface must be
	 * p2p or loopback (see the check above.)
	 */
	if ((ifp->if_flags & IFF_POINTOPOINT) && dst6.sin6_family == AF_INET6 &&
	    !IN6_ARE_ADDR_EQUAL(&dst6.sin6_addr, &ia6->ia_dstaddr.sin6_addr)) {
		struct ifaddr *ifa = &ia6->ia_ifa;

		if ((ia6->ia_flags & IFA_ROUTE) != 0 &&
		    rt_ifa_del(ifa, RTF_HOST, ifa->ifa_dstaddr,
		     ifp->if_rdomain) != 0) {
			nd6log((LOG_ERR, "%s: failed to remove a route "
			    "to the old destination: %s\n", __func__,
			    inet_ntop(AF_INET6, &ia6->ia_addr.sin6_addr,
			    addr, sizeof(addr))));
			/* proceed anyway... */
		} else
			ia6->ia_flags &= ~IFA_ROUTE;
		ia6->ia_dstaddr = dst6;
	}

	/*
	 * Set lifetimes.  We do not refer to ia6t_expire and ia6t_preferred
	 * to see if the address is deprecated or invalidated, but initialize
	 * these members for applications.
	 */
	ia6->ia6_updatetime = time_uptime;
	ia6->ia6_lifetime = ifra->ifra_lifetime;
	if (ia6->ia6_lifetime.ia6t_vltime != ND6_INFINITE_LIFETIME) {
		ia6->ia6_lifetime.ia6t_expire =
		    time_uptime + ia6->ia6_lifetime.ia6t_vltime;
	} else
		ia6->ia6_lifetime.ia6t_expire = 0;
	if (ia6->ia6_lifetime.ia6t_pltime != ND6_INFINITE_LIFETIME) {
		ia6->ia6_lifetime.ia6t_preferred =
		    time_uptime + ia6->ia6_lifetime.ia6t_pltime;
	} else
		ia6->ia6_lifetime.ia6t_preferred = 0;

	/* reset the interface and routing table appropriately. */
	if ((error = in6_ifinit(ifp, ia6, hostIsNew)) != 0)
		goto unlink;

	/* re-run DAD */
	if (ia6->ia6_flags & (IN6_IFF_TENTATIVE|IN6_IFF_DUPLICATED))
		ifra->ifra_flags |= IN6_IFF_TENTATIVE;
	/*
	 * configure address flags.
	 */
	ia6->ia6_flags = ifra->ifra_flags;

	nd6_expire_timer_update(ia6);

	/*
	 * We are done if we have simply modified an existing address.
	 */
	if (!hostIsNew)
		return (error);

	/*
	 * Beyond this point, we should call in6_purgeaddr upon an error,
	 * not just go to unlink.
	 */

	/* join necessary multiast groups */
	if ((ifp->if_flags & IFF_MULTICAST) != 0) {
		struct sockaddr_in6 mltaddr, mltmask;

		/* join solicited multicast addr for new host id */
		struct sockaddr_in6 llsol;

		bzero(&llsol, sizeof(llsol));
		llsol.sin6_family = AF_INET6;
		llsol.sin6_len = sizeof(llsol);
		llsol.sin6_addr.s6_addr16[0] = htons(0xff02);
		llsol.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
		llsol.sin6_addr.s6_addr32[1] = 0;
		llsol.sin6_addr.s6_addr32[2] = htonl(1);
		llsol.sin6_addr.s6_addr32[3] =
		    ifra->ifra_addr.sin6_addr.s6_addr32[3];
		llsol.sin6_addr.s6_addr8[12] = 0xff;
		imm = in6_joingroup(ifp, &llsol.sin6_addr, &error);
		if (!imm)
			goto cleanup;
		LIST_INSERT_HEAD(&ia6->ia6_memberships, imm, i6mm_chain);

		bzero(&mltmask, sizeof(mltmask));
		mltmask.sin6_len = sizeof(struct sockaddr_in6);
		mltmask.sin6_family = AF_INET6;
		mltmask.sin6_addr = in6mask32;

		/*
		 * join link-local all-nodes address
		 */
		bzero(&mltaddr, sizeof(mltaddr));
		mltaddr.sin6_len = sizeof(struct sockaddr_in6);
		mltaddr.sin6_family = AF_INET6;
		mltaddr.sin6_addr = in6addr_linklocal_allnodes;
		mltaddr.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
		mltaddr.sin6_scope_id = 0;

		/*
		 * XXX: do we really need this automatic routes?
		 * We should probably reconsider this stuff.  Most applications
		 * actually do not need the routes, since they usually specify
		 * the outgoing interface.
		 */
		rt = rtalloc(sin6tosa(&mltaddr), 0, ifp->if_rdomain);
		if (rt) {
			/* 32bit came from "mltmask" */
			if (memcmp(&mltaddr.sin6_addr,
			    &satosin6(rt_key(rt))->sin6_addr,
			    32 / 8)) {
				rtfree(rt);
				rt = NULL;
			}
		}
		if (!rt) {
			struct rt_addrinfo info;

			bzero(&info, sizeof(info));
			info.rti_ifa = &ia6->ia_ifa;
			info.rti_info[RTAX_DST] = sin6tosa(&mltaddr);
			info.rti_info[RTAX_GATEWAY] = sin6tosa(&ia6->ia_addr);
			info.rti_info[RTAX_NETMASK] = sin6tosa(&mltmask);
			info.rti_info[RTAX_IFA] = sin6tosa(&ia6->ia_addr);
			info.rti_flags = RTF_MULTICAST;
			error = rtrequest(RTM_ADD, &info, RTP_CONNECTED, NULL,
			    ifp->if_rdomain);
			if (error)
				goto cleanup;
		} else {
			rtfree(rt);
		}
		imm = in6_joingroup(ifp, &mltaddr.sin6_addr, &error);
		if (!imm)
			goto cleanup;
		LIST_INSERT_HEAD(&ia6->ia6_memberships, imm, i6mm_chain);

		/*
		 * join interface-local all-nodes address.
		 * (ff01::1%ifN, and ff01::%ifN/32)
		 */
		bzero(&mltaddr, sizeof(mltaddr));
		mltaddr.sin6_len = sizeof(struct sockaddr_in6);
		mltaddr.sin6_family = AF_INET6;
		mltaddr.sin6_addr = in6addr_intfacelocal_allnodes;
		mltaddr.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
		mltaddr.sin6_scope_id = 0;

		/* XXX: again, do we really need the route? */
		rt = rtalloc(sin6tosa(&mltaddr), 0, ifp->if_rdomain);
		if (rt) {
			/* 32bit came from "mltmask" */
			if (memcmp(&mltaddr.sin6_addr,
			    &satosin6(rt_key(rt))->sin6_addr,
			    32 / 8)) {
				rtfree(rt);
				rt = NULL;
			}
		}
		if (!rt) {
			struct rt_addrinfo info;

			bzero(&info, sizeof(info));
			info.rti_ifa = &ia6->ia_ifa;
			info.rti_info[RTAX_DST] = sin6tosa(&mltaddr);
			info.rti_info[RTAX_GATEWAY] = sin6tosa(&ia6->ia_addr);
			info.rti_info[RTAX_NETMASK] = sin6tosa(&mltmask);
			info.rti_info[RTAX_IFA] = sin6tosa(&ia6->ia_addr);
			info.rti_flags = RTF_MULTICAST;
			error = rtrequest(RTM_ADD, &info, RTP_CONNECTED, NULL,
			    ifp->if_rdomain);
			if (error)
				goto cleanup;
		} else {
			rtfree(rt);
		}
		imm = in6_joingroup(ifp, &mltaddr.sin6_addr, &error);
		if (!imm)
			goto cleanup;
		LIST_INSERT_HEAD(&ia6->ia6_memberships, imm, i6mm_chain);
	}

	return (error);

  unlink:
	/*
	 * XXX: if a change of an existing address failed, keep the entry
	 * anyway.
	 */
	if (hostIsNew)
		in6_unlink_ifa(ia6, ifp);
	return (error);

  cleanup:
	in6_purgeaddr(&ia6->ia_ifa);
	return error;
}

void
in6_purgeaddr(struct ifaddr *ifa)
{
	struct ifnet *ifp = ifa->ifa_ifp;
	struct in6_ifaddr *ia6 = ifatoia6(ifa);
	struct in6_multi_mship *imm;

	/* stop DAD processing */
	nd6_dad_stop(ifa);

	/*
	 * delete route to the destination of the address being purged.
	 * The interface must be p2p or loopback in this case.
	 */
	if ((ifp->if_flags & IFF_POINTOPOINT) && (ia6->ia_flags & IFA_ROUTE) &&
	    ia6->ia_dstaddr.sin6_len != 0) {
		int e;

		e = rt_ifa_del(ifa, RTF_HOST, ifa->ifa_dstaddr,
		    ifp->if_rdomain);
		if (e != 0) {
			char addr[INET6_ADDRSTRLEN];
			log(LOG_ERR, "in6_purgeaddr: failed to remove "
			    "a route to the p2p destination: %s on %s, "
			    "errno=%d\n",
			    inet_ntop(AF_INET6, &ia6->ia_addr.sin6_addr,
				addr, sizeof(addr)),
			    ifp->if_xname, e);
			/* proceed anyway... */
		} else
			ia6->ia_flags &= ~IFA_ROUTE;
	}

	/* Remove ownaddr's loopback rtentry, if it exists. */
	rt_ifa_dellocal(&(ia6->ia_ifa));

	/*
	 * leave from multicast groups we have joined for the interface
	 */
	while (!LIST_EMPTY(&ia6->ia6_memberships)) {
		imm = LIST_FIRST(&ia6->ia6_memberships);
		LIST_REMOVE(imm, i6mm_chain);
		in6_leavegroup(imm);
	}

	in6_unlink_ifa(ia6, ifp);
}

void
in6_unlink_ifa(struct in6_ifaddr *ia6, struct ifnet *ifp)
{
	struct ifaddr *ifa = &ia6->ia_ifa;
	extern int ifatrash;
	int plen;

	NET_ASSERT_LOCKED();

	/* Release the reference to the base prefix. */
	plen = in6_mask2len(&ia6->ia_prefixmask.sin6_addr, NULL);
	if ((ifp->if_flags & IFF_LOOPBACK) == 0 && plen != 128) {
		rt_ifa_del(ifa, RTF_CLONING | RTF_CONNECTED,
		    ifa->ifa_addr, ifp->if_rdomain);
	}

	rt_ifa_purge(ifa);
	ifa_del(ifp, ifa);

	ifatrash++;
	ia6->ia_ifp = NULL;
	ifafree(&ia6->ia_ifa);
}

/*
 * Initialize an interface's intetnet6 address
 * and routing table entry.
 */
int
in6_ifinit(struct ifnet *ifp, struct in6_ifaddr *ia6, int newhost)
{
	int	error = 0, plen, ifacount = 0;
	struct ifaddr *ifa;

	NET_ASSERT_LOCKED();

	/*
	 * Give the interface a chance to initialize
	 * if this is its first address (or it is a CARP interface)
	 * and to validate the address if necessary.
	 */
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		ifacount++;
	}

	if ((ifacount <= 1 || ifp->if_type == IFT_CARP ||
	    (ifp->if_flags & (IFF_LOOPBACK|IFF_POINTOPOINT))) &&
	    (error = (*ifp->if_ioctl)(ifp, SIOCSIFADDR, (caddr_t)ia6))) {
		return (error);
	}

	ia6->ia_ifa.ifa_metric = ifp->if_metric;

	/* we could do in(6)_socktrim here, but just omit it at this moment. */

	/*
	 * Special case:
	 * If the destination address is specified for a point-to-point
	 * interface, install a route to the destination as an interface
	 * direct route.
	 */
	plen = in6_mask2len(&ia6->ia_prefixmask.sin6_addr, NULL); /* XXX */
	if ((ifp->if_flags & IFF_POINTOPOINT) && plen == 128 &&
	    ia6->ia_dstaddr.sin6_family == AF_INET6) {
		ifa = &ia6->ia_ifa;
		error = rt_ifa_add(ifa, RTF_HOST | RTF_MPATH,
		    ifa->ifa_dstaddr, ifp->if_rdomain);
		if (error != 0)
			return (error);
		ia6->ia_flags |= IFA_ROUTE;
	}

	if (newhost)
		error = rt_ifa_addlocal(&(ia6->ia_ifa));

	return (error);
}

/*
 * Add an address to the list of IP6 multicast addresses for a
 * given interface.
 */
struct in6_multi *
in6_addmulti(struct in6_addr *maddr6, struct ifnet *ifp, int *errorp)
{
	struct	in6_ifreq ifr;
	struct	in6_multi *in6m;

	NET_ASSERT_LOCKED();

	*errorp = 0;
	/*
	 * See if address already in list.
	 */
	IN6_LOOKUP_MULTI(*maddr6, ifp, in6m);
	if (in6m != NULL) {
		/*
		 * Found it; just increment the refrence count.
		 */
		in6m->in6m_refcnt++;
	} else {
		/*
		 * New address; allocate a new multicast record
		 * and link it into the interface's multicast list.
		 */
		in6m = malloc(sizeof(*in6m), M_IPMADDR, M_NOWAIT | M_ZERO);
		if (in6m == NULL) {
			*errorp = ENOBUFS;
			return (NULL);
		}

		in6m->in6m_sin.sin6_len = sizeof(struct sockaddr_in6);
		in6m->in6m_sin.sin6_family = AF_INET6;
		in6m->in6m_sin.sin6_addr = *maddr6;
		in6m->in6m_refcnt = 1;
		in6m->in6m_ifidx = ifp->if_index;
		in6m->in6m_ifma.ifma_addr = sin6tosa(&in6m->in6m_sin);

		/*
		 * Ask the network driver to update its multicast reception
		 * filter appropriately for the new address.
		 */
		memcpy(&ifr.ifr_addr, &in6m->in6m_sin, sizeof(in6m->in6m_sin));
		*errorp = (*ifp->if_ioctl)(ifp, SIOCADDMULTI, (caddr_t)&ifr);
		if (*errorp) {
			free(in6m, M_IPMADDR, sizeof(*in6m));
			return (NULL);
		}

		TAILQ_INSERT_HEAD(&ifp->if_maddrlist, &in6m->in6m_ifma,
		    ifma_list);

		/*
		 * Let MLD6 know that we have joined a new IP6 multicast
		 * group.
		 */
		mld6_start_listening(in6m);
	}

	return (in6m);
}

/*
 * Delete a multicast address record.
 */
void
in6_delmulti(struct in6_multi *in6m)
{
	struct	in6_ifreq ifr;
	struct	ifnet *ifp;

	NET_ASSERT_LOCKED();

	if (--in6m->in6m_refcnt == 0) {
		/*
		 * No remaining claims to this record; let MLD6 know
		 * that we are leaving the multicast group.
		 */
		mld6_stop_listening(in6m);
		ifp = if_get(in6m->in6m_ifidx);

		/*
		 * Notify the network driver to update its multicast
		 * reception filter.
		 */
		if (ifp != NULL) {
			bzero(&ifr.ifr_addr, sizeof(struct sockaddr_in6));
			ifr.ifr_addr.sin6_len = sizeof(struct sockaddr_in6);
			ifr.ifr_addr.sin6_family = AF_INET6;
			ifr.ifr_addr.sin6_addr = in6m->in6m_addr;
			(*ifp->if_ioctl)(ifp, SIOCDELMULTI, (caddr_t)&ifr);

			TAILQ_REMOVE(&ifp->if_maddrlist, &in6m->in6m_ifma,
			    ifma_list);
		}
		if_put(ifp);

		free(in6m, M_IPMADDR, sizeof(*in6m));
	}
}

/*
 * Return 1 if the multicast group represented by ``maddr6'' has been
 * joined by interface ``ifp'', 0 otherwise.
 */
int
in6_hasmulti(struct in6_addr *maddr6, struct ifnet *ifp)
{
	struct in6_multi *in6m;
	int joined;

	IN6_LOOKUP_MULTI(*maddr6, ifp, in6m);
	joined = (in6m != NULL);

	return (joined);
}

struct in6_multi_mship *
in6_joingroup(struct ifnet *ifp, struct in6_addr *addr, int *errorp)
{
	struct in6_multi_mship *imm;

	imm = malloc(sizeof(*imm), M_IPMADDR, M_NOWAIT);
	if (!imm) {
		*errorp = ENOBUFS;
		return NULL;
	}
	imm->i6mm_maddr = in6_addmulti(addr, ifp, errorp);
	if (!imm->i6mm_maddr) {
		/* *errorp is alrady set */
		free(imm, M_IPMADDR, sizeof(*imm));
		return NULL;
	}
	return imm;
}

void
in6_leavegroup(struct in6_multi_mship *imm)
{

	if (imm->i6mm_maddr)
		in6_delmulti(imm->i6mm_maddr);
	free(imm,  M_IPMADDR, sizeof(*imm));
}

/*
 * Find an IPv6 interface link-local address specific to an interface.
 */
struct in6_ifaddr *
in6ifa_ifpforlinklocal(struct ifnet *ifp, int ignoreflags)
{
	struct ifaddr *ifa;

	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (IN6_IS_ADDR_LINKLOCAL(IFA_IN6(ifa))) {
			if ((ifatoia6(ifa)->ia6_flags & ignoreflags) != 0)
				continue;
			break;
		}
	}

	return (ifatoia6(ifa));
}


/*
 * find the internet address corresponding to a given interface and address.
 */
struct in6_ifaddr *
in6ifa_ifpwithaddr(struct ifnet *ifp, struct in6_addr *addr)
{
	struct ifaddr *ifa;

	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (IN6_ARE_ADDR_EQUAL(addr, IFA_IN6(ifa)))
			break;
	}

	return (ifatoia6(ifa));
}

/*
 * Get a scope of the address. Node-local, link-local, site-local or global.
 */
int
in6_addrscope(struct in6_addr *addr)
{
	int scope;

	if (addr->s6_addr8[0] == 0xfe) {
		scope = addr->s6_addr8[1] & 0xc0;

		switch (scope) {
		case 0x80:
			return __IPV6_ADDR_SCOPE_LINKLOCAL;
			break;
		case 0xc0:
			return __IPV6_ADDR_SCOPE_SITELOCAL;
			break;
		default:
			return __IPV6_ADDR_SCOPE_GLOBAL; /* just in case */
			break;
		}
	}


	if (addr->s6_addr8[0] == 0xff) {
		scope = addr->s6_addr8[1] & 0x0f;

		/*
		 * due to other scope such as reserved,
		 * return scope doesn't work.
		 */
		switch (scope) {
		case __IPV6_ADDR_SCOPE_INTFACELOCAL:
			return __IPV6_ADDR_SCOPE_INTFACELOCAL;
			break;
		case __IPV6_ADDR_SCOPE_LINKLOCAL:
			return __IPV6_ADDR_SCOPE_LINKLOCAL;
			break;
		case __IPV6_ADDR_SCOPE_SITELOCAL:
			return __IPV6_ADDR_SCOPE_SITELOCAL;
			break;
		default:
			return __IPV6_ADDR_SCOPE_GLOBAL;
			break;
		}
	}

	if (bcmp(&in6addr_loopback, addr, sizeof(*addr) - 1) == 0) {
		if (addr->s6_addr8[15] == 1) /* loopback */
			return __IPV6_ADDR_SCOPE_INTFACELOCAL;
		if (addr->s6_addr8[15] == 0) /* unspecified */
			return __IPV6_ADDR_SCOPE_LINKLOCAL;
	}

	return __IPV6_ADDR_SCOPE_GLOBAL;
}

int
in6_addr2scopeid(unsigned int ifidx, struct in6_addr *addr)
{
	int scope = in6_addrscope(addr);

	switch(scope) {
	case __IPV6_ADDR_SCOPE_INTFACELOCAL:
	case __IPV6_ADDR_SCOPE_LINKLOCAL:
		/* XXX: we do not distinguish between a link and an I/F. */
		return (ifidx);

	case __IPV6_ADDR_SCOPE_SITELOCAL:
		return (0);	/* XXX: invalid. */

	default:
		return (0);	/* XXX: treat as global. */
	}
}

/*
 * return length of part which dst and src are equal
 * hard coding...
 */
int
in6_matchlen(struct in6_addr *src, struct in6_addr *dst)
{
	int match = 0;
	u_char *s = (u_char *)src, *d = (u_char *)dst;
	u_char *lim = s + 16, r;

	while (s < lim)
		if ((r = (*d++ ^ *s++)) != 0) {
			while (r < 128) {
				match++;
				r <<= 1;
			}
			break;
		} else
			match += 8;
	return match;
}

void
in6_prefixlen2mask(struct in6_addr *maskp, int len)
{
	u_char maskarray[8] = {0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};
	int bytelen, bitlen, i;

	/* sanity check */
	if (0 > len || len > 128) {
		log(LOG_ERR, "in6_prefixlen2mask: invalid prefix length(%d)\n",
		    len);
		return;
	}

	bzero(maskp, sizeof(*maskp));
	bytelen = len / 8;
	bitlen = len % 8;
	for (i = 0; i < bytelen; i++)
		maskp->s6_addr[i] = 0xff;
	/* len == 128 is ok because bitlen == 0 then */
	if (bitlen)
		maskp->s6_addr[bytelen] = maskarray[bitlen - 1];
}

/*
 * return the best address out of the same scope
 */
struct in6_ifaddr *
in6_ifawithscope(struct ifnet *oifp, struct in6_addr *dst, u_int rdomain)
{
	int dst_scope =	in6_addrscope(dst), src_scope, best_scope = 0;
	int blen = -1;
	struct ifaddr *ifa;
	struct ifnet *ifp;
	struct in6_ifaddr *ia6_best = NULL;

	if (oifp == NULL) {
		printf("%s: output interface is not specified\n", __func__);
		return (NULL);
	}

	/*
	 * We search for all addresses on all interfaces from the beginning.
	 * Comparing an interface with the outgoing interface will be done
	 * only at the final stage of tiebreaking.
	 */
	TAILQ_FOREACH(ifp, &ifnet, if_list) {
		if (ifp->if_rdomain != rdomain)
			continue;
#if NCARP > 0
		/*
		 * Never use a carp address of an interface which is not
		 * the master.
		 */
		if (ifp->if_type == IFT_CARP && !carp_iamatch(ifp))
			continue;
#endif

		/*
		 * We can never take an address that breaks the scope zone
		 * of the destination.
		 */
		if (in6_addr2scopeid(ifp->if_index, dst) !=
		    in6_addr2scopeid(oifp->if_index, dst))
			continue;

		TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
			int tlen = -1, dscopecmp, bscopecmp, matchcmp;

			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;

			src_scope = in6_addrscope(IFA_IN6(ifa));

#ifdef ADDRSELECT_DEBUG		/* should be removed after stabilization */
		{
			char adst[INET6_ADDRSTRLEN], asrc[INET6_ADDRSTRLEN];
			char bestaddr[INET6_ADDRSTRLEN];


			dscopecmp = IN6_ARE_SCOPE_CMP(src_scope, dst_scope);
			printf("%s: dst=%s bestaddr=%s, "
			    "newaddr=%s, scope=%x, dcmp=%d, bcmp=%d, "
			    "matchlen=%d, flgs=%x\n", __func__,
			    inet_ntop(AF_INET6, dst, adst, sizeof(adst)),
			    (ia6_best == NULL) ? "none" :
			    inet_ntop(AF_INET6, &ia6_best->ia_addr.sin6_addr,
			    bestaddr, sizeof(bestaddr)),
			    inet_ntop(AF_INET6, IFA_IN6(ifa),
			    asrc, sizeof(asrc)),
			    src_scope, dscopecmp, ia6_best ?
			    IN6_ARE_SCOPE_CMP(src_scope, best_scope) : -1,
			    in6_matchlen(IFA_IN6(ifa), dst),
			    ifatoia6(ifa)->ia6_flags);
		}
#endif

			/*
			 * Don't use an address before completing DAD
			 * nor a duplicated address.
			 */
			if (ifatoia6(ifa)->ia6_flags &
			    (IN6_IFF_TENTATIVE|IN6_IFF_DUPLICATED))
				continue;

			/* XXX: is there any case to allow anycasts? */
			if (ifatoia6(ifa)->ia6_flags & IN6_IFF_ANYCAST)
				continue;

			if (ifatoia6(ifa)->ia6_flags & IN6_IFF_DETACHED)
				continue;

			/*
			 * If this is the first address we find,
			 * keep it anyway.
			 */
			if (ia6_best == NULL)
				goto replace;

			/*
			 * ia6_best is never NULL beyond this line except
			 * within the block labeled "replace".
			 */

			/*
			 * If ia6_best has a smaller scope than dst and
			 * the current address has a larger one than
			 * (or equal to) dst, always replace ia6_best.
			 * Also, if the current address has a smaller scope
			 * than dst, ignore it unless ia6_best also has a
			 * smaller scope.
			 */
			if (IN6_ARE_SCOPE_CMP(best_scope, dst_scope) < 0 &&
			    IN6_ARE_SCOPE_CMP(src_scope, dst_scope) >= 0)
				goto replace;
			if (IN6_ARE_SCOPE_CMP(src_scope, dst_scope) < 0 &&
			    IN6_ARE_SCOPE_CMP(best_scope, dst_scope) >= 0)
				continue;

			/*
			 * A deprecated address SHOULD NOT be used in new
			 * communications if an alternate (non-deprecated)
			 * address is available and has sufficient scope.
			 * RFC 2462, Section 5.5.4.
			 */
			if (ifatoia6(ifa)->ia6_flags & IN6_IFF_DEPRECATED) {
				/*
				 * Ignore any deprecated addresses if
				 * specified by configuration.
				 */
				if (!ip6_use_deprecated)
					continue;

				/*
				 * If we have already found a non-deprecated
				 * candidate, just ignore deprecated addresses.
				 */
				if ((ia6_best->ia6_flags & IN6_IFF_DEPRECATED)
				    == 0)
					continue;
			}

			/*
			 * A non-deprecated address is always preferred
			 * to a deprecated one regardless of scopes and
			 * address matching.
			 */
			if ((ia6_best->ia6_flags & IN6_IFF_DEPRECATED) &&
			    (ifatoia6(ifa)->ia6_flags &
			     IN6_IFF_DEPRECATED) == 0)
				goto replace;

			/* RFC 3484 5. Rule 5: Prefer outgoing interface */
			if (ia6_best->ia_ifp == oifp && ifp != oifp)
				continue;
			if (ia6_best->ia_ifp != oifp && ifp == oifp)
				goto replace;

			/*
			 * At this point, we have two cases:
			 * 1. we are looking at a non-deprecated address,
			 *    and ia6_best is also non-deprecated.
			 * 2. we are looking at a deprecated address,
			 *    and ia6_best is also deprecated.
			 * Also, we do not have to consider a case where
			 * the scope of if_best is larger(smaller) than dst and
			 * the scope of the current address is smaller(larger)
			 * than dst. Such a case has already been covered.
			 * Tiebreaking is done according to the following
			 * items:
			 * - the scope comparison between the address and
			 *   dst (dscopecmp)
			 * - the scope comparison between the address and
			 *   ia6_best (bscopecmp)
			 * - if the address match dst longer than ia6_best
			 *   (matchcmp)
			 * - if the address is on the outgoing I/F (outI/F)
			 *
			 * Roughly speaking, the selection policy is
			 * - the most important item is scope. The same scope
			 *   is best. Then search for a larger scope.
			 *   Smaller scopes are the last resort.
			 * - A deprecated address is chosen only when we have
			 *   no address that has an enough scope, but is
			 *   prefered to any addresses of smaller scopes.
			 * - Longest address match against dst is considered
			 *   only for addresses that has the same scope of dst.
			 * - If there is no other reasons to choose one,
			 *   addresses on the outgoing I/F are preferred.
			 *
			 * The precise decision table is as follows:
			 * dscopecmp bscopecmp matchcmp outI/F | replace?
			 *    !equal     equal      N/A    Yes |      Yes (1)
			 *    !equal     equal      N/A     No |       No (2)
			 *    larger    larger      N/A    N/A |       No (3)
			 *    larger   smaller      N/A    N/A |      Yes (4)
			 *   smaller    larger      N/A    N/A |      Yes (5)
			 *   smaller   smaller      N/A    N/A |       No (6)
			 *     equal   smaller      N/A    N/A |      Yes (7)
			 *     equal    larger       (already done)
			 *     equal     equal   larger    N/A |      Yes (8)
			 *     equal     equal  smaller    N/A |       No (9)
			 *     equal     equal    equal    Yes |      Yes (a)
			 *     equal     equal    equal     No |       No (b)
			 */
			dscopecmp = IN6_ARE_SCOPE_CMP(src_scope, dst_scope);
			bscopecmp = IN6_ARE_SCOPE_CMP(src_scope, best_scope);

			if (dscopecmp && bscopecmp == 0) {
				if (oifp == ifp) /* (1) */
					goto replace;
				continue; /* (2) */
			}
			if (dscopecmp > 0) {
				if (bscopecmp > 0) /* (3) */
					continue;
				goto replace; /* (4) */
			}
			if (dscopecmp < 0) {
				if (bscopecmp > 0) /* (5) */
					goto replace;
				continue; /* (6) */
			}

			/* now dscopecmp must be 0 */
			if (bscopecmp < 0)
				goto replace; /* (7) */

			/*
			 * At last both dscopecmp and bscopecmp must be 0.
			 * We need address matching against dst for
			 * tiebreaking.
			 * Privacy addresses are preferred over public
			 * addresses (RFC3484 requires a config knob for
			 * this which we don't provide).
			 */
			if (oifp == ifp) {
				/* Do not replace temporary autoconf addresses
				 * with non-temporary addresses. */
				if ((ia6_best->ia6_flags & IN6_IFF_PRIVACY) &&
				    !(ifatoia6(ifa)->ia6_flags &
				    IN6_IFF_PRIVACY))
					continue;

				/* Replace non-temporary autoconf addresses
				 * with temporary addresses. */
				if (!(ia6_best->ia6_flags & IN6_IFF_PRIVACY) &&
				    (ifatoia6(ifa)->ia6_flags &
				    IN6_IFF_PRIVACY))
					goto replace;
			}
			tlen = in6_matchlen(IFA_IN6(ifa), dst);
			matchcmp = tlen - blen;
			if (matchcmp > 0) { /* (8) */
#if NCARP > 0
				/*
				 * Don't let carp interfaces win a tie against
				 * the output interface based on matchlen.
				 * We should only use a carp address if no
				 * other interface has a usable address.
				 * Otherwise, when communicating from a carp
				 * master to a carp slave, the slave won't
				 * respond since the carp address is also
				 * configured as a local address on the slave.
				 * Note that carp interfaces in backup state
				 * were already skipped above.
				 */
				if (ifp->if_type == IFT_CARP &&
				    oifp->if_type != IFT_CARP)
					continue;
#endif
				goto replace;
			}
			if (matchcmp < 0) /* (9) */
				continue;
			if (oifp == ifp) /* (a) */
				goto replace;
			continue; /* (b) */

		  replace:
			ia6_best = ifatoia6(ifa);
			blen = tlen >= 0 ? tlen :
			    in6_matchlen(IFA_IN6(ifa), dst);
			best_scope =
			    in6_addrscope(&ia6_best->ia_addr.sin6_addr);
		}
	}

	/* count statistics for future improvements */
	if (ia6_best == NULL)
		ip6stat_inc(ip6s_sources_none);
	else {
		if (oifp == ia6_best->ia_ifp)
			ip6stat_inc(ip6s_sources_sameif + best_scope);
		else
			ip6stat_inc(ip6s_sources_otherif + best_scope);

		if (best_scope == dst_scope)
			ip6stat_inc(ip6s_sources_samescope + best_scope);
		else
			ip6stat_inc(ip6s_sources_otherscope + best_scope);

		if ((ia6_best->ia6_flags & IN6_IFF_DEPRECATED) != 0)
			ip6stat_inc(ip6s_sources_deprecated + best_scope);
	}

	return (ia6_best);
}

int
in6if_do_dad(struct ifnet *ifp)
{
	if ((ifp->if_flags & IFF_LOOPBACK) != 0)
		return (0);

	switch (ifp->if_type) {
#if NCARP > 0
	case IFT_CARP:
		/*
		 * XXX: DAD does not work currently on carp(4)
		 * so disable it for now.
		 */
		return (0);
#endif
	default:
		/*
		 * Our DAD routine requires the interface up and running.
		 * However, some interfaces can be up before the RUNNING
		 * status.  Additionaly, users may try to assign addresses
		 * before the interface becomes up (or running).
		 * We simply skip DAD in such a case as a work around.
		 * XXX: we should rather mark "tentative" on such addresses,
		 * and do DAD after the interface becomes ready.
		 */
		if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) !=
		    (IFF_UP|IFF_RUNNING))
			return (0);

		return (1);
	}
}

void *
in6_domifattach(struct ifnet *ifp)
{
	struct in6_ifextra *ext;

	ext = malloc(sizeof(*ext), M_IFADDR, M_WAITOK | M_ZERO);

	ext->nd_ifinfo = nd6_ifattach(ifp);
	ext->nprefixes = 0;
	ext->ndefrouters = 0;
	return ext;
}

void
in6_domifdetach(struct ifnet *ifp, void *aux)
{
	struct in6_ifextra *ext = (struct in6_ifextra *)aux;

	nd6_ifdetach(ext->nd_ifinfo);
	free(ext, M_IFADDR, sizeof(*ext));
}
