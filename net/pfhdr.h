/*	$OpenBSD$	*/

/*
 * Copyright (c) 2016 Alexander Bluhm <bluhm@openbsd.org>
 * Copyright (c) 2010 Henning Brauer <henning@openbsd.org>
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

#ifndef _NET_PFHDR_H_
#define _NET_PFHDR_H_

/*
 * Cannot fold into pf_pdesc directly, unknown storage size outside pf.c.
 * Cannot be put into pfvar.h as this is included in too many places.
 */
union pf_headers {
	struct tcphdr		tcp;
	struct udphdr		udp;
	struct icmp		icmp;
#ifdef INET6
	struct icmp6_hdr	icmp6;
	struct mld_hdr		mld;
	struct nd_neighbor_solicit nd_ns;
#endif /* INET6 */
};

#endif /* _NET_PFHDR_H_ */
