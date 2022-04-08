/*
 * Copyright (c) 2017 Christiano Haesbaert <haesbaert@haesbaert.org>
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

#ifndef PFSYNC_VAR
#define PFSYNC_VAR

/* Needed by pf_state/tdb */
enum pfsync_msg_type {
	PFSYNC_MSG_STATE,
	PFSYNC_MSG_BUS,
	PFSYNC_MSG_CLR,
	PFSYNC_MSG_UPD_REQ,
	PFSYNC_MSG_TDB,
};

/* Needed by pf_state/tdb */
struct pfsync_msg {
	enum pfsync_msg_type	 msg_type;
	void			*msg_data;
	TAILQ_ENTRY(pfsync_msg)	 msg_entry;
	TAILQ_ENTRY(pfsync_msg)	 msg_entry_tmp;
};

#endif
