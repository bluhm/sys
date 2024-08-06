/*	$OpenBSD: if_vio.c,v 1.45 2024/08/01 11:13:19 sf Exp $	*/

/*
 * Copyright (c) 2012 Stefan Fritsch, Alexander Fiveg.
 * Copyright (c) 2010 Minoura Makoto.
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
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "bpfilter.h"
#include "vlan.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/intrmap.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/sockio.h>
#include <sys/timeout.h>

#include <dev/pv/virtioreg.h>
#include <dev/pv/virtiovar.h>

#include <net/if.h>
#include <net/if_media.h>
#include <net/route.h>

#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>

#if NBPFILTER > 0
#include <net/bpf.h>
#endif

#if VIRTIO_DEBUG
#define DPRINTF(x...) printf(x)
#else
#define DPRINTF(x...)
#endif

/*
 * if_vioreg.h:
 */
/* Configuration registers */
#define VIRTIO_NET_CONFIG_MAC		 0 /*  8 bit x 6 byte */
#define VIRTIO_NET_CONFIG_STATUS	 6 /* 16 bit */
#define VIRTIO_NET_CONFIG_MAX_QUEUES	 8 /* 16 bit */
#define VIRTIO_NET_CONFIG_MTU		10 /* 16 bit */
#define VIRTIO_NET_CONFIG_SPEED		12 /* 32 bit */
#define VIRTIO_NET_CONFIG_DUPLEX	16 /*  8 bit */
#define VIRTIO_NET_CONFIG_RSS_SIZE	17 /*  8 bit */
#define VIRTIO_NET_CONFIG_RSS_LEN	18 /* 16 bit */
#define VIRTIO_NET_CONFIG_HASH_TYPES	20 /* 16 bit */

/* Feature bits */
#define VIRTIO_NET_F_CSUM			(1ULL<<0)
#define VIRTIO_NET_F_GUEST_CSUM			(1ULL<<1)
#define VIRTIO_NET_F_CTRL_GUEST_OFFLOADS        (1ULL<<2)
#define VIRTIO_NET_F_MTU                        (1ULL<<3)
#define VIRTIO_NET_F_MAC			(1ULL<<5)
#define VIRTIO_NET_F_GSO			(1ULL<<6)
#define VIRTIO_NET_F_GUEST_TSO4			(1ULL<<7)
#define VIRTIO_NET_F_GUEST_TSO6			(1ULL<<8)
#define VIRTIO_NET_F_GUEST_ECN			(1ULL<<9)
#define VIRTIO_NET_F_GUEST_UFO			(1ULL<<10)
#define VIRTIO_NET_F_HOST_TSO4			(1ULL<<11)
#define VIRTIO_NET_F_HOST_TSO6			(1ULL<<12)
#define VIRTIO_NET_F_HOST_ECN			(1ULL<<13)
#define VIRTIO_NET_F_HOST_UFO			(1ULL<<14)
#define VIRTIO_NET_F_MRG_RXBUF			(1ULL<<15)
#define VIRTIO_NET_F_STATUS			(1ULL<<16)
#define VIRTIO_NET_F_CTRL_VQ			(1ULL<<17)
#define VIRTIO_NET_F_CTRL_RX			(1ULL<<18)
#define VIRTIO_NET_F_CTRL_VLAN			(1ULL<<19)
#define VIRTIO_NET_F_CTRL_RX_EXTRA		(1ULL<<20)
#define VIRTIO_NET_F_GUEST_ANNOUNCE		(1ULL<<21)
#define VIRTIO_NET_F_MQ				(1ULL<<22)
#define VIRTIO_NET_F_CTRL_MAC_ADDR		(1ULL<<23)
#define VIRTIO_NET_F_HOST_USO			(1ULL<<56)
#define VIRTIO_NET_F_HASH_REPORT		(1ULL<<57)
#define VIRTIO_NET_F_GUEST_HDRLEN		(1ULL<<59)
#define VIRTIO_NET_F_RSS			(1ULL<<60)
#define VIRTIO_NET_F_RSC_EXT			(1ULL<<61)
#define VIRTIO_NET_F_STANDBY			(1ULL<<62)
#define VIRTIO_NET_F_SPEED_DUPLEX		(1ULL<<63)
/*
 * Config(8) flags. The lowest byte is reserved for generic virtio stuff.
 */

/* Workaround for vlan related bug in qemu < version 2.0 */
#define CONFFLAG_QEMU_VLAN_BUG		(1<<8)

static const struct virtio_feature_name virtio_net_feature_names[] = {
#if VIRTIO_DEBUG
	{ VIRTIO_NET_F_CSUM,			"CSum" },
	{ VIRTIO_NET_F_GUEST_CSUM,		"GuestCSum" },
	{ VIRTIO_NET_F_CTRL_GUEST_OFFLOADS,	"CtrlGuestOffl" },
	{ VIRTIO_NET_F_MTU,			"MTU", },
	{ VIRTIO_NET_F_MAC,			"MAC" },
	{ VIRTIO_NET_F_GSO,			"GSO" },
	{ VIRTIO_NET_F_GUEST_TSO4,		"GuestTSO4" },
	{ VIRTIO_NET_F_GUEST_TSO6,		"GuestTSO6" },
	{ VIRTIO_NET_F_GUEST_ECN,		"GuestECN" },
	{ VIRTIO_NET_F_GUEST_UFO,		"GuestUFO" },
	{ VIRTIO_NET_F_HOST_TSO4,		"HostTSO4" },
	{ VIRTIO_NET_F_HOST_TSO6,		"HostTSO6" },
	{ VIRTIO_NET_F_HOST_ECN,		"HostECN" },
	{ VIRTIO_NET_F_HOST_UFO,		"HostUFO" },
	{ VIRTIO_NET_F_MRG_RXBUF,		"MrgRXBuf" },
	{ VIRTIO_NET_F_STATUS,			"Status" },
	{ VIRTIO_NET_F_CTRL_VQ,			"CtrlVQ" },
	{ VIRTIO_NET_F_CTRL_RX,			"CtrlRX" },
	{ VIRTIO_NET_F_CTRL_VLAN,		"CtrlVLAN" },
	{ VIRTIO_NET_F_CTRL_RX_EXTRA,		"CtrlRXExtra" },
	{ VIRTIO_NET_F_GUEST_ANNOUNCE,		"GuestAnnounce" },
	{ VIRTIO_NET_F_MQ,			"MQ" },
	{ VIRTIO_NET_F_CTRL_MAC_ADDR,		"CtrlMAC" },
	{ VIRTIO_NET_F_HOST_USO,		"HostUso" },
	{ VIRTIO_NET_F_HASH_REPORT,		"HashRpt" },
	{ VIRTIO_NET_F_GUEST_HDRLEN,		"GuestHdrlen" },
	{ VIRTIO_NET_F_RSS,			"RSS" },
	{ VIRTIO_NET_F_RSC_EXT,			"RSSExt" },
	{ VIRTIO_NET_F_STANDBY,			"Stdby" },
	{ VIRTIO_NET_F_SPEED_DUPLEX,		"SpdDplx" },
#endif
	{ 0,					NULL }
};

/* Status */
#define VIRTIO_NET_S_LINK_UP	1

/* Packet header structure */
struct virtio_net_hdr {
	uint8_t		flags;
	uint8_t		gso_type;
	uint16_t	hdr_len;
	uint16_t	gso_size;
	uint16_t	csum_start;
	uint16_t	csum_offset;

	/* only present if VIRTIO_NET_F_MRG_RXBUF is negotiated */
	uint16_t	num_buffers;
} __packed;

#define VIRTIO_NET_HDR_F_NEEDS_CSUM	1 /* flags */
#define VIRTIO_NET_HDR_F_DATA_VALID	2 /* flags */
#define VIRTIO_NET_HDR_GSO_NONE		0 /* gso_type */
#define VIRTIO_NET_HDR_GSO_TCPV4	1 /* gso_type */
#define VIRTIO_NET_HDR_GSO_UDP		3 /* gso_type */
#define VIRTIO_NET_HDR_GSO_TCPV6	4 /* gso_type */
#define VIRTIO_NET_HDR_GSO_ECN		0x80 /* gso_type, |'ed */

#define VIRTIO_NET_MAX_GSO_LEN		(65536+ETHER_HDR_LEN)

/* Control virtqueue */
struct virtio_net_ctrl_cmd {
	uint8_t	class;
	uint8_t	command;
} __packed;
#define VIRTIO_NET_CTRL_RX		0
# define VIRTIO_NET_CTRL_RX_PROMISC	0
# define VIRTIO_NET_CTRL_RX_ALLMULTI	1

#define VIRTIO_NET_CTRL_MAC		1
# define VIRTIO_NET_CTRL_MAC_TABLE_SET	0

#define VIRTIO_NET_CTRL_VLAN		2
# define VIRTIO_NET_CTRL_VLAN_ADD	0
# define VIRTIO_NET_CTRL_VLAN_DEL	1

#define VIRTIO_NET_CTRL_MQ		4
# define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET	0
# define VIRTIO_NET_CTRL_MQ_RSS_CONFIG		1
# define VIRTIO_NET_CTRL_MQ_HASH_CONFIG		2

#define VIRTIO_NET_CTRL_GUEST_OFFLOADS	5
# define VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET	0

struct virtio_net_ctrl_status {
	uint8_t	ack;
} __packed;
#define VIRTIO_NET_OK			0
#define VIRTIO_NET_ERR			1

struct virtio_net_ctrl_rx {
	uint8_t	onoff;
} __packed;

struct virtio_net_ctrl_mq_pairs_set {
	uint16_t virtqueue_pairs;
};
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN	1
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX	0x8000
//#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX	1 // XXX

struct virtio_net_ctrl_guest_offloads {
	uint64_t offloads;
} __packed;

struct virtio_net_ctrl_mac_tbl {
	uint32_t nentries;
	uint8_t macs[][ETHER_ADDR_LEN];
} __packed;

struct virtio_net_ctrl_vlan {
	uint16_t id;
} __packed;

/*
 * if_viovar.h:
 */
enum vio_ctrl_state {
	FREE, INUSE, DONE, RESET
};

struct vio_queue {
	struct vio_softc	 *sc;
	struct virtio_net_hdr	 *tx_hdrs;
	bus_dmamap_t		 *arrays;
#define rx_dmamaps arrays
	bus_dmamap_t		 *tx_dmamaps;
	struct mbuf		**rx_mbufs;
	struct mbuf		**tx_mbufs;
	struct if_rxring	  rx_ring;
	struct ifiqueue		 *ifiq;
	struct ifqueue		 *ifq;
	struct virtqueue	 *rx_vq;
	struct virtqueue	 *tx_vq;
	struct mutex		  tx_mtx, rx_mtx;
	int			  tx_free_slots;
} __aligned(64);

struct vio_softc {
	struct device		sc_dev;

	struct virtio_softc	*sc_virtio;
	struct virtqueue	*sc_ctl_vq;

	struct arpcom		sc_ac;
	struct ifmedia		sc_media;

	short			sc_ifflags;

	/* bus_dmamem */
	bus_dma_segment_t	sc_dma_seg;
	bus_dmamap_t		sc_dma_map;
	size_t			sc_dma_size;
	caddr_t			sc_dma_kva;

	int			sc_hdr_size;
	struct virtio_net_ctrl_cmd		*sc_ctrl_cmd;
	struct virtio_net_ctrl_status		*sc_ctrl_status;
	struct virtio_net_ctrl_rx		*sc_ctrl_rx;
	struct virtio_net_ctrl_mq_pairs_set	*sc_ctrl_mq_pairs;
	struct virtio_net_ctrl_guest_offloads	*sc_ctrl_guest_offloads;
	struct virtio_net_ctrl_mac_tbl		*sc_ctrl_mac_tbl_uc;
#define sc_ctrl_mac_info sc_ctrl_mac_tbl_uc
	struct virtio_net_ctrl_mac_tbl		*sc_ctrl_mac_tbl_mc;

	struct intrmap		*sc_intrmap;
	struct vio_queue	*sc_queue;
	uint16_t		sc_nqueues;
	int			sc_tx_slots_per_req;

	enum vio_ctrl_state	sc_ctrl_inuse;

	struct timeout          sc_txtick, sc_rxtick;
};

#define VIO_DMAMEM_OFFSET(sc, p) ((caddr_t)(p) - (sc)->sc_dma_kva)
#define VIO_DMAMEM_SYNC(vsc, sc, p, size, flags)		\
	bus_dmamap_sync((vsc)->sc_dmat, (sc)->sc_dma_map,	\
	    VIO_DMAMEM_OFFSET((sc), (p)), (size), (flags))
#define VIO_DMAMEM_ENQUEUE(sc, vq, slot, p, size, write)	\
	virtio_enqueue_p((vq), (slot), (sc)->sc_dma_map,	\
	    VIO_DMAMEM_OFFSET((sc), (p)), (size), (write))
#define VIO_HAVE_MRG_RXBUF(sc)					\
	((sc)->sc_hdr_size == sizeof(struct virtio_net_hdr))

#define VIRTIO_NET_TX_MAXNSEGS		16 /* for larger chains, defrag */
#define VIRTIO_NET_CTRL_MAC_MC_ENTRIES	64 /* for more entries, use ALLMULTI */
#define VIRTIO_NET_CTRL_MAC_UC_ENTRIES	 1 /* one entry for own unicast addr */
#define VIRTIO_NET_CTRL_TIMEOUT		(5*1000*1000*1000ULL) /* 5 seconds */

#define VIO_CTRL_MAC_INFO_SIZE					\
	(2*sizeof(struct virtio_net_ctrl_mac_tbl) +		\
	 (VIRTIO_NET_CTRL_MAC_MC_ENTRIES +			\
	  VIRTIO_NET_CTRL_MAC_UC_ENTRIES) * ETHER_ADDR_LEN)

/* cfattach interface functions */
int	vio_match(struct device *, void *, void *);
void	vio_attach(struct device *, struct device *, void *);

/* ifnet interface functions */
int	vio_init(struct ifnet *);
void	vio_stop(struct ifnet *, int);
void	vio_start(struct ifqueue *);
int	vio_ioctl(struct ifnet *, u_long, caddr_t);
void	vio_get_lladdr(struct arpcom *ac, struct virtio_softc *vsc);
void	vio_put_lladdr(struct arpcom *ac, struct virtio_softc *vsc);

/* rx */
int	vio_add_rx_mbuf(struct vio_softc *, struct vio_queue *, int);
void	vio_free_rx_mbuf(struct vio_softc *, struct vio_queue *, int);
void	vio_populate_rx_mbufs(struct vio_softc *, struct vio_queue *);
int	vio_rxeof(struct vio_queue *);
int	vio_rx_intr(struct virtqueue *);
void	vio_rx_drain(struct vio_softc *);
void	vio_rxtick(void *);

/* tx */
int	vio_tx_intr(struct virtqueue *);
int	vio_tx_dequeue(struct virtqueue *);
int	vio_txeof(struct virtqueue *);
void	vio_tx_drain(struct vio_softc *);
int	vio_encap(struct vio_queue *, int, struct mbuf *);
void	vio_txtick(void *);

int	vio_queue_intr(void *);
int	vio_admin_intr(void *);

/* other control */
void	vio_link_state(struct ifnet *);
int	vio_config_change(struct virtio_softc *);
int	vio_ctrl_rx(struct vio_softc *, int, int);
int	vio_ctrl_mq(struct vio_softc *);
int	vio_ctrl_guest_offloads(struct vio_softc *, uint64_t);
int	vio_set_rx_filter(struct vio_softc *);
void	vio_iff(struct vio_softc *);
int	vio_media_change(struct ifnet *);
void	vio_media_status(struct ifnet *, struct ifmediareq *);
int	vio_ctrleof(struct virtqueue *);
int	vio_wait_ctrl(struct vio_softc *sc);
int	vio_wait_ctrl_done(struct vio_softc *sc);
void	vio_ctrl_wakeup(struct vio_softc *, enum vio_ctrl_state);
int	vio_alloc_mem(struct vio_softc *);
int	vio_alloc_dmamem(struct vio_softc *);
void	vio_free_dmamem(struct vio_softc *);

#if VIRTIO_DEBUG
void	vio_dump(struct vio_softc *);
#endif

int
vio_match(struct device *parent, void *match, void *aux)
{
	struct virtio_attach_args *va = aux;

	if (va->va_devid == PCI_PRODUCT_VIRTIO_NETWORK)
		return 1;

	return 0;
}

const struct cfattach vio_ca = {
	sizeof(struct vio_softc), vio_match, vio_attach, NULL
};

struct cfdriver vio_cd = {
	NULL, "vio", DV_IFNET
};

int
vio_alloc_dmamem(struct vio_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	int nsegs;

	if (bus_dmamap_create(vsc->sc_dmat, sc->sc_dma_size, 1,
	    sc->sc_dma_size, 0, BUS_DMA_NOWAIT | BUS_DMA_ALLOCNOW,
	    &sc->sc_dma_map) != 0)
		goto err;
	if (bus_dmamem_alloc(vsc->sc_dmat, sc->sc_dma_size, 16, 0,
	    &sc->sc_dma_seg, 1, &nsegs, BUS_DMA_NOWAIT | BUS_DMA_ZERO) != 0)
		goto destroy;
	if (bus_dmamem_map(vsc->sc_dmat, &sc->sc_dma_seg, nsegs,
	    sc->sc_dma_size, &sc->sc_dma_kva, BUS_DMA_NOWAIT) != 0)
		goto free;
	if (bus_dmamap_load(vsc->sc_dmat, sc->sc_dma_map, sc->sc_dma_kva,
	    sc->sc_dma_size, NULL, BUS_DMA_NOWAIT) != 0)
		goto unmap;
	return (0);

unmap:
	bus_dmamem_unmap(vsc->sc_dmat, sc->sc_dma_kva, sc->sc_dma_size);
free:
	bus_dmamem_free(vsc->sc_dmat, &sc->sc_dma_seg, 1);
destroy:
	bus_dmamap_destroy(vsc->sc_dmat, sc->sc_dma_map);
err:
	return (1);
}

void
vio_free_dmamem(struct vio_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;

	bus_dmamap_unload(vsc->sc_dmat, sc->sc_dma_map);
	bus_dmamem_unmap(vsc->sc_dmat, sc->sc_dma_kva, sc->sc_dma_size);
	bus_dmamem_free(vsc->sc_dmat, &sc->sc_dma_seg, 1);
	bus_dmamap_destroy(vsc->sc_dmat, sc->sc_dma_map);
}

/* allocate memory */
/*
 * dma memory is used for:
 *   tx_hdrs[slot]:	 metadata array for frames to be sent (WRITE)
 *   sc_ctrl_cmd:	 command to be sent via ctrl vq (WRITE)
 *   sc_ctrl_status:	 return value for a command via ctrl vq (READ)
 *   sc_ctrl_rx:	 parameter for a VIRTIO_NET_CTRL_RX class command
 *			 (WRITE)
 *   sc_ctrl_mq_pairs_set: XXX
 *   sc_ctrl_guest_offloads: XXX
 *   sc_ctrl_mac_tbl_uc: unicast MAC address filter for a VIRTIO_NET_CTRL_MAC
 *			 class command (WRITE)
 *   sc_ctrl_mac_tbl_mc: multicast MAC address filter for a VIRTIO_NET_CTRL_MAC
 *			 class command (WRITE)
 * sc_ctrl_* structures are allocated only one each; they are protected by
 * sc_ctrl_inuse, which must only be accessed at splnet
 *
 * metadata headers for received frames are stored at the start of the
 * rx mbufs.
 */
/*
 * dynamically allocated memory is used for:
 *   rx_dmamaps[slot]:		bus_dmamap_t array for received payload
 *   tx_dmamaps[slot]:		bus_dmamap_t array for sent payload
 *   rx_mbufs[slot]:		mbuf pointer array for received frames
 *   tx_mbufs[slot]:		mbuf pointer array for sent frames
 */
int
vio_alloc_mem(struct vio_softc *sc)
{
	struct virtio_softc	*vsc = sc->sc_virtio;
	struct ifnet		*ifp = &sc->sc_ac.ac_if;
	size_t			 allocsize, rxqsize, txqsize, offset = 0;
	bus_size_t		 txsize;
	caddr_t			 kva;
	int			 i, j, r;

	rxqsize = sc->sc_queue[0].rx_vq->vq_num;
	txqsize = sc->sc_queue[0].tx_vq->vq_num;

	printf("%s: rxqsize %zd txqsize %zd\n", __func__, rxqsize, txqsize);
	/*
	 * For simplicity, we always allocate the full virtio_net_hdr size
	 * even if VIRTIO_NET_F_MRG_RXBUF is not negotiated and
	 * only a part of the memory is ever used.
	 */
	allocsize = sizeof(struct virtio_net_hdr) * txqsize * sc->sc_nqueues;

	if (virtio_has_feature(vsc, VIRTIO_NET_F_CTRL_VQ)) {
		allocsize += sizeof(struct virtio_net_ctrl_cmd) * 1;
		allocsize += sizeof(struct virtio_net_ctrl_status) * 1;
		allocsize += sizeof(struct virtio_net_ctrl_rx) * 1;
		allocsize += sizeof(struct virtio_net_ctrl_mq_pairs_set) * 1;
		allocsize += sizeof(struct virtio_net_ctrl_guest_offloads) * 1;
		allocsize += VIO_CTRL_MAC_INFO_SIZE;
	}
	sc->sc_dma_size = allocsize;

	if (vio_alloc_dmamem(sc) != 0) {
		printf("unable to allocate dma region\n");
		return -1;
	}

	kva = sc->sc_dma_kva;

	for (i = 0; i < sc->sc_nqueues; i++) {
		// XXX cacheline align / separate alloc?
		sc->sc_queue[i].tx_hdrs =
		    (struct virtio_net_hdr*)(kva + offset);
		offset += sizeof(struct virtio_net_hdr) * txqsize;
	}

	if (virtio_has_feature(vsc, VIRTIO_NET_F_CTRL_VQ)) {
		sc->sc_ctrl_cmd = (void*)(kva + offset);
		offset += sizeof(*sc->sc_ctrl_cmd);
		sc->sc_ctrl_status = (void*)(kva + offset);
		offset += sizeof(*sc->sc_ctrl_status);
		sc->sc_ctrl_rx = (void*)(kva + offset);
		offset += sizeof(*sc->sc_ctrl_rx);
		sc->sc_ctrl_mq_pairs = (void*)(kva + offset);
		offset += sizeof(*sc->sc_ctrl_mq_pairs);
		sc->sc_ctrl_guest_offloads = (void*)(kva + offset);
		offset += sizeof(*sc->sc_ctrl_guest_offloads);
		sc->sc_ctrl_mac_tbl_uc = (void*)(kva + offset);
		offset += sizeof(*sc->sc_ctrl_mac_tbl_uc) +
		    ETHER_ADDR_LEN * VIRTIO_NET_CTRL_MAC_UC_ENTRIES;
		sc->sc_ctrl_mac_tbl_mc = (void*)(kva + offset);
		offset += sizeof(*sc->sc_ctrl_mac_tbl_mc) +
		    ETHER_ADDR_LEN * VIRTIO_NET_CTRL_MAC_MC_ENTRIES;
	}
	printf("%s: allocsize %zd offset %zd\n", __func__, allocsize, offset);
	assert(offset == allocsize);

	txsize = ifp->if_hardmtu + sc->sc_hdr_size + ETHER_HDR_LEN;

	for (i = 0; i < sc->sc_nqueues; i++) {
		struct vio_queue *vioq = &sc->sc_queue[i];

		vioq->arrays = mallocarray(rxqsize + txqsize,
		    sizeof(bus_dmamap_t) + sizeof(struct mbuf *), M_DEVBUF,
		    M_WAITOK | M_CANFAIL | M_ZERO); // XXX in current falsch???
		if (vioq->arrays == NULL) {
			printf("unable to allocate mem for dmamaps\n");
			goto free;
		}

		vioq->tx_dmamaps = vioq->arrays + rxqsize;
		vioq->rx_mbufs = (void*)(vioq->tx_dmamaps + txqsize);
		vioq->tx_mbufs = vioq->rx_mbufs + rxqsize;
		printf("%s:%d: %d tx_dmamaps %p rx_mbufs %p tx_mbufs %p\n", __func__, __LINE__,
		    i, vioq->tx_dmamaps, vioq->rx_mbufs, vioq->tx_mbufs);

		for (j = 0; j < rxqsize; j++) {
			r = bus_dmamap_create(vsc->sc_dmat, MAXMCLBYTES,
			    MAXMCLBYTES/PAGE_SIZE + 1, MCLBYTES, 0,
			    BUS_DMA_NOWAIT|BUS_DMA_ALLOCNOW, &vioq->rx_dmamaps[j]);
			if (r != 0)
				goto destroy;
		}

		for (j = 0; j < txqsize; j++) {
			r = bus_dmamap_create(vsc->sc_dmat, txsize,
			    VIRTIO_NET_TX_MAXNSEGS, txsize, 0,
			    BUS_DMA_NOWAIT|BUS_DMA_ALLOCNOW,
			    &vioq->tx_dmamaps[j]);
			if (r != 0)
				goto destroy;
		}
	}
	printf("%s:%d: sc_nqueues %d\n", __func__, __LINE__, sc->sc_nqueues);

	return 0;

 destroy:
	printf("dmamap creation failed, error %d\n", r);
	for (i = 0; i < sc->sc_nqueues; i++) {
		struct vio_queue *vioq = &sc->sc_queue[i];

		for (j = 0; j < txqsize; j++) {
			if (vioq->tx_dmamaps[j])
				bus_dmamap_destroy(vsc->sc_dmat, vioq->tx_dmamaps[j]);
		}
		for (j = 0; j < rxqsize; j++) {
			if (vioq->rx_dmamaps[j])
				bus_dmamap_destroy(vsc->sc_dmat, vioq->rx_dmamaps[j]);
		}
		if (vioq->arrays) {
			free(vioq->arrays, M_DEVBUF,
			    (rxqsize + txqsize) *
			    (2 * sizeof(bus_dmamap_t) + sizeof(struct mbuf *)));
			vioq->arrays = NULL;
		}
	}
 free:
	vio_free_dmamem(sc);
	return -1;
}

void
vio_get_lladdr(struct arpcom *ac, struct virtio_softc *vsc)
{
	int i;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		ac->ac_enaddr[i] = virtio_read_device_config_1(vsc,
		    VIRTIO_NET_CONFIG_MAC + i);
	}
}

void
vio_put_lladdr(struct arpcom *ac, struct virtio_softc *vsc)
{
	int i;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		virtio_write_device_config_1(vsc, VIRTIO_NET_CONFIG_MAC + i,
		     ac->ac_enaddr[i]);
	}
}

static int
vio_needs_reset(struct vio_softc *sc)
{
	if (virtio_get_status(sc->sc_virtio) &
	    VIRTIO_CONFIG_DEVICE_STATUS_DEVICE_NEEDS_RESET) {
		printf("%s: device needs reset\n", sc->sc_dev.dv_xname);
		vio_ctrl_wakeup(sc, RESET);
		return 1;
	}
	return 0;
}

void
vio_attach(struct device *parent, struct device *self, void *aux)
{
	struct vio_softc *sc = (struct vio_softc *)self;
	struct virtio_softc *vsc = (struct virtio_softc *)parent;
	struct virtio_attach_args *va = aux;
	int i, r;
	struct ifnet *ifp = &sc->sc_ac.ac_if;

	printf("\n%s\n", __func__);

	if (vsc->sc_child != NULL) {
		printf(": child already attached for %s; something wrong...\n",
		    parent->dv_xname);
		return;
	}

	sc->sc_virtio = vsc;

	vsc->sc_child = self;
	vsc->sc_ipl = IPL_NET | IPL_MPSAFE;
	vsc->sc_config_change = NULL;
	vsc->sc_driver_features = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS |
	    VIRTIO_NET_F_CTRL_VQ | VIRTIO_NET_F_CTRL_RX |
	    VIRTIO_NET_F_MRG_RXBUF | VIRTIO_NET_F_CSUM |
	    VIRTIO_F_RING_EVENT_IDX | VIRTIO_NET_F_GUEST_CSUM;

	vsc->sc_driver_features |= VIRTIO_NET_F_MTU;
	if (va->va_nintr > 2)
		vsc->sc_driver_features |= VIRTIO_NET_F_MQ;

	vsc->sc_driver_features |= VIRTIO_NET_F_HOST_TSO4;
	vsc->sc_driver_features |= VIRTIO_NET_F_HOST_TSO6;

	vsc->sc_driver_features |= VIRTIO_NET_F_CTRL_GUEST_OFFLOADS;
	vsc->sc_driver_features |= VIRTIO_NET_F_GUEST_TSO4;
	vsc->sc_driver_features |= VIRTIO_NET_F_GUEST_TSO6;

	virtio_negotiate_features(vsc, virtio_net_feature_names);

	if (virtio_has_feature(vsc, VIRTIO_NET_F_MQ)) {
		i = virtio_read_device_config_2(vsc,
		    VIRTIO_NET_CONFIG_MAX_QUEUES);
		vsc->sc_nvqs = 2 * i + 1;
		printf("%s: parent %p sc %p aux %p MAX_QUEUES %d nintrs %d\n", __func__,
		    parent, sc, aux, i, va->va_nintr);
		i = MIN(i, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX);
		sc->sc_intrmap = intrmap_create(&sc->sc_dev, i,
		    va->va_nintr - 1, 0);
		sc->sc_nqueues = intrmap_count(sc->sc_intrmap);
		printf(": %u queue%s", sc->sc_nqueues,
		    sc->sc_nqueues > 1 ? "s"  : "");
	} else {
		sc->sc_nqueues = 1;
		printf(": 1 queue");
		vsc->sc_nvqs = 2;
		if (virtio_has_feature(vsc, VIRTIO_NET_F_CTRL_VQ))
			vsc->sc_nvqs++;
	}
	// XXX intrs allokieren
	// XXX umbauen auf 1 interrupt fuer rx+tx, wie bei nicht MSIX? erst mal funktionen so lassen und im
	// 	ihandler virtio_check_vqs aufrufen?

	vsc->sc_vqs = mallocarray(vsc->sc_nvqs, sizeof(*vsc->sc_vqs), M_DEVBUF,
	    M_NOWAIT | M_ZERO);
	if (vsc->sc_vqs == NULL)
		goto err;

	sc->sc_queue = mallocarray(sc->sc_nqueues, sizeof(*sc->sc_queue),
	    M_DEVBUF, M_NOWAIT | M_ZERO);
	if (sc->sc_queue == NULL)
		goto err;

	if (sc->sc_intrmap) {
		r = virtio_intr_establish(vsc, va, 0, NULL, vio_admin_intr, sc);
		if (r != 0) {
			printf("%s: cannot alloc adm intr: %d\n", sc->sc_dev.dv_xname, r);
			goto err;
		}

		for (i = 0; i < sc->sc_nqueues; i++) {
			struct cpu_info *ci = NULL;
			ci = intrmap_cpu(sc->sc_intrmap, i);
			r = virtio_intr_establish(vsc, va, i + 1, ci, vio_queue_intr, &sc->sc_queue[i]);
			if (r != 0) {
				printf("%s: cannot alloc q%d intr: %d\n", sc->sc_dev.dv_xname, i, r);
				goto err;
			}
		}
	}

	if (virtio_has_feature(vsc, VIRTIO_NET_F_MAC)) {
		vio_get_lladdr(&sc->sc_ac, vsc);
	} else {
		ether_fakeaddr(ifp);
		vio_put_lladdr(&sc->sc_ac, vsc);
	}
	printf(", address %s\n", ether_sprintf(sc->sc_ac.ac_enaddr));

	if (virtio_has_feature(vsc, VIRTIO_NET_F_MRG_RXBUF) ||
	    vsc->sc_version_1) {
		sc->sc_hdr_size = sizeof(struct virtio_net_hdr);
	} else {
		sc->sc_hdr_size = offsetof(struct virtio_net_hdr, num_buffers);
	}
	if (virtio_has_feature(vsc, VIRTIO_NET_F_MRG_RXBUF))
		ifp->if_hardmtu = MAXMCLBYTES;
	else
		ifp->if_hardmtu = MAXMCLBYTES - sc->sc_hdr_size - ETHER_HDR_LEN;
	if (virtio_has_feature(vsc, VIRTIO_NET_F_MTU)) {
		ifp->if_hardmtu = MIN(ifp->if_hardmtu,
		    virtio_read_device_config_2(vsc, VIRTIO_NET_CONFIG_MTU));
	}

	if (virtio_has_feature(vsc, VIRTIO_F_RING_INDIRECT_DESC))
		sc->sc_tx_slots_per_req = 1;
	else
		sc->sc_tx_slots_per_req = VIRTIO_NET_TX_MAXNSEGS + 1;

	printf("sc %p vsc %p\n", sc, vsc);
	for (i = 0; i < sc->sc_nqueues; i++) {
		int vqidx = 2 * i;
		struct vio_queue *vioq = &sc->sc_queue[i];
		vioq->rx_vq = &vsc->sc_vqs[vqidx];
		mtx_init(&vioq->tx_mtx, IPL_NET);
		mtx_init(&vioq->rx_mtx, IPL_NET);
		vioq->sc = sc;
		if (virtio_alloc_vq(vsc, vioq->rx_vq, vqidx, MCLBYTES,
		    2, "rx") != 0)
			goto err;
		vioq->rx_vq->vq_done = vio_rx_intr;
		virtio_start_vq_intr(vsc, vioq->rx_vq);

		vqidx++;
		vioq->tx_vq = &vsc->sc_vqs[vqidx];
		if (virtio_alloc_vq(vsc, vioq->tx_vq, vqidx,
		    sc->sc_hdr_size + ifp->if_hardmtu + ETHER_HDR_LEN,
		    VIRTIO_NET_TX_MAXNSEGS + 1, "tx") != 0) {
			goto err;
		}
		vioq->tx_vq->vq_done = vio_tx_intr;
		if (virtio_has_feature(vsc, VIRTIO_F_RING_EVENT_IDX))
			virtio_postpone_intr_far(vioq->tx_vq);
		else
			virtio_stop_vq_intr(vsc, vioq->tx_vq);
		vioq->tx_free_slots = vioq->tx_vq->vq_num - 1;
		KASSERT(vioq->tx_free_slots > sc->sc_tx_slots_per_req);
		if (vioq->tx_vq->vq_num != sc->sc_queue[0].tx_vq->vq_num) {
			printf("inequal tx queue size %d: %d != %d\n", i,
			    vioq->tx_vq->vq_num, sc->sc_queue[0].tx_vq->vq_num);
			goto err;
		}
		printf("%d: q %p rx %p tx %p\n", i, vioq, vioq->rx_vq, vioq->tx_vq);

		if (sc->sc_intrmap != NULL) {
			vioq->rx_vq->vq_intr_vec = i + 1;
			vioq->tx_vq->vq_intr_vec = i + 1;
		}
	}
	// XXX wie intr setup. virtio_pci macht msix-setup erst nach child attach
	// noetige schrite
	// 	pci_intr_msix_count -> evtl. in virtio_softc uebergeben?
	// 	ueberlegen wieviele queues wir haben wollen
	// 	intrmap_create fuer queues
	// 	evtl. mehr msix interrupts, z.B. fuer config interrupt + control queue
	// oder callback-funktion virtio_intrmap_create?
	// 	wie geben wir pci_attach_args weiter, die liegen auf dem stack
	// 	kann man in config_found() weiter geben, zweites argument ist aux und wir
	// 		geben da sc weiter, was redundant ist.
	// wie api um interrupts zu konfigurieren?
	// 	evtl.:
	// 		zahl verfuegbare vektoren in aux oder virtio_softc
	// 		feld in struct virtioqueue mit vektor nummer,
	// 			default AUTO oder so,
	// 			kann von vio_attach aus gesetzt werden
	// 			virtio_pci-code wertet das aus
	// 		XXX wie werden die zugehoerigen vio_q argumente fuer den intr-handler konfiguriert?
	// 		XXX config msix vektor nur wenn sc_config_change gesetzt ist?
	// 		XXX evtl. pci_attach_args als aux weiter geben und vio macht alles selbst?
	// 		neues Feld in virtqueue vq_vec -> Vektor-Nummer, default "auto"
	// 		virtio_intrmap_establish(vsc, va, intrmap, func, args, basename)
	// 			erzeugt interrupts nach intrmap
	// 			erzeugt config interrupt wenn sc_config_change gesetzt
	// 			Child-Treiber setzt vq_vec

	/* control queue */
	if (virtio_has_feature(vsc, VIRTIO_NET_F_CTRL_VQ)) {
		i = 2;
		if (virtio_has_feature(vsc, VIRTIO_NET_F_MQ)) {
			i = 2 * virtio_read_device_config_2(vsc,
			    VIRTIO_NET_CONFIG_MAX_QUEUES);
		}
		printf("ctrl-q %d/%d\n", i, vsc->sc_nvqs);
		sc->sc_ctl_vq =  &vsc->sc_vqs[i];
		if (virtio_alloc_vq(vsc, sc->sc_ctl_vq, i, NBPG, 1,
		    "control") != 0)
			goto err;
		sc->sc_ctl_vq->vq_done = vio_ctrleof;
		sc->sc_ctl_vq->vq_intr_vec = 0;
		virtio_start_vq_intr(vsc, sc->sc_ctl_vq);
	}

	if (vio_alloc_mem(sc) < 0)
		goto err;

	strlcpy(ifp->if_xname, self->dv_xname, IFNAMSIZ);
	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_xflags = IFXF_MPSAFE;
	ifp->if_qstart = vio_start;
	ifp->if_ioctl = vio_ioctl;
	ifp->if_capabilities = 0;
#if NVLAN > 0
	ifp->if_capabilities |= IFCAP_VLAN_MTU;
	ifp->if_capabilities |= IFCAP_VLAN_HWOFFLOAD;
#endif
	if (virtio_has_feature(vsc, VIRTIO_NET_F_CSUM))
		ifp->if_capabilities |= IFCAP_CSUM_TCPv4|IFCAP_CSUM_UDPv4|
		    IFCAP_CSUM_TCPv6|IFCAP_CSUM_UDPv6;
	if (virtio_has_feature(vsc, VIRTIO_NET_F_HOST_TSO4))
		ifp->if_capabilities |= IFCAP_TSOv4;
	if (virtio_has_feature(vsc, VIRTIO_NET_F_HOST_TSO6))
		ifp->if_capabilities |= IFCAP_TSOv6;

	if (virtio_has_feature(vsc, VIRTIO_NET_F_CTRL_GUEST_OFFLOADS) &&
	    (virtio_has_feature(vsc, VIRTIO_NET_F_GUEST_TSO4) ||
	     virtio_has_feature(vsc, VIRTIO_NET_F_GUEST_TSO6))) {
		ifp->if_xflags |= IFXF_LRO;
		ifp->if_capabilities |= IFCAP_LRO;
	}

	ifq_init_maxlen(&ifp->if_snd, vsc->sc_vqs[1].vq_num - 1);
	ifmedia_init(&sc->sc_media, 0, vio_media_change, vio_media_status);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(&sc->sc_media, IFM_ETHER | IFM_AUTO);
	vsc->sc_config_change = vio_config_change;
	timeout_set(&sc->sc_txtick, vio_txtick, sc);
	timeout_set(&sc->sc_rxtick, vio_rxtick, sc);

	virtio_set_status(vsc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);
	printf("DRIVER_OK\n");

	if (virtio_has_feature(vsc, VIRTIO_NET_F_MQ)) {
		/* ctrl queue works only after DRIVER_OK */
		vio_ctrl_mq(sc);
	}

	if_attach(ifp);
	ether_ifattach(ifp);
	vio_link_state(ifp);

	if_attach_queues(ifp, sc->sc_nqueues);
        if_attach_iqueues(ifp, sc->sc_nqueues);

	for (i = 0; i < sc->sc_nqueues; i++) {
                ifp->if_ifqs[i]->ifq_softc = &sc->sc_queue[i];
                sc->sc_queue[i].ifq = ifp->if_ifqs[i];
                sc->sc_queue[i].ifiq = ifp->if_iqs[i];
	}

	return;

err:
	for (i = 0; i < vsc->sc_nvqs; i++)
		virtio_free_vq(vsc, &vsc->sc_vqs[i]);
	vsc->sc_nvqs = 0;
	vsc->sc_child = VIRTIO_CHILD_ERROR;
	return;
}

/* check link status */
void
vio_link_state(struct ifnet *ifp)
{
	struct vio_softc *sc = ifp->if_softc;
	struct virtio_softc *vsc = sc->sc_virtio;
	int link_state = LINK_STATE_FULL_DUPLEX;

	if (virtio_has_feature(vsc, VIRTIO_NET_F_STATUS)) {
		int status = virtio_read_device_config_2(vsc,
		    VIRTIO_NET_CONFIG_STATUS);
		if (!(status & VIRTIO_NET_S_LINK_UP))
			link_state = LINK_STATE_DOWN;
	}
	if (ifp->if_link_state != link_state) {
		ifp->if_link_state = link_state;
		if_link_state_change(ifp);
	}
}

int
vio_admin_intr(void *arg)
{
	struct vio_softc *sc = arg;
	int r;

	KERNEL_LOCK();
	r = vio_config_change(sc->sc_virtio);
	KERNEL_UNLOCK();
	if (virtio_has_feature(sc->sc_virtio, VIRTIO_NET_F_CTRL_VQ))
		r |= virtio_check_vq(sc->sc_virtio, sc->sc_ctl_vq);

	return r;
}

int
vio_queue_intr(void *arg)
{
	struct vio_queue *vioq = arg;
	struct virtio_softc *vsc = vioq->sc->sc_virtio;
	int r;
	r = virtio_check_vq(vsc, vioq->tx_vq);
	r |= virtio_check_vq(vsc, vioq->rx_vq);
	return r;
}

int
vio_config_change(struct virtio_softc *vsc)
{
	struct vio_softc *sc = (struct vio_softc *)vsc->sc_child;
	vio_link_state(&sc->sc_ac.ac_if);
	vio_needs_reset(sc);
	return 1;
}

int
vio_media_change(struct ifnet *ifp)
{
	/* Ignore */
	return (0);
}

void
vio_media_status(struct ifnet *ifp, struct ifmediareq *imr)
{
	imr->ifm_active = IFM_ETHER | IFM_AUTO;
	imr->ifm_status = IFM_AVALID;

	vio_link_state(ifp);
	if (LINK_STATE_IS_UP(ifp->if_link_state) && ifp->if_flags & IFF_UP)
		imr->ifm_status |= IFM_ACTIVE|IFM_FDX;
}

/*
 * Interface functions for ifnet
 */
int
vio_init(struct ifnet *ifp)
{
	struct vio_softc *sc = ifp->if_softc;
	struct virtio_softc *vsc = sc->sc_virtio;
	int qidx;

	vio_stop(ifp, 0);
	for (qidx = 0; qidx < sc->sc_nqueues; qidx++) {
		struct vio_queue *vioq = &sc->sc_queue[qidx];
		if_rxr_init(&vioq->rx_ring, 2 * ((ifp->if_hardmtu / MCLBYTES) + 1),
		    vioq->rx_vq->vq_num);
		vio_populate_rx_mbufs(sc, vioq);
		ifq_clr_oactive(vioq->ifq);
	}
	vio_iff(sc);
	vio_link_state(ifp);

	if (virtio_has_feature(vsc, VIRTIO_NET_F_CTRL_GUEST_OFFLOADS)) {
		uint64_t features = 0;

		if (virtio_has_feature(vsc, VIRTIO_NET_F_GUEST_CSUM))
			SET(features, VIRTIO_NET_F_GUEST_CSUM);

		if (ISSET(ifp->if_xflags, IFXF_LRO)) {
			if (virtio_has_feature(vsc, VIRTIO_NET_F_GUEST_TSO4))
				SET(features, VIRTIO_NET_F_GUEST_TSO4);
			if (virtio_has_feature(vsc, VIRTIO_NET_F_GUEST_TSO6))
				SET(features, VIRTIO_NET_F_GUEST_TSO6);
		}

		vio_ctrl_guest_offloads(sc, features);
	}

	SET(ifp->if_flags, IFF_RUNNING);
#if 0
	for (qidx = 0; qidx < sc->sc_nqueues; qidx++)
		ifq_restart(sc->sc_queue[qidx]->ifq);
#endif

	return 0;
}

void
vio_stop(struct ifnet *ifp, int disable)
{
	struct vio_softc *sc = ifp->if_softc;
	struct virtio_softc *vsc = sc->sc_virtio;
	int i;

	CLR(ifp->if_flags, IFF_RUNNING);
	timeout_del(&sc->sc_txtick);
	timeout_del(&sc->sc_rxtick);
	/* only way to stop I/O and DMA is resetting... */
	virtio_reset(vsc);
	for (i = 0; i < sc->sc_nqueues; i++) {
		mtx_enter(&sc->sc_queue[i].rx_mtx);
		vio_rxeof(&sc->sc_queue[i]);
		mtx_leave(&sc->sc_queue[i].rx_mtx);
	}

	if (virtio_has_feature(vsc, VIRTIO_NET_F_CTRL_VQ))
		vio_ctrl_wakeup(sc, RESET);
	vio_tx_drain(sc);
	if (disable)
		vio_rx_drain(sc);

	virtio_reinit_start(vsc);
	for (i = 0; i < sc->sc_nqueues; i++) {
		virtio_start_vq_intr(vsc, sc->sc_queue[i].rx_vq);
		virtio_stop_vq_intr(vsc, sc->sc_queue[i].tx_vq);
	}
	if (virtio_has_feature(vsc, VIRTIO_NET_F_CTRL_VQ))
		virtio_start_vq_intr(vsc, sc->sc_ctl_vq);
	virtio_reinit_end(vsc);
	if (virtio_has_feature(vsc, VIRTIO_NET_F_MQ))
		vio_ctrl_mq(sc);
	if (virtio_has_feature(vsc, VIRTIO_NET_F_CTRL_VQ))
		vio_ctrl_wakeup(sc, FREE);
}

static inline uint16_t
vio_cksum_update(uint32_t cksum, uint16_t paylen)
{
	/* Add payload length */
	cksum += paylen;

	/* Fold back to 16 bit */
	cksum += cksum >> 16;

	return (uint16_t)(cksum);
}

void
vio_tx_offload(struct virtio_net_hdr *hdr, struct mbuf *m)
{
	struct ether_extracted ext;

	/*
	 * Checksum Offload
	 */

	if (!ISSET(m->m_pkthdr.csum_flags, M_TCP_CSUM_OUT) &&
	    !ISSET(m->m_pkthdr.csum_flags, M_UDP_CSUM_OUT))
		return;

	ether_extract_headers(m, &ext);

	/* Consistency Checks */
	if ((!ext.ip4 && !ext.ip6) || (!ext.tcp && !ext.udp))
		return;

	if ((ext.tcp && !ISSET(m->m_pkthdr.csum_flags, M_TCP_CSUM_OUT)) ||
	    (ext.udp && !ISSET(m->m_pkthdr.csum_flags, M_UDP_CSUM_OUT)))
		return;

	hdr->csum_start = sizeof(*ext.eh);
#if NVLAN > 0
	if (ext.evh)
		hdr->csum_start = sizeof(*ext.evh);
#endif
	hdr->csum_start += ext.iphlen;

	if (ext.tcp)
		hdr->csum_offset = offsetof(struct tcphdr, th_sum);
	else if (ext.udp)
		hdr->csum_offset = offsetof(struct udphdr, uh_sum);

	hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

	/*
	 * TCP Segmentation Offload
	 */

	if (!ISSET(m->m_pkthdr.csum_flags, M_TCP_TSO))
		return;

	if (!ext.tcp || m->m_pkthdr.ph_mss == 0) {
		tcpstat_inc(tcps_outbadtso);
		return;
	}

	hdr->hdr_len = hdr->csum_start + ext.tcphlen;
	hdr->gso_size = m->m_pkthdr.ph_mss;

	if (ext.ip4)
		hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
#ifdef INET6
	else if (ext.ip6)
		hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
#endif

	/* VirtIO-Net need pseudo header cksum with IP-payload length for TSO */
	ext.tcp->th_sum = vio_cksum_update(ext.tcp->th_sum,
	    htons(ext.iplen - ext.iphlen));

	tcpstat_add(tcps_outpkttso,
	    (ext.paylen + m->m_pkthdr.ph_mss - 1) / m->m_pkthdr.ph_mss);
}

void
vio_start(struct ifqueue *ifq)
{
	struct ifnet *ifp = ifq->ifq_if;
	struct vio_queue *vioq = ifq->ifq_softc;
	struct vio_softc *sc = ifp->if_softc;
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = vioq->tx_vq;
	struct mbuf *m;
	int queued = 0, free_slots, used_slots;;

	mtx_enter(&vioq->tx_mtx);
	vio_tx_dequeue(vq);


again:
	free_slots = vioq->tx_free_slots;
	KASSERT(free_slots >= 0);
	used_slots = 0;
	for (;;) {
		int slot, r;
		struct virtio_net_hdr *hdr;

		if (free_slots - used_slots < sc->sc_tx_slots_per_req) {
			ifq_set_oactive(ifq);
			break;
		}

		m = ifq_dequeue(ifq);
		if (m == NULL)
			break;

		r = virtio_enqueue_prep(vq, &slot);
		if (r == EAGAIN) {
			printf("%s: virtio_enqueue_prep failed?\n", __func__);
			m_freem(m);
			ifp->if_oerrors++;
			break;
		}
		if (r != 0)
			panic("%s: enqueue_prep for tx buffer: %d",
			    sc->sc_dev.dv_xname, r);

		hdr = &sc->sc_queue[0].tx_hdrs[slot];
		memset(hdr, 0, sc->sc_hdr_size);
		vio_tx_offload(hdr, m);

		r = vio_encap(vioq, slot, m);
		if (r != 0) {
			virtio_enqueue_abort(vq, slot);
			m_freem(m);
			ifp->if_oerrors++;
			continue;
		}
		r = virtio_enqueue_reserve(vq, slot,
		    vioq->tx_dmamaps[slot]->dm_nsegs + 1);
		if (r != 0) {
			printf("%s: virtio_enqueue_reserve failed?\n", __func__);
			m_freem(m);
			ifp->if_oerrors++;
			bus_dmamap_unload(vsc->sc_dmat,
			    vioq->tx_dmamaps[slot]);
			vioq->tx_mbufs[slot] = NULL;
			break;
		}
		if (sc->sc_tx_slots_per_req == 1)
			used_slots++;
		else
			used_slots += vioq->tx_dmamaps[slot]->dm_nsegs + 1;


		bus_dmamap_sync(vsc->sc_dmat, vioq->tx_dmamaps[slot], 0,
		    vioq->tx_dmamaps[slot]->dm_mapsize, BUS_DMASYNC_PREWRITE);
		VIO_DMAMEM_SYNC(vsc, sc, hdr, sc->sc_hdr_size,
		    BUS_DMASYNC_PREWRITE);
		VIO_DMAMEM_ENQUEUE(sc, vq, slot, hdr, sc->sc_hdr_size, 1);
		virtio_enqueue(vq, slot, vioq->tx_dmamaps[slot], 1);
		virtio_enqueue_commit(vsc, vq, slot, 0);
		queued++;
#if NBPFILTER > 0
		if (ifp->if_bpf)
			bpf_mtap(ifp->if_bpf, m, BPF_DIRECTION_OUT);
#endif
	}
	 if (used_slots > 0) {
		if (used_slots > vioq->tx_free_slots)
			printf("%s: used_slots %d tx_free_slots %d free_slots %d\n",
			    __func__, used_slots, vioq->tx_free_slots, free_slots);
		vioq->tx_free_slots -= used_slots;
		KASSERT(vioq->tx_free_slots >= 0);
	}
	if (ifq_is_oactive(ifq)) {
		int r;
		if (virtio_has_feature(vsc, VIRTIO_F_RING_EVENT_IDX))
			r = virtio_postpone_intr_smart(vq);
		else
			r = virtio_start_vq_intr(vsc, vq);
		if (r) {
			vio_tx_dequeue(vq);
			goto again;
		}
	}
	mtx_leave(&vioq->tx_mtx);

	if (queued > 0) {
		virtio_notify(vsc, vq); // XXX mutex?
		timeout_add_sec(&sc->sc_txtick, 1);
	}
}

#if VIRTIO_DEBUG
void
vio_dump(struct vio_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct virtio_softc *vsc = sc->sc_virtio;
	int i;

	printf("%s status dump:\n", ifp->if_xname);
	printf("tx tick active: %d\n", !timeout_triggered(&sc->sc_txtick));
	printf("max tx slots per req %d\n", sc->sc_tx_slots_per_req);
	printf("rx tick active: %d\n", !timeout_triggered(&sc->sc_rxtick));
	for (i = 0; i < sc->sc_nqueues; i++) {
		printf("%d: TX virtqueue:\n", i);
		printf("  tx free slots %d\n", sc->sc_queue[i].tx_free_slots);
		virtio_vq_dump(sc->sc_queue[i].tx_vq);
		printf("%d: RX virtqueue:\n", i);
		virtio_vq_dump(sc->sc_queue[i].rx_vq);
	}
	if (virtio_has_feature(vsc, VIRTIO_NET_F_CTRL_VQ)) {
		printf("CTL virtqueue:\n");
		virtio_vq_dump(sc->sc_ctl_vq);
		printf("ctrl_inuse: %d\n", sc->sc_ctrl_inuse);
	}
}
#endif

static int
vio_rxr_info(struct vio_softc *sc, struct if_rxrinfo *ifri)
{
	struct if_rxring_info *ifrs, *ifr;
	int error;
	unsigned int i;

	ifrs = mallocarray(sc->sc_nqueues, sizeof(*ifrs),
	    M_TEMP, M_WAITOK|M_ZERO|M_CANFAIL);
	if (ifrs == NULL)
		return (ENOMEM);

	for (i = 0; i < sc->sc_nqueues; i++) {
		ifr = &ifrs[i];

		ifr->ifr_size = MCLBYTES;
		snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), "%u", i);
		ifr->ifr_info = sc->sc_queue[i].rx_ring;
	}

	error = if_rxr_info_ioctl(ifri, i, ifrs);

	free(ifrs, M_TEMP, i * sizeof(*ifrs));

	return (error);
}

int
vio_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct vio_softc *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *)data;
	int s, r = 0;

	s = splnet();
	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		if (!(ifp->if_flags & IFF_RUNNING))
			vio_init(ifp);
		break;
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP) {
#if VIRTIO_DEBUG
			if (ifp->if_flags & IFF_DEBUG)
				vio_dump(sc);
#endif
			if (ifp->if_flags & IFF_RUNNING)
				r = ENETRESET;
			else
				vio_init(ifp);
		} else {
			if (ifp->if_flags & IFF_RUNNING)
				vio_stop(ifp, 1);
		}
		break;
	case SIOCGIFMEDIA:
	case SIOCSIFMEDIA:
		r = ifmedia_ioctl(ifp, ifr, &sc->sc_media, cmd);
		break;
	case SIOCGIFRXR:
		r = vio_rxr_info(sc, (struct if_rxrinfo *)ifr->ifr_data);
		break;
	default:
		r = ether_ioctl(ifp, &sc->sc_ac, cmd, data);
	}

	if (r == ENETRESET) {
		if (ifp->if_flags & IFF_RUNNING)
			vio_iff(sc);
		r = 0;
	}
	splx(s);
	return r;
}

/*
 * Receive implementation
 */
/* allocate and initialize a mbuf for receive */
int
vio_add_rx_mbuf(struct vio_softc *sc, struct vio_queue *vioq, int i)
{
	struct mbuf *m;
	int r;

	m = MCLGETL(NULL, M_DONTWAIT, MCLBYTES);
	if (m == NULL)
		return ENOBUFS;
	vioq->rx_mbufs[i] = m;
	m->m_len = m->m_pkthdr.len = m->m_ext.ext_size;
	r = bus_dmamap_load_mbuf(sc->sc_virtio->sc_dmat,
	    vioq->rx_dmamaps[i], m, BUS_DMA_READ|BUS_DMA_NOWAIT);
	if (r) {
		m_freem(m);
		vioq->rx_mbufs[i] = NULL;
		return r;
	}

	return 0;
}

/* free a mbuf for receive */
void
vio_free_rx_mbuf(struct vio_softc *sc, struct vio_queue *vioq, int i)
{
	bus_dmamap_unload(sc->sc_virtio->sc_dmat, vioq->rx_dmamaps[i]);
	m_freem(vioq->rx_mbufs[i]);
	vioq->rx_mbufs[i] = NULL;
}

/* add mbufs for all the empty receive slots */
void
vio_populate_rx_mbufs(struct vio_softc *sc, struct vio_queue *vioq)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	int r, done = 0;
	u_int slots;
	struct virtqueue *vq = vioq->rx_vq;
	int mrg_rxbuf = VIO_HAVE_MRG_RXBUF(sc);

	for (slots = if_rxr_get(&vioq->rx_ring, vq->vq_num);
	    slots > 0; slots--) {
		int slot;
		r = virtio_enqueue_prep(vq, &slot);
		if (r == EAGAIN)
			break;
		if (r != 0)
			panic("%s: enqueue_prep for rx buffer: %d",
			    sc->sc_dev.dv_xname, r);
		if (vioq->rx_mbufs[slot] == NULL) {
			r = vio_add_rx_mbuf(sc, vioq, slot);
			if (r != 0) {
				virtio_enqueue_abort(vq, slot);
				break;
			}
		}
		r = virtio_enqueue_reserve(vq, slot,
		    vioq->rx_dmamaps[slot]->dm_nsegs + (mrg_rxbuf ? 0 : 1));
		if (r != 0) {
			vio_free_rx_mbuf(sc, vioq, slot);
			break;
		}
		bus_dmamap_sync(vsc->sc_dmat, vioq->rx_dmamaps[slot], 0,
		    vioq->rx_dmamaps[slot]->dm_mapsize, BUS_DMASYNC_PREREAD);
		if (mrg_rxbuf) {
			virtio_enqueue(vq, slot, vioq->rx_dmamaps[slot], 0);
		} else {
			/*
			 * Buggy kvm wants a buffer of exactly the size of
			 * the header in this case, so we have to split in
			 * two.
			 */
			virtio_enqueue_p(vq, slot, vioq->rx_dmamaps[slot],
			    0, sc->sc_hdr_size, 0);
			virtio_enqueue_p(vq, slot, vioq->rx_dmamaps[slot],
			    sc->sc_hdr_size, MCLBYTES - sc->sc_hdr_size, 0);
		}
		virtio_enqueue_commit(vsc, vq, slot, 0);
		done = 1;
	}
	if_rxr_put(&vioq->rx_ring, slots);

	if (done)
		virtio_notify(vsc, vq);
	timeout_add_sec(&sc->sc_rxtick, 1);
}

void
vio_rx_offload(struct mbuf *m, struct virtio_net_hdr *hdr)
{
	struct ether_extracted ext;

	if (!ISSET(hdr->flags, VIRTIO_NET_HDR_F_DATA_VALID) &&
	    !ISSET(hdr->flags, VIRTIO_NET_HDR_F_NEEDS_CSUM))
		return;

	ether_extract_headers(m, &ext);

	if (ext.ip4)
		SET(m->m_pkthdr.csum_flags, M_IPV4_CSUM_IN_OK);

	if (ext.tcp) {
		SET(m->m_pkthdr.csum_flags, M_TCP_CSUM_IN_OK);
		if (ISSET(hdr->flags, VIRTIO_NET_HDR_F_NEEDS_CSUM))
			SET(m->m_pkthdr.csum_flags, M_TCP_CSUM_OUT);
	} else if (ext.udp) {
		SET(m->m_pkthdr.csum_flags, M_UDP_CSUM_IN_OK);
		if (ISSET(hdr->flags, VIRTIO_NET_HDR_F_NEEDS_CSUM))
			SET(m->m_pkthdr.csum_flags, M_UDP_CSUM_OUT);
	}

	if (hdr->gso_type == VIRTIO_NET_HDR_GSO_TCPV4 ||
	    hdr->gso_type == VIRTIO_NET_HDR_GSO_TCPV6) {
		uint16_t mss = hdr->gso_size;

		if (!ext.tcp || mss == 0) {
			tcpstat_inc(tcps_inbadlro);
			return;
		}

		if ((ext.paylen + mss - 1) / mss <= 1)
			return;

		tcpstat_inc(tcps_inhwlro);
		tcpstat_add(tcps_inpktlro, (ext.paylen + mss - 1) / mss);
		SET(m->m_pkthdr.csum_flags, M_TCP_TSO);
		m->m_pkthdr.ph_mss = mss;
	}
}

/* dequeue received packets */
int
vio_rxeof(struct vio_queue *vioq)
{
	struct vio_softc *sc = vioq->sc;
	struct virtio_softc *vsc = sc->sc_virtio;
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct mbuf_list ml = MBUF_LIST_INITIALIZER();
	struct mbuf *m, *m0 = NULL, *mlast;
	int r = 0;
	int slot, len, bufs_left;
	struct virtio_net_hdr *hdr;

	MUTEX_ASSERT_LOCKED(&vioq->rx_mtx);
	while (virtio_dequeue(vsc, vioq->rx_vq, &slot, &len) == 0) {
		r = 1;
		bus_dmamap_sync(vsc->sc_dmat, vioq->rx_dmamaps[slot], 0,
		    vioq->rx_dmamaps[slot]->dm_mapsize, BUS_DMASYNC_POSTREAD);
		m = vioq->rx_mbufs[slot];
		KASSERT(m != NULL);
		bus_dmamap_unload(vsc->sc_dmat, vioq->rx_dmamaps[slot]);
		vioq->rx_mbufs[slot] = NULL;
		virtio_dequeue_commit(vioq->rx_vq, slot);
		if_rxr_put(&vioq->rx_ring, 1);
		m->m_len = m->m_pkthdr.len = len;
		m->m_pkthdr.csum_flags = 0;
		if (m0 == NULL) {
			hdr = mtod(m, struct virtio_net_hdr *);
			m_adj(m, sc->sc_hdr_size);
			m0 = mlast = m;
			if (VIO_HAVE_MRG_RXBUF(sc))
				bufs_left = hdr->num_buffers - 1;
			else
				bufs_left = 0;
		} else {
			m->m_flags &= ~M_PKTHDR;
			m0->m_pkthdr.len += m->m_len;
			mlast->m_next = m;
			mlast = m;
			bufs_left--;
		}

		if (bufs_left == 0) {
			if (virtio_has_feature(vsc, VIRTIO_NET_F_GUEST_CSUM))
				vio_rx_offload(m0, hdr);
			ml_enqueue(&ml, m0);
			m0 = NULL;
		}
	}
	if (m0 != NULL) {
		DPRINTF("%s: expected %u buffers, got %u\n", __func__,
		    hdr->num_buffers, hdr->num_buffers - bufs_left);
		ifp->if_ierrors++;
		m_freem(m0);
	}

	if (ifiq_input(vioq->ifiq, &ml))
		if_rxr_livelocked(&vioq->rx_ring);

	return r;
}

int
vio_rx_intr(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct vio_softc *sc = (struct vio_softc *)vsc->sc_child;
	struct vio_queue *vioq = &sc->sc_queue[vq->vq_index/2];
	int r, sum = 0;

	mtx_enter(&vioq->rx_mtx);
again:
	r = vio_rxeof(vioq);
	sum += r;
	if (r) {
		vio_populate_rx_mbufs(sc, vioq);
		/* set used event index to the next slot */
		if (virtio_has_feature(vsc, VIRTIO_F_RING_EVENT_IDX)) {
			if (virtio_start_vq_intr(vq->vq_owner, vq))
				goto again;
		}
	}

	mtx_leave(&vioq->rx_mtx);
	return sum;
}

void
vio_rxtick(void *arg)
{
	struct vio_softc *sc = arg;
	int i;

	for (i = 0; i < sc->sc_nqueues; i++) {
		mtx_enter(&sc->sc_queue[i].rx_mtx);
		vio_populate_rx_mbufs(sc, &sc->sc_queue[i]);
		mtx_leave(&sc->sc_queue[i].rx_mtx);
	}
}

/* free all the mbufs; called from if_stop(disable) */
void
vio_rx_drain(struct vio_softc *sc)
{
	struct vio_queue *vioq;
	int i, qidx;

	for (qidx = 0; qidx < sc->sc_nqueues; qidx++) {
		vioq = &sc->sc_queue[qidx];
		for (i = 0; i < vioq->rx_vq->vq_num; i++) {
			if (vioq->rx_mbufs[i] == NULL)
				continue;
			vio_free_rx_mbuf(sc, vioq, i);
		}
	}
}

/*
 * Transmission implementation
 */
/* actual transmission is done in if_start */
/* tx interrupt; dequeue and free mbufs */
/*
 * tx interrupt is actually disabled unless the tx queue is full, i.e.
 * IFF_OACTIVE is set. vio_txtick is used to make sure that mbufs
 * are dequeued and freed even if no further transfer happens.
 */
int
vio_tx_intr(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct vio_softc *sc = (struct vio_softc *)vsc->sc_child;
	struct vio_queue *vioq = &sc->sc_queue[vq->vq_index/2];
	int r;

	r = vio_txeof(vq);
	vio_start(vioq->ifq);
	return r;
}

void
vio_txtick(void *arg)
{
	struct vio_softc *sc = arg;
	int i;

	for (i = 0; i < sc->sc_nqueues; i++)
		virtio_check_vq(sc->sc_virtio, sc->sc_queue[i].tx_vq);
}

int
vio_tx_dequeue(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct vio_softc *sc = (struct vio_softc *)vsc->sc_child;
	struct vio_queue *vioq = &sc->sc_queue[vq->vq_index/2];
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct mbuf *m;
	int r = 0;
	int slot, len, freed = 0;

	MUTEX_ASSERT_LOCKED(&vioq->tx_mtx);
	if (!ISSET(ifp->if_flags, IFF_RUNNING))
		return 0;

	while (virtio_dequeue(vsc, vq, &slot, &len) == 0) {
		struct virtio_net_hdr *hdr = &vioq->tx_hdrs[slot];
		r++;
		VIO_DMAMEM_SYNC(vsc, sc, hdr, sc->sc_hdr_size,
		    BUS_DMASYNC_POSTWRITE);
		bus_dmamap_sync(vsc->sc_dmat, vioq->tx_dmamaps[slot], 0,
		    vioq->tx_dmamaps[slot]->dm_mapsize, BUS_DMASYNC_POSTWRITE);
		m = vioq->tx_mbufs[slot];
		bus_dmamap_unload(vsc->sc_dmat, vioq->tx_dmamaps[slot]);
		vioq->tx_mbufs[slot] = NULL;
		// XXX muss auch gelockt werden!
		freed += virtio_dequeue_commit(vq, slot);
		m_freem(m);
	}
	KASSERT(vioq->tx_free_slots >= 0);
	vioq->tx_free_slots += freed;
	return r;
}


int
vio_txeof(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct vio_softc *sc = (struct vio_softc *)vsc->sc_child;
	struct vio_queue *vioq = &sc->sc_queue[vq->vq_index/2];
	int r;

	mtx_enter(&vioq->tx_mtx);
	r = vio_tx_dequeue(vq);
	mtx_leave(&vioq->tx_mtx);

	if (r) {
		if (ifq_is_oactive(vioq->ifq)) {
			mtx_enter(&vioq->tx_mtx);
			virtio_stop_vq_intr(vsc, vq); // XXX
			mtx_leave(&vioq->tx_mtx);
			ifq_restart(vioq->ifq);
		}
	}
	if (vq->vq_used_idx == vq->vq_avail_idx)
		timeout_del(&sc->sc_txtick);
	else if (r)
		timeout_add_sec(&sc->sc_txtick, 1);
	return r;
}

int
vio_encap(struct vio_queue *vioq, int slot, struct mbuf *m)
{
	struct virtio_softc	*vsc = vioq->sc->sc_virtio;
	bus_dmamap_t		 dmap = vioq->tx_dmamaps[slot];
	int			 r;

	r = bus_dmamap_load_mbuf(vsc->sc_dmat, dmap, m,
	    BUS_DMA_WRITE|BUS_DMA_NOWAIT);
	switch (r) {
	case 0:
		break;
	case EFBIG:
		if (m_defrag(m, M_DONTWAIT) == 0 &&
		    bus_dmamap_load_mbuf(vsc->sc_dmat, dmap, m,
		    BUS_DMA_WRITE|BUS_DMA_NOWAIT) == 0)
			break;

		/* FALLTHROUGH */
	default:
		return ENOBUFS;
	}
	vioq->tx_mbufs[slot] = m;
	return 0;
}

/* free all the mbufs already put on vq; called from if_stop(disable) */
void
vio_tx_drain(struct vio_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct vio_queue *vioq;
	int i, q;

	for (q = 0; q < sc->sc_nqueues; q++) {
		vioq = &sc->sc_queue[q];
		printf("%s: %d %p start %p %p\n", __func__, q, vioq, vioq->tx_vq, vioq->tx_mbufs);
		mtx_enter(&vioq->tx_mtx);
		for (i = 0; i < vioq->tx_vq->vq_num; i++) {
			if (vioq->tx_mbufs[i] == NULL)
				continue;
			printf("%s: %d %d\n", __func__, q, i);
			bus_dmamap_unload(vsc->sc_dmat, vioq->tx_dmamaps[i]);
			m_freem(vioq->tx_mbufs[i]);
			vioq->tx_mbufs[i] = NULL;
		}
		printf("%s: %d %p stop\n", __func__, q, vioq);
		ifq_purge(vioq->ifq);
		ifq_clr_oactive(vioq->ifq);
		mtx_leave(&vioq->tx_mtx);
	}
}

/*
 * Control vq
 */
/* issue a VIRTIO_NET_CTRL_RX class command and wait for completion */
int
vio_ctrl_rx(struct vio_softc *sc, int cmd, int onoff)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = sc->sc_ctl_vq;
	int r, slot;

	splassert(IPL_NET);

	if ((r = vio_wait_ctrl(sc)) != 0)
		return r;

	sc->sc_ctrl_cmd->class = VIRTIO_NET_CTRL_RX;
	sc->sc_ctrl_cmd->command = cmd;
	sc->sc_ctrl_rx->onoff = onoff;

	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_cmd,
	    sizeof(*sc->sc_ctrl_cmd), BUS_DMASYNC_PREWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_rx,
	    sizeof(*sc->sc_ctrl_rx), BUS_DMASYNC_PREWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_status,
	    sizeof(*sc->sc_ctrl_status), BUS_DMASYNC_PREREAD);

	r = virtio_enqueue_prep(vq, &slot);
	if (r != 0)
		panic("%s: %s virtio_enqueue_prep: control vq busy",
		    sc->sc_dev.dv_xname, __func__);
	r = virtio_enqueue_reserve(vq, slot, 3);
	if (r != 0)
		panic("%s: %s virtio_enqueue_reserve: control vq busy",
		    sc->sc_dev.dv_xname, __func__);
	VIO_DMAMEM_ENQUEUE(sc, vq, slot, sc->sc_ctrl_cmd,
	    sizeof(*sc->sc_ctrl_cmd), 1);
	VIO_DMAMEM_ENQUEUE(sc, vq, slot, sc->sc_ctrl_rx,
	    sizeof(*sc->sc_ctrl_rx), 1);
	VIO_DMAMEM_ENQUEUE(sc, vq, slot, sc->sc_ctrl_status,
	    sizeof(*sc->sc_ctrl_status), 0);
	virtio_enqueue_commit(vsc, vq, slot, 1);

	if ((r = vio_wait_ctrl_done(sc)) != 0)
		goto out;

	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_cmd,
	    sizeof(*sc->sc_ctrl_cmd), BUS_DMASYNC_POSTWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_rx,
	    sizeof(*sc->sc_ctrl_rx), BUS_DMASYNC_POSTWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_status,
	    sizeof(*sc->sc_ctrl_status), BUS_DMASYNC_POSTREAD);

	if (sc->sc_ctrl_status->ack == VIRTIO_NET_OK) {
		r = 0;
	} else {
		printf("%s: ctrl cmd %d failed\n", sc->sc_dev.dv_xname, cmd);
		r = EIO;
	}

	DPRINTF("%s: cmd %d %d: %d\n", __func__, cmd, onoff, r);
out:
	vio_ctrl_wakeup(sc, FREE);
	return r;
}

/* issue a VIRTIO_NET_CTRL_MQ class command and wait for completion */
int
vio_ctrl_mq(struct vio_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = sc->sc_ctl_vq;
	int r, slot;

	printf("%s: sc_nqueues %d vq_index %d\n", __func__, sc->sc_nqueues, vq->vq_index);

	splassert(IPL_NET);

	if ((r = vio_wait_ctrl(sc)) != 0)
		return r;

	sc->sc_ctrl_cmd->class = VIRTIO_NET_CTRL_MQ;
	sc->sc_ctrl_cmd->command = VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET;
	sc->sc_ctrl_mq_pairs->virtqueue_pairs = sc->sc_nqueues;

	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_cmd,
	    sizeof(*sc->sc_ctrl_cmd), BUS_DMASYNC_PREWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_mq_pairs,
	    sizeof(*sc->sc_ctrl_mq_pairs), BUS_DMASYNC_PREWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_status,
	    sizeof(*sc->sc_ctrl_status), BUS_DMASYNC_PREREAD);

	r = virtio_enqueue_prep(vq, &slot);
	if (r != 0)
		panic("%s: %s virtio_enqueue_prep: control vq busy",
		    sc->sc_dev.dv_xname, __func__);
	r = virtio_enqueue_reserve(vq, slot, 3);
	if (r != 0)
		panic("%s: %s virtio_enqueue_reserve: control vq busy",
		    sc->sc_dev.dv_xname, __func__);
	VIO_DMAMEM_ENQUEUE(sc, vq, slot, sc->sc_ctrl_cmd,
	    sizeof(*sc->sc_ctrl_cmd), 1);
	VIO_DMAMEM_ENQUEUE(sc, vq, slot, sc->sc_ctrl_mq_pairs,
	    sizeof(*sc->sc_ctrl_mq_pairs), 1);
	VIO_DMAMEM_ENQUEUE(sc, vq, slot, sc->sc_ctrl_status,
	    sizeof(*sc->sc_ctrl_status), 0);
	virtio_enqueue_commit(vsc, vq, slot, 1);

	if ((r = vio_wait_ctrl_done(sc)) != 0)
		goto out;

	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_cmd,
	    sizeof(*sc->sc_ctrl_cmd), BUS_DMASYNC_POSTWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_mq_pairs,
	    sizeof(*sc->sc_ctrl_mq_pairs), BUS_DMASYNC_POSTWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_status,
	    sizeof(*sc->sc_ctrl_status), BUS_DMASYNC_POSTREAD);

	if (sc->sc_ctrl_status->ack == VIRTIO_NET_OK) {
		r = 0;
	} else {
		printf("%s: ctrl cmd %d failed\n", sc->sc_dev.dv_xname,
		    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET);
		r = EIO;
	}

	DPRINTF("%s: cmd %d %d: %d\n", __func__,
	    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET, sc->sc_nqueues, r);
out:
	vio_ctrl_wakeup(sc, FREE);
	return r;
}

int
vio_ctrl_guest_offloads(struct vio_softc *sc, uint64_t features)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = sc->sc_ctl_vq;
	int r, slot;

	splassert(IPL_NET);

	if ((r = vio_wait_ctrl(sc)) != 0)
		return r;

	sc->sc_ctrl_cmd->class = VIRTIO_NET_CTRL_GUEST_OFFLOADS;
	sc->sc_ctrl_cmd->command = VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET;
	sc->sc_ctrl_guest_offloads->offloads = features;

	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_cmd,
	    sizeof(*sc->sc_ctrl_cmd), BUS_DMASYNC_PREWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_guest_offloads,
	    sizeof(*sc->sc_ctrl_guest_offloads), BUS_DMASYNC_PREWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_status,
	    sizeof(*sc->sc_ctrl_status), BUS_DMASYNC_PREREAD);

	r = virtio_enqueue_prep(vq, &slot);
	if (r != 0)
		panic("%s: %s virtio_enqueue_prep: control vq busy",
		    sc->sc_dev.dv_xname, __func__);
	r = virtio_enqueue_reserve(vq, slot, 3);
	if (r != 0)
		panic("%s: %s virtio_enqueue_reserve: control vq busy",
		    sc->sc_dev.dv_xname, __func__);
	VIO_DMAMEM_ENQUEUE(sc, vq, slot, sc->sc_ctrl_cmd,
	    sizeof(*sc->sc_ctrl_cmd), 1);
	VIO_DMAMEM_ENQUEUE(sc, vq, slot, sc->sc_ctrl_guest_offloads,
	    sizeof(*sc->sc_ctrl_guest_offloads), 1);
	VIO_DMAMEM_ENQUEUE(sc, vq, slot, sc->sc_ctrl_status,
	    sizeof(*sc->sc_ctrl_status), 0);
	virtio_enqueue_commit(vsc, vq, slot, 1);

	if ((r = vio_wait_ctrl_done(sc)) != 0)
		goto out;

	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_cmd,
	    sizeof(*sc->sc_ctrl_cmd), BUS_DMASYNC_POSTWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_guest_offloads,
	    sizeof(*sc->sc_ctrl_guest_offloads), BUS_DMASYNC_POSTWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_status,
	    sizeof(*sc->sc_ctrl_status), BUS_DMASYNC_POSTREAD);

	if (sc->sc_ctrl_status->ack == VIRTIO_NET_OK) {
		r = 0;
	} else {
		printf("%s: features 0x%llx failed\n", sc->sc_dev.dv_xname,
		    features);
		r = EIO;
	}

	DPRINTF("%s: features 0x%llx: %d\n", __func__, features, r);
 out:
	vio_ctrl_wakeup(sc, FREE);
	return r;
}

int
vio_wait_ctrl(struct vio_softc *sc)
{
	int r = 0;

	while (sc->sc_ctrl_inuse != FREE) {
		if (sc->sc_ctrl_inuse == RESET || vio_needs_reset(sc))
			return ENXIO;
		r = tsleep_nsec(&sc->sc_ctrl_inuse, PRIBIO, "viowait", INFSLP);
	}
	sc->sc_ctrl_inuse = INUSE;

	return r;
}

int
vio_wait_ctrl_done(struct vio_softc *sc)
{
	int r = 0;

	while (sc->sc_ctrl_inuse != DONE) {
		if (sc->sc_ctrl_inuse == RESET || vio_needs_reset(sc))
			return ENXIO;
		r = tsleep_nsec(&sc->sc_ctrl_inuse, PRIBIO, "viodone",
		    VIRTIO_NET_CTRL_TIMEOUT);
		if (r == EWOULDBLOCK) {
			printf("%s: ctrl queue timeout\n", sc->sc_dev.dv_xname);
			vio_ctrl_wakeup(sc, RESET);
			return ENXIO;
		}
		if (cold)
			virtio_check_vq(sc->sc_virtio, sc->sc_ctl_vq);
	}
	return r;
}

void
vio_ctrl_wakeup(struct vio_softc *sc, enum vio_ctrl_state new)
{
	sc->sc_ctrl_inuse = new;
	wakeup(&sc->sc_ctrl_inuse);
}

int
vio_ctrleof(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct vio_softc *sc = (struct vio_softc *)vsc->sc_child;
	int r = 0, ret, slot;

	 KERNEL_LOCK();
again:
	ret = virtio_dequeue(vsc, vq, &slot, NULL);
	if (ret == ENOENT)
		goto out;
	virtio_dequeue_commit(vq, slot);
	r++;
	vio_ctrl_wakeup(sc, DONE);
	if (virtio_start_vq_intr(vsc, vq))
		goto again;

out:
	KERNEL_UNLOCK();
	return r;
}

/* issue VIRTIO_NET_CTRL_MAC_TABLE_SET command and wait for completion */
int
vio_set_rx_filter(struct vio_softc *sc)
{
	/* filter already set in sc_ctrl_mac_tbl */
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = sc->sc_ctl_vq;
	int r, slot;

	splassert(IPL_NET);

	if ((r = vio_wait_ctrl(sc)) != 0)
		return r;

	sc->sc_ctrl_cmd->class = VIRTIO_NET_CTRL_MAC;
	sc->sc_ctrl_cmd->command = VIRTIO_NET_CTRL_MAC_TABLE_SET;

	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_cmd,
	    sizeof(*sc->sc_ctrl_cmd), BUS_DMASYNC_PREWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_mac_info,
	    VIO_CTRL_MAC_INFO_SIZE, BUS_DMASYNC_PREWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_status,
	    sizeof(*sc->sc_ctrl_status), BUS_DMASYNC_PREREAD);

	r = virtio_enqueue_prep(vq, &slot);
	if (r != 0)
		panic("%s: %s virtio_enqueue_prep: control vq busy",
		    sc->sc_dev.dv_xname, __func__);
	r = virtio_enqueue_reserve(vq, slot, 4);
	if (r != 0)
		panic("%s: %s virtio_enqueue_reserve: control vq busy",
		    sc->sc_dev.dv_xname, __func__);
	VIO_DMAMEM_ENQUEUE(sc, vq, slot, sc->sc_ctrl_cmd,
	    sizeof(*sc->sc_ctrl_cmd), 1);
	VIO_DMAMEM_ENQUEUE(sc, vq, slot, sc->sc_ctrl_mac_tbl_uc,
	    sizeof(*sc->sc_ctrl_mac_tbl_uc) +
	    sc->sc_ctrl_mac_tbl_uc->nentries * ETHER_ADDR_LEN, 1);
	VIO_DMAMEM_ENQUEUE(sc, vq, slot, sc->sc_ctrl_mac_tbl_mc,
	    sizeof(*sc->sc_ctrl_mac_tbl_mc) +
	    sc->sc_ctrl_mac_tbl_mc->nentries * ETHER_ADDR_LEN, 1);
	VIO_DMAMEM_ENQUEUE(sc, vq, slot, sc->sc_ctrl_status,
	    sizeof(*sc->sc_ctrl_status), 0);
	virtio_enqueue_commit(vsc, vq, slot, 1);

	if ((r = vio_wait_ctrl_done(sc)) != 0)
		goto out;

	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_cmd,
	    sizeof(*sc->sc_ctrl_cmd), BUS_DMASYNC_POSTWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_mac_info,
	    VIO_CTRL_MAC_INFO_SIZE, BUS_DMASYNC_POSTWRITE);
	VIO_DMAMEM_SYNC(vsc, sc, sc->sc_ctrl_status,
	    sizeof(*sc->sc_ctrl_status), BUS_DMASYNC_POSTREAD);

	if (sc->sc_ctrl_status->ack == VIRTIO_NET_OK) {
		r = 0;
	} else {
		/* The host's filter table is not large enough */
		printf("%s: failed setting rx filter\n", sc->sc_dev.dv_xname);
		r = EIO;
	}

out:
	vio_ctrl_wakeup(sc, FREE);
	return r;
}

void
vio_iff(struct vio_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct arpcom *ac = &sc->sc_ac;
	struct ether_multi *enm;
	struct ether_multistep step;
	int nentries = 0;
	int promisc = 0, allmulti = 0, rxfilter = 0;
	int r;

	splassert(IPL_NET);

	ifp->if_flags &= ~IFF_ALLMULTI;

	if (!virtio_has_feature(vsc, VIRTIO_NET_F_CTRL_RX)) {
		/* no ctrl vq; always promisc */
		ifp->if_flags |= IFF_ALLMULTI | IFF_PROMISC;
		return;
	}

	if (sc->sc_dev.dv_cfdata->cf_flags & CONFFLAG_QEMU_VLAN_BUG)
		ifp->if_flags |= IFF_PROMISC;

	if (ifp->if_flags & IFF_PROMISC || ac->ac_multirangecnt > 0 ||
	    ac->ac_multicnt >= VIRTIO_NET_CTRL_MAC_MC_ENTRIES) {
		ifp->if_flags |= IFF_ALLMULTI;
		if (ifp->if_flags & IFF_PROMISC)
			promisc = 1;
		else
			allmulti = 1;
	} else {
		rxfilter = 1;

		ETHER_FIRST_MULTI(step, ac, enm);
		while (enm != NULL) {
			memcpy(sc->sc_ctrl_mac_tbl_mc->macs[nentries++],
			    enm->enm_addrlo, ETHER_ADDR_LEN);

			ETHER_NEXT_MULTI(step, enm);
		}
	}

	/* set unicast address, VirtualBox wants that */
	memcpy(sc->sc_ctrl_mac_tbl_uc->macs[0], ac->ac_enaddr, ETHER_ADDR_LEN);
	sc->sc_ctrl_mac_tbl_uc->nentries = 1;

	sc->sc_ctrl_mac_tbl_mc->nentries = rxfilter ? nentries : 0;

	r = vio_set_rx_filter(sc);
	if (r == EIO)
		allmulti = 1; /* fallback */
	else if (r != 0)
		return;

	r = vio_ctrl_rx(sc, VIRTIO_NET_CTRL_RX_ALLMULTI, allmulti);
	if (r == EIO)
		promisc = 1; /* fallback */
	else if (r != 0)
		return;

	vio_ctrl_rx(sc, VIRTIO_NET_CTRL_RX_PROMISC, promisc);
}
