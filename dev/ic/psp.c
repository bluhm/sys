/*	$OpenBSD: psp.c,v 1.12 2024/11/08 17:34:22 bluhm Exp $ */

/*
 * Copyright (c) 2023, 2024 Hans-Joerg Hoexer <hshoexer@genua.de>
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
#include <sys/device.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/pledge.h>
#include <sys/proc.h>
#include <sys/rwlock.h>

#include <machine/bus.h>

#include <uvm/uvm.h>
#include <crypto/xform.h>

#include <dev/ic/ccpvar.h>
#include <dev/ic/pspvar.h>

struct psp_softc {
	struct device		sc_dev;
	bus_space_tag_t		sc_iot;
	bus_space_handle_t	sc_ioh;

	bus_dma_tag_t		sc_dmat;

	bus_size_t		sc_reg_inten;
	bus_size_t		sc_reg_intsts;
	bus_size_t		sc_reg_cmdresp;
	bus_size_t		sc_reg_addrlo;
	bus_size_t		sc_reg_addrhi;

	bus_dmamap_t		sc_cmd_map;
	bus_dma_segment_t	sc_cmd_seg;
	size_t			sc_cmd_size;
	caddr_t			sc_cmd_kva;

	bus_dmamap_t		sc_tmr_map;
	bus_dma_segment_t	sc_tmr_seg;
	size_t			sc_tmr_size;
	caddr_t			sc_tmr_kva;

	struct rwlock		sc_lock;
	struct mutex		psp_lock;

	uint32_t		sc_flags;
#define PSPF_INITIALIZED	0x1
#define PSPF_UCODELOADED	0x2
#define PSPF_NOUCODE		0x4

	u_char			*sc_ucodebuf;
	size_t			sc_ucodelen;
};

int	psp_get_pstatus(struct psp_softc *, struct psp_platform_status *);
int	psp_init(struct psp_softc *, struct psp_init *);
int	psp_reinit(struct psp_softc *);
int	psp_match(struct device *, void *, void *);
void	psp_attach(struct device *, struct device *, void *);
void	psp_load_ucode(struct psp_softc *);

struct cfdriver psp_cd = {
	NULL, "psp", DV_DULL
};

const struct cfattach psp_ca = {
	sizeof(struct psp_softc),
	psp_match,
	psp_attach
};

int
psp_sev_intr(void *arg)
{
	struct ccp_softc *csc = arg;
	struct psp_softc *sc = (struct psp_softc *)csc->sc_psp;
	uint32_t status;

	mtx_enter(&sc->psp_lock);
	status = bus_space_read_4(sc->sc_iot, sc->sc_ioh, sc->sc_reg_intsts);
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, sc->sc_reg_intsts, status);
	mtx_leave(&sc->psp_lock);

	if (!(status & PSP_CMDRESP_COMPLETE))
		return (0);

	wakeup(sc);

	return (1);
}

int
psp_match(struct device *parent, void *match, void *aux)
{
	return (1);
}

void
psp_attach(struct device *parent, struct device *self, void *aux)
{
	struct psp_softc		*sc = (struct psp_softc *)self;
	struct psp_attach_args		*arg = aux;
	struct psp_platform_status	pst;
	size_t				size;
	int				nsegs;

	printf(":");
	sc->sc_iot = arg->iot;
	sc->sc_ioh = arg->ioh;
	sc->sc_dmat = arg->dmat;
	if (arg->version == 1) {
		sc->sc_reg_inten = PSPV1_REG_INTEN;
		sc->sc_reg_intsts = PSPV1_REG_INTSTS;
		sc->sc_reg_cmdresp = PSPV1_REG_CMDRESP;
		sc->sc_reg_addrlo = PSPV1_REG_ADDRLO;
		sc->sc_reg_addrhi = PSPV1_REG_ADDRHI;
	} else {
		sc->sc_reg_inten = PSP_REG_INTEN;
		sc->sc_reg_intsts = PSP_REG_INTSTS;
		sc->sc_reg_cmdresp = PSP_REG_CMDRESP;
		sc->sc_reg_addrlo = PSP_REG_ADDRLO;
		sc->sc_reg_addrhi = PSP_REG_ADDRHI;
	}
	if (arg->version)
		printf(" vers %d,", arg->version);

	rw_init(&sc->sc_lock, "psp_lock");
	mtx_init(&sc->psp_lock, IPL_BIO);

	/* create and map SEV command buffer */
	sc->sc_cmd_size = size = PAGE_SIZE;
	if (bus_dmamap_create(sc->sc_dmat, size, 1, size, 0,
	    BUS_DMA_WAITOK | BUS_DMA_ALLOCNOW | BUS_DMA_64BIT,
	    &sc->sc_cmd_map) != 0)
		return;

	if (bus_dmamem_alloc(sc->sc_dmat, size, 0, 0, &sc->sc_cmd_seg, 1,
	    &nsegs, BUS_DMA_WAITOK | BUS_DMA_ZERO) != 0)
		goto fail_0;

	if (bus_dmamem_map(sc->sc_dmat, &sc->sc_cmd_seg, nsegs, size,
	    &sc->sc_cmd_kva, BUS_DMA_WAITOK) != 0)
		goto fail_1;

	if (bus_dmamap_load(sc->sc_dmat, sc->sc_cmd_map, sc->sc_cmd_kva,
	    size, NULL, BUS_DMA_WAITOK) != 0)
		goto fail_2;

	if (psp_get_pstatus(sc, &pst)) {
		printf(" platform status");
		goto fail_3;
	}
	if (pst.state != PSP_PSTATE_UNINIT) {
		printf(" uninitialized state");
		goto fail_3;
	}
	printf(" api %u.%u, build %u, SEV, SEV-ES",
	    pst.api_major, pst.api_minor, pst.cfges_build >> 24);

	/* enable interrupts */
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, sc->sc_reg_inten, -1);

	printf("\n");

	return;

fail_3:
	bus_dmamap_unload(sc->sc_dmat, sc->sc_cmd_map);
fail_2:
	bus_dmamem_unmap(sc->sc_dmat, sc->sc_cmd_kva, size);
fail_1:
	bus_dmamem_free(sc->sc_dmat, &sc->sc_cmd_seg, 1);
fail_0:
	bus_dmamap_destroy(sc->sc_dmat, sc->sc_cmd_map);

	printf(" failed\n");

	return;
}

static int
ccp_wait(struct psp_softc *sc, uint32_t *status, int poll)
{
	uint32_t	cmdword;
	int		count;

	MUTEX_ASSERT_LOCKED(&sc->psp_lock);

	if (poll) {
		count = 0;
		while (count++ < 400) {
			cmdword = bus_space_read_4(sc->sc_iot, sc->sc_ioh,
			    sc->sc_reg_cmdresp);
			if (cmdword & PSP_CMDRESP_RESPONSE)
				goto done;
			delay(5000);
		}

		/* timeout */
		return (1);
	}

	if (msleep_nsec(sc, &sc->psp_lock, PWAIT, "psp", SEC_TO_NSEC(2))
	    == EWOULDBLOCK)
		return (1);

	cmdword = bus_space_read_4(sc->sc_iot, sc->sc_ioh, sc->sc_reg_cmdresp);
done:
	if (status != NULL)
		*status = cmdword;
	return (0);
}

static int
ccp_docmd(struct psp_softc *sc, int cmd, uint64_t paddr)
{
	uint32_t	plo, phi, cmdword, status;
	int		ret;

	plo = ((paddr >> 0) & 0xffffffff);
	phi = ((paddr >> 32) & 0xffffffff);
	cmdword = (cmd & 0x3ff) << 16;
	if (!cold)
		cmdword |= PSP_CMDRESP_IOC;

	mtx_enter(&sc->psp_lock);
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, sc->sc_reg_addrlo, plo);
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, sc->sc_reg_addrhi, phi);
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, sc->sc_reg_cmdresp, cmdword);

	ret = ccp_wait(sc, &status, cold);
	mtx_leave(&sc->psp_lock);
	if (ret)
		return (1);

	/* Did PSP sent a response code? */
	if (status & PSP_CMDRESP_RESPONSE) {
		if ((status & PSP_STATUS_MASK) != PSP_STATUS_SUCCESS)
			return (1);
	}

	return (0);
}

int
psp_init(struct psp_softc *sc, struct psp_init *uinit)
{
	struct psp_init		*init;
	int			 ret;

	init = (struct psp_init *)sc->sc_cmd_kva;
	bzero(init, sizeof(*init));

	init->enable_es = uinit->enable_es;
	init->tmr_paddr = uinit->tmr_paddr;
	init->tmr_length = uinit->tmr_length;

	ret = ccp_docmd(sc, PSP_CMD_INIT, sc->sc_cmd_map->dm_segs[0].ds_addr);
	if (ret != 0)
		return (EIO);

	wbinvd_on_all_cpus_acked();

	sc->sc_flags |= PSPF_INITIALIZED;

	return (0);
}

int
psp_reinit(struct psp_softc *sc)
{
	struct psp_init	init;
	size_t		size;
	int		nsegs;

	if (sc->sc_flags & PSPF_INITIALIZED) {
		printf("%s: invalid flags 0x%x\n", __func__, sc->sc_flags);
		return (EINVAL);
	}

	if (sc->sc_tmr_map != NULL)
		return (EINVAL);

	/*
	 * create and map Trusted Memory Region (TMR); size 1 Mbyte,
	 * needs to be aligend to 1 Mbyte.
	 */
	sc->sc_tmr_size = size = PSP_TMR_SIZE;
	if (bus_dmamap_create(sc->sc_dmat, size, 1, size, 0,
	    BUS_DMA_WAITOK | BUS_DMA_ALLOCNOW | BUS_DMA_64BIT,
	    &sc->sc_tmr_map) != 0)
		return (ENOMEM);

	if (bus_dmamem_alloc(sc->sc_dmat, size, size, 0, &sc->sc_tmr_seg, 1,
	    &nsegs, BUS_DMA_WAITOK | BUS_DMA_ZERO) != 0)
		goto fail_0;

	if (bus_dmamem_map(sc->sc_dmat, &sc->sc_tmr_seg, nsegs, size,
	    &sc->sc_tmr_kva, BUS_DMA_WAITOK) != 0)
		goto fail_1;

	if (bus_dmamap_load(sc->sc_dmat, sc->sc_tmr_map, sc->sc_tmr_kva,
	    size, NULL, BUS_DMA_WAITOK) != 0)
		goto fail_2;

	memset(&init, 0, sizeof(init));
	init.enable_es = 1;
	init.tmr_length = PSP_TMR_SIZE;
	init.tmr_paddr = sc->sc_tmr_map->dm_segs[0].ds_addr;
	if (psp_init(sc, &init))
		goto fail_3;

	return (0);

fail_3:
	bus_dmamap_unload(sc->sc_dmat, sc->sc_tmr_map);
fail_2:
	bus_dmamem_unmap(sc->sc_dmat, sc->sc_tmr_kva, size);
fail_1:
	bus_dmamem_free(sc->sc_dmat, &sc->sc_tmr_seg, 1);
fail_0:
	bus_dmamap_destroy(sc->sc_dmat, sc->sc_tmr_map);

	return (ENOMEM);
}

int
psp_shutdown(struct psp_softc *sc)
{
	int ret;

	if (sc->sc_tmr_map == NULL)
		return (EINVAL);

	ret = ccp_docmd(sc, PSP_CMD_SHUTDOWN, 0x0);

	if (ret != 0)
		return (EIO);

	/* wbinvd right after SHUTDOWN */
	wbinvd_on_all_cpus_acked();

	/* release TMR */
	bus_dmamap_unload(sc->sc_dmat, sc->sc_tmr_map);
	bus_dmamem_unmap(sc->sc_dmat, sc->sc_tmr_kva, sc->sc_tmr_size);
	bus_dmamem_free(sc->sc_dmat, &sc->sc_tmr_seg, 1);
	bus_dmamap_destroy(sc->sc_dmat, sc->sc_tmr_map);
	sc->sc_tmr_map = NULL;

	/* reset flags */
	sc->sc_flags = 0;

	return (0);
}

int
psp_get_pstatus(struct psp_softc *sc, struct psp_platform_status *ustatus)
{
	struct psp_platform_status *status;
	int			 ret;

	status = (struct psp_platform_status *)sc->sc_cmd_kva;
	bzero(status, sizeof(*status));

	ret = ccp_docmd(sc, PSP_CMD_PLATFORMSTATUS,
	    sc->sc_cmd_map->dm_segs[0].ds_addr);

	if (ret != 0)
		return (EIO);

	bcopy(status, ustatus, sizeof(*ustatus));

	return (0);
}

int
psp_df_flush(struct psp_softc *sc)
{
	int			 ret;

	wbinvd_on_all_cpus_acked();

	ret = ccp_docmd(sc, PSP_CMD_DF_FLUSH, 0x0);

	if (ret != 0)
		return (EIO);

	return (0);
}

int
psp_decommission(struct psp_softc *sc, struct psp_decommission *udecom)
{
	struct psp_decommission	*decom;
	int			 ret;

	decom = (struct psp_decommission *)sc->sc_cmd_kva;
	bzero(decom, sizeof(*decom));

	decom->handle = udecom->handle;

	ret = ccp_docmd(sc, PSP_CMD_DECOMMISSION,
	    sc->sc_cmd_map->dm_segs[0].ds_addr);

	if (ret != 0)
		return (EIO);

	return (0);
}

int
psp_get_gstatus(struct psp_softc *sc, struct psp_guest_status *ustatus)
{
	struct psp_guest_status	*status;
	int			 ret;

	status = (struct psp_guest_status *)sc->sc_cmd_kva;
	bzero(status, sizeof(*status));

	status->handle = ustatus->handle;

	ret = ccp_docmd(sc, PSP_CMD_GUESTSTATUS,
	    sc->sc_cmd_map->dm_segs[0].ds_addr);

	if (ret != 0)
		return (EIO);

	ustatus->policy = status->policy;
	ustatus->asid = status->asid;
	ustatus->state = status->state;

	return (0);
}

int
psp_launch_start(struct psp_softc *sc, struct psp_launch_start *ustart)
{
	struct psp_launch_start	*start;
	int			 ret;

	start = (struct psp_launch_start *)sc->sc_cmd_kva;
	bzero(start, sizeof(*start));

	start->handle = ustart->handle;
	start->policy = ustart->policy;

	ret = ccp_docmd(sc, PSP_CMD_LAUNCH_START,
	    sc->sc_cmd_map->dm_segs[0].ds_addr);

	if (ret != 0)
		return (EIO);

	/* If requested, return new handle. */
	if (ustart->handle == 0)
		ustart->handle = start->handle;

	return (0);
}

int
psp_launch_update_data(struct psp_softc *sc,
    struct psp_launch_update_data *ulud, struct proc *p)
{
	struct psp_launch_update_data	*ludata;
	pmap_t				 pmap;
	vaddr_t				 v, next, end;
	size_t				 size, len, off;
	int				 ret;

	/* Ensure AES_XTS_BLOCKSIZE alignment and multiplicity. */
	if ((ulud->paddr & (AES_XTS_BLOCKSIZE - 1)) != 0 ||
	    (ulud->length % AES_XTS_BLOCKSIZE) != 0)
		return (EINVAL);

	ludata = (struct psp_launch_update_data *)sc->sc_cmd_kva;
	bzero(ludata, sizeof(*ludata));

	ludata->handle = ulud->handle;

	/* Drain caches before we encrypt memory. */
	wbinvd_on_all_cpus_acked();

	/*
	 * Launch update one physical page at a time.  We could
	 * optimise this for contiguous pages of physical memory.
	 *
	 * vmd(8) provides the guest physical address, thus convert
	 * to system physical address.
	 */
	pmap = vm_map_pmap(&p->p_vmspace->vm_map);
	size = ulud->length;
	end = ulud->paddr + ulud->length;
	for (v = ulud->paddr; v < end; v = next) {
		off = v & PAGE_MASK;

		len = MIN(PAGE_SIZE - off, size);

		/* Wire mapping. */
		if (uvm_map_pageable(&p->p_vmspace->vm_map, v, v+len, FALSE, 0))
			return (EINVAL);
		if (!pmap_extract(pmap, v, (paddr_t *)&ludata->paddr))
			return (EINVAL);
		ludata->length = len;

		ret = ccp_docmd(sc, PSP_CMD_LAUNCH_UPDATE_DATA,
		    sc->sc_cmd_map->dm_segs[0].ds_addr);

		if (ret != 0)
			return (EIO);

		size -= len;
		next = v + len;
	}

	return (0);
}

int
psp_launch_measure(struct psp_softc *sc, struct psp_launch_measure *ulm)
{
	struct psp_launch_measure *lm;
	int			 ret;
	uint64_t		 paddr;

	if (ulm->measure_len != sizeof(ulm->psp_measure))
		return (EINVAL);

	lm = (struct psp_launch_measure *)sc->sc_cmd_kva;
	bzero(lm, sizeof(*lm));

	lm->handle = ulm->handle;
	paddr = sc->sc_cmd_map->dm_segs[0].ds_addr;
	lm->measure_paddr =
	    paddr + offsetof(struct psp_launch_measure, psp_measure);
	lm->measure_len = sizeof(lm->psp_measure);

	ret = ccp_docmd(sc, PSP_CMD_LAUNCH_MEASURE, paddr);

	if (ret != 0 || lm->measure_len != ulm->measure_len)
		return (EIO);

	bcopy(&lm->psp_measure, &ulm->psp_measure, ulm->measure_len);

	return (0);
}

int
psp_launch_finish(struct psp_softc *sc, struct psp_launch_finish *ulf)
{
	struct psp_launch_finish *lf;
	int			 ret;

	lf = (struct psp_launch_finish *)sc->sc_cmd_kva;
	bzero(lf, sizeof(*lf));

	lf->handle = ulf->handle;

	ret = ccp_docmd(sc, PSP_CMD_LAUNCH_FINISH,
	    sc->sc_cmd_map->dm_segs[0].ds_addr);

	if (ret != 0)
		return (EIO);

	return (0);
}

int
psp_attestation(struct psp_softc *sc, struct psp_attestation *uat)
{
	struct psp_attestation	*at;
	int			 ret;
	uint64_t		 paddr;

	if (uat->attest_len != sizeof(uat->psp_report))
		return (EINVAL);

	at = (struct psp_attestation *)sc->sc_cmd_kva;
	bzero(at, sizeof(*at));

	at->handle = uat->handle;
	paddr = sc->sc_cmd_map->dm_segs[0].ds_addr;
	at->attest_paddr =
	    paddr + offsetof(struct psp_attestation, psp_report);
	bcopy(uat->attest_nonce, at->attest_nonce, sizeof(at->attest_nonce));
	at->attest_len = sizeof(at->psp_report);

	ret = ccp_docmd(sc, PSP_CMD_ATTESTATION, paddr);

	if (ret != 0 || at->attest_len != uat->attest_len)
		return (EIO);

	bcopy(&at->psp_report, &uat->psp_report, uat->attest_len);

	return (0);
}

int
psp_activate(struct psp_softc *sc, struct psp_activate *uact)
{
	struct psp_activate	*act;
	int			 ret;

	act = (struct psp_activate *)sc->sc_cmd_kva;
	bzero(act, sizeof(*act));

	act->handle = uact->handle;
	act->asid = uact->asid;

	ret = ccp_docmd(sc, PSP_CMD_ACTIVATE,
	    sc->sc_cmd_map->dm_segs[0].ds_addr);

	if (ret != 0)
		return (EIO);

	return (0);
}

int
psp_deactivate(struct psp_softc *sc, struct psp_deactivate *udeact)
{
	struct psp_deactivate	*deact;
	int			 ret;

	deact = (struct psp_deactivate *)sc->sc_cmd_kva;
	bzero(deact, sizeof(*deact));

	deact->handle = udeact->handle;

	ret = ccp_docmd(sc, PSP_CMD_DEACTIVATE,
	    sc->sc_cmd_map->dm_segs[0].ds_addr);

	if (ret != 0)
		return (EIO);

	return (0);
}

int
psp_downloadfirmware(struct psp_softc *sc, struct psp_downloadfirmware *udlfw)
{
	struct psp_downloadfirmware *dlfw;
	bus_dmamap_t		 map;
	bus_dma_segment_t	 seg;
	caddr_t			 kva;
	int			 nsegs;
	int			 ret;

	dlfw = (struct psp_downloadfirmware *)sc->sc_cmd_kva;
	bzero(dlfw, sizeof(*dlfw));

	ret = ENOMEM;
	if (bus_dmamap_create(sc->sc_dmat, udlfw->fw_len, 1, udlfw->fw_len, 0,
	    BUS_DMA_WAITOK | BUS_DMA_ALLOCNOW | BUS_DMA_64BIT, &map) != 0)
		return (ret);
	if (bus_dmamem_alloc(sc->sc_dmat, udlfw->fw_len, 0, 0, &seg, 1,
	    &nsegs, BUS_DMA_WAITOK | BUS_DMA_ZERO) != 0 || nsegs != 1)
		goto fail_0;
	if (bus_dmamem_map(sc->sc_dmat, &seg, nsegs, udlfw->fw_len, &kva,
	    BUS_DMA_WAITOK) != 0)
		goto fail_1;
	if (bus_dmamap_load(sc->sc_dmat, map, kva, udlfw->fw_len, NULL,
	    BUS_DMA_WAITOK) != 0)
		goto fail_2;

	bcopy((void *)udlfw->fw_paddr, kva, udlfw->fw_len);

	dlfw->fw_paddr = map->dm_segs[0].ds_addr;
	dlfw->fw_len = map->dm_segs[0].ds_len;

	ret = ccp_docmd(sc, PSP_CMD_DOWNLOADFIRMWARE,
	    sc->sc_cmd_map->dm_segs[0].ds_addr);

	if (ret != 0)
		ret = EIO;

	bus_dmamap_unload(sc->sc_dmat, map);
fail_2:
	bus_dmamem_unmap(sc->sc_dmat, kva, udlfw->fw_len);
fail_1:
	bus_dmamem_free(sc->sc_dmat, &seg, 1);
fail_0:
	bus_dmamap_destroy(sc->sc_dmat, map);

	return (ret);
}

int
psp_guest_shutdown(struct psp_softc *sc, struct psp_guest_shutdown *ugshutdown)
{
	struct psp_deactivate	deact;
	struct psp_decommission	decom;
	int			ret;

	bzero(&deact, sizeof(deact));
	deact.handle = ugshutdown->handle;
	if ((ret = psp_deactivate(sc, &deact)) != 0)
		return (ret);

	if ((ret = psp_df_flush(sc)) != 0)
		return (ret);

	bzero(&decom, sizeof(decom));
	decom.handle = ugshutdown->handle;
	if ((ret = psp_decommission(sc, &decom)) != 0)
		return (ret);

	return (0);
}

int
psp_snp_get_pstatus(struct psp_softc *sc,
    struct psp_snp_platform_status *ustatus)
{
	struct psp_snp_platform_status *status;
	int			 ret;

	status = (struct psp_snp_platform_status *)sc->sc_cmd_kva;
	bzero(status, sizeof(*status));

	ret = ccp_docmd(sc, PSP_CMD_SNP_PLATFORMSTATUS,
	    sc->sc_cmd_map->dm_segs[0].ds_addr);

	if (ret != 0)
		return (EIO);

	bcopy(status, ustatus, sizeof(*ustatus));

	return (0);
}

int
pspopen(dev_t dev, int flag, int mode, struct proc *p)
{
	struct psp_softc *sc;

	sc = (struct psp_softc *)device_lookup(&psp_cd, minor(dev));
	if (sc == NULL)
		return (ENXIO);

	psp_load_ucode(sc);

	if (!(sc->sc_flags & PSPF_INITIALIZED))
		return (psp_reinit(sc));

	return (0);
}

int
pspclose(dev_t dev, int flag, int mode, struct proc *p)
{
	struct psp_softc *sc;

	sc = (struct psp_softc *)device_lookup(&psp_cd, minor(dev));
	if (sc == NULL)
		return (ENXIO);

	return (0);
}

int
pspioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
	struct psp_softc *sc;
	int ret;

	sc = (struct psp_softc *)device_lookup(&psp_cd, minor(dev));
	if (sc == NULL)
		return (ENXIO);

	KERNEL_UNLOCK();

	rw_enter_write(&sc->sc_lock);

	switch (cmd) {
	case PSP_IOC_INIT:
		ret = psp_reinit(sc);
		break;
	case PSP_IOC_SHUTDOWN:
		ret = psp_shutdown(sc);
		break;
	case PSP_IOC_GET_PSTATUS:
		ret = psp_get_pstatus(sc, (struct psp_platform_status *)data);
		break;
	case PSP_IOC_DF_FLUSH:
		ret = psp_df_flush(sc);
		break;
	case PSP_IOC_DECOMMISSION:
		ret = psp_decommission(sc, (struct psp_decommission *)data);
		break;
	case PSP_IOC_GET_GSTATUS:
		ret = psp_get_gstatus(sc, (struct psp_guest_status *)data);
		break;
	case PSP_IOC_LAUNCH_START:
		ret = psp_launch_start(sc, (struct psp_launch_start *)data);
		break;
	case PSP_IOC_LAUNCH_UPDATE_DATA:
		ret = psp_launch_update_data(sc,
		    (struct psp_launch_update_data *)data, p);
		break;
	case PSP_IOC_LAUNCH_MEASURE:
		ret = psp_launch_measure(sc, (struct psp_launch_measure *)data);
		break;
	case PSP_IOC_LAUNCH_FINISH:
		ret = psp_launch_finish(sc, (struct psp_launch_finish *)data);
		break;
	case PSP_IOC_ATTESTATION:
		ret = psp_attestation(sc, (struct psp_attestation *)data);
		break;
	case PSP_IOC_ACTIVATE:
		ret = psp_activate(sc, (struct psp_activate *)data);
		break;
	case PSP_IOC_DEACTIVATE:
		ret = psp_deactivate(sc, (struct psp_deactivate *)data);
		break;
	case PSP_IOC_GUEST_SHUTDOWN:
		ret = psp_guest_shutdown(sc, (struct psp_guest_shutdown *)data);
		break;
	case PSP_IOC_SNP_GET_PSTATUS:
		ret = psp_snp_get_pstatus(sc,
		    (struct psp_snp_platform_status *)data);
		break;
	default:
		ret = ENOTTY;
		break;
	}

	rw_exit_write(&sc->sc_lock);

	KERNEL_LOCK();

	return (ret);
}

int
pledge_ioctl_psp(struct proc *p, long com)
{
	switch (com) {
	case PSP_IOC_GET_PSTATUS:
	case PSP_IOC_DF_FLUSH:
	case PSP_IOC_GET_GSTATUS:
	case PSP_IOC_LAUNCH_START:
	case PSP_IOC_LAUNCH_UPDATE_DATA:
	case PSP_IOC_LAUNCH_MEASURE:
	case PSP_IOC_LAUNCH_FINISH:
	case PSP_IOC_ACTIVATE:
	case PSP_IOC_GUEST_SHUTDOWN:
		return (0);
	default:
		return (pledge_fail(p, EPERM, PLEDGE_VMM));
	}
}

int
pspprint(void *aux, const char *pnp)
{
	return QUIET;
}

int
pspsubmatch(struct device *parent, void *match, void *aux)
{
	struct psp_attach_args *arg = aux;
	struct cfdata *cf = match;

	if (!(arg->capabilities & PSP_CAP_SEV))
		return (0);
	return ((*cf->cf_attach->ca_match)(parent, cf, aux));
}

struct ucode {
	uint8_t		 family;
	uint8_t		 model;
	const char	*uname;
} const psp_ucode_table[] = {
	{ 0x17, 0x0, "amdsev/amd_sev_fam17h_model0xh.sbin" },
	{ 0x17, 0x3, "amdsev/amd_sev_fam17h_model3xh.sbin" },
	{ 0x19, 0x0, "amdsev/amd_sev_fam19h_model0xh.sbin" },
	{ 0x19, 0x1, "amdsev/amd_sev_fam19h_model1xh.sbin" },
	{ 0, 0, NULL }
};

void
psp_load_ucode(struct psp_softc *sc)
{
	struct psp_downloadfirmware dlfw;
	struct cpu_info		*ci = &cpu_info_primary;
	const struct ucode	*uc;
	uint8_t			 family, model;
	int			 error;

	if ((sc->sc_flags & PSPF_UCODELOADED) ||
	    (sc->sc_flags & PSPF_NOUCODE) ||
	    (sc->sc_flags & PSPF_INITIALIZED))
		return;

	family = ci->ci_family;
	model = (ci->ci_model & 0xf0) >> 4;

	for (uc = psp_ucode_table; uc->uname; uc++) {
		if ((uc->family == family) && (uc->model == model))
			break;
	}

	if (uc->uname == NULL) {
		printf("%s: no firmware found, CPU family 0x%x model 0x%x\n",
		    sc->sc_dev.dv_xname, family, model);
		sc->sc_flags |= PSPF_NOUCODE;
		return;
	}

	error = loadfirmware(uc->uname, &sc->sc_ucodebuf, &sc->sc_ucodelen);
	if (error) {
		if (error != ENOENT) {
			printf("%s: error %d, could not read firmware %s\n",
			    sc->sc_dev.dv_xname, error, uc->uname);
		}
		sc->sc_flags |= PSPF_NOUCODE;
		return;
	}

	bzero(&dlfw, sizeof(dlfw));
	dlfw.fw_len = sc->sc_ucodelen;
	dlfw.fw_paddr = (uint64_t)sc->sc_ucodebuf;

	if (psp_downloadfirmware(sc, &dlfw) < 0)
		goto out;

	sc->sc_flags |= PSPF_UCODELOADED;
out:
	if (sc->sc_ucodebuf) {
		free(sc->sc_ucodebuf, M_DEVBUF, sc->sc_ucodelen);
		sc->sc_ucodebuf = NULL;
		sc->sc_ucodelen = 0;
	}
}