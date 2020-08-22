/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2014 Hwanju Kim
 * Copyright (c) 2016 José Fernando Zazo Roll�
 * Copyright (c) 2016, 2017 Vincenzo Maffione
 * Copyright (c) 2016, 2017, 2019 Marcin Wójci
 * Copyright (c) 2020 Denis Salopek
 *
 * This software was developed by Stanford University and the University of
 * Cambridge Computer Laboratory under National Science Foundation under Grant
 * No. CNS-0855268, the University of Cambridge Computer Laboratory under EPSRC
 * INTERNET Project EP/H040536/1 and by the University of Cambridge Computer
 * Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"), as part of
 * the DARPA MRC research programme and under the SSICLOPS (grant agreement No.
 * 644866) project as part of the European Union's Horizon 2020 research and
 * innovation programme 2014-2018 and under EPSRC EARL project EP/P025374/1.
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: $");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/if_var.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <machine/bus.h>

#include "adapter.h"

/* SUME bus driver interface */
static int sume_probe(device_t);
static int sume_attach(device_t);
static int sume_detach(device_t);

static device_method_t sume_methods[] = {
	DEVMETHOD(device_probe,		sume_probe),
	DEVMETHOD(device_attach,	sume_attach),
	DEVMETHOD(device_detach,	sume_detach),
	DEVMETHOD_END
};

static driver_t sume_driver = {
	"sume",
	sume_methods,
	sizeof(struct sume_adapter)
};

/*
 * Internal registers
 * Every module in the SUME hardware has its own set of internal registers
 * (IDs, for debugging and statistic purposes, etc.). Their base addresses are
 * defined in 'contrib-projects/nic_v2/hw/tcl/nic_v2_defines.tcl' and the
 * offsets to different memory locations of every module are defined in their
 * corresponding folder inside the library. These registers can be RO/RW and
 * there is a special method to fetch/change this data by writing / reading to
 * / from special PCI register offsets.
 */

MALLOC_DECLARE(M_SUME);
MALLOC_DEFINE(M_SUME, "sume", "NetFPGA SUME nic_v2 device driver");

static int sume_uam_rx_refill(struct nf_uam_priv *);
static int sume_uam_rx_clean(struct nf_uam_priv *);
static void sume_uam_tx_clean(struct nf_uam_priv *);
static void sume_if_start_locked(struct ifnet *);
static void sume_uam_down(struct sume_adapter *, struct ifnet *);

static struct unrhdr *unr;

static struct {
	uint16_t device;
	char *desc;
} sume_pciids[] = {
	{PCI_DEVICE_ID_SUME, "NetFPGA SUME UAM"},
};

#if 0
static inline uint32_t
read_reg(struct sume_adapter *adapter, int offset)
{

	return (bus_space_read_4(adapter->bt0, adapter->bh0, offset));
}
#endif

static inline uint32_t
read_reg_bar2(struct sume_adapter *adapter, int offset)
{

	return (bus_space_read_4(adapter->bt2, adapter->bh2, offset));
}

static inline void
write_reg(struct sume_adapter *adapter, int offset, uint32_t val)
{

	bus_space_write_4(adapter->bt0, adapter->bh0, offset, val);
}

static inline void
write_reg_bar2(struct sume_adapter *adapter, int offset, uint32_t val)
{

	bus_space_write_4(adapter->bt2, adapter->bh2, offset, val);
}

static int
sume_probe(device_t dev)
{
	int i;
	uint16_t v = pci_get_vendor(dev);
	uint16_t d = pci_get_device(dev);

	if (v != PCI_VENDOR_ID_XILINX)
		return (ENXIO);

	for (i = 0; i < nitems(sume_pciids); i++) {
		if (d == sume_pciids[i].device) {
			device_set_desc(dev, sume_pciids[i].desc);
			return (BUS_PROBE_DEFAULT);
		}
	}

	return (ENXIO);
}

static void
sume_uam_intr_handler_tx(void *arg)
{
	//printf("TX interrrupt.\n");
	struct sume_adapter *adapter = arg;

        adapter->dma->dma_common_block.irq_enable = 1;
}

static void
sume_uam_intr_handler(void *arg)
{
	//printf("Got interrupt!\n");
	struct sume_adapter *adapter = arg;
	struct dma_engine *rx_engine;
	rx_engine = adapter->dma->dma_engine + DMA_ENG_RX;
	struct dma_descriptor *desc;
        struct desc_info *info;
        int n;
	int budget = NUM_DESCRIPTORS - 1;
	budget = adapter->rx_budget;
	struct ifnet *ifp = adapter->ifp[0];
	struct nf_uam_priv *nf_priv = ifp->if_softc;
	struct mbuf *m;
	uint64_t readlen;

	for (n = 0; (nf_priv->rx_ntc != rx_engine->head) && (n < budget); n++) {
		desc = rx_engine->dma_descriptor + nf_priv->rx_ntc;
		info = nf_priv->rx_desc_info + nf_priv->rx_ntc;

		memcpy(&readlen, &desc->size, 8);

		readlen -= SUME_METADATA_LEN; /* Subtract metadata length. */

		if (info->buf == NULL)
			continue;

		m = (struct mbuf *) info->buf;
		info->buf = NULL;

		struct nf_metadata *mdata = mtod(m, struct nf_metadata *);
		if (le16toh(mdata->magic) != 0xCAFE) {
			//printf ("no cafe %d\n", info->rb);
			m_freem(m);
			goto skip;
		}

		if (le16toh(mdata->plen) != readlen + sizeof(struct nf_metadata)) {
			//printf ("wrong size %d\n", info->rb);
			//printf ("le16toh(mdata->plen) %d\n", le16toh(mdata->plen));
			//printf ("readlen + 16 %lu\n", readlen + sizeof(struct nf_metadata));
			m_free(m);
			goto skip;
		}

		m->m_pkthdr.rcvif = ifp;
		m_adj(m, sizeof(struct nf_metadata));
		m->m_len = m->m_pkthdr.len = readlen;

		(*ifp->if_input)(ifp, m);

skip:
		nf_priv->rx_ntc = RING_NEXT_IDX(nf_priv->rx_ntc);
		sume_uam_rx_refill(nf_priv);
	}

	if (n) {
		int tmp = nf_priv->rx_ntc - nf_priv->rx_ntu;
		if (tmp < 0)
			tmp += NUM_DESCRIPTORS;

		adapter->rx_budget = NUM_DESCRIPTORS - tmp - 1;
		//printf("End with budget: %d\n", adapter->rx_budget);
	}

	write_reg(adapter, TAIL_RX_OFFSET, nf_priv->rx_ntu);

        adapter->dma->dma_common_block.irq_enable = 1;
}

static int
sume_intr_filter(void *arg)
{
	//printf("Got filter\n");
	struct sume_adapter *adapter = arg;

        adapter->dma->dma_common_block.irq_enable = 0;

	return (FILTER_SCHEDULE_THREAD);
}

static void
sume_free_ifp(struct sume_adapter *adapter)
{
	struct nf_uam_priv *nf_priv;
	struct ifnet *ifp;
	int i;

	for (i = 0; i < SUME_NPORTS; i++) {
		ifp = adapter->ifp[i];

		if (ifp == NULL)
			continue;

		sume_uam_down(adapter, ifp);

		ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
		nf_priv = ifp->if_softc;
		if (nf_priv != NULL) {
			if (ifp->if_flags & IFF_UP)
				if_down(ifp);
			ifmedia_removeall(&nf_priv->media);
			free_unr(unr, nf_priv->unit);
		}

		ifp->if_flags &= ~IFF_UP;
		ether_ifdetach(ifp);

		sume_uam_tx_clean(nf_priv);

		if (i == 0) {
			sume_uam_rx_clean(nf_priv);
		}

		if (nf_priv != NULL)
			free(nf_priv, M_SUME);
	}
}

/* If there is no sume_if_init, the ether_ioctl panics. */
static void
sume_if_init(void *sc)
{
}

static void
callback_dma(void *arg, bus_dma_segment_t *segs, int nseg, int err)
{
	if (err) {
		printf("DMA error\n");
		return;
	}

	KASSERT(nseg == 1, ("%s: %d segments returned!", __func__, nseg));

	*(bus_addr_t *) arg = segs[0].ds_addr;
}

#if 1
static void
sume_if_start(struct ifnet *ifp)
{
	struct nf_uam_priv *nf_priv = ifp->if_softc;
	struct sume_adapter *adapter = nf_priv->adapter;

	if (!(ifp->if_flags & IFF_UP))
		return;

	SUME_LOCK(adapter);
	sume_if_start_locked(ifp);
	SUME_UNLOCK(adapter);
}
#endif

/*
 * Packet to transmit. We take the packet data from the mbuf and copy it to the
 * descriptor assigned DMA address + 16. The 16 bytes before the packet data
 * are for metadata: sport/dport (depending on our source interface), packet
 * length and magic 0xcafe. We tell the SUME about the transfer, fill the first
 * 3*sizeof(uint32_t) bytes of the bouncebuffer with the information about the
 * start and length of the packet and trigger the transaction.
 */
static void
sume_if_start_locked(struct ifnet *ifp)
{
	struct mbuf *m;
	struct nf_uam_priv *nf_priv = ifp->if_softc;
	struct sume_adapter *adapter = nf_priv->adapter;
	struct nf_metadata *mdata;
	int plen = SUME_MIN_PKT_SIZE;
	struct dma_core *dma;
	struct dma_engine *tx_engine;
	struct dma_descriptor *desc;
	struct dma_descriptor *desc_base;
	struct desc_info *info;

	if (!(ifp->if_flags & IFF_UP))
		return;

	dma = adapter->dma;

	tx_engine = dma->dma_engine + DMA_ENG_TX;
	desc_base = tx_engine->dma_descriptor;

	IFQ_DEQUEUE(&ifp->if_snd, m);
	if (m == NULL)
		return;

tryagain:
	desc = desc_base + nf_priv->tx_ntu;
	info = nf_priv->tx_desc_info + nf_priv->tx_ntu;

	bus_dmamap_sync(adapter->my_tag, info->map,
	    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	/* Packets large enough do not need to be padded */
	if (m->m_pkthdr.len > SUME_MIN_PKT_SIZE)
		plen = m->m_pkthdr.len;

	mdata = (struct nf_metadata *) info->buf;

	/* Make sure we fit with the 16 bytes nf_metadata. */
	if ((m->m_pkthdr.len + sizeof(struct nf_metadata)) >
	    1560) { // ?
		device_printf(adapter->dev, "%s: Packet too big for bounce buffer "
		    "(%d)\n", __func__, m->m_pkthdr.len);
		m_freem(m);
		nf_priv->stats.tx_dropped++;
		return;
	}

	info->len = plen + sizeof(struct nf_metadata);

	/* Zero out the padded data */
	if (m->m_pkthdr.len < SUME_MIN_PKT_SIZE)
		bzero(info->buf + sizeof(struct nf_metadata), SUME_MIN_PKT_SIZE);
	/* Skip the first 16 bytes for the metadata. */
	m_copydata(m, 0, m->m_pkthdr.len, info->buf + sizeof(struct nf_metadata));
	m_freem(m);

	/* Fill in the metadata: CPU(DMA) ports are odd, MAC ports are even. */
	mdata->sport = htole16(1 << (nf_priv->port * 2 + 1));
	mdata->dport = htole16(1 << (nf_priv->port * 2));
	mdata->plen = htole16(info->len);
	mdata->magic = htole16(SUME_RIFFA_MAGIC);
	mdata->t1 = htole32(0);
	mdata->t2 = htole32(0);

	adapter->last_ifc = nf_priv->port;

	memcpy(&desc->size, &info->len, 8);

	bus_dmamap_sync(adapter->my_tag, info->map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	nf_priv->tx_ntu = RING_NEXT_IDX(nf_priv->tx_ntu);
	nf_priv->tx_ntc = RING_NEXT_IDX(nf_priv->tx_ntc);

	IFQ_DEQUEUE(&ifp->if_snd, m);
	if (m != NULL)
		goto tryagain;

	write_reg(adapter, TAIL_TX_OFFSET, RING_PREV_IDX(nf_priv->tx_ntu));
	
	nf_priv->stats.tx_packets++;
	nf_priv->stats.tx_bytes += plen;

	return;
}

static void
reset_core_dma(struct sume_adapter *adapter)
{
	char *tmp = (char *) adapter->dma->dma_engine + 2;
	struct dma_engine *engine = (struct dma_engine *) tmp;

	uint64_t val = -1;
	memcpy(engine, &val, sizeof(val));
}

static void
sume_uam_tx_clean(struct nf_uam_priv *nf_priv)
{
	struct sume_adapter *adapter = nf_priv->adapter;
	struct desc_info *info;
	int i;

	for (i = 0; i < NUM_DESCRIPTORS; i++) {
		info = nf_priv->tx_desc_info + i;
		if (info->buf) {
			bus_dmamem_free(adapter->my_tag, info->buf, info->map);
			bus_dmamap_unload(adapter->my_tag, info->map);
			bus_dmamap_destroy(adapter->my_tag, info->map);
			info->buf = NULL;
		}
	}
}

static int
sume_uam_rx_clean(struct nf_uam_priv *nf_priv)
{
	//printf("Start clean\n");
	struct sume_adapter *adapter = nf_priv->adapter;
	struct dma_engine *engine;
	struct dma_descriptor *desc;
	struct desc_info *info;
	struct mbuf *m;
	int n = 0;

	engine = adapter->dma->dma_engine + DMA_ENG_RX;
	do {
		desc = engine->dma_descriptor + nf_priv->rx_ntc;
		info = nf_priv->rx_desc_info + nf_priv->rx_ntc;

		if (info->buf) {
			//printf("Cleaning desc %d\n", info->rb);
			m = (struct mbuf *) info->buf;
			m_freem(m);
			info->buf = 0;
			bus_dmamap_unload(adapter->my_tag, info->map);
			bus_dmamap_destroy(adapter->my_tag, info->map);
			n++;
		}
	} while ((nf_priv->rx_ntc = RING_NEXT_IDX(nf_priv->rx_ntc)) != nf_priv->rx_ntu);

	bus_dmamap_unload(adapter->my_tag, adapter->my_map);
	bus_dmamap_destroy(adapter->my_tag, adapter->my_map);

	printf("End clean n = %d\n", n);
	return 0;
}

static int
sume_uam_tx_alloc(struct nf_uam_priv *nf_priv)
{
	struct desc_info *info;
	struct sume_adapter *adapter = nf_priv->adapter;
	int len = 1560; // ?
	int i, err;
	struct dma_descriptor *desc_base;
	struct dma_descriptor *desc;
	struct dma_engine *tx_engine;
	tx_engine = adapter->dma->dma_engine + DMA_ENG_TX;
	desc_base = tx_engine->dma_descriptor;

	for (i = 0; i < NUM_DESCRIPTORS; i++) {
		info = nf_priv->tx_desc_info + i;
		desc = desc_base + i;
		info->rb = i;
		if (!info->buf) {
			err = bus_dmamem_alloc(adapter->my_tag, (void **)
			    &info->buf, BUS_DMA_WAITOK | BUS_DMA_COHERENT |
			    BUS_DMA_ZERO, &info->map);
			if (err) {
				device_printf(adapter->dev, "%s: bus_dmamem_alloc "
				    "info->buf failed.\n", __func__);
				return (err);
			}

			bzero(info->buf, len);

			//info->buf = malloc(len, M_SUME, M_ZERO | M_WAITOK);
			if (!info->buf) {
				sume_uam_tx_clean(nf_priv);
				return (ENOMEM);
			}
			// DESK
			err = bus_dmamap_load(adapter->my_tag, info->map, info->buf, len,
			    callback_dma, &info->paddr, BUS_DMA_NOWAIT);
			if (err) {
				sume_uam_tx_clean(nf_priv);
				device_printf(adapter->dev, "%s: bus_dmamap_load "
				    "paddr failed.\n", __func__);
				return (err);
			}
			memcpy(&desc->address, &info->paddr, 8);
			desc->generate_irq = 1;
			bus_dmamap_sync(adapter->my_tag, info->map,
			    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		}
	}

	return (0);
}

static int
sume_uam_rx_refill(struct nf_uam_priv *nf_priv)
{
	//printf("Reffil start\n");
	struct sume_adapter *adapter = nf_priv->adapter;
	struct dma_descriptor *desc_base;
	struct dma_descriptor *desc;
	struct dma_engine *engine;
	struct desc_info *info;
	uint64_t len = 1600;
	int n = 0;
	int error = 0;
	struct mbuf *m;
	bus_dma_segment_t segs[1];
	int nseg;

	engine = adapter->dma->dma_engine + DMA_ENG_RX;
	desc_base = engine->dma_descriptor;
	do {
		desc = desc_base + nf_priv->rx_ntu;

		info = nf_priv->rx_desc_info + nf_priv->rx_ntu;
		info->rb = nf_priv->rx_ntu;

		bus_dmamap_sync(adapter->my_tag, info->map,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(adapter->my_tag, info->map);

		m = m_getcl(M_WAITOK, MT_DATA, M_PKTHDR);
		if (m == NULL) {
			printf("NOMEM\n");
			continue;
			return (ENOMEM);
		}

                info->len = len;
		info->buf = (char *) m;

		m->m_len = m->m_pkthdr.len = len;

		error = bus_dmamap_load_mbuf_sg(adapter->my_tag, info->map,
		    m, segs, &nseg, BUS_DMA_NOWAIT);
		if (error) {
			m_freem(m);
			device_printf(adapter->dev, "can't map mbuf error %d\n", error);
			return (ENOMEM);
		}

		if (nseg != 1) {
			m_freem(m);
			bus_dmamap_unload(adapter->my_tag, info->map);
			printf("nseg != 1\n");
			return (ENOMEM);
		}

		bus_dmamap_sync(adapter->my_tag, info->map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		info->paddr = segs->ds_addr;

		memcpy(&desc->address, &info->paddr, 8);
		memcpy(&desc->size, &info->len, 8);
                desc->generate_irq = 1;

                n++;

	} while ((nf_priv->rx_ntu = RING_NEXT_IDX(nf_priv->rx_ntu)) != nf_priv->rx_ntc);

	return (0);
}

static void
sume_uam_up(struct sume_adapter *adapter, struct ifnet *ifp)
{
	printf("UP\n");
	struct nf_uam_priv *nf_priv = ifp->if_softc;
	//char msix_name[32];
	int err; //, i;
	device_t dev = adapter->dev;

	/* Is this needed? */
	if (!pcie_flr(dev, max(pcie_get_max_completion_timeout(dev) / 1000, 10), true)) {
		device_printf(dev, "PCIE FLR failed\n");
		int ps = pci_get_powerstate(dev);
		if (ps != PCI_POWERSTATE_D0 && ps != PCI_POWERSTATE_D3)
			pci_set_powerstate(dev, PCI_POWERSTATE_D0);
		if (pci_get_powerstate(dev) != PCI_POWERSTATE_D3)
			pci_set_powerstate(dev, PCI_POWERSTATE_D3);
		pci_set_powerstate(dev, ps);
		//return;
	}

	reset_core_dma(adapter);

	memset(nf_priv->tx_desc_info, 0, sizeof(nf_priv->tx_desc_info));
	memset(nf_priv->rx_desc_info, 0, sizeof(nf_priv->rx_desc_info));

	err = bus_dmamap_create(adapter->my_tag, 0,
            &adapter->my_map);
        if (err != 0) {
                device_printf(dev,
                    "could not create Rx spare DMA map\n");
                return;
        }

	err = sume_uam_rx_refill(nf_priv);
	if (err) {
		device_printf(adapter->dev, "Failed to allocate RX buffers\n");
		return;
	}

	printf("rx_engine->head = %d\n", nf_priv->adapter->dma->dma_engine[0].head);
	printf("rx_engine->tail = %d\n", nf_priv->adapter->dma->dma_engine[0].tail);
	printf("tx_engine->head = %d\n", nf_priv->adapter->dma->dma_engine[1].head);
	printf("tx_engine->tail = %d\n", nf_priv->adapter->dma->dma_engine[1].tail);
	nf_priv->rx_ntu = nf_priv->adapter->dma->dma_engine[0].head;
	nf_priv->rx_ntc = RING_PREV_IDX(nf_priv->rx_ntu);
	nf_priv->tx_ntu = nf_priv->adapter->dma->dma_engine[1].head;
	nf_priv->tx_ntc = RING_PREV_IDX(nf_priv->tx_ntu);

	adapter->rx_budget = NUM_DESCRIPTORS - 1;

	err = sume_uam_tx_alloc(nf_priv);
	if (err) {
		device_printf(adapter->dev, "Failed to allocate TX buffers\n");
		sume_uam_rx_clean(nf_priv);
		return;
	}

	nf_priv->rx_ntc = nf_priv->adapter->dma->dma_engine[0].head;
	nf_priv->adapter->dma->dma_common_block.irq_enable = 1;
}

static void
sume_uam_down(struct sume_adapter *adapter, struct ifnet *ifp)
{
	printf("DOWN\n");
	struct nf_uam_priv *nf_priv = ifp->if_softc;

        nf_priv->adapter->dma->dma_common_block.irq_enable = 0;

        sume_uam_tx_clean(nf_priv);
        sume_uam_rx_clean(nf_priv);

	return;
}

static int
sume_if_ioctl(struct ifnet *ifp, unsigned long cmd, caddr_t data)
{
	struct nf_uam_priv *nf_priv = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *) data;
	struct sume_ifreq sifr;
	int error = 0;
	struct sume_adapter *adapter = nf_priv->adapter;
#if 0
	struct dma_engine *rx_engine = adapter->dma->dma_engine + DMA_ENG_RX;
	struct dma_engine *tx_engine = adapter->dma->dma_engine + DMA_ENG_TX;
#endif

	switch (cmd) {
	case SIOCGIFMEDIA:
	case SIOCGIFXMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &nf_priv->media, cmd);
		break;

	case SUME_IOCTL_CMD_WRITE_REG:
#if 0
	printf("rx_engine->head = %d\n", rx_engine->head);
	printf("rx_engine->tail = %d\n", rx_engine->tail);
	printf("tx_engine->head = %d\n", tx_engine->head);
	printf("tx_engine->tail = %d\n", tx_engine->tail);
	printf("nf_priv->rx_ntc = %d\n", nf_priv->rx_ntc);
	printf("nf_priv->rx_ntu = %d\n", nf_priv->rx_ntu);
	break;
#endif

		error = copyin(ifr_data_get_ptr(ifr), &sifr, sizeof(sifr));
		if (error) {
			error = EINVAL;
			break;
		}

		write_reg(adapter, BASE_ADDRESS_OFFSET, sifr.addr & BASE_ADDRESS_MASK);
                write_reg_bar2(adapter, sifr.addr & ~BASE_ADDRESS_MASK, sifr.val);

		break;

	case SUME_IOCTL_CMD_READ_REG:
		error = copyin(ifr_data_get_ptr(ifr), &sifr, sizeof(sifr));
		if (error) {
			error = EINVAL;
			break;
		}

		write_reg(adapter, BASE_ADDRESS_OFFSET, sifr.addr & BASE_ADDRESS_MASK);
                sifr.val = read_reg_bar2(adapter, sifr.addr & ~BASE_ADDRESS_MASK);

		error = copyout(&sifr, ifr_data_get_ptr(ifr), sizeof(sifr));
		if (error)
			error = EINVAL;


		break;

	case SIOCSIFFLAGS:
		if (!nf_priv->port_up && (ifp->if_flags & IFF_UP)) {
			sume_uam_up(adapter, ifp);
			nf_priv->port_up = 1;
		} else if (nf_priv->port_up && !(ifp->if_flags & IFF_UP)) {
			sume_uam_down(adapter, ifp);
			nf_priv->port_up = 0;
		}

	default:
		error = ether_ioctl(ifp, cmd, data);
		break;
	}

	return (error);
}

static int
sume_media_change(struct ifnet *ifp)
{
	struct nf_uam_priv *nf_priv = ifp->if_softc;
	struct ifmedia *ifm = &nf_priv->media;

	if (IFM_TYPE(ifm->ifm_media) != IFM_ETHER)
		return (EINVAL);

	if (IFM_SUBTYPE(ifm->ifm_media) == IFM_10G_SR)
		ifp->if_baudrate = ifmedia_baudrate(IFM_ETHER | IFM_10G_SR);
	else
		ifp->if_baudrate = ifmedia_baudrate(ifm->ifm_media);

	return (0);
}

static void
sume_media_status(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct nf_uam_priv *nf_priv = ifp->if_softc;
	struct ifmedia *ifm = &nf_priv->media;
	struct sume_adapter *adapter = nf_priv->adapter;
	struct sume_ifreq sifr;
	int link_status;

	if (ifm->ifm_cur->ifm_media == (IFM_ETHER | IFM_10G_SR) &&
	    (ifp->if_flags & IFF_UP))
		ifmr->ifm_active = IFM_ETHER | IFM_10G_SR;
	else
		ifmr->ifm_active = ifm->ifm_cur->ifm_media;

	ifmr->ifm_status |= IFM_AVALID;

	sifr.addr = SUME_NF_LINK_STATUS_ADDR(nf_priv->port);
	sifr.val = 0;

	write_reg(adapter, BASE_ADDRESS_OFFSET, sifr.addr & BASE_ADDRESS_MASK);
	sifr.val = read_reg_bar2(adapter, sifr.addr & ~BASE_ADDRESS_MASK);

	link_status = SUME_NF_LINK_STATUS(sifr.val);
	if (link_status)
		ifmr->ifm_status |= IFM_ACTIVE;
}

static int
sume_ifp_alloc(struct sume_adapter *adapter, uint32_t port)
{
	int error = 0;
	struct ifnet *ifp;
	struct nf_uam_priv *nf_priv = malloc(sizeof(struct nf_uam_priv), M_SUME,
	    M_ZERO | M_WAITOK);
	device_t dev = adapter->dev;

	ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		device_printf(dev, "Cannot allocate ifnet\n");
		error = ENOMEM;
		goto error;
	}

	adapter->ifp[port] = ifp;
	ifp->if_softc = nf_priv;

	nf_priv->unit = alloc_unr(unr);

	if_initname(ifp, SUME_ETH_DEVICE_NAME, nf_priv->unit);
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;

	ifp->if_init = sume_if_init;
	ifp->if_start = sume_if_start;
	ifp->if_ioctl = sume_if_ioctl;

	nf_priv->adapter = adapter;
	nf_priv->ifp = ifp;
	nf_priv->port = port;
	nf_priv->tx_ntu = 0;
	nf_priv->tx_ntc = 0;
	nf_priv->rx_ntu = 0;
	nf_priv->rx_ntc = 0;

	uint8_t hw_addr[ETHER_ADDR_LEN] = DEFAULT_ETHER_ADDRESS;
	hw_addr[ETHER_ADDR_LEN-1] = nf_priv->unit;
	ether_ifattach(ifp, hw_addr);

	ifmedia_init(&nf_priv->media, IFM_IMASK, sume_media_change,
	    sume_media_status);
	ifmedia_add(&nf_priv->media, IFM_ETHER | IFM_10G_SR, 0, NULL);
	ifmedia_set(&nf_priv->media, IFM_ETHER | IFM_10G_SR);

	ifp->if_drv_flags |= IFF_DRV_RUNNING;

	return (0);

error:
	return (error);
}

static int
sume_probe_riffa_pci(struct sume_adapter *adapter)
{
	device_t dev = adapter->dev;
	int i, error = 0, count, mps, read_req;

	/* 1. PCI device init. */
	mps = pci_get_max_payload(dev);
	if (mps != 128) {
		device_printf(dev, "MPS != 128 (%d)\n", mps);
		//return (ENXIO);
	}

	read_req = pci_set_max_read_req(dev, 4096);
	if (read_req != 4096) {
		device_printf(dev, "Cannot set max_read_req to 4096 (%d)\n",
		    read_req);
		return (ENXIO);
	}

	/* 2. create adapter & netdev and cross-link data structures. */
	for (i = 0; i < SUME_NPORTS; i++) {
		error = sume_ifp_alloc(adapter, i);
		if (error != 0)
			goto error;
	}

	pci_enable_busmaster(dev);

	/* Map BAR0, BAR1 and BAR2 memory regions. */
	adapter->rid0 = PCIR_BAR(0);
	adapter->bar0_addr = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &adapter->rid0, RF_ACTIVE);
	if (adapter->bar0_addr == NULL) {
		device_printf(dev, "Unable to allocate bus resource: "
		    "bar0_addr\n");
		error = ENXIO;
		goto error;
	}
	adapter->bt0 = rman_get_bustag(adapter->bar0_addr);
	adapter->bh0 = rman_get_bushandle(adapter->bar0_addr);
	adapter->bar0_len = rman_get_size(adapter->bar0_addr);
	if (adapter->bar0_len == 0) {
		device_printf(dev, "%s: bar0_len %lu != 1024\n", __func__,
		    adapter->bar0_len);
		error = ENXIO;
		goto error;
	}

#ifdef USE_BAR1
	adapter->rid1 = PCIR_BAR(1);
	printf("rid1 = %d\n", adapter->rid1);
	adapter->bar1_addr = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &adapter->rid1, RF_ACTIVE);
	if (adapter->bar1_addr == NULL) {
		device_printf(dev, "Unable to allocate bus resource: "
		    "bar1_addr\n");
		error = ENXIO;
		goto error;
	}
	adapter->bt1 = rman_get_bustag(adapter->bar1_addr);
	adapter->bh1 = rman_get_bushandle(adapter->bar1_addr);
	adapter->bar1_len = rman_get_size(adapter->bar1_addr);
	if (adapter->bar1_len == 0) {
		device_printf(dev, "%s: bar1_len %lu != 1024\n", __func__,
		    adapter->bar1_len);
		error = ENXIO;
		goto error;
	}
#endif

	adapter->rid2 = PCIR_BAR(2);
	adapter->bar2_addr = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &adapter->rid2, RF_ACTIVE);
	if (adapter->bar2_addr == NULL) {
		device_printf(dev, "Unable to allocate bus resource: "
		    "bar2_addr\n");
		error = ENXIO;
		goto error;
	}
	adapter->bt2 = rman_get_bustag(adapter->bar2_addr);
	adapter->bh2 = rman_get_bushandle(adapter->bar2_addr);
	adapter->bar2_len = rman_get_size(adapter->bar2_addr);
	if (adapter->bar2_len == 0) {
		device_printf(dev, "%s: bar2_len %lu != 1024\n", __func__,
		    adapter->bar2_len);
		error = ENXIO;
		goto error;
	}

	char *tmp = (char *) rman_get_virtual(adapter->bar0_addr) + (DMA_OFFSET * 8);
	adapter->dma = (struct dma_core *) tmp;

	/* Reset the descriptors. */
	for (i = 0; i < NUM_DMA_ENGINES; i++) {
                memset(adapter->dma->dma_engine[i].dma_descriptor, 0,
                       sizeof(adapter->dma->dma_engine[i].dma_descriptor));
        }

	/* 3. Init interrupts. */
	count = pci_msix_count(dev);
	error = pci_alloc_msix(dev, &count);
	if (error) {
		device_printf(dev, "Unable to allocate bus resource: PCI "
		    "MSI\n");
		error = ENXIO;
		goto error;
	}

	adapter->irq0.rid = 1; /* Should be 1, thus says pci_alloc_msi() */
	adapter->irq0.res = bus_alloc_resource_any(dev, SYS_RES_IRQ,
	    &adapter->irq0.rid, RF_SHAREABLE | RF_ACTIVE);
	if (adapter->irq0.res == NULL) {
		device_printf(dev, "Unable to allocate bus resource: IRQ "
		    "memory\n");
		error = ENXIO;
		goto error;
	}

	error = bus_setup_intr(dev, adapter->irq0.res, INTR_MPSAFE |
	    INTR_TYPE_NET, sume_intr_filter, sume_uam_intr_handler, adapter,
	    &adapter->irq0.tag);
	if (error) {
		device_printf(dev, "failed to setup interrupt for rid %d, name"
		    " %s: %d\n", adapter->irq0.rid, "SUME_INTR0", error);
		error = ENXIO;
		goto error;
	} else
		bus_describe_intr(dev, adapter->irq0.res, adapter->irq0.tag,
		    "%s", "SUME_INTR0");

	adapter->irq1.rid = 2; /* Should be 2, thus says pci_alloc_msi() */
	adapter->irq1.res = bus_alloc_resource_any(dev, SYS_RES_IRQ,
	    &adapter->irq1.rid, RF_SHAREABLE | RF_ACTIVE);
	if (adapter->irq1.res == NULL) {
		device_printf(dev, "Unable to allocate bus resource: IRQ "
		    "memory\n");
		error = ENXIO;
		goto error;
	}

	error = bus_setup_intr(dev, adapter->irq1.res, INTR_MPSAFE |
	    INTR_TYPE_NET, sume_intr_filter, sume_uam_intr_handler_tx, adapter,
	    &adapter->irq1.tag);
	if (error) {
		device_printf(dev, "failed to setup interrupt for rid %d, name"
		    " %s: %d\n", adapter->irq1.rid, "SUME_INTR2", error);
		error = ENXIO;
		goto error;
	} else
		bus_describe_intr(dev, adapter->irq1.res, adapter->irq1.tag,
		    "%s", "SUME_INTR2");

	return (0);

error:

	return (error);
}

static int
sume_prepare_dma(struct sume_adapter *adapter)
{
	device_t dev = adapter->dev;
	int err;

	err = bus_dma_tag_create(bus_get_dma_tag(dev),
	    PAGE_SIZE, 0,
	    BUS_SPACE_MAXADDR,
	    BUS_SPACE_MAXADDR,
	    NULL, NULL,
	    1600, // CHECK
	    1,
	    1600, // CHECK
	    0,
	    NULL,
	    NULL,
	    &adapter->my_tag);

	if (err) {
		device_printf(dev, "%s: bus_dma_tag_create) "
		    "failed.\n", __func__);
		return (err);
	}

	return (0);
}

#if 0
static void
sume_sysctl_init(struct sume_adapter *adapter)
{
	device_t dev = adapter->dev;
	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(dev);
	struct sysctl_oid *tree = device_get_sysctl_tree(dev);
	struct sysctl_oid_list *child = SYSCTL_CHILDREN(tree);
	struct sysctl_oid *tmp_tree;
	int i;

	tree = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, "sume", CTLFLAG_RW,
	    0, "SUME top-level tree");
	if (tree == NULL) {
		device_printf(dev, "SYSCTL_ADD_NODE failed.\n");
		return;
	}
	SYSCTL_ADD_INT(ctx, child, OID_AUTO, "debug", CTLFLAG_RW,
	    &adapter->sume_debug, 0, "debug int leaf");

	/* total RX error stats */
	SYSCTL_ADD_U64(ctx, child, OID_AUTO, "rx_epkts",
	    CTLFLAG_RD, &adapter->packets_err, 0, "rx errors");
	SYSCTL_ADD_U64(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "rx_ebytes",
	    CTLFLAG_RD, &adapter->bytes_err, 0, "rx errors");

#define	IFC_NAME_LEN 4
	char namebuf[IFC_NAME_LEN];

	for (i = SUME_NPORTS - 1; i >= 0; i--) {
		struct ifnet *ifp = adapter->ifp[i];
		if (ifp == NULL)
			continue;

		struct nf_priv *nf_priv = ifp->if_softc;

		snprintf(namebuf, IFC_NAME_LEN, "nf%d", nf_priv->unit);
		tmp_tree = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, namebuf,
		    CTLFLAG_RW, 0, "SUME ifc tree");
		if (tmp_tree == NULL) {
			device_printf(dev, "SYSCTL_ADD_NODE failed.\n");
			return;
		}

		/* RX stats */
		SYSCTL_ADD_U64(ctx, SYSCTL_CHILDREN(tmp_tree), OID_AUTO,
		    "rx_bytes", CTLFLAG_RD, &nf_priv->stats.rx_bytes, 0,
		    "rx bytes");
		SYSCTL_ADD_U64(ctx, SYSCTL_CHILDREN(tmp_tree), OID_AUTO,
		    "rx_dropped", CTLFLAG_RD, &nf_priv->stats.rx_dropped, 0,
		    "rx dropped");
		SYSCTL_ADD_U64(ctx, SYSCTL_CHILDREN(tmp_tree), OID_AUTO,
		    "rx_packets", CTLFLAG_RD, &nf_priv->stats.rx_packets, 0,
		    "rx packets");

		/* TX stats */
		SYSCTL_ADD_U64(ctx, SYSCTL_CHILDREN(tmp_tree), OID_AUTO,
		    "tx_bytes", CTLFLAG_RD, &nf_priv->stats.tx_bytes, 0,
		    "tx bytes");
		SYSCTL_ADD_U64(ctx, SYSCTL_CHILDREN(tmp_tree), OID_AUTO,
		    "tx_dropped", CTLFLAG_RD, &nf_priv->stats.tx_dropped, 0,
		    "tx dropped");
		SYSCTL_ADD_U64(ctx, SYSCTL_CHILDREN(tmp_tree), OID_AUTO,
		    "tx_packets", CTLFLAG_RD, &nf_priv->stats.tx_packets, 0,
		    "tx packets");
	}
}
#endif

static int
sume_attach(device_t dev)
{
	struct sume_adapter *adapter = device_get_softc(dev);
	adapter->dev = dev;
	int error;

	/* OK finish up RIFFA. */
	error = sume_probe_riffa_pci(adapter);
	if (error != 0)
		goto error;

	sume_prepare_dma(adapter);

	mtx_init(&adapter->lock, "Global lock", NULL, MTX_DEF);

	return (0);
error:
	sume_detach(dev);

	return (error);
}

static int
sume_detach(device_t dev)
{
	struct sume_adapter *adapter = device_get_softc(dev);
	sume_free_ifp(adapter);

	if (adapter->irq0.tag)
		bus_teardown_intr(dev, adapter->irq0.res, adapter->irq0.tag);
	if (adapter->irq0.res)
		bus_release_resource(dev, SYS_RES_IRQ, adapter->irq0.rid,
		    adapter->irq0.res);

	if (adapter->irq1.tag)
		bus_teardown_intr(dev, adapter->irq1.res, adapter->irq1.tag);
	if (adapter->irq1.res)
		bus_release_resource(dev, SYS_RES_IRQ, adapter->irq1.rid,
		    adapter->irq1.res);

	pci_release_msi(dev);

	bus_dma_tag_destroy(adapter->my_tag);

	if (adapter->bar0_addr)
		bus_release_resource(dev, SYS_RES_MEMORY, adapter->rid0,
		    adapter->bar0_addr);

	if (adapter->bar2_addr)
		bus_release_resource(dev, SYS_RES_MEMORY, adapter->rid2,
		    adapter->bar2_addr);

	mtx_destroy(&adapter->lock);

	return (0);
}

static int
mod_event(module_t mod, int cmd, void *arg)
{
	int rc = 0;

	switch (cmd) {
	case MOD_LOAD:
		unr = new_unrhdr(0, INT_MAX, NULL);
		break;

	case MOD_UNLOAD:
		delete_unrhdr(unr);
		break;
	}

	return (rc);
}
static devclass_t sume_devclass;

DRIVER_MODULE(sume, pci, sume_driver, sume_devclass, mod_event, 0);
MODULE_VERSION(sume, 1);
