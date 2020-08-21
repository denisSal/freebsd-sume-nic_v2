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
#include <sys/taskqueue.h>

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
static void sume_start_locked(struct ifnet *);
static void sume_uam_down(struct sume_adapter *, struct ifnet *);
static int sume_allocate_msix(struct nf_uam_priv *);
static void sume_free_tx_buffers(struct tx_ring *);
static void sume_free_rx_buffers(struct rx_ring *);
static void sume_txeof(struct tx_ring *);
static void sume_free_msix(struct nf_uam_priv *);
static void sume_free_spare(struct nf_uam_priv *);

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
sume_rxeof(struct rx_ring *rxr, int count)
{
	struct nf_uam_priv *nf_priv = rxr->nf_priv;
	struct ifnet *ifp = nf_priv->ifp;
	struct sume_adapter *adapter = nf_priv->adapter;
	struct dma_engine *rx_engine= adapter->dma->dma_engine + DMA_ENG_RX;
	struct dma_descriptor *rx_desc;
	struct desc_info *rxbuf;
	struct mbuf *m;
	struct nf_metadata *mdata;
	int rxdone = 0;
	uint64_t readlen;

	SUME_RX_LOCK(rxr);
	while (nf_priv->rx_ntc != rx_engine->head && count != 0) {
		//if (!(ifp->if_flags & IFF_UP))
			//break;

		//printf("got desc = %d\n", nf_priv->rx_ntc);
		rx_desc = &rxr->rx_base[nf_priv->rx_ntc];
		rxbuf = &rxr->rx_buffers[nf_priv->rx_ntc];
		//printf("RX %d\n", rxbuf->rb);

                //rx_desc->generate_irq = 0;
		readlen = rx_desc->size;
		readlen -= SUME_METADATA_LEN; /* Subtract metadata length. */

		//printf("got readlen = %lu\n", readlen);
		//bus_dmamap_sync(rxr->rxtag, rxbuf->map,
		    //BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		//bus_dmamap_unload(rxr->rxtag, rxbuf->map);

		m = (struct mbuf *) rxbuf->buf;

		--count;
		mdata = mtod(m, struct nf_metadata *);
		if (le16toh(mdata->magic) != 0xCAFE) {
			printf("no cafe %d\n", rxbuf->rb);
			m_freem(m);
			goto skip;
		}

		if (le16toh(mdata->plen) != readlen + sizeof(struct nf_metadata)) {
			printf("wrong size %d\n", rxbuf->rb);
			//printf("mdata->plen = %d\n", mdata->plen);
			//printf("readlen + 16 = %lu\n", readlen + 16);
			m_free(m);
			goto skip;
		}
		
		m->m_pkthdr.rcvif = ifp;
		m_adj(m, sizeof(struct nf_metadata));
		m->m_len = m->m_pkthdr.len = readlen;

		SUME_RX_UNLOCK(rxr);
		(*ifp->if_input)(ifp, m);
		//m_freem(m);
		SUME_RX_LOCK(rxr);

skip:
		rxbuf->buf = NULL;
		++rxdone;
		rxr->rx_avail--;
		nf_priv->rx_ntc = RING_NEXT_IDX(nf_priv->rx_ntc);
		if (count < 768) {
			sume_uam_rx_refill(nf_priv);
			write_reg(adapter, TAIL_RX_OFFSET, nf_priv->rx_ntc);
		}
	}

	if (rxdone) {
		if (rxr->rx_avail < 769)
			sume_uam_rx_refill(nf_priv);
		write_reg(adapter, TAIL_RX_OFFSET, nf_priv->rx_ntc);
	}

	SUME_RX_UNLOCK(rxr);
}

#if 0
static void
sume_msix_tx(void *arg)
{
	//return;
	struct tx_ring *txr = arg;
	//printf("TX interrrupt %lu.\n", txr->tx_irq + 1);
	//struct sume_adapter *adapter = txr->adapter;
	//struct nf_uam_priv *nf_priv = txr->nf_priv;
	//struct ifnet *ifp = nf_priv->ifp;

	++txr->tx_irq;
	SUME_TX_LOCK(txr);
	sume_txeof(txr);

	//sume_start_locked(ifp);

	SUME_TX_UNLOCK(txr);
}
#endif

static void
sume_msix_rx(void *arg)
{
	struct rx_ring *rxr = arg;
	//printf("RX interrrupt %lu.\n", rxr->rx_irq + 1);
	struct sume_adapter *adapter = rxr->adapter;
	struct nf_uam_priv *nf_priv = rxr->nf_priv;
	struct ifnet *ifp = nf_priv->ifp;

	++rxr->rx_irq;
	if (!(ifp->if_drv_flags & IFF_DRV_RUNNING))
		return;
	sume_rxeof(rxr, adapter->rx_process_limit);
}

static void
sume_free_ifp(struct sume_adapter *adapter)
{
	struct nf_uam_priv *nf_priv;
	struct ifnet *ifp;
	struct tx_ring *txr;
	struct rx_ring *rxr;
	int i;
	int rid;

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

		sume_free_msix(nf_priv);

		ifp->if_flags &= ~IFF_UP;
		ether_ifdetach(ifp);

		rxr = nf_priv->rxr;
		txr = nf_priv->txr;

		sume_free_tx_buffers(txr);
		sume_free_rx_buffers(rxr);

		if (rxr != NULL) {
			rid = rxr->msix + 1;
			if (mtx_initialized(&rxr->rx_mtx))
				mtx_destroy(&rxr->rx_mtx);
			if (rxr->rx_buffers)
				free(rxr->rx_buffers, M_SUME);
			free(rxr, M_SUME);
		}

		if (txr != NULL) {
			rid = txr->msix + 1;
			if (mtx_initialized(&txr->tx_mtx))
				mtx_destroy(&txr->tx_mtx);
			if (txr->tx_buffers)
				free(txr->tx_buffers, M_SUME);
			if (txr)
				free(txr, M_SUME);
		}

		sume_free_spare(nf_priv);

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
	if (err)
		return;

	KASSERT(nseg == 1, ("%s: %d segments returned!", __func__, nseg));

	*(bus_addr_t *) arg = segs[0].ds_addr;
}

static void
sume_if_start(struct ifnet *ifp)
{
	struct nf_uam_priv *nf_priv = ifp->if_softc;
	struct tx_ring *txr = nf_priv->txr;

	if (!(ifp->if_flags & IFF_UP))
		return;

	SUME_TX_LOCK(txr);
	sume_start_locked(ifp);
	SUME_TX_UNLOCK(txr);
}

static void
sume_txeof(struct tx_ring *txr)
{
	//printf("%s\n", __func__);
	struct nf_uam_priv *nf_priv = txr->nf_priv;
	//struct sume_adapter *adapter = nf_priv->adapter;
	int first, done, processed;
	struct desc_info *txbuf;
	struct dma_descriptor *tx_desc;
	int len = 1560;
	//len = MCLBYTES;

	if (txr->tx_avail == nf_priv->num_tx_desc) {
		txr->busy = 0;
		return;
	}

	processed = 0;
	first = nf_priv->tx_ntc;
	done = nf_priv->tx_ntu;

	while (first != done) {
		txbuf = &txr->tx_buffers[first];
		tx_desc = &txr->tx_base[first];
		++txr->tx_avail;
		++processed;
		if (!txbuf->buf) {
			bus_dmamap_sync(txr->txtag, txbuf->map,
			    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

			bzero(txbuf->buf, len);
			txbuf->len = len;
			tx_desc->size = txbuf->len;

			bus_dmamap_sync(txr->txtag, txbuf->map,
			    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		}
		first = RING_NEXT_IDX(first);
	}

	nf_priv->tx_ntc = first;

	if (processed == 0) {
		if (txr->busy != 10)
			++txr->busy;
	} else
		txr->busy = 1;

	if (txr->tx_avail == nf_priv->num_tx_desc)
		txr->busy = 0;
}

static void
sume_xmit(struct tx_ring *txr, struct mbuf **mp)
{
	//printf("%s\n", __func__);
	struct nf_uam_priv *nf_priv = txr->nf_priv;
	struct sume_adapter *adapter = nf_priv->adapter;
	struct mbuf *m;
	struct desc_info *txbuf;
	struct dma_descriptor *cur_txd = NULL;
	int plen = SUME_MIN_PKT_SIZE;
	struct nf_metadata *mdata;

	m = *mp;
	if (m->m_pkthdr.len > SUME_MIN_PKT_SIZE)
		plen = m->m_pkthdr.len;

	txbuf = &txr->tx_buffers[nf_priv->tx_ntu];
	cur_txd = &txr->tx_base[nf_priv->tx_ntu];

	bus_dmamap_sync(txr->txtag, txbuf->map,
	    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	mdata = (struct nf_metadata *) txbuf->buf;

	/* Make sure we fit with the 16 bytes nf_metadata. */
	if ((m->m_pkthdr.len + sizeof(struct nf_metadata)) >
	    1560) { // ?
		device_printf(adapter->dev, "%s: Packet too big for bounce buffer "
		    "(%d)\n", __func__, m->m_pkthdr.len);
		m_freem(m);
		nf_priv->stats.tx_dropped++;
		return;
	}

	//if (adapter->sume_debug)
		//printf("Sending %d bytes to nf%d\n", plen, nf_priv->unit);

	txbuf->len = plen + sizeof(struct nf_metadata);
	cur_txd->size = txbuf->len;

	/* Zero out the padded data */
	if (m->m_pkthdr.len < SUME_MIN_PKT_SIZE)
		bzero(txbuf->buf + sizeof(struct nf_metadata), SUME_MIN_PKT_SIZE);
	/* Skip the first 16 bytes for the metadata. */
	m_copydata(m, 0, m->m_pkthdr.len, txbuf->buf + sizeof(struct nf_metadata));
	m_freem(m);
	m = NULL;

	/* Fill in the metadata: CPU(DMA) ports are odd, MAC ports are even. */
	mdata->sport = htole16(1 << (nf_priv->port * 2 + 1));
	mdata->dport = htole16(1 << (nf_priv->port * 2));
	mdata->plen = htole16(txbuf->len);
	mdata->magic = htole16(SUME_RIFFA_MAGIC);
	mdata->t1 = htole32(0);
	mdata->t2 = htole32(0);

	nf_priv->tx_ntu = RING_NEXT_IDX(nf_priv->tx_ntu);

	txr->tx_avail--;

	bus_dmamap_sync(txr->txtag, txbuf->map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
}

static void
sume_msix_rxtx(void *arg)
{
	//printf("INTERRUPT\n");
	struct nf_uam_priv *nf_priv = arg;
	//struct tx_ring *txr = nf_priv->txr;
	struct rx_ring *rxr = nf_priv->rxr;
	struct sume_adapter *adapter = nf_priv->adapter;

        adapter->dma->dma_common_block.irq_enable = 0;
	sume_msix_rx(rxr);
	//sume_msix_tx(txr);
        adapter->dma->dma_common_block.irq_enable = 1;
}

#define	SUME_TX_CLEANUP_THRESH		NUM_DESCRIPTORS / 8

static void
sume_start_locked(struct ifnet *ifp)
{
	//printf("%s\n", __func__);
	struct nf_uam_priv *nf_priv = ifp->if_softc;
	struct sume_adapter *adapter = nf_priv->adapter;
	struct tx_ring *txr = nf_priv->txr;
	struct mbuf *m;

	do {
		if (txr->tx_avail <= SUME_TX_CLEANUP_THRESH)
			sume_txeof(txr);

		IFQ_DEQUEUE(&ifp->if_snd, m);
		if (m == NULL)
			break;

		sume_xmit(txr, &m);

		if (txr->busy == 0)
			txr->busy = 1;

		/* Send a copy of the frame to the BPF listener */
		//ETHER_BPF_MTAP(ifp, m);
	} while (m != NULL);

	//printf("Setting TX tail to %d\n", RING_PREV_IDX(nf_priv->tx_ntu));
	write_reg(adapter, TAIL_TX_OFFSET, RING_PREV_IDX(nf_priv->tx_ntu));
}

static void
reset_core_dma(struct sume_adapter *adapter)
{
	char *tmp = (char *) adapter->dma->dma_engine + 2;
	struct dma_engine *engine = (struct dma_engine *) tmp;

	uint64_t val = -1;
	memcpy(engine, &val, sizeof(val));
}

static int
sume_uam_rx_alloc(struct nf_uam_priv *nf_priv)
{
	struct sume_adapter *adapter = nf_priv->adapter;
	struct dma_descriptor *rx_desc;
	struct dma_engine *rx_engine;
	struct desc_info *rxbuf;
	uint64_t len = 1600;
	//len = MCLBYTES;
	int n = 0;
	int error = 0;
	struct mbuf *m;
	struct rx_ring *rxr = nf_priv->rxr;
	bus_dma_segment_t segs[1];
	int nseg;
	int i;

	if (nf_priv->port) {
		//printf("Only nf0 works.\n");
		return (EINVAL);;
	}

	rx_engine = adapter->dma->dma_engine + DMA_ENG_RX;
	rxr->rx_base = rx_engine->dma_descriptor;

	for (i = 0; i < NUM_DESCRIPTORS; i++) {
		rx_desc = rxr->rx_base + i;
		rxbuf = rxr->rx_buffers + i;
		rxbuf->rb = i;

		bus_dmamap_sync(rxr->rxtag, rxbuf->map,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		if (rxbuf->map)
			bus_dmamap_unload(rxr->rxtag, rxbuf->map);

		m = m_getjcl(M_WAITOK, MT_DATA, M_PKTHDR, MCLBYTES);
		if (m == NULL) {
			device_printf(adapter->dev, "NOMEM\n");
			continue;
		}

		rxbuf->len = m->m_len = m->m_pkthdr.len = len;

		error = bus_dmamap_load_mbuf_sg(rxr->rxtag, rxbuf->map,
		    m, segs, &nseg, BUS_DMA_WAITOK);
		if (error) {
			m_freem(m);
			device_printf(adapter->dev, "can't map mbuf error %d\n", error);
			return (ENOMEM);
		}

		if (nseg != 1) {
			m_freem(m);
			bus_dmamap_unload(rxr->rxtag, rxbuf->map);
			printf("nseg %d != 1\n", nseg);
			return (ENOMEM);
		}

		rxbuf->buf = (char *) m;

		bus_dmamap_sync(rxr->rxtag, rxbuf->map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		rxbuf->paddr = segs->ds_addr;

		//printf("rxbuf->buf = 0x%lx\n", (uint64_t) rxbuf->buf);
		//printf("rxbuf->paddr = 0x%lx\n", rxbuf->paddr);

		rx_desc->address = rxbuf->paddr;
		rx_desc->size = rxbuf->len;
		rx_desc->generate_irq = 1;

		n++;
	}

	return (0);
}

static int
sume_uam_tx_alloc(struct nf_uam_priv *nf_priv)
{
	struct desc_info *txbuf;
	struct sume_adapter *adapter = nf_priv->adapter;
	int len = 1560; // ?
	//len = MCLBYTES;
	int i, err;
	struct dma_descriptor *tx_desc;
	struct dma_engine *tx_engine;
	tx_engine = adapter->dma->dma_engine + DMA_ENG_TX;
	struct tx_ring *txr;

	if (nf_priv->port) {
		//printf("Only nf0 works.\n");
		return (EINVAL);;
	}

	txr = nf_priv->txr;
	txr->tx_base = tx_engine->dma_descriptor;

	for (i = 0; i < NUM_DESCRIPTORS; i++) {
		txbuf = txr->tx_buffers + i;
		tx_desc = txr->tx_base + i;
		txbuf->rb = i;
		if (!txbuf->buf) {
			err = bus_dmamem_alloc(txr->txtag, (void **)
			    &txbuf->buf, BUS_DMA_WAITOK | BUS_DMA_COHERENT |
			    BUS_DMA_ZERO, &txbuf->map);
			if (err) {
				device_printf(adapter->dev, "%s: bus_dmamem_alloc "
				    "txbuf->buf failed.\n", __func__);
				return (err);
			}

			bzero(txbuf->buf, len);

			if (!txbuf->buf) {
				sume_free_tx_buffers(txr);
				return (ENOMEM);
			}

			err = bus_dmamap_load(txr->txtag, txbuf->map, txbuf->buf, len,
			    callback_dma, &txbuf->paddr, BUS_DMA_NOWAIT);
			if (err) {
				sume_free_tx_buffers(txr);
				device_printf(adapter->dev, "%s: bus_dmamap_load "
				    "paddr failed.\n", __func__);
				return (err);
			}

			tx_desc->address = txbuf->paddr;

			tx_desc->generate_irq = 1;
			bus_dmamap_sync(txr->txtag, txbuf->map,
			    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		}
	}

	return (0);
}

static int
sume_uam_rx_refill(struct nf_uam_priv *nf_priv)
{
	struct sume_adapter *adapter = nf_priv->adapter;
	struct dma_descriptor *rx_desc;
	struct desc_info *rxbuf;
	uint64_t len = 1600;
	//len = MCLBYTES;
	int n = 0;
	int error = 0;
	struct mbuf *m;
	struct rx_ring *rxr = nf_priv->rxr;
	bus_dma_segment_t segs[1];
	int nseg;
	bus_dmamap_t map;

	if (nf_priv->port) {
		//printf("Only nf0 works.\n");
		return (EINVAL);;
	}

	do {
		rx_desc = rxr->rx_base + nf_priv->rx_ntu;
		rxbuf = rxr->rx_buffers + nf_priv->rx_ntu;

		//printf("Refilling %d\n", rxbuf->rb);
		//printf("old buf = 0x%lx\n", (uint64_t) rxbuf->buf);
		//printf("old paddr = 0x%lx\n", (uint64_t) rxbuf->paddr);

		//m = m_getjcl(M_USE_RESERVE | M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
		m = m_getjcl(M_WAITOK, MT_DATA, M_PKTHDR, MCLBYTES);
		if (m == NULL) {
			device_printf(adapter->dev, "No memory for mbuf\n");
			continue;
		}

		rxbuf->len = m->m_len = m->m_pkthdr.len = len;

		//if (rxbuf->buf != NULL) {
			//bus_dmamap_sync(rxr->rxtag, rxbuf->map, BUS_DMASYNC_POSTREAD);
			//bus_dmamap_unload(rxr->rxtag, rxbuf->map);
		//}

		//error = bus_dmamap_load_mbuf_sg(rxr->rxtag, rxbuf->map,
		    //m, segs, &nseg, BUS_DMA_NOWAIT);
		//error = bus_dmamap_load_mbuf_sg(rxr->rxtag, rxbuf->map,
		    //m, segs, &nseg, BUS_DMA_WAITOK | BUS_DMA_NOCACHE);

		//error = bus_dmamap_load_mbuf_sg(nf_priv->spare_tag, nf_priv->spare_map,
		    //m, segs, &nseg, BUS_DMA_WAITOK | BUS_DMA_NOCACHE);
		//error = bus_dmamap_load_mbuf_sg(rxr->rxtag, rxbuf->map,
		    //m, segs, &nseg, BUS_DMA_WAITOK);
		error = bus_dmamap_load_mbuf_sg(nf_priv->spare_tag, nf_priv->spare_map,
		    m, segs, &nseg, BUS_DMA_WAITOK);
		if (error) {
			m_freem(m);
			device_printf(adapter->dev, "can't map mbuf error %d\n", error);
			return (ENOMEM);
		}

#if 0
		if (nseg != 1) {
			m_freem(m);
			bus_dmamap_unload(rxr->rxtag, rxbuf->map);
			printf("nseg %d != 1\n", nseg);
			return (ENOMEM);
		}
#endif

		bus_dmamap_sync(rxr->rxtag, rxbuf->map,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(rxr->rxtag, rxbuf->map);

		map = rxbuf->map;
		rxbuf->map = nf_priv->spare_map;
		nf_priv->spare_map = map;

		rxbuf->buf = (char *) m;
		rxbuf->paddr = segs->ds_addr;

		//printf("new buf = 0x%lx\n", (uint64_t) rxbuf->buf);
		//printf("new paddr = 0x%lx\n", (uint64_t) rxbuf->paddr);

		bus_dmamap_sync(rxr->rxtag, rxbuf->map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		rx_desc->address = rxbuf->paddr;
		rx_desc->size = rxbuf->len;
                rx_desc->generate_irq = 1;

		rxr->rx_avail++;
                n++;
	} while ((nf_priv->rx_ntu = RING_NEXT_IDX(nf_priv->rx_ntu)) != nf_priv->rx_ntc);

	//if (n)
		//write_reg(adapter, TAIL_RX_OFFSET, nf_priv->rx_ntu);


	return (0);
}

static void
sume_uam_up(struct sume_adapter *adapter, struct ifnet *ifp)
{
	printf("UP\n");
	struct nf_uam_priv *nf_priv = ifp->if_softc;
	//int err; //, i;
	//device_t dev = adapter->dev;

	if (nf_priv->port) {
		printf("Only nf0 works.\n");
		return;
	}

#if 0
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
#endif

	nf_priv->rx_ntu = nf_priv->rx_ntc =
	    nf_priv->adapter->dma->dma_engine[DMA_ENG_RX].head;
	nf_priv->tx_ntu = nf_priv->tx_ntc =
	    nf_priv->adapter->dma->dma_engine[DMA_ENG_TX].head;

	printf("nf_priv->rx_ntu = %d\n", nf_priv->rx_ntu);
	printf("nf_priv->rx_ntc = %d\n", nf_priv->rx_ntc);
	printf("nf_priv->tx_ntu = %d\n", nf_priv->tx_ntu);
	printf("nf_priv->tx_ntc = %d\n", nf_priv->tx_ntc);

	adapter->rx_process_limit = NUM_DESCRIPTORS - 1;
	nf_priv->ctr = 0;

	nf_priv->adapter->dma->dma_common_block.irq_enable = 1;
}

static void
sume_uam_down(struct sume_adapter *adapter, struct ifnet *ifp)
{
	printf("DOWN\n");
	struct nf_uam_priv *nf_priv = ifp->if_softc;

	if (nf_priv->port) {
		//printf("Only nf0 works.\n");
		return;
	}

}

static int
sume_if_ioctl(struct ifnet *ifp, unsigned long cmd, caddr_t data)
{
	struct nf_uam_priv *nf_priv = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *) data;
	struct sume_ifreq sifr;
	int error = 0;
	struct sume_adapter *adapter = nf_priv->adapter;
#if 1
	struct dma_engine *rx_engine = adapter->dma->dma_engine + DMA_ENG_RX;
	struct dma_engine *tx_engine = adapter->dma->dma_engine + DMA_ENG_TX;
#endif

	switch (cmd) {
	case SIOCGIFMEDIA:
	case SIOCGIFXMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &nf_priv->media, cmd);
		break;

	case SUME_IOCTL_CMD_WRITE_REG:
#if 1
	//reset_core_dma(adapter);
	printf("Engines finished = 0x%x\n", adapter->dma->dma_common_block.engine_finished);
	printf("rx_engine->head = %d\n", rx_engine->head);
	printf("rx_engine->tail = %d\n", rx_engine->tail);
	printf("tx_engine->head = %d\n", tx_engine->head);
	printf("tx_engine->tail = %d\n", tx_engine->tail);
	printf("nf_priv->rx_ntc = %d\n", nf_priv->rx_ntc);
	printf("nf_priv->rx_ntu = %d\n", nf_priv->rx_ntu);
	//adapter->dma->dma_common_block.user_reset = 1;
	//printf("Engines finished = 0x%x\n", adapter->dma->dma_common_block.engine_finished);
	//printf("rx_engine->head = %d\n", rx_engine->head);
	//printf("rx_engine->tail = %d\n", rx_engine->tail);
	//printf("tx_engine->head = %d\n", tx_engine->head);
	//printf("tx_engine->tail = %d\n", tx_engine->tail);
	//printf("nf_priv->rx_ntc = %d\n", nf_priv->rx_ntc);
	//printf("nf_priv->rx_ntu = %d\n", nf_priv->rx_ntu);
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

static void
sume_free_rx_buffers(struct rx_ring *rxr)
{
	struct desc_info *rxbuf;
	struct nf_uam_priv *nf_priv = rxr->nf_priv;
	struct mbuf *m;
	int i;

	if (!rxr)
		return;

	for (i = 0; i < nf_priv->num_rx_desc; i++) {
		if (!rxr->rx_buffers)
			continue;
		rxbuf = &rxr->rx_buffers[i];
		if (!rxbuf)
			continue;

		m = (struct mbuf *) rxbuf->buf;
		if (m) {
			bus_dmamap_unload(rxr->rxtag, rxbuf->map);
			m_freem(m);
			rxbuf->buf = NULL;
			if (rxbuf->map) {
				bus_dmamap_destroy(rxr->rxtag, rxbuf->map);
				rxbuf->map = NULL;
			}
		} else if (rxbuf->map) {
			bus_dmamap_unload(rxr->rxtag, rxbuf->map);
			bus_dmamap_destroy(rxr->rxtag, rxbuf->map);
			rxbuf->map = NULL;
		}
	}

	if (rxr->rx_buffers) {
		free(rxr->rx_buffers, M_SUME);
		rxr->rx_buffers = NULL;
	}

	if (rxr->rxtag) {
		bus_dma_tag_destroy(rxr->rxtag);
		rxr->rxtag = NULL;
	}
}

static void
sume_free_tx_buffers(struct tx_ring *txr)
{
	struct desc_info *txbuf;
	struct nf_uam_priv *nf_priv = txr->nf_priv;
	int i;

	if (!txr)
		return;

	for (i = 0; i < nf_priv->num_tx_desc; i++) {
		if (!txr->tx_buffers)
			continue;
		txbuf = &txr->tx_buffers[i];
		if (!txbuf)
			continue;

		if (txbuf->buf) {
			bus_dmamap_unload(txr->txtag, txbuf->map);
			bus_dmamem_free(txr->txtag, txbuf->buf, txbuf->map);
			txbuf->buf = NULL;
			if (txbuf->map) {
				bus_dmamap_destroy(txr->txtag, txbuf->map);
				txbuf->map = NULL;
			}
		} else if (txbuf->map) {
			bus_dmamap_unload(txr->txtag, txbuf->map);
			bus_dmamap_destroy(txr->txtag, txbuf->map);
			txbuf->map = NULL;
		}
	}

	if (txr->tx_buffers) {
		free(txr->tx_buffers, M_SUME);
		txr->tx_buffers = NULL;
	}

	if (txr->txtag) {
		bus_dma_tag_destroy(txr->txtag);
		txr->txtag = NULL;
	}
}

static void
sume_free_spare(struct nf_uam_priv *nf_priv)
{
	if (nf_priv->spare_map) {
		bus_dmamap_unload(nf_priv->spare_tag, nf_priv->spare_map);
		bus_dmamap_destroy(nf_priv->spare_tag, nf_priv->spare_map);
		nf_priv->spare_map = NULL;
	}

	if (nf_priv->spare_tag) {
		bus_dma_tag_destroy(nf_priv->spare_tag);
		nf_priv->spare_tag = NULL;
	}
}

static int
sume_create_spare(struct nf_uam_priv *nf_priv)
{
	struct sume_adapter *adapter = nf_priv->adapter;
	device_t dev = adapter->dev;
	int error;
	int size = 1600;
	//size = MCLBYTES;

	error = bus_dma_tag_create(bus_get_dma_tag(dev),
	    1, 0,
	    BUS_SPACE_MAXADDR,
	    BUS_SPACE_MAXADDR,
	    NULL, NULL,
	    size,
	    1,
	    size,
	    0,
	    NULL,
	    NULL,
	    &nf_priv->spare_tag);

	if (error) {
		device_printf(dev, "%s: bus_dma_tag_create) "
		    "failed.\n", __func__);
		goto fail;
	}

	/* Create spare DMA map for RX buffers. */
        error = bus_dmamap_create(nf_priv->spare_tag, 0, &nf_priv->spare_map);
        if (error != 0) {
                device_printf(dev, "cannot create spare DMA map for RX.\n");
                goto fail;
        }

	return (0);
fail:
	sume_free_spare(nf_priv);

	return (error);

}

static int
sume_rx_buffers(struct rx_ring *rxr)
{
	struct sume_adapter *adapter = rxr->adapter;
	struct nf_uam_priv *nf_priv = rxr->nf_priv;
	device_t dev = adapter->dev;
	struct desc_info *rxbuf;
	int error;
	int size = 1600;
	//size = MCLBYTES;
	int i;

	error = bus_dma_tag_create(bus_get_dma_tag(dev),
	    1, 0,
	    BUS_SPACE_MAXADDR,
	    BUS_SPACE_MAXADDR,
	    NULL, NULL,
	    size * NUM_DESCRIPTORS,
	    1,
	    size,
	    0,
	    NULL,
	    NULL,
	    &rxr->rxtag);

	if (error) {
		device_printf(dev, "%s: bus_dma_tag_create) "
		    "failed.\n", __func__);
		goto fail;
	}

	if (!(rxr->rx_buffers = malloc(sizeof(struct desc_info) *
	    nf_priv->num_rx_desc, M_SUME, M_NOWAIT | M_ZERO))) {
		device_printf(dev, "NO TX_BUFFER");
		error = ENOMEM;
		goto fail;
	}

	rxbuf = &rxr->rx_buffers[0];
	for (i = 0; i < nf_priv->num_rx_desc; i++, rxbuf++) {
		error = bus_dmamap_create(rxr->rxtag, 0, &rxbuf->map);
		if (error) {
			device_printf(dev, "Unable to create TX DMA\n");
			goto fail;
		}
	}

	return (0);

fail:
	sume_free_rx_buffers(rxr);

	return (error);
}

static int
sume_tx_buffers(struct tx_ring *txr)
{
	struct sume_adapter *adapter = txr->adapter;
	struct nf_uam_priv *nf_priv = txr->nf_priv;
	device_t dev = adapter->dev;
	struct desc_info *txbuf;
	int error;
	int size = 1560;
	//size = MCLBYTES;
	int i;

	error = bus_dma_tag_create(bus_get_dma_tag(dev),
	    1, 0,
	    BUS_SPACE_MAXADDR,
	    BUS_SPACE_MAXADDR,
	    NULL, NULL,
	    size * NUM_DESCRIPTORS,
	    1,
	    size,
	    0,
	    NULL,
	    NULL,
	    &txr->txtag);

	if (error) {
		device_printf(dev, "%s: bus_dma_tag_create) "
		    "failed.\n", __func__);
		goto fail;
	}

	if (!(txr->tx_buffers = malloc(sizeof(struct desc_info) *
	    nf_priv->num_tx_desc, M_SUME, M_NOWAIT | M_ZERO))) {
		device_printf(dev, "NO TX_BUFFER");
		error = ENOMEM;
		goto fail;
	}

	txbuf = &txr->tx_buffers[0];
	for (i = 0; i < nf_priv->num_tx_desc; i++, txbuf++) {
		error = bus_dmamap_create(txr->txtag, 0, &txbuf->map);
		if (error) {
			device_printf(dev, "Unable to create TX DMA\n");
			goto fail;
		}
	}

	return (0);

fail:
	sume_free_tx_buffers(txr);

	return (error);
}

static int
sume_allocate_queues(struct nf_uam_priv *nf_priv)
{
	struct sume_adapter *adapter = nf_priv->adapter;
	device_t dev = adapter->dev;
	struct tx_ring *txr = NULL;
	struct rx_ring *rxr = NULL;
	int rtsize, error;

	if (nf_priv->port)
		return (0);

	if (!(nf_priv->txr = malloc(sizeof(struct tx_ring),
	    M_SUME, M_NOWAIT | M_ZERO))) {
		device_printf(dev, "Unable to allocate TX ring memory\n");
		error = ENOMEM;
		goto fail;
	}

	if (!(nf_priv->rxr = malloc(sizeof(struct rx_ring),
	    M_SUME, M_NOWAIT | M_ZERO))) {
		device_printf(dev, "Unable to allocate RX ring memory\n");
		error = ENOMEM;
		goto rx_fail;
	}

	error = sume_create_spare(nf_priv);
	if (error)
		goto rx_fail;

	rtsize = roundup2(NUM_DESCRIPTORS * sizeof(struct dma_descriptor), SUME_DBA_ALIGN);

	txr = nf_priv->txr;
	txr->nf_priv = nf_priv;
	txr->adapter = adapter;
	txr->me = nf_priv->port;
	txr->tx_avail = nf_priv->num_tx_desc;
	txr->busy = 0;

	error = sume_tx_buffers(txr);
	if (error)
		goto rx_fail;

	snprintf(txr->mtx_name, sizeof(txr->mtx_name), "%s:tx(%d)",
	    device_get_nameunit(dev), txr->me);
	mtx_init(&txr->tx_mtx, txr->mtx_name, NULL, MTX_DEF);

	rxr = nf_priv->rxr;
	rxr->nf_priv = nf_priv;
	rxr->adapter = adapter;
	rxr->me = nf_priv->port;
	rxr->rx_avail = nf_priv->num_rx_desc;

	error = sume_rx_buffers(rxr);
	if (error)
		goto rx_fail;

	snprintf(rxr->mtx_name, sizeof(txr->mtx_name), "%s:rx(%d)",
	    device_get_nameunit(dev), rxr->me);
	mtx_init(&rxr->rx_mtx, rxr->mtx_name, NULL, MTX_DEF);

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

	memset(txr->tx_buffers, 0, nf_priv->num_tx_desc * sizeof(struct desc_info));
	memset(rxr->rx_buffers, 0, nf_priv->num_rx_desc * sizeof(struct desc_info));

	error = sume_uam_tx_alloc(nf_priv);
	if (error) {
		device_printf(dev, "Failed to allocate TX buffers\n");
		goto rx_fail;
	}

	error = sume_uam_rx_alloc(nf_priv);
	if (error) {
		device_printf(dev, "Failed to allocate RX buffers\n");
		goto err_rx_desc;
	}

	return (0);

err_rx_desc:
	sume_free_rx_buffers(rxr);
rx_fail:
	free(nf_priv->txr, M_SUME);
fail:
	return (error);
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
	nf_priv->num_tx_desc = NUM_DESCRIPTORS;
	nf_priv->num_rx_desc = NUM_DESCRIPTORS;

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

static void
sume_free_msix(struct nf_uam_priv *nf_priv)
{
	struct sume_adapter *adapter = nf_priv->adapter;
	device_t dev = adapter->dev;
	struct tx_ring *txr = nf_priv->txr;
	struct rx_ring *rxr = nf_priv->rxr;
	int rid;

	if (nf_priv->port) {
		//printf("Only nf0 works.\n");
		return;
	}

	if (rxr != NULL) {
		rid = rxr->msix + 1;
		if (rxr->tag)
			bus_teardown_intr(dev, rxr->res, rxr->tag);
		if (rxr->res)
			bus_release_resource(dev, SYS_RES_IRQ, rid, rxr->res);
	}

	if (txr != NULL) {
		rid = txr->msix + 1;
		if (txr->tag)
			bus_teardown_intr(dev, txr->res, txr->tag);
		if (txr->res)
			bus_release_resource(dev, SYS_RES_IRQ, rid, txr->res);
	}
}

static int
sume_allocate_msix(struct nf_uam_priv *nf_priv)
{
	struct sume_adapter *adapter = nf_priv->adapter;
	device_t dev = adapter->dev;
	struct tx_ring *txr = nf_priv->txr;
	struct rx_ring *rxr = nf_priv->rxr;
	int port = nf_priv->port;
	int error;
	int rid;

	if (nf_priv->port) {
		//printf("Only nf0 works.\n");
		return (0);;
	}

	/* RX interrupts */
	rid = adapter->vector + 1;

	rxr->res = bus_alloc_resource_any(dev, SYS_RES_IRQ,
	    &rid, RF_ACTIVE);
	if (rxr->res == NULL) {
		device_printf(dev, "Unable to allocate bus resource: IRQ "
		    "memory for RX interrupt%d\n", port);
		error = ENXIO;
		goto error;
	}

	    //INTR_TYPE_NET, NULL, sume_msix_rx, rxr,
	if ((error = bus_setup_intr(dev, rxr->res, INTR_MPSAFE |
	    INTR_TYPE_NET, NULL, sume_msix_rxtx, nf_priv,
	    &rxr->tag)) != 0) {
		device_printf(dev, "Failed to setup interrupt for RX "
		    "rid %d, error %d\n", rid, error);
		goto error;
	}
	bus_describe_intr(dev, rxr->res, rxr->tag, "rx%d", port);

	rxr->msix = adapter->vector++;
	rxr->nf_priv = nf_priv;

	/* TX interrupts */
	rid = adapter->vector + 1;

	txr->res = bus_alloc_resource_any(dev, SYS_RES_IRQ,
	    &rid, RF_ACTIVE);
	if (txr->res == NULL) {
		device_printf(dev, "Unable to allocate bus resource: IRQ "
		    "memory for TX interrupt%d\n", port);
		error = ENXIO;
		goto error;
	}

	    //INTR_TYPE_NET, NULL, sume_msix_tx, txr,
	if ((error = bus_setup_intr(dev, txr->res, INTR_MPSAFE |
	    INTR_TYPE_NET, NULL, sume_msix_rxtx, nf_priv,
	    &txr->tag)) != 0) {
		device_printf(dev, "Failed to setup interrupt for TX "
		    "rid %d, error %d\n", rid, error);
		goto error;
	}

	bus_describe_intr(dev, txr->res, txr->tag, "tx%d", port);

	txr->msix = adapter->vector++;
	txr->nf_priv = nf_priv;

	return (0);

error:
	sume_free_msix(nf_priv);
	return (error);
}

static int
sume_setup_msix(struct sume_adapter *adapter)
{
	device_t dev = adapter->dev;
	int count, error;

	count = pci_msix_count(dev);
	error = pci_alloc_msix(dev, &count);
	if (error) {
		device_printf(dev, "Unable to allocate bus resource: PCI "
		    "MSI\n");
		return (ENXIO);
	}

	return (0);
}

static int
sume_probe_riffa_pci(struct sume_adapter *adapter)
{
	device_t dev = adapter->dev;
	int i, error = 0, mps, read_req;

	/* 1. PCI device init. */
	mps = pci_get_max_payload(dev);
	if (mps != 128) {
		device_printf(dev, "MPS != 128 (%d)\n", mps);
		//return (ENXIO); // ?
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
	error = sume_setup_msix(adapter);
	if (error)
		goto error;

	adapter->vector = 0;

	for (i = 0; i < SUME_NPORTS; i++) {
		struct nf_uam_priv *nf_priv = adapter->ifp[i]->if_softc;
		error = sume_allocate_queues(nf_priv);
		if (error)
			goto error;
		error = sume_allocate_msix(nf_priv);
		if (error) {
			device_printf(dev, "Failed to allocate MSIX, ifc down\n");
			sume_free_rx_buffers(nf_priv->rxr);
			sume_free_tx_buffers(nf_priv->txr);
			goto error;
		}
	}

	return (0);
error:

	return (error);
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

	mtx_init(&adapter->lock, "Global lock", NULL, MTX_DEF);

	/* OK finish up RIFFA. */
	error = sume_probe_riffa_pci(adapter);
	if (error != 0)
		goto error;

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

	pci_release_msi(dev);

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
