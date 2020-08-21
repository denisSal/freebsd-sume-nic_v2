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
 *
 * $FreeBSD$
 */

#define	PCI_VENDOR_ID_XILINX	0x10ee
#define	PCI_DEVICE_ID_SUME	0x7038

#define SUME_METADATA_LEN       16

#define	DEFAULT_ETHER_ADDRESS		"\02UUME\00"
#define	SUME_ETH_DEVICE_NAME		"nf"

#define	SUME_NPORTS			4

#define	SUME_IOCTL_CMD_WRITE_REG	(SIOCGPRIVATE_0)
#define	SUME_IOCTL_CMD_READ_REG		(SIOCGPRIVATE_1)

#define	SUME_LOCK(adapter)		mtx_lock(&adapter->lock);
#define	SUME_UNLOCK(adapter)		mtx_unlock(&adapter->lock);

/* Currently SUME only uses 2 fixed channels for all port traffic and regs. */
#define	SUME_RIFFA_CHANNEL_DATA		0
#define	SUME_RIFFA_CHANNEL_REG		1
#define	SUME_RIFFA_CHANNELS		2

/* RIFFA constants. */
#define	RIFFA_MAX_CHNLS			12
#define	RIFFA_MAX_BUS_WIDTH_PARAM	4
#define	RIFFA_SG_BUF_SIZE		(4*1024)
#define	RIFFA_SG_ELEMS			200

/* RIFFA register offsets. */
#define	RIFFA_RX_SG_LEN_REG_OFF		0x0
#define	RIFFA_RX_SG_ADDR_LO_REG_OFF	0x1
#define	RIFFA_RX_SG_ADDR_HI_REG_OFF	0x2
#define	RIFFA_RX_LEN_REG_OFF		0x3
#define	RIFFA_RX_OFFLAST_REG_OFF	0x4
#define	RIFFA_TX_SG_LEN_REG_OFF		0x5
#define	RIFFA_TX_SG_ADDR_LO_REG_OFF	0x6
#define	RIFFA_TX_SG_ADDR_HI_REG_OFF	0x7
#define	RIFFA_TX_LEN_REG_OFF		0x8
#define	RIFFA_TX_OFFLAST_REG_OFF	0x9
#define	RIFFA_INFO_REG_OFF		0xA
#define	RIFFA_IRQ_REG0_OFF		0xB
#define	RIFFA_IRQ_REG1_OFF		0xC
#define	RIFFA_RX_TNFR_LEN_REG_OFF	0xD
#define	RIFFA_TX_TNFR_LEN_REG_OFF	0xE

#define	RIFFA_CHNL_REG(c, o)		((c << 4) + o)

/*
 * RIFFA state machine;
 * rather than using complex circular buffers for 1 transaction.
 */
#define	SUME_RIFFA_CHAN_STATE_IDLE	0x01
#define	SUME_RIFFA_CHAN_STATE_READY	0x02
#define	SUME_RIFFA_CHAN_STATE_READ	0x04
#define	SUME_RIFFA_CHAN_STATE_LEN	0x08

#define	SUME_CHAN_STATE_RECOVERY_FLAG	0x80000000

/* Various bits and pieces. */
#define	SUME_RIFFA_MAGIC		0xcafe

/* Accessor macros. */
#define	SUME_OFFLAST			((0 << 1) | (1 & 0x01))
#define	SUME_RIFFA_LAST(offlast)	((offlast) & 0x01)
#define	SUME_RIFFA_OFFSET(offlast)	((uint64_t)((offlast) >> 1) << 2)
#define	SUME_RIFFA_LEN(len)		((uint64_t)(len) << 2)

#define	SUME_RIFFA_LO_ADDR(addr)	(addr & 0xFFFFFFFF)
#define	SUME_RIFFA_HI_ADDR(addr)	((addr >> 32) & 0xFFFFFFFF)

/* Vector bits. */
#define	SUME_MSI_RXQUE			(1 << 0)
#define	SUME_MSI_RXBUF			(1 << 1)
#define	SUME_MSI_RXDONE			(1 << 2)
#define	SUME_MSI_TXBUF			(1 << 3)
#define	SUME_MSI_TXDONE			(1 << 4)

/* Invalid vector. */
#define	SUME_INVALID_VECT		0xc0000000

#define	SUME_DPORT_MASK			0xaa

#define	SUME_MIN_PKT_SIZE		(ETHER_MIN_LEN - ETHER_CRC_LEN)

#define	SUME_NF_LINK_STATUS_ADDR(port)	(0x44040048 + port * 0x10000)
#define	SUME_NF_LINK_STATUS(val)	((val >> 12) & 0x1)

//#define	USE_BAR1

/* Maximum number of DMA engines in the DEVICE:
 *   0 -> Card2System (C2S)
 *   1 -> System2Card (S2C)
 */
#define NUM_DMA_ENGINES   2
#define DMA_ENG_RX    0
#define DMA_ENG_TX    1

#define	NUM_DESCRIPTORS			1024

/* Offset in 64bit words between engines in the HDL design. */
#define OFFSET_BETWEEN_ENGINES  0x2000
/* Initial offset in the BAR0 to the DMA registers.
 *  At DMA_OFFSET                          dma_engine[0]
 *  At DMA_OFFSET+OFFSET_BETWEEN_ENGINES   dma_engine[1]
 *               ...
 *               ...
 *               ...
 *  At DMA_OFFSET+i*OFFSET_BETWEEN_ENGINES dma_engine[i]
 *  At DMA_OFFSET+NUM_DMA_ENGINES*OFFSET_BETWEEN_ENGINES:  dma_common_block
*/
#define DMA_OFFSET              0x200
#define BASE_ADDRESS_OFFSET              0x1FF
#define BASE_ADDRESS ((BASE_ADDRESS_OFFSET)*8)

#define	RING_NEXT_IDX(_idx) \
    ((_idx) + 1 == NUM_DESCRIPTORS ? 0 : (_idx) + 1)

#define	RING_PREV_IDX(_idx) \
    ((_idx) == 0 ? NUM_DESCRIPTORS - 1 : (_idx) - 1)

#define	TAIL_RX_OFFSET ((DMA_OFFSET+OFFSET_BETWEEN_ENGINES*DMA_ENG_RX)*8+8)
#define	TAIL_TX_OFFSET ((DMA_OFFSET+OFFSET_BETWEEN_ENGINES*DMA_ENG_TX)*8+8)

#define	AXI4LITE_MASK 0x000FFFFF
#define	BASE_ADDRESS_MASK ~AXI4LITE_MASK

struct dma_descriptor {
  uint64_t  address;
  uint64_t  size;
  uint64_t  generate_irq : 1;
  uint64_t  u0           : 63;
  uint64_t  u1;
} __attribute__ ((__packed__));

struct dma_engine {
  /* Enable bit, used tell the hardware that descriptors are ready. */
  uint64_t  enable : 1;
  /* Reset the state machines for this engine. */
  uint64_t  reset  : 1;
  uint64_t  irq_enable: 1;
  uint64_t  u0     : 61;
  /* Next descriptor to be prepared by software.
   * Written by software, read by hardware. */
  uint64_t  tail : 10;
  uint64_t  u1 : 6;
  /* Next descriptor to be processed by hardware.
   * Written by hardware, read by software. */
  uint64_t  head : 10;
  uint64_t  u2 : 38;
  /* On read: time that was consumed during the previous operation.
   * On write: Maximum timeout for a C2S operation. */
  uint64_t  total_time;
  uint64_t  total_bytes; /* Read only. */
  struct dma_descriptor  dma_descriptor[NUM_DESCRIPTORS];
  uint64_t u4[OFFSET_BETWEEN_ENGINES - 4 -
         NUM_DESCRIPTORS * sizeof(struct dma_descriptor) / 8];
	
} __attribute__ ((__packed__));

struct dma_common_block {
  /* The maximum payload size being used by the DMA core.
   * This size may be different than the system-programmed Max Payload
         * The size is expressed as: 2^{max_payload} * 128 bytes. Common examples:
         *           · 000 = 128  Bytes
         *           · 001 = 256  Bytes
         *           · 010 = 512  Bytes
         *           · 011 = 1024 Bytes
         *           · 100 = 2048 Bytes
         *           · 101 = 4096 Bytes
   */
  uint64_t max_payload : 3;
  /* The read request size being used by the DMA core.
         * This size may be different than the system-programmed Max Read Request
         * The size is expressed as: 2^{max_payload} * 128 bytes. Common examples:
         *           · 000 = 128  Bytes
         *           · 001 = 256  Bytes
         *           · 010 = 512  Bytes
         *           · 011 = 1024 Bytes
         *           · 100 = 2048 Bytes
         *           · 101 = 4096 Bytes
   */
  uint64_t max_read_request : 3;
  /* Global DMA Interrupt Enable, to globally enable/disable
   * interrupts. */
  uint64_t irq_enable  : 1;
  uint64_t user_reset  : 1;
  /* Bitmask of engines that have completed the operation, useful for
   * polling. */
  uint64_t engine_finished : 16;
  uint64_t u0 : 32;
} __attribute__ ((__packed__));

struct dma_core {
  struct dma_engine       dma_engine[NUM_DMA_ENGINES];
  struct dma_common_block dma_common_block;
} __attribute__ ((__packed__));

struct desc_info {
	bus_addr_t		paddr;
	bus_dma_tag_t		tag;
	bus_dmamap_t		map;
	bus_dmamap_t		my_map;
	uint64_t len;
	char *buf;
	int rb;
};

struct nf_stats {
	uint64_t		rx_packets;
	uint64_t		rx_dropped;
	uint64_t		rx_bytes;
	uint64_t		tx_packets;
	uint64_t		tx_dropped;
	uint64_t		tx_bytes;
};

struct nf_uam_priv {
	struct sume_adapter *adapter;
	struct ifnet *ifp;
	uint32_t port;

	uint32_t tx_ntu;
	uint32_t tx_ntc;

	uint32_t rx_ntu;
	uint32_t rx_ntc;

	struct desc_info tx_desc_info[NUM_DESCRIPTORS];
	struct desc_info rx_desc_info[NUM_DESCRIPTORS];

	//struct napi_struct napi;

	/* MY */
	struct ifmedia		media;
	uint32_t		unit;
	uint32_t		port_up;
	uint32_t		last_head;
	struct nf_stats		stats;
};
/********/

struct irq {
	struct resource		*res;
	uint32_t		rid;
	void			*tag;
} __aligned(CACHE_LINE_SIZE);

struct riffa_chnl_dir {
	char			*buf_addr;	/* bouncebuf addresses+len. */
	bus_addr_t		buf_hw_addr;	/* -- " -- mapped. */
	uint32_t		num_sg;
	uint32_t		state;
	uint32_t		flags;
	uint32_t		offlast;
	uint32_t		len;		/* words */
	uint32_t		rtag;

	bus_dma_tag_t		my_tag;
	bus_dmamap_t		my_map;

	/* Used only for register read/write */
	uint32_t		event;
};

struct sume_ifreq {
	uint32_t		addr;
	uint32_t		val;
};

struct nf_priv {
	struct sume_adapter	*adapter;
	struct ifnet		*ifp;
	uint32_t		unit;
	uint32_t		port;
	uint32_t		riffa_channel;
	struct ifmedia		media;
	struct nf_stats		stats;
};

struct sume_adapter {
	device_t		dev;
	uint32_t		rid0;
	struct resource		*bar0_addr;
	bus_size_t		bar0_len;
	bus_space_tag_t		bt0;
	bus_space_handle_t	bh0;
#ifdef USE_BAR1
	uint32_t		rid1;
	struct resource		*bar1_addr;
	bus_size_t		bar1_len;
	bus_space_tag_t		bt1;
	bus_space_handle_t	bh1;
#endif
	uint32_t		rid2;
	struct resource		*bar2_addr;
	bus_size_t		bar2_len;
	bus_space_tag_t		bt2;
	bus_space_handle_t	bh2;

	struct irq		irq0;
	struct irq		irq1;

	uint32_t		num_chnls;
	uint32_t		num_sg;
	uint32_t		sg_buf_size;
	uint32_t		running;
	struct ifnet		*ifp[4];
	struct mtx		lock;

	uint32_t		last_ifc;

	uint64_t		packets_err;
	uint64_t		bytes_err;
	uint32_t		sume_debug;

	/* MY */
	struct dma_core		*dma;
	bus_dma_tag_t		my_tag;
	bus_dmamap_t		my_map;

	uint32_t		rx_budget;
};

/* SUME metadata:
 * sport - not used for RX. For TX, set to 0x02, 0x08, 0x20, 0x80, depending on
 *     the sending interface (nf0, nf1, nf2 or nf3).
 * dport - For RX, is set to 0x02, 0x08, 0x20, 0x80, depending on the receiving
 *     interface (nf0, nf1, nf2 or nf3). For TX, set to 0x01, 0x04, 0x10, 0x40,
 *     depending on the sending HW interface (nf0, nf1, nf2 or nf3).
 * plen - length of the send/receive packet data (in bytes)
 * magic - SUME hardcoded magic number which should be 0xcafe
 * t1, t1 - could be used for timestamping by SUME
 */
struct nf_metadata {
	uint16_t		sport;
	uint16_t		dport;
	uint16_t		plen;
	uint16_t		magic;
	uint32_t		t1;
	uint32_t		t2;
};

/* Used for ioctl communication with the rwaxi program used to read/write SUME
 *    internally defined register data.
 * addr - address of the SUME module register to read/write
 * val - value to write/read to/from the register
 * rtag - returned on read: transaction tag, for syncronization
 * strb - 0x1f when writing, 0x00 for reading
 */
struct nf_regop_data {
	uint32_t		addr;
	uint32_t		val;
	uint32_t		rtag;
	uint32_t		strb;
};

/* Our bouncebuffer "descriptor". This holds our physical address (lower and
 * upper values) of the beginning of the DMA data to RX/TX. The len is number
 * of words to transmit.
 */
struct nf_bb_desc {
	uint32_t		lower;
	uint32_t		upper;
	uint32_t		len;
};
