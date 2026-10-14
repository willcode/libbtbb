/* -*- c -*- */
/*
 * Copyright 2007 - 2012 Mike Ryan, Dominic Spill, Michael Ossmann
 * Copyright 2005, 2006 Free Software Foundation, Inc.
 *
 * This file is part of libbtbb
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libbtbb; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */
#ifndef INCLUDED_BLUETOOTH_LE_PACKET_H
#define INCLUDED_BLUETOOTH_LE_PACKET_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Largest LE packet: access address (4) + header (2, or 3 with CTEInfo)
 * + payload (up to 255) + CRC (3).  A 3 byte header with a 255 byte
 * payload can't happen: data PDUs (the only ones with CTEInfo in the
 * header) are limited to 251 bytes. */
#define MAX_LE_SYMBOLS 264

/* number of bytes copied by the legacy lell_allocate_and_decode() */
#define LEGACY_LE_SYMBOLS 64

#define LE_ADV_AA 0x8E89BED6

/* Advertising physical channel PDU types (PDU header bits 0-3).  Types
 * 3, 5 and 7 have different names on the secondary advertising channels
 * (channel index 0-36). */
#define ADV_IND			0
#define ADV_DIRECT_IND	1
#define ADV_NONCONN_IND	2
#define SCAN_REQ		3
#define AUX_SCAN_REQ	3
#define SCAN_RSP		4
#define CONNECT_REQ		5	/* called CONNECT_IND since Bluetooth 5.0 */
#define CONNECT_IND		5
#define AUX_CONNECT_REQ	5
#define ADV_SCAN_IND	6
#define ADV_EXT_IND		7	/* AUX_ADV_IND, AUX_SCAN_RSP, AUX_SYNC_IND,
					   AUX_CHAIN_IND on secondary channels */
#define AUX_CONNECT_RSP	8

/* LL control PDU opcodes used by the library */
#define LL_CONNECTION_UPDATE_IND 0x00
#define LL_CHANNEL_MAP_IND       0x01
#define LL_TERMINATE_IND         0x02
#define LL_START_ENC_REQ         0x05
#define LL_PAUSE_ENC_RSP         0x0B
#define LL_PHY_UPDATE_IND        0x18

struct lell_packet {
	// raw unwhitened bytes of packet, including access address
	uint8_t symbols[MAX_LE_SYMBOLS];

	uint32_t access_address;

	// channel index
	uint8_t channel_idx;
	uint8_t channel_k;

	// PDU payload length from the PDU header (0-255)
	int length;

	uint32_t clk100ns;

	// advertising packet header info
	uint8_t adv_type;
	int adv_tx_add;
	int adv_rx_add;
	int adv_chsel;

	unsigned access_address_offenses;
	uint32_t refcount;

	// number of bytes of symbols[] actually captured (from the AA on)
	unsigned captured_len;

	// PDU header length: 2, or 3 for data PDUs carrying CTEInfo (CP=1)
	uint8_t header_len;

	// CTEInfo byte of data PDUs with CP=1
	uint8_t cte_info;

	// PHY the packet was received on: 0 = LE 1M, 1 = LE 2M, 2 = LE Coded
	uint8_t phy;

	// set by the capture device: 0 unknown, 1 master to slave, 2 slave to master
	uint8_t direction;

	// set by the capture device: 0 not checked, 1 bad, 2 valid
	uint8_t crc_status;

	/* flags */
	union {
		struct {
			uint32_t access_address_ok : 1;
			uint32_t is_data : 1;
			uint32_t encrypted : 1;
			uint32_t has_cte_info : 1;
		} as_bits;
		uint32_t as_word;
	} flags;
};

/* Number of bytes of the packet on the air, from the access address up
 * to and including the CRC. */
static inline unsigned le_pdu_total_len(const struct lell_packet *pkt)
{
	return 4 + pkt->header_len + pkt->length + 3;
}

/* Number of those bytes that were actually captured. */
static inline unsigned le_pdu_avail_len(const struct lell_packet *pkt)
{
	unsigned total = le_pdu_total_len(pkt);
	return pkt->captured_len < total ? pkt->captured_len : total;
}

/* Offset of the PDU payload in symbols[] */
static inline unsigned le_payload_offset(const struct lell_packet *pkt)
{
	return 4 + pkt->header_len;
}

/* Number of payload bytes that were captured (<= pkt->length) */
static inline unsigned le_payload_avail(const struct lell_packet *pkt)
{
	unsigned off = le_payload_offset(pkt);
	unsigned avail = pkt->captured_len > off ? pkt->captured_len - off : 0;
	return avail < (unsigned) pkt->length ? avail : (unsigned) pkt->length;
}

/* LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR PDU type (bits 7-9) and PHY (bits
 * 14-15) flags for a packet */
uint16_t le_phdr_flags(const struct lell_packet *pkt);

#endif /* INCLUDED_BLUETOOTH_LE_PACKET_H */
