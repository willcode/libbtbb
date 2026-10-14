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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "btbb.h"
#include "bluetooth_le_packet.h"
#include "uthash.h"
#include <ctype.h>
#include <string.h>

/* company identifier lookup */
const char *bt_compidtostr(uint16_t compid);

/* string representations of advertising packet type (primary channels) */
static const char *ADV_TYPE_NAMES[] = {
	"ADV_IND", "ADV_DIRECT_IND", "ADV_NONCONN_IND", "SCAN_REQ",
	"SCAN_RSP", "CONNECT_IND", "ADV_SCAN_IND", "ADV_EXT_IND",
};

/* source clock accuracy in a connect packet */
static const char *CONNECT_SCA[] = {
	"251 ppm to 500 ppm", "151 ppm to 250 ppm", "101 ppm to 150 ppm",
	"76 ppm to 100 ppm", "51 ppm to 75 ppm", "31 ppm to 50 ppm",
	"21 ppm to 30 ppm", "0 ppm to 20 ppm",
};

/* flags */
static const char *FLAGS[] = {
	"LE Limited Discoverable Mode", "LE General Discoverable Mode",
	"BR/EDR Not Supported",
	"Simultaneous LE and BR/EDR to Same Device Capable (Controller)",
	"Simultaneous LE and BR/EDR to Same Device Capable (Host)",
	"Reserved", "Reserved", "Reserved",
};

/* LL control PDU opcodes, Core Specification 5.3 Vol 6 Part B 2.4.2 */
static const char *LL_OPCODE_NAMES[] = {
	"LL_CONNECTION_UPDATE_IND",	/* 0x00 */
	"LL_CHANNEL_MAP_IND",		/* 0x01 */
	"LL_TERMINATE_IND",		/* 0x02 */
	"LL_ENC_REQ",			/* 0x03 */
	"LL_ENC_RSP",			/* 0x04 */
	"LL_START_ENC_REQ",		/* 0x05 */
	"LL_START_ENC_RSP",		/* 0x06 */
	"LL_UNKNOWN_RSP",		/* 0x07 */
	"LL_FEATURE_REQ",		/* 0x08 */
	"LL_FEATURE_RSP",		/* 0x09 */
	"LL_PAUSE_ENC_REQ",		/* 0x0A */
	"LL_PAUSE_ENC_RSP",		/* 0x0B */
	"LL_VERSION_IND",		/* 0x0C */
	"LL_REJECT_IND",		/* 0x0D */
	"LL_PERIPHERAL_FEATURE_REQ",	/* 0x0E */
	"LL_CONNECTION_PARAM_REQ",	/* 0x0F */
	"LL_CONNECTION_PARAM_RSP",	/* 0x10 */
	"LL_REJECT_EXT_IND",		/* 0x11 */
	"LL_PING_REQ",			/* 0x12 */
	"LL_PING_RSP",			/* 0x13 */
	"LL_LENGTH_REQ",		/* 0x14 */
	"LL_LENGTH_RSP",		/* 0x15 */
	"LL_PHY_REQ",			/* 0x16 */
	"LL_PHY_RSP",			/* 0x17 */
	"LL_PHY_UPDATE_IND",		/* 0x18 */
	"LL_MIN_USED_CHANNELS_IND",	/* 0x19 */
	"LL_CTE_REQ",			/* 0x1A */
	"LL_CTE_RSP",			/* 0x1B */
	"LL_PERIODIC_SYNC_IND",		/* 0x1C */
	"LL_CLOCK_ACCURACY_REQ",	/* 0x1D */
	"LL_CLOCK_ACCURACY_RSP",	/* 0x1E */
	"LL_CIS_REQ",			/* 0x1F */
	"LL_CIS_RSP",			/* 0x20 */
	"LL_CIS_IND",			/* 0x21 */
	"LL_CIS_TERMINATE_IND",		/* 0x22 */
	"LL_POWER_CONTROL_REQ",		/* 0x23 */
	"LL_POWER_CONTROL_RSP",		/* 0x24 */
	"LL_POWER_CHANGE_IND",		/* 0x25 */
	"LL_SUBRATE_REQ",		/* 0x26 */
	"LL_SUBRATE_IND",		/* 0x27 */
	"LL_CHANNEL_REPORTING_IND",	/* 0x28 */
	"LL_CHANNEL_STATUS_IND",	/* 0x29 */
};

static const char *PHY_NAMES[] = { "LE 1M", "LE 2M", "LE Coded", "Reserved" };

// count of objects in an array, shamelessly stolen from Chrome
#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

static uint16_t le16(const uint8_t *b)
{
	return (uint16_t) (b[0] | (b[1] << 8));
}

static uint32_t le24(const uint8_t *b)
{
	return (uint32_t) b[0] | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16);
}

static uint32_t le32(const uint8_t *b)
{
	return le24(b) | ((uint32_t) b[3] << 24);
}

static uint8_t count_bits(uint32_t n)
{
	uint8_t i = 0;
	for (i = 0; n != 0; i++)
		n &= n - 1;
	return i;
}

static int aa_access_channel_off_by_one(const uint32_t aa) {
	int retval = 0;
	if(count_bits(aa ^ LE_ADV_AA) == 1) {
		retval = 1;
	}
	return retval;
}

/* transitions within a byte, given the previous bit was 0 / 1 */
static const uint8_t EIGHT_BIT_TRANSITIONS_EVEN[256] = {
	0, 2, 2, 2, 2, 4, 2, 2, 2, 4, 4, 4, 2, 4, 2, 2,
	2, 4, 4, 4, 4, 6, 4, 4, 2, 4, 4, 4, 2, 4, 2, 2,
	2, 4, 4, 4, 4, 6, 4, 4, 4, 6, 6, 6, 4, 6, 4, 4,
	2, 4, 4, 4, 4, 6, 4, 4, 2, 4, 4, 4, 2, 4, 2, 2,
	2, 4, 4, 4, 4, 6, 4, 4, 4, 6, 6, 6, 4, 6, 4, 4,
	4, 6, 6, 6, 6, 8, 6, 6, 4, 6, 6, 6, 4, 6, 4, 4,
	2, 4, 4, 4, 4, 6, 4, 4, 4, 6, 6, 6, 4, 6, 4, 4,
	2, 4, 4, 4, 4, 6, 4, 4, 2, 4, 4, 4, 2, 4, 2, 2,
	1, 3, 3, 3, 3, 5, 3, 3, 3, 5, 5, 5, 3, 5, 3, 3,
	3, 5, 5, 5, 5, 7, 5, 5, 3, 5, 5, 5, 3, 5, 3, 3,
	3, 5, 5, 5, 5, 7, 5, 5, 5, 7, 7, 7, 5, 7, 5, 5,
	3, 5, 5, 5, 5, 7, 5, 5, 3, 5, 5, 5, 3, 5, 3, 3,
	1, 3, 3, 3, 3, 5, 3, 3, 3, 5, 5, 5, 3, 5, 3, 3,
	3, 5, 5, 5, 5, 7, 5, 5, 3, 5, 5, 5, 3, 5, 3, 3,
	1, 3, 3, 3, 3, 5, 3, 3, 3, 5, 5, 5, 3, 5, 3, 3,
	1, 3, 3, 3, 3, 5, 3, 3, 1, 3, 3, 3, 1, 3, 1, 1
};

static const uint8_t EIGHT_BIT_TRANSITIONS_ODD[256] = {
	1, 1, 3, 1, 3, 3, 3, 1, 3, 3, 5, 3, 3, 3, 3, 1,
	3, 3, 5, 3, 5, 5, 5, 3, 3, 3, 5, 3, 3, 3, 3, 1,
	3, 3, 5, 3, 5, 5, 5, 3, 5, 5, 7, 5, 5, 5, 5, 3,
	3, 3, 5, 3, 5, 5, 5, 3, 3, 3, 5, 3, 3, 3, 3, 1,
	3, 3, 5, 3, 5, 5, 5, 3, 5, 5, 7, 5, 5, 5, 5, 3,
	5, 5, 7, 5, 7, 7, 7, 5, 5, 5, 7, 5, 5, 5, 5, 3,
	3, 3, 5, 3, 5, 5, 5, 3, 5, 5, 7, 5, 5, 5, 5, 3,
	3, 3, 5, 3, 5, 5, 5, 3, 3, 3, 5, 3, 3, 3, 3, 1,
	2, 2, 4, 2, 4, 4, 4, 2, 4, 4, 6, 4, 4, 4, 4, 2,
	4, 4, 6, 4, 6, 6, 6, 4, 4, 4, 6, 4, 4, 4, 4, 2,
	4, 4, 6, 4, 6, 6, 6, 4, 6, 6, 8, 6, 6, 6, 6, 4,
	4, 4, 6, 4, 6, 6, 6, 4, 4, 4, 6, 4, 4, 4, 4, 2,
	2, 2, 4, 2, 4, 4, 4, 2, 4, 4, 6, 4, 4, 4, 4, 2,
	4, 4, 6, 4, 6, 6, 6, 4, 4, 4, 6, 4, 4, 4, 4, 2,
	2, 2, 4, 2, 4, 4, 4, 2, 4, 4, 6, 4, 4, 4, 4, 2,
	2, 2, 4, 2, 4, 4, 4, 2, 2, 2, 4, 2, 2, 2, 2, 0
};

/* six most significant bits of the AA with at least two transitions */
static const uint8_t AA_MSB6_ALLOWED[64] = {
	0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0
};

/*
 * A helper function for filtering bogus packets on data channels.
 *
 * If a candidate capture packet is random noise we would expect its
 * Access Address to be a randomly distributed 32-bit number.  An
 * exhaustive software analysis reveals that of 4294967296 possible
 * 32-bit Access Address values, 2900629660 (67.5%) are acceptable and
 * 1394337636 (32.5%) are invalid.  This function will identify which
 * category a candidate Access Address falls into by returning the
 * number of offenses contained.
 *
 * Refer to BT 4.x, Vol 6, Par B, Section 2.1.2.
 *
 * The Access Address in data channel packets meet the
 * following requirements:
 *  - It shall have no more than six consecutive zeros or ones.
 *  - It shall not be the advertising channel packets’ Access Address.
 *  - It shall not be a sequence that differs from the advertising channel packets’
 *    Access Address by only one bit.
 *  - It shall not have all four octets equal.
 *  - It shall have no more than 24 transitions.
 *  - It shall have a minimum of two transitions in the most significant six bits.
 */
static int aa_data_channel_offenses(const uint32_t aa) {
	int retval = 0, transitions = 0;
	unsigned shift, odd = (unsigned) (aa & 1);
	uint8_t aab3, aab2, aab1, aab0 = (uint8_t) (aa & 0xff);

	transitions += (odd ? EIGHT_BIT_TRANSITIONS_ODD[aab0] : EIGHT_BIT_TRANSITIONS_EVEN[aab0] );
	odd = (unsigned) (aab0 & 0x80);
	aab1 = (uint8_t) (aa >> 8);
	transitions += (odd ? EIGHT_BIT_TRANSITIONS_ODD[aab1] : EIGHT_BIT_TRANSITIONS_EVEN[aab1] );
	odd = (unsigned) (aab1 & 0x80);
	aab2 = (uint8_t) (aa >> 16);
	transitions += (odd ? EIGHT_BIT_TRANSITIONS_ODD[aab2] : EIGHT_BIT_TRANSITIONS_EVEN[aab2] );
	odd = (unsigned) (aab2 & 0x80);
	aab3 = (uint8_t) (aa >> 24);
	transitions += (odd ? EIGHT_BIT_TRANSITIONS_ODD[aab3] : EIGHT_BIT_TRANSITIONS_EVEN[aab3] );

	/* consider excessive transitions as offenses */
	if (transitions > 24) {
		retval += (transitions - 24);
	}

	/* consider excessive transitions in the 6 MSBs as an offense */
	retval += (1 - AA_MSB6_ALLOWED[aab3>>2]);

	/* consider all bytes as being equal an offense */
	retval += (((aab0 == aab1) && (aab0 == aab2) && (aab0 == aab3)) ? 1 : 0);

	/* access-channel address and off-by-ones are illegal */
	retval += ((aa == LE_ADV_AA) ? 1 : 0);
	retval += aa_access_channel_off_by_one(aa);

	/* inspect nibble triples for insufficient bit transitions */
	for(shift=0; shift<=20; shift+=4) {
		uint16_t twelvebits = (uint16_t) ((aa >> shift) & 0xfff);
		switch( twelvebits ) {
			/* seven consecutive zeroes */
		case 0x080: case 0x180: case 0x280: case 0x380: case 0x480:
		case 0x580: case 0x680: case 0x780: case 0x880: case 0x980:
		case 0xa80: case 0xb80: case 0xc80: case 0xd80: case 0xe80:
		case 0xf80: case 0x101: case 0x301: case 0x501: case 0x701:
		case 0x901: case 0xb01: case 0xd01: case 0xf01: case 0x202:
		case 0x602: case 0xa02: case 0xe02: case 0x203: case 0x603:
		case 0xa03: case 0xe03: case 0x404: case 0xc04: case 0x405:
		case 0xc05: case 0x406: case 0xc06: case 0x407: case 0xc07:
		case 0x808: case 0x809: case 0x80a: case 0x80b: case 0x80c:
		case 0x80d: case 0x80e: case 0x80f: case 0x010: case 0x011:
		case 0x012: case 0x013: case 0x014: case 0x015: case 0x016:
		case 0x017: case 0x018: case 0x019: case 0x01a: case 0x01b:
		case 0x01c: case 0x01d: case 0x01e: case 0x01f:
			/* eight consecutive zeroes */
		case 0x100: case 0x300: case 0x500: case 0x700: case 0x900:
		case 0xb00: case 0xd00: case 0xf00: case 0x201: case 0x601:
		case 0xa01: case 0xe01: case 0x402: case 0xc02: case 0x403:
		case 0xc03: case 0x804: case 0x805: case 0x806: case 0x807:
		case 0x008: case 0x009: case 0x00a: case 0x00b: case 0x00c:
		case 0x00d: case 0x00e: case 0x00f:
			/* nine consecutive zeroes */
		case 0xe00: case 0xc01: case 0x802: case 0x803: case 0x004:
		case 0x005: case 0x006: case 0x007:
			/* ten consecutive zeroes */
		case 0x400: case 0xc00: case 0x801: case 0x002: case 0x003:
			/* eleven consecutive zeroes */
		case 0x800: case 0x001:
			/* twelve consecutive zeroes */
		case 0x000:
			/* seven consecutive ones */
		case 0x07f: case 0x0fe: case 0x2fe: case 0x4fe: case 0x6fe:
		case 0x8fe: case 0xafe: case 0xcfe: case 0xefe: case 0x1fc:
		case 0x5fc: case 0x9fc: case 0xdfc: case 0x1fd: case 0x5fd:
		case 0x9fd: case 0xdfd: case 0x3f8: case 0xbf8: case 0x3f9:
		case 0xbf9: case 0x3fa: case 0xbfa: case 0x3fb: case 0xbfb:
		case 0x7f4: case 0x7f5: case 0x7f6: case 0x7f7: case 0xfe0:
			/* eight consecutive ones */
		case 0x0ff: case 0x2ff: case 0x4ff: case 0x6ff: case 0x8ff:
		case 0xaff: case 0xcff: case 0xeff: case 0x1fe: case 0x5fe:
		case 0x9fe: case 0xdfe: case 0x3fc: case 0xbfc: case 0x3fd:
		case 0xbfd: case 0x7f8: case 0x7f9: case 0x7fa: case 0x7fb:
		case 0xff0: case 0xff1: case 0xff2: case 0xff3: case 0xff4:
		case 0xff5: case 0xff6: case 0xff7:
			/* nine consecutive ones */
		case 0x1ff: case 0x5ff: case 0x9ff: case 0xdff: case 0x3fe:
		case 0xbfe: case 0x7fc: case 0x7fd: case 0xff8: case 0xff9:
		case 0xffa: case 0xffb:
			/* ten consecutive ones */
		case 0x3ff: case 0xbff: case 0x7fe: case 0xffc: case 0xffd:
			/* eleven consecutive ones */
		case 0x7ff: case 0xffe:
			/* all ones */
		case 0xfff:
			retval++;
			break;
		default:
			break;
		}
	}

	return retval;
}

lell_packet *
lell_packet_new(void)
{
	lell_packet *pkt = (lell_packet *)calloc(1, sizeof(lell_packet));
	if (pkt) {
		pkt->refcount = 1;
		pkt->header_len = 2;
	}
	return pkt;
}

void
lell_packet_ref(lell_packet *pkt)
{
	pkt->refcount++;
}

void
lell_packet_unref(lell_packet *pkt)
{
	pkt->refcount--;
	if (pkt->refcount == 0)
		free(pkt);
}

static uint8_t le_channel_index(uint16_t phys_channel) {
	uint8_t ret;
	if (phys_channel == 2402) {
		ret = 37;
	} else if (phys_channel < 2426) { // 0 - 10
		ret = (phys_channel >= 2404) ? (phys_channel - 2404) / 2 : 0;
	} else if (phys_channel == 2426) {
		ret = 38;
	} else if (phys_channel < 2480) { // 11 - 36
		ret = 11 + (phys_channel - 2428) / 2;
	} else {
		ret = 39;
	}
	return ret;
}

int lell_allocate_and_decode_len(const uint8_t *stream, size_t len,
				 uint16_t phys_channel, uint32_t clk100ns,
				 lell_packet **pkt)
{
	lell_packet *p;
	const uint8_t *s;
	size_t n;

	if (pkt == NULL)
		return -1;
	*pkt = p = lell_packet_new();
	if (p == NULL)
		return -1;

	/* bytes not captured stay zero */
	n = (stream == NULL) ? 0 : (len < MAX_LE_SYMBOLS ? len : MAX_LE_SYMBOLS);
	if (n)
		memcpy(p->symbols, stream, n);
	p->captured_len = (unsigned) n;
	s = p->symbols;

	p->channel_idx = le_channel_index(phys_channel);
	p->channel_k = (phys_channel >= 2402) ? (phys_channel - 2402) / 2 : 0;
	p->clk100ns = clk100ns;

	p->access_address = le32(&s[0]);
	p->header_len = 2;
	/* 8 bit Length field: data PDUs since Bluetooth 4.2, advertising
	 * PDUs since 5.0 */
	p->length = s[5];

	/* The access address decides: the secondary advertising channels
	 * (0-36) also carry AUX_* advertising PDUs, which use the
	 * advertising AA.  An AA one bit away from it can't be a data
	 * channel AA, so it is an advertising PDU with a bit error.  The
	 * primary channels (37-39) carry nothing but advertising PDUs. */
	if (p->channel_idx >= 37 || p->access_address == LE_ADV_AA ||
	    aa_access_channel_off_by_one(p->access_address)) {
		// advertising PDU
		p->flags.as_bits.is_data = 0;
		p->adv_type = s[4] & 0xf;
		p->adv_chsel = (s[4] >> 5) & 1;
		p->adv_tx_add = s[4] & 0x40 ? 1 : 0;
		p->adv_rx_add = s[4] & 0x80 ? 1 : 0;
		p->flags.as_bits.access_address_ok = (p->access_address == LE_ADV_AA);
		p->access_address_offenses = p->flags.as_bits.access_address_ok ? 0 :
			(aa_access_channel_off_by_one(p->access_address) ? 1 : 32);
	} else {
		// data PDU
		p->flags.as_bits.is_data = 1;
		p->access_address_offenses = aa_data_channel_offenses(p->access_address);
		p->flags.as_bits.access_address_ok = p->access_address_offenses ? 0 : 1;
		/* CP bit: a CTEInfo byte follows the Length byte */
		if (s[4] & 0x20) {
			p->flags.as_bits.has_cte_info = 1;
			p->header_len = 3;
			p->cte_info = s[6];
		}
	}
	return 0;
}

void lell_allocate_and_decode(const uint8_t *stream, uint16_t phys_channel, uint32_t clk100ns, lell_packet **pkt)
{
	(void) lell_allocate_and_decode_len(stream, LEGACY_LE_SYMBOLS,
					    phys_channel, clk100ns, pkt);
}

unsigned lell_packet_is_data(const lell_packet *pkt)
{
	return (unsigned) pkt->flags.as_bits.is_data;
}

uint32_t lell_get_access_address(const lell_packet *pkt)
{
	return pkt->access_address;
}

unsigned lell_get_access_address_offenses(const lell_packet *pkt)
{
	return pkt->access_address_offenses;
}

unsigned lell_get_channel_index(const lell_packet *pkt)
{
	return pkt->channel_idx;
}

unsigned lell_get_channel_k(const lell_packet *pkt)
{
	return pkt->channel_k;
}

unsigned lell_get_length(const lell_packet *pkt)
{
	return (unsigned) pkt->length;
}

unsigned lell_get_captured_length(const lell_packet *pkt)
{
	return pkt->captured_len;
}

int lell_packet_is_truncated(const lell_packet *pkt)
{
	return pkt->captured_len < le_pdu_total_len(pkt);
}

int lell_get_chsel(const lell_packet *pkt)
{
	if (lell_packet_is_data(pkt) || pkt->channel_idx < 37)
		return -1;
	switch (pkt->adv_type) {
	case ADV_IND:
	case ADV_DIRECT_IND:
	case CONNECT_IND:
		return pkt->adv_chsel;
	default:
		return -1;
	}
}

int lell_get_cte_info(const lell_packet *pkt)
{
	if (!lell_packet_is_data(pkt) || !pkt->flags.as_bits.has_cte_info)
		return -1;
	return pkt->cte_info;
}

void lell_packet_set_encrypted(lell_packet *pkt, int encrypted)
{
	pkt->flags.as_bits.encrypted = encrypted ? 1 : 0;
}

int lell_packet_is_encrypted(const lell_packet *pkt)
{
	return pkt->flags.as_bits.encrypted;
}

void lell_packet_set_phy(lell_packet *pkt, int phy)
{
	pkt->phy = (uint8_t) (phy & 0x3);
}

const char * lell_get_adv_type_str(const lell_packet *pkt)
{
	if (lell_packet_is_data(pkt))
		return NULL;
	if (pkt->channel_idx < 37) {
		/* secondary advertising channel */
		switch (pkt->adv_type) {
		case AUX_SCAN_REQ:	return "AUX_SCAN_REQ";
		case AUX_CONNECT_REQ:	return "AUX_CONNECT_REQ";
		case ADV_EXT_IND:	return "AUX_ADV_IND/AUX_CHAIN_IND/AUX_SYNC_IND/AUX_SCAN_RSP";
		case AUX_CONNECT_RSP:	return "AUX_CONNECT_RSP";
		default:		return "UNKNOWN";
		}
	}
	if (pkt->adv_type < COUNT_OF(ADV_TYPE_NAMES))
		return ADV_TYPE_NAMES[pkt->adv_type];
	return "UNKNOWN";
}

const char *lell_get_ll_opcode_str(int opcode)
{
	if (opcode >= 0 && (unsigned) opcode < COUNT_OF(LL_OPCODE_NAMES))
		return LL_OPCODE_NAMES[opcode];
	return "Reserved for Future Use";
}

int lell_get_ll_opcode(const lell_packet *pkt)
{
	if (!lell_packet_is_data(pkt) || pkt->flags.as_bits.encrypted)
		return -1;
	if ((pkt->symbols[4] & 0x3) != 3 || pkt->length < 1 ||
	    le_payload_avail(pkt) < 1)
		return -1;
	return pkt->symbols[le_payload_offset(pkt)];
}

int lell_get_instant(const lell_packet *pkt, uint16_t *instant)
{
	unsigned off; /* offset of Instant within the PDU payload */
	int opcode = lell_get_ll_opcode(pkt);

	switch (opcode) {
	case LL_CONNECTION_UPDATE_IND:	off = 1 + 9; break;
	case LL_CHANNEL_MAP_IND:	off = 1 + 5; break;
	case LL_PHY_UPDATE_IND:		off = 1 + 2; break;
	default:			return 0;
	}
	if (le_payload_avail(pkt) < off + 2)
		return 0;
	if (instant)
		*instant = le16(&pkt->symbols[le_payload_offset(pkt) + off]);
	return 1;
}

void lell_packet_set_direction(lell_packet *pkt, int direction)
{
	if (pkt)
		pkt->direction = (direction == 1 || direction == 2) ? direction : 0;
}

void lell_packet_set_crc_status(lell_packet *pkt, int checked, int valid)
{
	if (pkt)
		pkt->crc_status = checked ? (valid ? 2 : 1) : 0;
}

uint16_t le_phdr_flags(const lell_packet *pkt)
{
	uint16_t flags = 0;
	/* PDU type 1: Auxiliary Advertising (advertising PDU on a secondary
	 * channel); 2/3: data, master to slave / slave to master; 0:
	 * advertising or data, unspecified direction */
	if (!lell_packet_is_data(pkt) && pkt->channel_idx < 37)
		flags |= 1 << 7;
	else if (lell_packet_is_data(pkt) && pkt->direction)
		flags |= (uint16_t) ((pkt->direction + 1) << 7);
	/* CRC checked (0x0400) and valid (0x0800) */
	if (pkt->crc_status)
		flags |= 0x0400 | (pkt->crc_status == 2 ? 0x0800 : 0);
	flags |= (uint16_t) ((pkt->phy & 0x3) << 14);
	return flags;
}

/* ------------------------------------------------------------------ */
/* Extended advertising */

int lell_get_ext_adv_info(const lell_packet *pkt, lell_ext_adv_info *info)
{
	const uint8_t *p;
	unsigned len, avail, ehl, pos, end;

	if (info == NULL)
		return -1;
	memset(info, 0, sizeof(*info));
	if (lell_packet_is_data(pkt) ||
	    (pkt->adv_type != ADV_EXT_IND && pkt->adv_type != AUX_CONNECT_RSP))
		return -1;

	p = &pkt->symbols[le_payload_offset(pkt)];
	len = (unsigned) pkt->length;
	avail = le_payload_avail(pkt);
	if (len < 1)
		return -1;
	if (avail < 1)
		return -2;

	ehl = p[0] & 0x3f;
	info->adv_mode = p[0] >> 6;
	info->ext_header_len = (uint8_t) ehl;
	end = 1 + ehl;
	if (end > len)
		return -1;
	if (end > avail)
		return -2;

	pos = 1;
	if (ehl > 0) {
		uint8_t flags = p[pos++];
		info->ext_header_flags = flags & 0x7f;

#define NEED(n) do { if (pos + (n) > end) return -1; } while (0)
		if (flags & LELL_EXT_HDR_ADVA) {
			NEED(6);
			memcpy(info->adva, &p[pos], 6);
			info->adva_random = (uint8_t) pkt->adv_tx_add;
			pos += 6;
		}
		if (flags & LELL_EXT_HDR_TARGETA) {
			NEED(6);
			memcpy(info->targeta, &p[pos], 6);
			info->targeta_random = (uint8_t) pkt->adv_rx_add;
			pos += 6;
		}
		if (flags & LELL_EXT_HDR_CTEINFO) {
			NEED(1);
			info->cte_info = p[pos];
			pos += 1;
		}
		if (flags & LELL_EXT_HDR_ADI) {
			uint16_t adi;
			NEED(2);
			adi = le16(&p[pos]);
			info->adi_did = adi & 0x0fff;
			info->adi_sid = (uint8_t) (adi >> 12);
			pos += 2;
		}
		if (flags & LELL_EXT_HDR_AUXPTR) {
			uint16_t v;
			NEED(3);
			info->aux_ptr.channel_index = p[pos] & 0x3f;
			info->aux_ptr.clock_accuracy = (p[pos] >> 6) & 1;
			info->aux_ptr.offset_units = (p[pos] >> 7) & 1;
			v = le16(&p[pos + 1]);
			info->aux_ptr.aux_offset = v & 0x1fff;
			info->aux_ptr.aux_phy = (uint8_t) (v >> 13);
			info->aux_ptr.aux_offset_us = (uint32_t) info->aux_ptr.aux_offset *
				(info->aux_ptr.offset_units ? 300 : 30);
			pos += 3;
		}
		if (flags & LELL_EXT_HDR_SYNCINFO) {
			uint16_t v;
			NEED(18);
			v = le16(&p[pos]);
			info->sync_info.sync_packet_offset = v & 0x1fff;
			info->sync_info.offset_units = (v >> 13) & 1;
			info->sync_info.offset_adjust = (v >> 14) & 1;
			info->sync_info.interval = le16(&p[pos + 2]);
			memcpy(info->sync_info.chm, &p[pos + 4], 5);
			info->sync_info.chm[4] &= 0x1f;
			info->sync_info.sca = p[pos + 8] >> 5;
			info->sync_info.access_address = le32(&p[pos + 9]);
			info->sync_info.crc_init = le24(&p[pos + 13]);
			info->sync_info.event_counter = le16(&p[pos + 16]);
			pos += 18;
		}
		if (flags & LELL_EXT_HDR_TXPOWER) {
			NEED(1);
			info->tx_power = (int8_t) p[pos];
			pos += 1;
		}
#undef NEED
		/* the rest of the extended header is ACAD */
		info->acad = &p[pos];
		info->acad_len = (uint8_t) (end - pos);
	}

	info->adv_data = &p[end];
	info->adv_data_len = (uint8_t) (len - end);
	if (end + info->adv_data_len > avail) {
		info->adv_data_len = (uint8_t) (avail - end);
		info->truncated = 1;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Printing */

static void _print_addr6(const char *name, const uint8_t *a, int random) {
	int i;
	printf("    %s%02x", name, a[5]);
	for (i = 4; i >= 0; --i)
		printf(":%02x", a[i]);
	printf(" (%s)\n", random ? "random" : "public");
}

/* The _dump_* helpers print a field at 'offset' of the packet, or note
 * that it was not captured (lim = number of usable bytes of the packet:
 * the captured part of header and payload). */
static void _dump_addr(const char *name, const uint8_t *buf, unsigned lim, unsigned offset, int random) {
	if (offset + 6 > lim) {
		printf("    %s(not captured)\n", name);
		return;
	}
	_print_addr6(name, &buf[offset], random);
}

static void _dump_8(const char *name, const uint8_t *buf, unsigned lim, unsigned offset) {
	if (offset + 1 > lim) {
		printf("    %s(not captured)\n", name);
		return;
	}
	printf("    %s%02x (%d)\n", name, buf[offset], buf[offset]);
}

static void _dump_16(const char *name, const uint8_t *buf, unsigned lim, unsigned offset) {
	uint16_t val;
	if (offset + 2 > lim) {
		printf("    %s(not captured)\n", name);
		return;
	}
	val = le16(&buf[offset]);
	printf("    %s%04x (%d)\n", name, val, val);
}

static void _dump_24(const char *name, const uint8_t *buf, unsigned lim, unsigned offset) {
	if (offset + 3 > lim) {
		printf("    %s(not captured)\n", name);
		return;
	}
	printf("    %s%06x\n", name, le24(&buf[offset]));
}

static void _dump_32(const char *name, const uint8_t *buf, unsigned lim, unsigned offset) {
	if (offset + 4 > lim) {
		printf("    %s(not captured)\n", name);
		return;
	}
	printf("    %s%08x\n", name, le32(&buf[offset]));
}

static void _dump_hex(const char *name, const uint8_t *buf, unsigned n) {
	unsigned i;
	printf("    %s", name);
	for (i = 0; i < n; ++i)
		printf(" %02x", buf[i]);
	printf("\n");
}

static void _dump_uuid(const uint8_t *uuid) {
	int i;
	for (i = 0; i < 4; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 4; i < 6; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 6; i < 8; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 8; i < 10; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 10; i < 16; ++i)
		printf("%02x", uuid[i]);
}

// Refer to pg 1735 of Bluetooth Core Spec 4.0
static void _dump_scan_rsp_data(const uint8_t *buf, int len) {
	int pos = 0;
	int sublen, i;
	uint8_t type;
	uint16_t val;

	while (pos < len) {
		sublen = buf[pos];
		++pos;
		if (pos + sublen > len) {
			printf("Error: attempt to read past end of buffer (%d + %d > %d)\n", pos, sublen, len);
			return;
		}
		if (sublen == 0) {
			printf("Early return due to 0 length\n");
			return;
		}
		type = buf[pos];
		printf("        Type %02x", type);
		switch (type) {
			case 0x01:
				printf(" (Flags)\n");
				if (sublen < 2) {
					printf("           Wrong length (%d, should be 1)\n", sublen-1);
					break;
				}
				printf("           ");
				for (i = 0; i < 8; ++i)
					printf("%d", buf[pos+1] & (1 << (7-i)) ? 1 : 0);
				printf("\n");
				for (i = 0; i < 8; ++i) {
					if (buf[pos+1] & (1 << i)) {
						printf("               ");
						printf("%s\n", FLAGS[i]);
					}
				}
				printf("\n");
				break;
			case 0x02:
				printf(" (16-bit Service UUIDs, more available)\n");
				goto print16;
			case 0x03:
				printf(" (16-bit Service UUIDs) \n");
print16:
				if ((sublen - 1) % 2 == 0) {
					for (i = 0; i < sublen - 1; i += 2)
						printf("           %04x\n", le16(&buf[pos+1+i]));
				}
				else {
					printf("Wrong length (%d, must be divisible by 2)\n", sublen-1);
				}
				break;
			case 0x06:
				printf(" (128-bit Service UUIDs, more available)\n");
				goto print128;
			case 0x07:
				printf(" (128-bit Service UUIDs)\n");
print128:
				if ((sublen - 1) % 16 == 0) {
					uint8_t uuid[16];
					for (i = 0; i < sublen - 1; ++i) {
						uuid[15 - (i % 16)] = buf[pos+1+i];
						if ((i & 15) == 15) {
							printf("           ");
							_dump_uuid(uuid);
							printf("\n");
						}
					}
				}
				else {
					printf("Wrong length (%d, must be divisible by 16)\n", sublen-1);
				}
				break;
			case 0x08:
			case 0x09:
				printf(type == 0x08 ? " (Shortened Local Name)\n" : " (Complete Local Name)\n");
				printf("           ");
				for (i = 1; i < sublen; ++i)
					printf("%c", isprint(buf[pos+i]) ? buf[pos+i] : '.');
				printf("\n");
				break;
			case 0x0a:
				printf(" (Tx Power Level)\n");
				printf("           ");
				if (sublen-1 == 1) {
					printf("%d dBm\n", (int8_t) buf[pos+1]);
				} else {
					printf("Wrong length (%d, should be 1)\n", sublen-1);
				}
				break;
			case 0x12:
				printf(" (Slave Connection Interval Range)\n");
				printf("           ");
				if (sublen-1 == 4) {
					val = le16(&buf[pos+1]);
					printf("(%0.2f, ", val * 1.25);
					val = le16(&buf[pos+3]);
					printf("%0.2f) ms\n", val * 1.25);
				}
				else {
					printf("Wrong length (%d, should be 4)\n", sublen-1);
				}
				break;
			case 0x16:
				printf(" (Service Data)\n");
				printf("           ");
				if (sublen-1 >= 2) {
					val = le16(&buf[pos+1]);
					printf("UUID: %04x", val);
					if (sublen-1 > 2) {
						printf(", Additional:");
						for (i = 3; i < sublen; ++i)
							printf(" %02x", buf[pos+i]);
					}
					printf("\n");
				}
				else {
					printf("Wrong length (%d, should be >= 2)\n", sublen-1);
				}
				break;
			case 0xff:
				printf(" (Manufacturer Specific Data)\n");
				printf("           ");
				if (sublen - 1 >= 2) {
					uint16_t company = le16(&buf[pos+1]);
					printf("Company: %s\n", bt_compidtostr(company));
					printf("           ");
					printf("Data:");
					for (i = 3; i < sublen; ++i)
						printf(" %02x", buf[pos+i]);
					printf("\n");
				}
				else {
					printf("Wrong length (%d, should be >= 2)\n", sublen-1);
				}
				break;
			default:
				printf("\n");
				printf("           ");
				for (i = 1; i < sublen; ++i)
					printf(" %02x", buf[pos+i]);
				printf("\n");
		}
		pos += sublen;
	}
}

static const char *_phy_name(unsigned phy)
{
	return PHY_NAMES[phy & 3];
}

/* bit mask of PHYs (LL_PHY_REQ/RSP/UPDATE_IND) as text */
static void _print_phys(const char *name, uint8_t mask)
{
	printf("    %s0x%02x", name, mask);
	if (mask == 0)
		printf(" (no change)");
	if (mask & 0x01) printf(" LE 1M");
	if (mask & 0x02) printf(" LE 2M");
	if (mask & 0x04) printf(" LE Coded");
	printf("\n");
}

static const char *_version_name(uint8_t vers)
{
	static const char *names[] = {
		"1.0b", "1.1", "1.2", "2.0", "2.1", "3.0", "4.0", "4.1",
		"4.2", "5.0", "5.1", "5.2", "5.3", "5.4", "6.0",
	};
	return (vers < COUNT_OF(names)) ? names[vers] : "unknown";
}

static void _dump_cte_info(const char *name, uint8_t cte)
{
	static const char *types[] = { "AoA", "AoD 1 us slots", "AoD 2 us slots", "Reserved" };
	printf("    %s0x%02x (CTETime %u us, CTEType %s)\n", name, cte,
	       (cte & 0x1f) * 8, types[cte >> 6]);
}

/* LL control PDU: 'p' points to the opcode, 'avail' bytes were captured */
static void _dump_ll_control(const uint8_t *p, unsigned avail)
{
	int opcode;
	const uint8_t *c;
	unsigned n;

	if (avail < 1) {
		printf("    Opcode: (not captured)\n");
		return;
	}
	opcode = p[0];
	printf("    Opcode: %d / %s\n", opcode, lell_get_ll_opcode_str(opcode));
	c = p + 1;	/* CtrData */
	n = avail - 1;

#define NEED(k) do { if (n < (k)) { printf("    (CtrData not completely captured)\n"); return; } } while (0)
	switch (opcode) {
	case 0x00: /* LL_CONNECTION_UPDATE_IND */
		NEED(11);
		printf("    WinSize: %u (%.2f ms)\n", c[0], c[0] * 1.25);
		printf("    WinOffset: %u (%.2f ms)\n", le16(&c[1]), le16(&c[1]) * 1.25);
		printf("    Interval: %u (%.2f ms)\n", le16(&c[3]), le16(&c[3]) * 1.25);
		printf("    Latency: %u\n", le16(&c[5]));
		printf("    Timeout: %u (%u ms)\n", le16(&c[7]), le16(&c[7]) * 10);
		printf("    Instant: %u\n", le16(&c[9]));
		break;
	case 0x01: /* LL_CHANNEL_MAP_IND */
		NEED(7);
		printf("    ChM: %02x %02x %02x %02x %02x\n", c[0], c[1], c[2], c[3], c[4]);
		printf("    Instant: %u\n", le16(&c[5]));
		break;
	case 0x02: /* LL_TERMINATE_IND */
	case 0x0D: /* LL_REJECT_IND */
		NEED(1);
		printf("    ErrorCode: 0x%02x\n", c[0]);
		break;
	case 0x03: /* LL_ENC_REQ */
		NEED(22);
		_dump_hex("Rand:", &c[0], 8);
		printf("    EDIV: %04x\n", le16(&c[8]));
		_dump_hex("SKDm:", &c[10], 8);
		_dump_hex("IVm: ", &c[18], 4);
		break;
	case 0x04: /* LL_ENC_RSP */
		NEED(12);
		_dump_hex("SKDs:", &c[0], 8);
		_dump_hex("IVs: ", &c[8], 4);
		break;
	case 0x07: /* LL_UNKNOWN_RSP */
		NEED(1);
		printf("    UnknownType: 0x%02x (%s)\n", c[0], lell_get_ll_opcode_str(c[0]));
		break;
	case 0x08: /* LL_FEATURE_REQ */
	case 0x09: /* LL_FEATURE_RSP */
	case 0x0E: /* LL_PERIPHERAL_FEATURE_REQ */
		NEED(8);
		printf("    FeatureSet: 0x%08x%08x\n", le32(&c[4]), le32(&c[0]));
		break;
	case 0x0C: /* LL_VERSION_IND */
		NEED(5);
		printf("    VersNr: %u (Bluetooth %s)\n", c[0], _version_name(c[0]));
		printf("    CompId: 0x%04x (%s)\n", le16(&c[1]), bt_compidtostr(le16(&c[1])));
		printf("    SubVersNr: 0x%04x\n", le16(&c[3]));
		break;
	case 0x0F: /* LL_CONNECTION_PARAM_REQ */
	case 0x10: /* LL_CONNECTION_PARAM_RSP */
		NEED(11);
		printf("    Interval_Min: %u (%.2f ms)\n", le16(&c[0]), le16(&c[0]) * 1.25);
		printf("    Interval_Max: %u (%.2f ms)\n", le16(&c[2]), le16(&c[2]) * 1.25);
		printf("    Latency: %u\n", le16(&c[4]));
		printf("    Timeout: %u (%u ms)\n", le16(&c[6]), le16(&c[6]) * 10);
		printf("    PreferredPeriodicity: %u\n", c[8]);
		printf("    ReferenceConnEventCount: %u\n", le16(&c[9]));
		break;
	case 0x11: /* LL_REJECT_EXT_IND */
		NEED(2);
		printf("    RejectOpcode: 0x%02x (%s)\n", c[0], lell_get_ll_opcode_str(c[0]));
		printf("    ErrorCode: 0x%02x\n", c[1]);
		break;
	case 0x14: /* LL_LENGTH_REQ */
	case 0x15: /* LL_LENGTH_RSP */
		NEED(8);
		printf("    MaxRxOctets: %u\n", le16(&c[0]));
		printf("    MaxRxTime: %u us\n", le16(&c[2]));
		printf("    MaxTxOctets: %u\n", le16(&c[4]));
		printf("    MaxTxTime: %u us\n", le16(&c[6]));
		break;
	case 0x16: /* LL_PHY_REQ */
	case 0x17: /* LL_PHY_RSP */
		NEED(2);
		_print_phys("TX_PHYS: ", c[0]);
		_print_phys("RX_PHYS: ", c[1]);
		break;
	case 0x18: /* LL_PHY_UPDATE_IND */
		NEED(4);
		_print_phys("PHY_C_TO_P: ", c[0]);
		_print_phys("PHY_P_TO_C: ", c[1]);
		printf("    Instant: %u\n", le16(&c[2]));
		break;
	case 0x19: /* LL_MIN_USED_CHANNELS_IND */
		NEED(2);
		_print_phys("PHYS: ", c[0]);
		printf("    MinUsedChannels: %u\n", c[1]);
		break;
	default:
		break;
	}
#undef NEED
}

static void _dump_ext_adv(const lell_packet *pkt)
{
	static const char *modes[] = {
		"Non-connectable, non-scannable", "Connectable",
		"Scannable", "Reserved",
	};
	lell_ext_adv_info info;
	int rv = lell_get_ext_adv_info(pkt, &info);

	if (rv == -2) {
		printf("    Extended header not completely captured\n");
		return;
	}
	if (rv < 0) {
		printf("    Malformed extended advertising payload\n");
		return;
	}
	printf("    AdvMode: %u (%s)\n", info.adv_mode, modes[info.adv_mode & 3]);
	printf("    Extended Header Length: %u\n", info.ext_header_len);
	if (info.ext_header_len == 0)
		printf("    Extended Header: (none)\n");
	if (info.ext_header_flags & LELL_EXT_HDR_ADVA)
		_print_addr6("AdvA:  ", info.adva, info.adva_random);
	if (info.ext_header_flags & LELL_EXT_HDR_TARGETA)
		_print_addr6("TargetA: ", info.targeta, info.targeta_random);
	if (info.ext_header_flags & LELL_EXT_HDR_CTEINFO)
		_dump_cte_info("CTEInfo: ", info.cte_info);
	if (info.ext_header_flags & LELL_EXT_HDR_ADI)
		printf("    ADI: DID 0x%03x, SID %u\n", info.adi_did, info.adi_sid);
	if (info.ext_header_flags & LELL_EXT_HDR_AUXPTR)
		printf("    AuxPtr: Channel %u, %s, Offset %u us (%u x %u us), CA %s\n",
		       info.aux_ptr.channel_index, _phy_name(info.aux_ptr.aux_phy),
		       info.aux_ptr.aux_offset_us, info.aux_ptr.aux_offset,
		       info.aux_ptr.offset_units ? 300 : 30,
		       info.aux_ptr.clock_accuracy ? "0-50 ppm" : "51-500 ppm");
	if (info.ext_header_flags & LELL_EXT_HDR_SYNCINFO) {
		const lell_sync_info *si = &info.sync_info;
		printf("    SyncInfo: Offset %u (x %u us%s), Interval %u (%.2f ms)\n",
		       si->sync_packet_offset, si->offset_units ? 300 : 30,
		       si->offset_adjust ? ", +2.4576 s" : "",
		       si->interval, si->interval * 1.25);
		printf("              ChM %02x %02x %02x %02x %02x, SCA %u (%s)\n",
		       si->chm[0], si->chm[1], si->chm[2], si->chm[3], si->chm[4],
		       si->sca, CONNECT_SCA[si->sca & 7]);
		printf("              AA %08x, CRCInit %06x, Event Counter %u\n",
		       si->access_address, si->crc_init, si->event_counter);
	}
	if (info.ext_header_flags & LELL_EXT_HDR_TXPOWER)
		printf("    TxPower: %d dBm\n", info.tx_power);
	if (info.acad_len)
		_dump_hex("ACAD:", info.acad, info.acad_len);
	if (info.adv_data_len) {
		_dump_hex(pkt->adv_type == AUX_CONNECT_RSP ? "Data:" : "AdvData:",
			  info.adv_data, info.adv_data_len);
		if (!info.truncated)
			_dump_scan_rsp_data(info.adv_data, info.adv_data_len);
	}
	if (info.truncated)
		printf("    AdvData truncated by the capture\n");
}

/* CONNECT_IND / AUX_CONNECT_REQ LLData */
static void _dump_connect_ind(const lell_packet *pkt, unsigned lim)
{
	const uint8_t *s = pkt->symbols;
	unsigned i;

	_dump_addr("InitA: ", s, lim, 6, pkt->adv_tx_add);
	_dump_addr("AdvA:  ", s, lim, 12, pkt->adv_rx_add);
	_dump_32("AA:    ", s, lim, 18);
	_dump_24("CRCInit: ", s, lim, 22);
	_dump_8("WinSize: ", s, lim, 25);
	_dump_16("WinOffset: ", s, lim, 26);
	_dump_16("Interval: ", s, lim, 28);
	_dump_16("Latency: ", s, lim, 30);
	_dump_16("Timeout: ", s, lim, 32);

	if (lim < 40) {
		printf("    ChM, Hop, SCA: (not captured)\n");
		return;
	}
	printf("    ChM:");
	for (i = 0; i < 5; ++i)
		printf(" %02x", s[34+i]);
	printf("\n");

	printf("    Hop: %d\n", s[39] & 0x1f);
	printf("    SCA: %d, %s\n", s[39] >> 5, CONNECT_SCA[s[39] >> 5]);
}

void lell_print(const lell_packet *pkt)
{
	unsigned i;
	const uint8_t *s = pkt->symbols;
	unsigned poff = le_payload_offset(pkt);
	unsigned pavail = le_payload_avail(pkt);
	unsigned lim = poff + pavail;	/* captured bytes of AA, header, payload */
	unsigned avail = le_pdu_avail_len(pkt);
	unsigned total = le_pdu_total_len(pkt);
	unsigned crc_off;

	if (lell_packet_is_data(pkt)) {
		int llid = s[4] & 0x3;
		static const char *llid_str[] = {
			"Reserved",
			"LL Data PDU / empty or L2CAP continuation",
			"LL Data PDU / L2CAP start",
			"LL Control PDU",
		};

		printf("Data / AA %08x (%s) / %2d bytes\n", pkt->access_address,
		       pkt->flags.as_bits.access_address_ok ? "valid" : "invalid",
		       pkt->length);
		printf("    Channel Index: %d\n", pkt->channel_idx);
		printf("    LLID: %d / %s\n", llid, llid_str[llid]);
		printf("    NESN: %d  SN: %d  MD: %d", (s[4] >> 2) & 1,
		       (s[4] >> 3) & 1, (s[4] >> 4) & 1);
		if (pkt->flags.as_bits.has_cte_info)
			printf("  CP: 1");
		printf("\n");
		if (pkt->flags.as_bits.has_cte_info)
			_dump_cte_info("CTEInfo: ", pkt->cte_info);

		if (pkt->flags.as_bits.encrypted && pkt->length > 0) {
			printf("    encrypted (MIC = last 4 bytes)\n");
			if (pkt->length >= 4 && pavail == (unsigned) pkt->length)
				_dump_hex("MIC:", &s[poff + pkt->length - 4], 4);
		} else if (llid == 3) {
			// LL Control PDU
			_dump_ll_control(&s[poff], pavail);
		}
	} else {
		int chsel = lell_get_chsel(pkt);

		printf("Advertising / AA %08x (%s)/ %2d bytes\n", pkt->access_address,
		       pkt->flags.as_bits.access_address_ok ? "valid" : "invalid",
		       pkt->length);
		printf("    Channel Index: %d\n", pkt->channel_idx);
		printf("    Type:  %s\n", lell_get_adv_type_str(pkt));
		if (chsel >= 0)
			printf("    ChSel: %d (Channel Selection Algorithm #%d)\n",
			       chsel, chsel ? 2 : 1);

		if (pkt->channel_idx < 37) {
			/* secondary advertising channel */
			switch (pkt->adv_type) {
				case AUX_SCAN_REQ:
					_dump_addr("ScanA: ", s, lim, 6, pkt->adv_tx_add);
					_dump_addr("AdvA:  ", s, lim, 12, pkt->adv_rx_add);
					break;
				case AUX_CONNECT_REQ:
					_dump_connect_ind(pkt, lim);
					break;
				case ADV_EXT_IND:
				case AUX_CONNECT_RSP:
					_dump_ext_adv(pkt);
					break;
			}
		} else {
			switch(pkt->adv_type) {
				case ADV_IND:
				case ADV_NONCONN_IND:
				case ADV_SCAN_IND:
					_dump_addr("AdvA:  ", s, lim, 6, pkt->adv_tx_add);
					if (lim > 12) {
						_dump_hex("AdvData:", &s[12], lim - 12);
						_dump_scan_rsp_data(&s[12], lim - 12);
					}
					break;
				case ADV_DIRECT_IND:
					_dump_addr("AdvA:  ", s, lim, 6, pkt->adv_tx_add);
					_dump_addr("InitA: ", s, lim, 12, pkt->adv_rx_add);
					break;
				case SCAN_REQ:
					_dump_addr("ScanA: ", s, lim, 6, pkt->adv_tx_add);
					_dump_addr("AdvA:  ", s, lim, 12, pkt->adv_rx_add);
					break;
				case SCAN_RSP:
					_dump_addr("AdvA:  ", s, lim, 6, pkt->adv_tx_add);
					_dump_hex("ScanRspData:", &s[12], lim > 12 ? lim - 12 : 0);
					if (lim > 12)
						_dump_scan_rsp_data(&s[12], lim - 12);
					break;
				case CONNECT_IND:
					_dump_connect_ind(pkt, lim);
					break;
				case ADV_EXT_IND:
					_dump_ext_adv(pkt);
					break;
			}
		}
	}

	printf("\n");
	printf("    Data: ");
	for (i = poff; i < lim; ++i)
		printf(" %02x", s[i]);
	printf("\n");

	printf("    CRC:  ");
	crc_off = poff + pkt->length;
	for (i = 0; i < 3 && crc_off + i < avail; ++i)
		printf(" %02x", s[crc_off + i]);
	printf("\n");

	if (avail < total)
		printf("    Truncated: %u of %u bytes captured\n", avail, total);
}

/* ------------------------------------------------------------------ */
/* Encryption tracking */

/* bound on the number of tracked connections */
#define LELL_TRACKER_MAX_CONNS 4096

typedef struct {
	uint32_t aa;		/* key */
	uint8_t encrypted;
	UT_hash_handle hh;
} lell_conn;

struct lell_tracker {
	lell_conn *conns;
	unsigned count;
};

lell_tracker *lell_tracker_new(void)
{
	return (lell_tracker *) calloc(1, sizeof(lell_tracker));
}

static void tracker_clear(lell_tracker *t)
{
	lell_conn *c, *tmp;
	HASH_ITER(hh, t->conns, c, tmp) {
		HASH_DEL(t->conns, c);
		free(c);
	}
	t->count = 0;
}

void lell_tracker_free(lell_tracker *tracker)
{
	if (!tracker)
		return;
	tracker_clear(tracker);
	free(tracker);
}

static lell_conn *tracker_find(lell_tracker *t, uint32_t aa)
{
	lell_conn *c;
	HASH_FIND(hh, t->conns, &aa, sizeof(aa), c);
	return c;
}

static lell_conn *tracker_get(lell_tracker *t, uint32_t aa)
{
	lell_conn *c = tracker_find(t, aa);
	if (c)
		return c;
	if (t->count >= LELL_TRACKER_MAX_CONNS)
		tracker_clear(t);
	c = (lell_conn *) calloc(1, sizeof(lell_conn));
	if (!c)
		return NULL;
	c->aa = aa;
	HASH_ADD(hh, t->conns, aa, sizeof(c->aa), c);
	t->count++;
	return c;
}

static void tracker_del(lell_tracker *t, lell_conn *c)
{
	HASH_DEL(t->conns, c);
	free(c);
	t->count--;
}

void lell_track(lell_tracker *t, lell_packet *pkt)
{
	lell_conn *c;
	unsigned poff, pavail;
	int llid, opcode;

	if (!t || !pkt)
		return;

	if (!lell_packet_is_data(pkt)) {
		/* CONNECT_IND (or AUX_CONNECT_REQ): a new connection with this
		 * AA starts unencrypted */
		if (pkt->adv_type == CONNECT_IND && pkt->length == 34 &&
		    pkt->flags.as_bits.access_address_ok &&
		    le_payload_avail(pkt) >= 16) {
			uint32_t aa = le32(&pkt->symbols[6 + 12]);
			c = tracker_get(t, aa);
			if (c)
				c->encrypted = 0;
		}
		return;
	}

	/* empty PDUs are never encrypted */
	if (pkt->length == 0)
		return;

	c = tracker_find(t, pkt->access_address);

	/* the caller (e.g. the capture firmware) knows best */
	if (pkt->flags.as_bits.encrypted) {
		if (!c)
			c = tracker_get(t, pkt->access_address);
		if (c)
			c->encrypted = 1;
		return;
	}

	llid = pkt->symbols[4] & 0x3;
	poff = le_payload_offset(pkt);
	pavail = le_payload_avail(pkt);
	opcode = (llid == 3 && pavail >= 1) ? pkt->symbols[poff] : -1;

	if (c && c->encrypted) {
		/* An encrypted PDU carries at least 1 byte of payload plus
		 * a 4 byte MIC; a shorter one is plaintext. */
		if (pkt->length >= 5) {
			pkt->flags.as_bits.encrypted = 1;
			return;
		}
		/* The central's LL_PAUSE_ENC_RSP is sent unencrypted and
		 * ends encryption (until the next LL_START_ENC_REQ). */
		if (opcode == LL_PAUSE_ENC_RSP)
			c->encrypted = 0;
		return;
	}

	switch (opcode) {
	case LL_START_ENC_REQ:
		/* last unencrypted PDU: the LL_START_ENC_RSPs and everything
		 * after them are encrypted */
		if (!c)
			c = tracker_get(t, pkt->access_address);
		if (c)
			c->encrypted = 1;
		break;
	case LL_TERMINATE_IND:
		/* unencrypted connection terminated */
		if (c)
			tracker_del(t, c);
		break;
	default:
		break;
	}
}
