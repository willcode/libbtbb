/* -*- c -*- */
/*
 * Bluetooth LE regression tests for libbtbb: packet decoding with
 * truncated/long captures, BT 5.x extended advertising (incl. AuxPtr),
 * ChSel, CP/CTEInfo, LL control PDUs, the encryption tracker and
 * pcap/pcapng output.
 *
 * Usage: test_le [output directory for the generated capture files]
 *
 * This file is part of libbtbb; see the COPYING file for license terms.
 */

#include "btbb.h"
#include "bluetooth_le_packet.h"
#include "pcap-common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static int failures = 0;
#define CHECK(cond, ...) do { \
	if (!(cond)) { \
		failures++; \
		fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n"); \
	} \
} while (0)

static const char *outdir = ".";

static uint32_t rng_state = 4242;
static uint32_t rnd(void)
{
	rng_state = rng_state * 1103515245u + 12345u;
	return rng_state >> 8;
}

/* physical channel (MHz) of an LE channel index */
static uint16_t phys_of(int idx)
{
	if (idx == 37) return 2402;
	if (idx == 38) return 2426;
	if (idx == 39) return 2480;
	if (idx <= 10) return 2404 + 2 * idx;
	return 2428 + 2 * (idx - 11);
}

static void put32(uint8_t *b, uint32_t v)
{
	b[0] = v; b[1] = v >> 8; b[2] = v >> 16; b[3] = v >> 24;
}

/* AA + header + payload + (dummy) CRC */
static size_t make_pdu(uint8_t *buf, uint32_t aa, uint8_t hdr0,
		       const uint8_t *payload, unsigned plen,
		       int cte, uint8_t cte_info)
{
	size_t n = 0;
	put32(buf, aa);
	buf[4] = hdr0 | (cte ? 0x20 : 0);
	buf[5] = (uint8_t) plen;
	n = 6;
	if (cte)
		buf[n++] = cte_info;
	memcpy(buf + n, payload, plen);
	n += plen;
	buf[n++] = 0x11; buf[n++] = 0x22; buf[n++] = 0x33;
	return n;
}

static lell_packet *decode(const uint8_t *buf, size_t len, int idx)
{
	lell_packet *pkt = NULL;
	int rv = lell_allocate_and_decode_len(buf, len, phys_of(idx), 0, &pkt);
	CHECK(rv == 0 && pkt != NULL, "decode failed");
	return pkt;
}

/* run lell_print() and capture what it prints */
static char print_buf[65536];
static const char *print_to_buf(const lell_packet *pkt)
{
	FILE *tmp = tmpfile();
	int saved = dup(1);
	size_t n;
	fflush(stdout);
	dup2(fileno(tmp), 1);
	lell_print(pkt);
	fflush(stdout);
	dup2(saved, 1);
	close(saved);
	rewind(tmp);
	n = fread(print_buf, 1, sizeof(print_buf) - 1, tmp);
	print_buf[n] = '\0';
	fclose(tmp);
	return print_buf;
}

/* ADV_EXT_IND with ADI and AuxPtr */
static size_t build_adv_ext_ind(uint8_t *buf)
{
	uint8_t pl[16];
	unsigned n = 0;
	pl[n++] = 6 | (0 << 6);		/* ExtHdrLen 6, AdvMode non-conn */
	pl[n++] = 0x08 | 0x10;		/* ADI | AuxPtr */
	pl[n++] = 0x23; pl[n++] = 0x51;	/* DID 0x123, SID 5 */
	pl[n++] = 12 | 0x40 | 0x80;	/* chan 12, CA 0-50 ppm, 300 us units */
	pl[n++] = 0x64; pl[n++] = 0x20;	/* offset 100, PHY LE 2M */
	return make_pdu(buf, LE_ADV_AA, ADV_EXT_IND, pl, n, 0, 0);
}

/* AUX_ADV_IND with every extended header field, ACAD and AdvData */
static size_t build_aux_adv_ind(uint8_t *buf, unsigned *plen_out)
{
	uint8_t pl[255];
	unsigned n = 0, i;
	static const uint8_t advdata[] = { 0x02, 0x01, 0x06,
		0x05, 0x09, 'T', 'e', 's', 't' };

	pl[n++] = 41 | (1 << 6);	/* ExtHdrLen 41, connectable */
	pl[n++] = 0x7f;			/* all fields */
	for (i = 0; i < 6; i++) pl[n++] = 0xa0 + i;	/* AdvA */
	for (i = 0; i < 6; i++) pl[n++] = 0xb0 + i;	/* TargetA */
	pl[n++] = 0x45;					/* CTEInfo */
	pl[n++] = 0x23; pl[n++] = 0x51;			/* ADI */
	pl[n++] = 7; pl[n++] = 0x0a; pl[n++] = 0x00;	/* AuxPtr ch 7, 10*30us, 1M */
	/* SyncInfo */
	pl[n++] = 0x23; pl[n++] = 0x61;	/* offset 0x123, 300 us, adjust */
	pl[n++] = 0x50; pl[n++] = 0x00;	/* interval 80 */
	pl[n++] = 0xff; pl[n++] = 0xff; pl[n++] = 0xff; pl[n++] = 0xff;
	pl[n++] = 0x1f | (5 << 5);	/* ChM bits 32-36, SCA 5 */
	pl[n++] = 0x78; pl[n++] = 0x56; pl[n++] = 0x34; pl[n++] = 0x12; /* AA */
	pl[n++] = 0xef; pl[n++] = 0xcd; pl[n++] = 0xab;	/* CRCInit */
	pl[n++] = 0x02; pl[n++] = 0x01;			/* event counter */
	pl[n++] = (uint8_t) -12;			/* TxPower */
	pl[n++] = 0x02; pl[n++] = 0x01; pl[n++] = 0x1a;	/* ACAD (one AD structure) */
	memcpy(pl + n, advdata, sizeof(advdata));
	n += sizeof(advdata);
	*plen_out = n;
	/* TxAdd: AdvA random */
	return make_pdu(buf, LE_ADV_AA, ADV_EXT_IND | 0x40, pl, n, 0, 0);
}

static void test_ext_adv(void)
{
	uint8_t buf[300];
	size_t n;
	unsigned plen;
	lell_packet *pkt;
	lell_ext_adv_info info;
	const char *out;

	n = build_adv_ext_ind(buf);
	pkt = decode(buf, n, 37);
	CHECK(!lell_packet_is_data(pkt), "ADV_EXT_IND decoded as data");
	CHECK(strcmp(lell_get_adv_type_str(pkt), "ADV_EXT_IND") == 0,
	      "type %s", lell_get_adv_type_str(pkt));
	CHECK(lell_get_ext_adv_info(pkt, &info) == 0, "ADV_EXT_IND parse failed");
	CHECK(info.ext_header_flags == (LELL_EXT_HDR_ADI | LELL_EXT_HDR_AUXPTR),
	      "flags %02x", info.ext_header_flags);
	CHECK(info.adi_did == 0x123 && info.adi_sid == 5, "ADI %03x/%u",
	      info.adi_did, info.adi_sid);
	CHECK(info.aux_ptr.channel_index == 12, "AuxPtr channel %u",
	      info.aux_ptr.channel_index);
	CHECK(info.aux_ptr.clock_accuracy == 1, "AuxPtr CA");
	CHECK(info.aux_ptr.offset_units == 1, "AuxPtr units");
	CHECK(info.aux_ptr.aux_offset == 100, "AuxPtr offset %u", info.aux_ptr.aux_offset);
	CHECK(info.aux_ptr.aux_offset_us == 30000, "AuxPtr offset us %u",
	      info.aux_ptr.aux_offset_us);
	CHECK(info.aux_ptr.aux_phy == 1, "AuxPtr PHY %u", info.aux_ptr.aux_phy);
	CHECK(info.adv_data_len == 0, "AdvData len %u", info.adv_data_len);
	out = print_to_buf(pkt);
	CHECK(strstr(out, "AuxPtr: Channel 12, LE 2M, Offset 30000 us") != NULL,
	      "AuxPtr not printed:\n%s", out);
	CHECK((le_phdr_flags(pkt) & LE_PDU_TYPE_MASK) == 0,
	      "primary channel adv PDU marked auxiliary");
	lell_packet_unref(pkt);

	/* AUX_ADV_IND on secondary channel 7: the advertising AA makes it an
	 * advertising PDU even though channel 7 is a data channel */
	n = build_aux_adv_ind(buf, &plen);
	pkt = decode(buf, n, 7);
	CHECK(!lell_packet_is_data(pkt), "AUX_ADV_IND on channel 7 decoded as data");
	CHECK(lell_get_access_address_offenses(pkt) == 0, "AUX AA offenses %u",
	      lell_get_access_address_offenses(pkt));
	CHECK(strstr(lell_get_adv_type_str(pkt), "AUX_ADV_IND") != NULL,
	      "type %s", lell_get_adv_type_str(pkt));
	CHECK(lell_get_length(pkt) == plen && plen > 37,
	      "8 bit adv length %u (expected %u)", lell_get_length(pkt), plen);
	CHECK(lell_get_ext_adv_info(pkt, &info) == 0, "AUX_ADV_IND parse failed");
	CHECK(info.adv_mode == 1, "AdvMode %u", info.adv_mode);
	CHECK(info.ext_header_len == 41, "ExtHdrLen %u", info.ext_header_len);
	CHECK(info.ext_header_flags == 0x7f, "flags %02x", info.ext_header_flags);
	CHECK(info.adva[0] == 0xa0 && info.adva[5] == 0xa5 && info.adva_random == 1,
	      "AdvA");
	CHECK(info.targeta[0] == 0xb0 && info.targeta_random == 0, "TargetA");
	CHECK(info.cte_info == 0x45, "CTEInfo %02x", info.cte_info);
	CHECK(info.aux_ptr.channel_index == 7 && info.aux_ptr.aux_offset_us == 300 &&
	      info.aux_ptr.aux_phy == 0, "AuxPtr ch %u off %u phy %u",
	      info.aux_ptr.channel_index, info.aux_ptr.aux_offset_us, info.aux_ptr.aux_phy);
	CHECK(info.sync_info.sync_packet_offset == 0x123 &&
	      info.sync_info.offset_units == 1 && info.sync_info.offset_adjust == 1,
	      "SyncInfo offset");
	CHECK(info.sync_info.interval == 80, "SyncInfo interval");
	CHECK(info.sync_info.chm[4] == 0x1f && info.sync_info.sca == 5, "SyncInfo ChM/SCA");
	CHECK(info.sync_info.access_address == 0x12345678, "SyncInfo AA %08x",
	      info.sync_info.access_address);
	CHECK(info.sync_info.crc_init == 0xabcdef, "SyncInfo CRCInit");
	CHECK(info.sync_info.event_counter == 0x0102, "SyncInfo counter");
	CHECK(info.tx_power == -12, "TxPower %d", info.tx_power);
	CHECK(info.acad_len == 3 && info.acad[0] == 0x02 && info.acad[2] == 0x1a,
	      "ACAD len %u", info.acad_len);
	CHECK(info.adv_data_len == 9 && info.adv_data[4] == 0x09 && !info.truncated,
	      "AdvData len %u", info.adv_data_len);
	CHECK((le_phdr_flags(pkt) & LE_PDU_TYPE_MASK) == (1 << LE_PDU_TYPE_SHIFT),
	      "AUX PDU not marked as auxiliary advertising in PHDR flags");
	out = print_to_buf(pkt);
	CHECK(strstr(out, "SyncInfo") && strstr(out, "TxPower: -12 dBm") &&
	      strstr(out, "Complete Local Name"), "AUX_ADV_IND print:\n%s", out);
	lell_packet_unref(pkt);

	/* the same packet with the capture ending inside the AdvData */
	pkt = decode(buf, 6 + 1 + 41 + 4, 7);
	CHECK(lell_packet_is_truncated(pkt), "truncated packet not flagged");
	CHECK(lell_get_ext_adv_info(pkt, &info) == 0 && info.truncated &&
	      info.adv_data_len == 4, "truncated AdvData len %u", info.adv_data_len);
	lell_packet_unref(pkt);

	/* ... and ending inside the extended header */
	pkt = decode(buf, 6 + 20, 7);
	CHECK(lell_get_ext_adv_info(pkt, &info) == -2, "truncated ext header");
	lell_packet_unref(pkt);

	/* malformed: ExtHdrLen beyond the PDU */
	buf[6] = 63;
	pkt = decode(buf, n, 7);
	CHECK(lell_get_ext_adv_info(pkt, &info) == -1, "malformed ext header accepted");
	lell_packet_unref(pkt);
}

/* CONNECT_IND LLData with the given AA */
static size_t build_connect_ind(uint8_t *buf, uint32_t aa, int chsel)
{
	uint8_t pl[34];
	unsigned i;
	for (i = 0; i < 12; i++) pl[i] = 0x10 + i;	/* InitA, AdvA */
	put32(&pl[12], aa);
	pl[16] = 0x55; pl[17] = 0x55; pl[18] = 0x55;	/* CRCInit */
	pl[19] = 2;					/* WinSize */
	pl[20] = 0; pl[21] = 0;				/* WinOffset */
	pl[22] = 24; pl[23] = 0;			/* Interval */
	pl[24] = 0; pl[25] = 0;				/* Latency */
	pl[26] = 0x48; pl[27] = 0;			/* Timeout */
	pl[28] = 0xff; pl[29] = 0xff; pl[30] = 0xff; pl[31] = 0xff; pl[32] = 0x1f;
	pl[33] = 7 | (5 << 5);				/* Hop, SCA */
	return make_pdu(buf, LE_ADV_AA, CONNECT_IND | (chsel ? 0x20 : 0) | 0x40,
			pl, 34, 0, 0);
}

static void test_chsel_and_classification(void)
{
	uint8_t buf[300];
	size_t n;
	lell_packet *pkt;
	const char *out;
	uint8_t pl[8] = { 0 };

	n = build_connect_ind(buf, 0x50654c32, 1);
	pkt = decode(buf, n, 37);
	CHECK(lell_get_chsel(pkt) == 1, "ChSel %d", lell_get_chsel(pkt));
	out = print_to_buf(pkt);
	CHECK(strstr(out, "Type:  CONNECT_IND") && strstr(out, "ChSel: 1"),
	      "CONNECT_IND print:\n%s", out);
	lell_packet_unref(pkt);

	n = build_connect_ind(buf, 0x50654c32, 0);
	pkt = decode(buf, n, 38);
	CHECK(lell_get_chsel(pkt) == 0, "ChSel %d", lell_get_chsel(pkt));
	lell_packet_unref(pkt);

	/* same PDU on a secondary channel is an AUX_CONNECT_REQ: no ChSel */
	pkt = decode(buf, n, 20);
	CHECK(!lell_packet_is_data(pkt), "AUX_CONNECT_REQ classified as data");
	CHECK(strcmp(lell_get_adv_type_str(pkt), "AUX_CONNECT_REQ") == 0, "type %s",
	      lell_get_adv_type_str(pkt));
	CHECK(lell_get_chsel(pkt) == -1, "AUX_CONNECT_REQ has a ChSel");
	lell_packet_unref(pkt);

	/* SCAN_REQ has no ChSel */
	n = make_pdu(buf, LE_ADV_AA, SCAN_REQ | 0x20, pl, 0, 0, 0);
	pkt = decode(buf, n, 39);
	CHECK(lell_get_chsel(pkt) == -1, "SCAN_REQ has a ChSel");
	lell_packet_unref(pkt);

	/* a data AA on a data channel is a data PDU, on a primary
	 * advertising channel it is not */
	n = make_pdu(buf, 0x50654c32, 0x01, pl, 0, 0, 0);
	pkt = decode(buf, n, 5);
	CHECK(lell_packet_is_data(pkt), "data PDU not classified as data");
	CHECK(lell_get_access_address_offenses(pkt) == 0, "AA offenses %u",
	      lell_get_access_address_offenses(pkt));
	lell_packet_unref(pkt);
	pkt = decode(buf, n, 37);
	CHECK(!lell_packet_is_data(pkt), "packet on channel 37 classified as data");
	lell_packet_unref(pkt);

	/* advertising AA with a bit error on a secondary channel */
	n = make_pdu(buf, LE_ADV_AA ^ 0x100, ADV_EXT_IND, pl, 1, 0, 0);
	pkt = decode(buf, n, 3);
	CHECK(!lell_packet_is_data(pkt) && lell_get_access_address_offenses(pkt) == 1,
	      "off-by-one adv AA on secondary channel");
	lell_packet_unref(pkt);
}

static void test_ll_control_and_cte(void)
{
	uint8_t buf[300], pl[64];
	size_t n;
	lell_packet *pkt;
	uint16_t instant = 0;
	const char *out;
	uint32_t aa = 0x50654c32;

	/* LL_PHY_UPDATE_IND: C->P 2M, P->C 2M, instant 0x1234 */
	pl[0] = 0x18; pl[1] = 0x02; pl[2] = 0x02; pl[3] = 0x34; pl[4] = 0x12;
	n = make_pdu(buf, aa, 0x03, pl, 5, 0, 0);
	pkt = decode(buf, n, 9);
	CHECK(lell_get_ll_opcode(pkt) == 0x18, "opcode %d", lell_get_ll_opcode(pkt));
	CHECK(lell_get_instant(pkt, &instant) == 1 && instant == 0x1234,
	      "PHY_UPDATE_IND instant %04x", instant);
	out = print_to_buf(pkt);
	CHECK(strstr(out, "LL_PHY_UPDATE_IND") && strstr(out, "Instant: 4660"),
	      "PHY_UPDATE_IND print:\n%s", out);
	lell_packet_unref(pkt);

	/* LL_CONNECTION_UPDATE_IND: instant 0x0102 */
	memset(pl, 0, sizeof(pl));
	pl[0] = 0x00; pl[1] = 1; pl[4] = 40; pl[8] = 100; pl[10] = 0x02; pl[11] = 0x01;
	n = make_pdu(buf, aa, 0x03, pl, 12, 0, 0);
	pkt = decode(buf, n, 9);
	CHECK(lell_get_instant(pkt, &instant) == 1 && instant == 0x0102,
	      "CONNECTION_UPDATE_IND instant %04x", instant);
	lell_packet_unref(pkt);

	/* LL_CHANNEL_MAP_IND: instant 0x0a0b */
	pl[0] = 0x01; pl[1] = 0xff; pl[2] = 0xff; pl[3] = 0; pl[4] = 0; pl[5] = 0x1f;
	pl[6] = 0x0b; pl[7] = 0x0a;
	n = make_pdu(buf, aa, 0x03, pl, 8, 0, 0);
	pkt = decode(buf, n, 9);
	CHECK(lell_get_instant(pkt, &instant) == 1 && instant == 0x0a0b,
	      "CHANNEL_MAP_IND instant %04x", instant);
	lell_packet_unref(pkt);

	/* LL_LENGTH_REQ with CP=1 / CTEInfo: payload starts one byte later */
	pl[0] = 0x14; pl[1] = 251; pl[2] = 0; pl[3] = 0x48; pl[4] = 0x08;
	pl[5] = 251; pl[6] = 0; pl[7] = 0x48; pl[8] = 0x08;
	n = make_pdu(buf, aa, 0x03, pl, 9, 1, 0x45);
	pkt = decode(buf, n, 9);
	CHECK(lell_get_cte_info(pkt) == 0x45, "CTEInfo %d", lell_get_cte_info(pkt));
	CHECK(lell_get_ll_opcode(pkt) == 0x14, "opcode with CTEInfo %d",
	      lell_get_ll_opcode(pkt));
	CHECK(lell_get_captured_length(pkt) == n && !lell_packet_is_truncated(pkt),
	      "CTE packet length");
	out = print_to_buf(pkt);
	CHECK(strstr(out, "CP: 1") && strstr(out, "CTEType AoD 1 us slots") &&
	      strstr(out, "MaxRxOctets: 251"), "CTE/LENGTH_REQ print:\n%s", out);
	lell_packet_unref(pkt);

	CHECK(strcmp(lell_get_ll_opcode_str(0x29), "LL_CHANNEL_STATUS_IND") == 0, "0x29");
	CHECK(strcmp(lell_get_ll_opcode_str(0x23), "LL_POWER_CONTROL_REQ") == 0, "0x23");
	CHECK(strcmp(lell_get_ll_opcode_str(0x2a), "Reserved for Future Use") == 0, "0x2a");
	CHECK(strcmp(lell_get_ll_opcode_str(-1), "Reserved for Future Use") == 0, "-1");

	/* a 251 byte data PDU (8 bit length field) */
	memset(pl, 0xab, sizeof(pl));
	{
		uint8_t big[251];
		memset(big, 0x5a, sizeof(big));
		n = make_pdu(buf, aa, 0x02, big, 251, 0, 0);
		pkt = decode(buf, n, 9);
		CHECK(lell_get_length(pkt) == 251, "data length %u", lell_get_length(pkt));
		CHECK(!lell_packet_is_truncated(pkt), "251 byte PDU truncated");
		lell_packet_unref(pkt);
		/* captured by a device that only delivers 50 bytes */
		pkt = decode(buf, 50, 9);
		CHECK(lell_get_length(pkt) == 251 && lell_packet_is_truncated(pkt) &&
		      lell_get_captured_length(pkt) == 50, "50 byte capture of long PDU");
		out = print_to_buf(pkt);
		CHECK(strstr(out, "Truncated: 50 of 260 bytes captured") != NULL,
		      "truncation not reported:\n%s", out);
		lell_packet_unref(pkt);
	}
}

static lell_packet *ctrl(lell_tracker *t, uint32_t aa, uint8_t llid,
			 const uint8_t *pl, unsigned len)
{
	uint8_t buf[300];
	size_t n = make_pdu(buf, aa, llid, pl, len, 0, 0);
	lell_packet *pkt = decode(buf, n, 15);
	lell_track(t, pkt);
	return pkt;
}

static void test_encryption_tracker(void)
{
	lell_tracker *t = lell_tracker_new();
	uint8_t buf[300], pl[64];
	uint32_t aa = 0x50654c32, other = 0x71764129;
	lell_packet *pkt;
	size_t n;
	const char *out;

	memset(pl, 0x77, sizeof(pl));
	CHECK(t != NULL, "tracker allocation");

	n = build_connect_ind(buf, aa, 1);
	pkt = decode(buf, n, 37);
	lell_track(t, pkt);
	lell_packet_unref(pkt);

	/* LL_ENC_REQ / LL_ENC_RSP / LL_START_ENC_REQ are unencrypted */
	pl[0] = 0x03;
	pkt = ctrl(t, aa, 3, pl, 23);
	CHECK(!lell_packet_is_encrypted(pkt), "LL_ENC_REQ marked encrypted");
	lell_packet_unref(pkt);
	pl[0] = 0x04;
	pkt = ctrl(t, aa, 3, pl, 13);
	CHECK(!lell_packet_is_encrypted(pkt), "LL_ENC_RSP marked encrypted");
	lell_packet_unref(pkt);
	pl[0] = 0x05;
	pkt = ctrl(t, aa, 3, pl, 1);
	CHECK(!lell_packet_is_encrypted(pkt) && lell_get_ll_opcode(pkt) == 0x05,
	      "LL_START_ENC_REQ marked encrypted");
	lell_packet_unref(pkt);

	/* both LL_START_ENC_RSPs (1 byte + 4 byte MIC) are encrypted */
	pkt = ctrl(t, aa, 3, pl, 5);
	CHECK(lell_packet_is_encrypted(pkt), "LL_START_ENC_RSP not marked encrypted");
	CHECK(lell_get_ll_opcode(pkt) == -1, "opcode of encrypted PDU decoded");
	out = print_to_buf(pkt);
	CHECK(strstr(out, "encrypted (MIC = last 4 bytes)") && !strstr(out, "Opcode"),
	      "encrypted print:\n%s", out);
	lell_packet_unref(pkt);

	/* empty PDUs are never encrypted */
	pkt = ctrl(t, aa, 1, pl, 0);
	CHECK(!lell_packet_is_encrypted(pkt), "empty PDU marked encrypted");
	lell_packet_unref(pkt);

	/* L2CAP data is encrypted */
	pkt = ctrl(t, aa, 2, pl, 27);
	CHECK(lell_packet_is_encrypted(pkt), "L2CAP PDU not marked encrypted");
	lell_packet_unref(pkt);

	/* other connections are not affected */
	pkt = ctrl(t, other, 2, pl, 27);
	CHECK(!lell_packet_is_encrypted(pkt), "unrelated connection marked encrypted");
	lell_packet_unref(pkt);

	/* the central's unencrypted LL_PAUSE_ENC_RSP ends encryption */
	pl[0] = 0x0b;
	pkt = ctrl(t, aa, 3, pl, 1);
	CHECK(!lell_packet_is_encrypted(pkt), "LL_PAUSE_ENC_RSP marked encrypted");
	lell_packet_unref(pkt);
	pl[0] = 0x03;
	pkt = ctrl(t, aa, 3, pl, 23);
	CHECK(!lell_packet_is_encrypted(pkt), "LL_ENC_REQ after pause marked encrypted");
	lell_packet_unref(pkt);

	/* a new CONNECT_IND with the same AA starts unencrypted again */
	pl[0] = 0x05;
	lell_packet_unref(ctrl(t, aa, 3, pl, 1));
	n = build_connect_ind(buf, aa, 0);
	pkt = decode(buf, n, 38);
	lell_track(t, pkt);
	lell_packet_unref(pkt);
	pkt = ctrl(t, aa, 2, pl, 27);
	CHECK(!lell_packet_is_encrypted(pkt), "new connection marked encrypted");
	lell_packet_unref(pkt);

	/* the device can mark packets encrypted directly; the tracker then
	 * follows */
	n = make_pdu(buf, other, 2, pl, 20, 0, 0);
	pkt = decode(buf, n, 15);
	lell_packet_set_encrypted(pkt, 1);
	lell_track(t, pkt);
	CHECK(lell_packet_is_encrypted(pkt), "caller encrypted flag lost");
	lell_packet_unref(pkt);
	pkt = ctrl(t, other, 2, pl, 20);
	CHECK(lell_packet_is_encrypted(pkt), "tracker did not learn from caller flag");
	lell_packet_set_encrypted(pkt, 0);
	CHECK(!lell_packet_is_encrypted(pkt), "set_encrypted(0)");
	lell_packet_unref(pkt);

	lell_tracker_free(t);
	lell_tracker_free(NULL);
}

/* Decode, print, track and save random packets of every length from
 * 0 to beyond MAX_LE_SYMBOLS (run under ASan). */
static void test_truncated_and_long(void)
{
	char path[1024], path2[1024], path3[1024];
	lell_pcapng_handle *ng = NULL;
	lell_pcap_handle *pc = NULL, *ppi = NULL;
	lell_tracker *t = lell_tracker_new();
	uint8_t buf[400];
	int len, rep, saved, devnull;
	static const int channels[] = { 37, 38, 39, 0, 7, 20, 36 };

	snprintf(path, sizeof(path), "%s/test_le_fuzz.pcapng", outdir);
	snprintf(path2, sizeof(path2), "%s/test_le_fuzz.pcap", outdir);
	snprintf(path3, sizeof(path3), "%s/test_le_fuzz_ppi.pcap", outdir);
	unlink(path);
	CHECK(lell_pcapng_create_file(path, "test", &ng) == 0, "pcapng create");
	CHECK(lell_pcap_create_file(path2, &pc) == 0, "pcap create");
	CHECK(lell_pcap_ppi_create_file(path3, 0, &ppi) == 0, "ppi create");

	/* silence lell_print */
	fflush(stdout);
	saved = dup(1);
	devnull = open("/dev/null", O_WRONLY);
	dup2(devnull, 1);

	for (len = 0; len <= 300; len++) {
		for (rep = 0; rep < 14; rep++) {
			int idx = channels[rep % 7];
			lell_packet *pkt;
			lell_ext_adv_info info;
			uint16_t instant;
			int i;

			for (i = 0; i < 400; i++)
				buf[i] = rnd() & 0xff;
			if (rep & 1)
				put32(buf, LE_ADV_AA);
			else
				put32(buf, 0x50654c32);
			if (rep % 3 == 0)
				buf[4] = (buf[4] & 0xf0) | ADV_EXT_IND;
			if (rep % 5 == 0)
				buf[5] = 0xff;	/* maximum length field */
			pkt = decode(buf, (size_t) len, idx);
			if (!pkt)
				continue;
			if (rep == 13)
				lell_packet_set_encrypted(pkt, 1);
			CHECK(lell_get_captured_length(pkt) == (unsigned) (len < MAX_LE_SYMBOLS ? len : MAX_LE_SYMBOLS),
			      "captured length %u for %d", lell_get_captured_length(pkt), len);
			lell_track(t, pkt);
			lell_print(pkt);
			(void) lell_get_ext_adv_info(pkt, &info);
			(void) lell_get_instant(pkt, &instant);
			(void) lell_get_adv_type_str(pkt);
			CHECK(lell_pcapng_append_packet(ng, (uint64_t) len * 1000 + rep, -40, -90,
						       LE_ADV_AA, pkt) == 0, "pcapng append");
			CHECK(lell_pcap_append_packet(pc, (uint64_t) len * 1000 + rep, -40, -90,
						     LE_ADV_AA, pkt) == 0, "pcap append");
			CHECK(lell_pcap_append_ppi_packet(ppi, (uint64_t) len * 1000 + rep, 0,
							 -50, -40, -45, 3, pkt) == 0, "ppi append");
			lell_packet_unref(pkt);
		}
	}

	/* legacy API (reads exactly 64 bytes) */
	{
		lell_packet *pkt = NULL;
		lell_allocate_and_decode(buf, 2402, 0, &pkt);
		CHECK(pkt && lell_get_captured_length(pkt) == 64, "legacy decode");
		if (pkt) {
			lell_print(pkt);
			lell_packet_unref(pkt);
		}
	}

	fflush(stdout);
	dup2(saved, 1);
	close(saved);
	close(devnull);

	CHECK(lell_pcapng_close(ng) == 0, "pcapng close");
	CHECK(lell_pcap_close(pc) == 0, "pcap close");
	CHECK(lell_pcap_close(ppi) == 0, "ppi close");
	lell_tracker_free(t);
}

/* Many CONNECT_INDs used to overflow the pcapng interface description
 * block (unreadable file at ~150, crash at ~400). */
static void test_pcapng_connect_ind(void)
{
	char path[1024];
	lell_pcapng_handle *ng = NULL;
	uint8_t buf[300];
	int i;

	snprintf(path, sizeof(path), "%s/test_le_connect_ind.pcapng", outdir);
	unlink(path);
	CHECK(lell_pcapng_create_file(path, "Ubertooth test", &ng) == 0, "pcapng create");
	for (i = 0; i < 450; i++) {
		size_t n = build_connect_ind(buf, 0x50654c32 + (uint32_t) i * 0x01010101u, i & 1);
		lell_packet *pkt = decode(buf, n, 37 + (i % 3));
		CHECK(lell_pcapng_append_packet(ng, 1000000ull * i, -40, -90,
					       LE_ADV_AA, pkt) == 0, "append %d", i);
		lell_packet_unref(pkt);
	}
	CHECK(lell_pcapng_close(ng) == 0, "pcapng close");
}

/* a capture with BT5 PDUs for checking with tshark */
static void test_pcapng_bt5(void)
{
	char path[1024];
	lell_pcapng_handle *ng = NULL;
	uint8_t buf[300], pl[8] = { 0x14, 251, 0, 0x48, 0x08, 251, 0, 0x48 };
	unsigned plen;
	size_t n;
	lell_packet *pkt;

	snprintf(path, sizeof(path), "%s/test_le_bt5.pcapng", outdir);
	unlink(path);
	CHECK(lell_pcapng_create_file(path, "BT5 test", &ng) == 0, "pcapng create");

	n = build_adv_ext_ind(buf);
	pkt = decode(buf, n, 37);
	CHECK(lell_pcapng_append_packet(ng, 1000, -40, -90, LE_ADV_AA, pkt) == 0, "append");
	lell_packet_unref(pkt);

	n = build_aux_adv_ind(buf, &plen);
	pkt = decode(buf, n, 12);
	CHECK(lell_pcapng_append_packet(ng, 2000, -40, -90, LE_ADV_AA, pkt) == 0, "append");
	lell_packet_unref(pkt);

	/* LL_LENGTH_REQ (truncated: 1 byte of CtrData missing) */
	pl[0] = 0x14;
	n = make_pdu(buf, 0x50654c32, 0x03, pl, 8, 0, 0);
	pkt = decode(buf, n, 9);
	CHECK(lell_pcapng_append_packet(ng, 3000, -40, -90, 0, pkt) == 0, "append");
	lell_packet_unref(pkt);

	CHECK(lell_pcapng_close(ng) == 0, "pcapng close");
}

int main(int argc, char **argv)
{
	if (argc > 1)
		outdir = argv[1];

	test_ext_adv();
	test_chsel_and_classification();
	test_ll_control_and_cte();
	test_encryption_tracker();
	test_truncated_and_long();
	test_pcapng_connect_ind();
	test_pcapng_bt5();

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_le: all tests passed\n");
	return 0;
}
