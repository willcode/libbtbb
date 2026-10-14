/* -*- c -*- */
/*
 * BR/EDR baseband regression tests for libbtbb.
 *
 * Builds synthetic, correctly encoded BR packets (sync word, FEC 1/3
 * header with HEC, whitening, payload with CRC and FEC 2/3) and checks
 * that libbtbb decodes them, recovers the UAP/CLK1-6 from them and
 * corrects access code errors.
 *
 * This file includes bluetooth_packet.c directly so the encoder can use
 * the library's own static helpers (fec23, crcgen, uap_from_hec, ...).
 *
 * This file is part of libbtbb; see the COPYING file for license terms.
 */

#ifndef PKT_SRC
#define PKT_SRC "bluetooth_packet.c"
#endif
#include PKT_SRC

#include "bluetooth_piconet.h"
#include <string.h>

static int failures = 0;
#define CHECK(cond, ...) do { \
	if (!(cond)) { \
		failures++; \
		fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n"); \
	} \
} while (0)

#define TEST_LAP 0x9e8b33
#define TEST_UAP 0x5a

/* simple deterministic PRNG */
static uint32_t rng_state = 12345;
static uint32_t rnd(void)
{
	rng_state = rng_state * 1103515245u + 12345u;
	return rng_state >> 8;
}

static void host_to_air(uint32_t v, char *air, int bits)
{
	int i;
	for (i = 0; i < bits; i++)
		air[i] = (v >> i) & 1;
}

static uint8_t hec_for(uint16_t data10, uint8_t uap)
{
	int h;
	for (h = 0; h < 256; h++)
		if (uap_from_hec(data10, (uint8_t)h) == uap)
			return (uint8_t)h;
	return 0;
}

static void whiten(char *bits, int n, int clk6, int skip)
{
	btbb_packet tmp;
	char out[MAX_PAYLOAD_LENGTH + 32];
	memset(&tmp, 0, sizeof(tmp));
	btbb_packet_set_flag(&tmp, BTBB_WHITENED, 1);
	unwhiten(bits, out, clk6, n, skip, &tmp);
	memcpy(bits, out, n);
}

/* FEC 2/3 encode n bits (padded to a multiple of 10); returns symbols */
static int fec23_encode(const char *in, int n, char *out)
{
	int b, nblocks = (n + 9) / 10, o = 0;
	char block[10];
	for (b = 0; b < nblocks; b++) {
		int i;
		for (i = 0; i < 10; i++)
			block[i] = (b * 10 + i < n) ? in[b * 10 + i] : 0;
		memcpy(out + o, block, 10);
		host_to_air(fec23(air_to_host16(block, 10)) >> 10, out + o + 10, 5);
		o += 15;
	}
	return o;
}

static int fec13_encode(const char *in, int n, char *out)
{
	int i;
	for (i = 0; i < n; i++)
		out[3*i] = out[3*i+1] = out[3*i+2] = in[i];
	return 3 * n;
}

/* append payload CRC (computed over 'n' unwhitened bits) */
static int add_crc(char *bits, int n, uint8_t uap)
{
	host_to_air(crcgen(bits, n, uap), bits + n, 16);
	return n + 16;
}

/*
 * Build a whitened, FEC encoded packet of the given type into syms.
 * clk6 is CLK1-6 used for whitening.  Returns number of symbols.
 */
static int build_packet(char *syms, uint32_t lap, uint8_t uap, int clk6,
			int type, const uint8_t *body, int body_len)
{
	uint64_t sw = btbb_gen_syncword(lap);
	char hdr[18], pl[MAX_PAYLOAD_LENGTH + 64];
	int i, n = 0, msb;
	uint16_t data10;

	memset(syms, 0, MAX_SYMBOLS);
	for (i = 0; i < 64; i++)
		syms[i] = (sw >> i) & 1;
	msb = syms[63];
	syms[64] = !msb; syms[65] = msb; syms[66] = !msb; syms[67] = msb;

	data10 = 1 /* LT_ADDR */ | (type << 3) | (0x5 << 7) /* FLOW,ARQN,SEQN */;
	host_to_air(data10, hdr, 10);
	host_to_air(hec_for(data10, uap), hdr + 10, 8);
	whiten(hdr, 18, clk6, 0);
	fec13_encode(hdr, 18, syms + 68);

	switch (type) {
	case PACKET_TYPE_DM1:
	case PACKET_TYPE_DH1:
	case PACKET_TYPE_AUX1:
		/* 1 byte payload header: LLID=2, FLOW=1, LENGTH */
		host_to_air(2 | (1 << 2) | (body_len << 3), pl, 8);
		n = 8;
		break;
	case PACKET_TYPE_DM3:
	case PACKET_TYPE_DH3:
	case PACKET_TYPE_DM5:
	case PACKET_TYPE_DH5:
		/* 2 byte payload header: LLID=2, FLOW=1, LENGTH(10), RFU */
		host_to_air(2 | (1 << 2) | (body_len << 3), pl, 16);
		n = 16;
		break;
	default:
		break;
	}
	for (i = 0; i < body_len; i++) {
		host_to_air(body[i], pl + n, 8);
		n += 8;
	}
	if (type != PACKET_TYPE_AUX1 && type != PACKET_TYPE_HV1 &&
	    type != PACKET_TYPE_HV2 && type != PACKET_TYPE_HV3)
		n = add_crc(pl, n, uap);
	whiten(pl, n, clk6, 18);

	switch (type) {
	case PACKET_TYPE_DM1:
	case PACKET_TYPE_DM3:
	case PACKET_TYPE_DM5:
	case PACKET_TYPE_FHS:
	case PACKET_TYPE_HV2:
	case PACKET_TYPE_EV4:
		n = fec23_encode(pl, n, syms + 122);
		break;
	case PACKET_TYPE_HV1:
		n = fec13_encode(pl, n, syms + 122);
		break;
	default:
		memcpy(syms + 122, pl, n);
		break;
	}
	/* some trailing noise so the packet is not exactly as long as needed */
	for (i = 0; i < 64; i++)
		syms[122 + n + i] = rnd() & 1;
	return 122 + n + 64;
}

static btbb_packet *make_packet(int type, int body_len, int clk6, int flips)
{
	char syms[MAX_SYMBOLS];
	uint8_t body[400];
	int i, n;
	btbb_packet *pkt = btbb_packet_new();

	for (i = 0; i < body_len; i++)
		body[i] = rnd() & 0xff;
	n = build_packet(syms, TEST_LAP, TEST_UAP, clk6, type, body, body_len);
	/* optional symbol errors in the header/payload */
	for (i = 0; i < flips; i++)
		syms[68 + rnd() % (n - 68)] ^= 1;
	pkt->LAP = TEST_LAP;
	btbb_packet_set_flag(pkt, BTBB_WHITENED, 1);
	/* CLK1-27 = clk6 in its low bits; set_data takes CLK0-27 */
	btbb_packet_set_data(pkt, syms, n, 10, ((uint32_t)clk6 | 0x1000) << 1);
	return pkt;
}

#ifdef BTBB_DIFF_DUMP
/* Print try_clock()/crc_check() results for every clock: used to compare
 * the cached FEC implementation against the original one. */
static void diff_dump(void)
{
	static const int types[] = { PACKET_TYPE_DM1, PACKET_TYPE_DH1,
		PACKET_TYPE_DM3, PACKET_TYPE_DH3, PACKET_TYPE_DM5,
		PACKET_TYPE_DH5, PACKET_TYPE_FHS, PACKET_TYPE_HV1,
		PACKET_TYPE_HV2, PACKET_TYPE_HV3, PACKET_TYPE_DV,
		PACKET_TYPE_EV5 };
	int t, rep, clock;
	for (t = 0; t < (int)(sizeof(types)/sizeof(types[0])); t++) {
		for (rep = 0; rep < 40; rep++) {
			int len = (types[t] == PACKET_TYPE_DM1) ? 1 + rep % 17 :
				  (types[t] == PACKET_TYPE_FHS) ? 18 : 1 + rep * 3;
			btbb_packet *pkt = make_packet(types[t], len, rep & 0x3f,
						       rep % 4 == 3 ? 6 : rep % 3);
			for (clock = 0; clock < 64; clock++) {
				uint8_t uap = try_clock(clock, pkt);
				int rv = crc_check(clock, pkt);
				printf("%d %d %d uap=%02x type=%d rv=%d len=%d\n",
				       types[t], rep, clock, uap, pkt->packet_type,
				       rv, pkt->payload_length);
			}
			btbb_packet_unref(pkt);
		}
	}
}
#endif

static void test_decode_types(void)
{
	struct { int type, len, expect; } cases[] = {
		{ PACKET_TYPE_DM1,  17,   10 },
		{ PACKET_TYPE_DH1,  27,   10 },
		{ PACKET_TYPE_DM3,  121,  10 },
		{ PACKET_TYPE_DH3,  183,  10 },
		{ PACKET_TYPE_DM5,  224,  10 },
		{ PACKET_TYPE_DH5,  339,  10 },
		{ PACKET_TYPE_FHS,  18, 1000 },
		{ PACKET_TYPE_AUX1, 29,    2 },
		{ PACKET_TYPE_HV1,  10,    2 },
		{ PACKET_TYPE_HV2,  20,    2 },
	};
	int i, clk6 = 0x2b;

	for (i = 0; i < (int)(sizeof(cases)/sizeof(cases[0])); i++) {
		btbb_packet *pkt = make_packet(cases[i].type, cases[i].len, clk6, 0);
		int rv;
		CHECK(btbb_header_present(pkt), "type %d: header not detected", cases[i].type);
		btbb_packet_set_uap(pkt, TEST_UAP);
		btbb_packet_set_flag(pkt, BTBB_CLK6_VALID, 1);
		CHECK(btbb_decode_header(pkt), "type %d: header decode failed", cases[i].type);
		CHECK(btbb_packet_get_type(pkt) == cases[i].type, "type %d: decoded type %d",
		      cases[i].type, btbb_packet_get_type(pkt));
		rv = btbb_decode_payload(pkt);
		CHECK(rv == cases[i].expect, "type %d: decode rv=%d, expected %d",
		      cases[i].type, rv, cases[i].expect);
		if (cases[i].type == PACKET_TYPE_AUX1)
			/* AUX1 payload used to be truncated to 0 bytes */
			CHECK(btbb_packet_get_payload_length(pkt) == cases[i].len + 1,
			      "AUX1 payload length %d", btbb_packet_get_payload_length(pkt));
		btbb_packet_unref(pkt);
	}
}

static void test_uap_recovery(void)
{
	int clk6 = 0x17;
	btbb_piconet *pn = btbb_piconet_new();
	btbb_packet *pkt = make_packet(PACKET_TYPE_DM1, 9, clk6, 0);
	int rv;

	btbb_init_piconet(pn, TEST_LAP);
	rv = btbb_uap_from_header(pkt, pn);
	CHECK(rv == 1, "UAP not recovered from a DM1 packet (rv=%d)", rv);
	CHECK(btbb_piconet_get_flag(pn, BTBB_UAP_VALID) &&
	      btbb_piconet_get_uap(pn) == TEST_UAP,
	      "recovered UAP %02x, expected %02x", btbb_piconet_get_uap(pn), TEST_UAP);
	CHECK(btbb_piconet_get_flag(pn, BTBB_CLK6_VALID),
	      "CLK6 not recovered");
	CHECK(((btbb_piconet_get_clk_offset(pn) + pkt->clkn) & 0x3f) == (uint32_t)clk6,
	      "CLK6 offset %d wrong", btbb_piconet_get_clk_offset(pn));
	btbb_packet_unref(pkt);
	btbb_piconet_unref(pn);

	/* the same with an FHS packet */
	pn = btbb_piconet_new();
	btbb_init_piconet(pn, TEST_LAP);
	pkt = make_packet(PACKET_TYPE_FHS, 18, 0x2a, 0);
	rv = btbb_uap_from_header(pkt, pn);
	CHECK(rv == 1 && btbb_piconet_get_uap(pn) == TEST_UAP,
	      "UAP not recovered from FHS (rv=%d uap=%02x)", rv, btbb_piconet_get_uap(pn));
	btbb_packet_unref(pkt);
	btbb_piconet_unref(pn);
}

static void test_access_code(void)
{
	char stream[400];
	int i, offset;
	uint64_t sw = btbb_gen_syncword(TEST_LAP);
	btbb_packet *pkt = NULL;

	for (i = 0; i < 400; i++)
		stream[i] = rnd() & 1;
	for (i = 0; i < 64; i++)
		stream[100 + i] = (sw >> i) & 1;
	/* two bit errors in the LAP/parity part of the sync word */
	stream[100 + 5] ^= 1;
	stream[100 + 40] ^= 1;

	CHECK(btbb_init(2) == 0, "btbb_init failed");
	offset = btbb_find_ac(stream, 400 - 64, LAP_ANY, 2, &pkt);
	CHECK(offset == 100, "promiscuous search offset %d", offset);
	if (pkt) {
		CHECK(btbb_packet_get_lap(pkt) == TEST_LAP, "LAP %06x", btbb_packet_get_lap(pkt));
		CHECK(btbb_packet_get_ac_errors(pkt) == 2, "ac_errors %d",
		      btbb_packet_get_ac_errors(pkt));
	}

	offset = btbb_find_ac(stream, 400 - 64, TEST_LAP, 2, &pkt);
	CHECK(offset == 100, "known LAP search offset %d", offset);
	offset = btbb_find_ac(stream, 400 - 64, TEST_LAP, 1, &pkt);
	CHECK(offset < 0, "known LAP search with 1 allowed error found offset %d", offset);
	/* growing the error limit rebuilds the syndrome table */
	CHECK(btbb_init(3) == 0, "btbb_init(3) failed");
	if (pkt)
		btbb_packet_unref(pkt);
}

int main(void)
{
#ifdef BTBB_DIFF_DUMP
	diff_dump();
	return 0;
#else
	test_decode_types();
	test_uap_recovery();
	test_access_code();
	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_bredr: all tests passed\n");
	return 0;
#endif
}
