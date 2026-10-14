/* -*- c -*- */
/*
 * BR/EDR piconet regression tests for libbtbb: AFH hop selection,
 * the clock candidate bound, AFH map handling and survey results.
 *
 * This file is part of libbtbb; see the COPYING file for license terms.
 */

#include "bluetooth_packet.h"
#include "bluetooth_piconet.h"

#include <stdio.h>
#include <stdlib.h>
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

static uint32_t rng_state = 777;
static uint32_t rnd(void)
{
	rng_state = rng_state * 1103515245u + 12345u;
	return rng_state >> 4;
}

static void set_map(uint8_t *map, int nchannels, int step)
{
	int c, n = 0;
	memset(map, 0, 10);
	for (c = 0; c < 79 && n < nchannels; c += step, n++)
		map[c / 8] |= 1 << (c % 8);
}

/*
 * Reference hop selection straight from the spec (Vol 2 Part B 2.6),
 * connection state, for a clock CLK (bit 0 included):
 *   basic: channel = bank[(PERM5 + E + F + Y2) mod 79],  F = 16*CLK27-7 mod 79
 *   AFH (2.6.3): the basic channel of the Central's slot if it is used,
 *        otherwise bank'[(PERM5 + E + F' + Y2) mod N], F' = 16*CLK27-7 mod N,
 *        bank' the used channels in bank order; the Peripheral answers on
 *        the Central's channel (same channel mechanism)
 */
static int ref_hop(btbb_piconet *pn, uint32_t clk, int afh)
{
	if (afh)
		clk &= ~2u;   /* the Central's slot */
	int x = (clk >> 2) & 0x1f;
	int y1 = (clk >> 1) & 1;
	int y2 = 32 * y1;
	int a = (pn->a1 ^ (clk >> 21)) & 0x1f;
	int c = (pn->c1 ^ (clk >> 16)) & 0x1f;
	int d = (pn->d1 ^ (clk >> 7)) & 0x1ff;
	uint32_t clk27_7 = (clk >> 7) & 0x1fffff;
	int perm = perm5(((x + a) % 32) ^ pn->b, (y1 * 0x1f) ^ c, d);
	int basic = ((perm + pn->e + (16 * clk27_7) % 79 + y2) % 79) * 2 % 79;
	if (!afh || (pn->afh_map[basic / 8] >> (basic % 8)) & 1)
		return basic;
	int n = pn->used_channels;
	return pn->bank[(perm + pn->e + (16 * clk27_7) % n + y2) % n];
}

static btbb_piconet *make_pn(uint32_t lap, uint8_t uap)
{
	btbb_piconet *pn = btbb_piconet_new();
	btbb_init_piconet(pn, lap);
	pn->UAP = uap;
	return pn;
}

static void check_sequence(btbb_piconet *pn, int afh, const char *what)
{
	int i, mism_ref = 0, mism_single = 0;
	for (i = 0; i < 200000; i++) {
		uint32_t clk = (rnd() & 0x7ffffff) << 1;   /* CLK, bit 0 = 0 */
		int seq = pn->sequence[clk >> 1];
		if (seq != ref_hop(pn, clk, afh))
			mism_ref++;
		if (seq != single_hop((int) clk, pn))
			mism_single++;
	}
	CHECK(mism_ref == 0, "%s: %d hops differ from the spec formula", what, mism_ref);
	CHECK(mism_single == 0, "%s: %d hops differ from single_hop()", what, mism_single);
}

static void test_hop_selection(void)
{
	uint8_t map[10];
	btbb_piconet *pn = make_pn(0x9e8b33, 0x47);

	/* basic hopping */
	btbb_piconet_set_flag(pn, BTBB_UAP_VALID, 1);
	get_hop_pattern(pn);
	CHECK(pn->sequence != NULL, "no sequence");
	if (pn->sequence)
		check_sequence(pn, 0, "basic hopping");

	/* AFH with 27 used channels: the AFH sequence must be generated
	 * (not the cached basic one) and use F' = 16*CLK27-7 mod N */
	set_map(map, 27, 3);
	btbb_piconet_set_flag(pn, BTBB_IS_AFH, 1);
	btbb_piconet_set_afh_map(pn, map);
	CHECK(pn->used_channels == 27, "used channels %d", pn->used_channels);
	CHECK(pn->seq_afh == 1, "AFH map change reused the basic sequence");
	if (pn->sequence)
		check_sequence(pn, 1, "AFH, 27 channels");

	/* changing the map regenerates the sequence */
	set_map(map, 40, 2);
	btbb_piconet_set_afh_map(pn, map);
	CHECK(pn->used_channels == 40, "used channels %d", pn->used_channels);
	if (pn->sequence)
		check_sequence(pn, 1, "AFH, 40 channels");

	btbb_piconet_unref(pn);
}

static void test_afh_maps(void)
{
	uint8_t map[10];
	btbb_piconet *pn = make_pn(0x123456, 0x00);
	int i;

	/* bit 79 is reserved: an all-ones map has 79 used channels */
	memset(map, 0xff, sizeof(map));
	btbb_piconet_set_afh_map(pn, map);
	CHECK(pn->used_channels == 79, "all-ones map: %d used channels", pn->used_channels);
	CHECK((btbb_piconet_get_afh_map(pn)[9] & 0x80) == 0, "bit 79 kept");

	/* out of range channels must not touch memory past the map */
	CHECK(btbb_piconet_set_channel_seen(pn, 79) == 0, "channel 79 accepted");
	CHECK(btbb_piconet_set_channel_seen(pn, 200) == 0, "channel 200 accepted");
	CHECK(btbb_piconet_clear_channel_seen(pn, 255) == 0, "channel 255 accepted");
	CHECK(pn->used_channels == 79, "used channels changed");

	/* an empty AFH map used to divide by zero (SIGFPE) */
	memset(map, 0, sizeof(map));
	btbb_piconet_set_flag(pn, BTBB_IS_AFH, 1);
	btbb_piconet_set_flag(pn, BTBB_UAP_VALID, 1);
	btbb_piconet_set_afh_map(pn, map);
	CHECK(pn->sequence != NULL, "no sequence for empty AFH map");
	for (i = 0; i < 1000; i++)
		(void) single_hop((int) (rnd() & 0xfffffff), pn);

	btbb_piconet_unref(pn);
}

/* init_candidates() used to overflow clock_candidates with AFH and fewer
 * than ~40 used channels */
static void test_candidate_bound(void)
{
	uint8_t map[10];
	int n, nch;
	static const int counts[] = { 20, 1 };
	int k;

	for (k = 0; k < 2; k++) {
		btbb_piconet *pn = make_pn(0x2468ac, 0x13);
		nch = counts[k];
		set_map(map, nch, 2);
		btbb_piconet_set_flag(pn, BTBB_IS_AFH, 1);
		btbb_piconet_set_afh_map(pn, map);
		pn->pattern_channels[0] = 0;   /* first channel of the map */
		pn->first_pkt_time = 5;
		pn->clk_offset = 0;
		n = btbb_init_hop_reversal(0, pn);
		CHECK(n > 0 && (uint32_t) n <= pn->max_candidates,
		      "%d channels: %d candidates, capacity %u", nch, n, pn->max_candidates);
		if (nch == 1)
			/* every position of the sequence matches */
			CHECK(n == SEQUENCE_LENGTH / 64, "1 channel: %d candidates", n);
		else
			/* more than the old fixed buffer of (2^27/79)/32 */
			CHECK(n > (SEQUENCE_LENGTH / BT_NUM_CHANNELS) / 32,
			      "%d channels: only %d candidates", nch, n);
		btbb_piconet_unref(pn);
	}
}

/* btbb_next_survey_result() used to free entries without removing them
 * from the hash table: continuing the survey afterwards touched freed
 * memory */
static void test_survey(void)
{
	btbb_packet *pkt = btbb_packet_new();
	char syms[200];
	btbb_piconet *pn;
	int i, n = 0;

	memset(syms, 0, sizeof(syms));
	btbb_init_survey();
	/* a LAP is listed from its second sighting */
	for (i = 0; i < 40; i++) {
		pkt->LAP = 0x100000 + i / 2;
		btbb_packet_set_data(pkt, syms, 100, i / 2, 0);
		btbb_process_packet(pkt, NULL);
	}
	/* take two results, then keep surveying */
	for (i = 0; i < 2; i++) {
		pn = btbb_next_survey_result();
		CHECK(pn != NULL, "missing survey result");
		if (pn) {
			btbb_piconet_unref(pn);
			n++;
		}
	}
	for (i = 0; i < 80; i++) {
		pkt->LAP = 0x100000 + i / 2;
		btbb_packet_set_data(pkt, syms, 100, (i / 2) % 79, 0);
		btbb_process_packet(pkt, NULL);
	}
	while ((pn = btbb_next_survey_result()) != NULL) {
		btbb_piconet_unref(pn);
		n++;
	}
	/* 20 LAPs, 2 taken and then re-added, plus 20 new ones */
	CHECK(n == 42, "survey returned %d piconets", n);
	btbb_packet_unref(pkt);
}

/* access codes with random LAPs (sent by someone, or noise) must not grow the
 * survey without limit, nor push out a LAP with real traffic */
static void test_survey_bounded(void)
{
	btbb_packet *pkt = btbb_packet_new();
	char syms[200];
	btbb_piconet *pn;
	int i, n = 0, busy = 0;

	memset(syms, 0, sizeof(syms));
	btbb_init_survey();
	for (i = 0; i < 20; i++) {
		pkt->LAP = 0x9e8b33;
		btbb_packet_set_data(pkt, syms, 100, 10, 0);
		btbb_process_packet(pkt, NULL);
	}
	for (i = 0; i < 2 * 5000; i++) {
		pkt->LAP = (0x200000 + i / 2) & 0xffffff;
		btbb_packet_set_data(pkt, syms, 100, i % 79, 0);
		btbb_process_packet(pkt, NULL);
	}
	while ((pn = btbb_next_survey_result()) != NULL) {
		busy += btbb_piconet_get_lap(pn) == 0x9e8b33;
		btbb_piconet_unref(pn);
		n++;
	}
	CHECK(n <= 1024, "survey kept %d piconets", n);
	CHECK(busy == 1, "the busy LAP was dropped");
	btbb_packet_unref(pkt);
}

int main(void)
{
	test_hop_selection();
	test_afh_maps();
	test_candidate_bound();
	test_survey();
	test_survey_bounded();
	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_piconet: all tests passed\n");
	return 0;
}
