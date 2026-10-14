/* -*- c -*- */
/*
 * Clock recovery and map deduction for AFH piconets without the channel map.
 *
 * Traffic comes from an independent implementation of adapted hopping
 * (Vol 2 Part B 2.6.3): a 15-channel receiver, fixed or scanning the band,
 * sees the packets that land in its view, 5% of them on a wrong channel. The library must find CLK1-27,
 * deduce the exact map, and follow a later change of the map.
 *
 * This file is part of libbtbb; see the COPYING file for license terms.
 */

/* the internal functions (blind_winnow, afh_map_observe) are static */
#include "bluetooth_piconet.c"

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

static uint32_t rng_state;
static uint32_t rnd(void)
{
	rng_state = rng_state * 1103515245u + 12345u;
	return rng_state >> 4;
}

/* the 5-bit permutation, written out from the spec's butterfly table */
static int ref_perm5(int z, int p_high, int p_low)
{
	static const int i1[] = {0, 2, 1, 3, 0, 1, 0, 3, 1, 0, 2, 1, 0, 1};
	static const int i2[] = {1, 3, 2, 4, 4, 3, 2, 4, 4, 3, 4, 3, 3, 2};
	int p = (p_high << 9) | p_low, i;
	for (i = 13; i >= 0; i--) {
		int a = (z >> i1[i]) & 1, b = (z >> i2[i]) & 1;
		if (((p >> i) & 1) && a != b)
			z ^= (1 << i1[i]) | (1 << i2[i]);
	}
	return z;
}

typedef struct {
	uint32_t addr;          /* UAP 3-0 and LAP */
	char used[79];
	int bank[79], n;
} afh_gen;

static void gen_map(afh_gen *g, int n)
{
	int k, i;
	memset(g->used, 0, sizeof(g->used));
	for (k = 0; k < n; ) {
		int ch = rnd() % 79;
		if (!g->used[ch]) {
			g->used[ch] = 1;
			k++;
		}
	}
	g->n = 0;
	for (i = 0; i < 79; i++)
		if (g->used[(i * 2) % 79])
			g->bank[g->n++] = (i * 2) % 79;
}

/* adapted hopping for slot s (CLK1-27) */
static int gen_channel(const afh_gen *g, uint32_t s)
{
	uint32_t clk = (s & ~1u) << 1;   /* the Central's slot */
	uint32_t a28 = g->addr;
	int A = (a28 >> 23) & 0x1f, B = (a28 >> 19) & 0xf, D = (a28 >> 10) & 0x1ff;
	int C = ((a28 >> 4) & 0x10) | ((a28 >> 3) & 8) | ((a28 >> 2) & 4) | ((a28 >> 1) & 2) | (a28 & 1);
	int E = ((a28 >> 7) & 0x40) | ((a28 >> 6) & 0x20) | ((a28 >> 5) & 0x10) |
	        ((a28 >> 4) & 8) | ((a28 >> 3) & 4) | ((a28 >> 2) & 2) | ((a28 >> 1) & 1);
	int X = (clk >> 2) & 0x1f;
	int perm = ref_perm5(((X + (A ^ ((clk >> 21) & 0x1f))) % 32) ^ B,
	                     C ^ ((clk >> 16) & 0x1f), D ^ ((clk >> 7) & 0x1ff));
	uint32_t F = 16 * ((clk >> 7) & 0x1fffff);
	int f = ((perm + E + F % 79) % 79) * 2 % 79;
	return g->used[f] ? f : g->bank[(perm + E + F % g->n) % g->n];
}

static int map_equal(const btbb_piconet *pn, const afh_gen *g)
{
	int i;
	for (i = 0; i < 79; i++)
		if (((pn->afh_map[i / 8] >> (i % 8)) & 1) != g->used[i])
			return 0;
	return 1;
}

/* One piconet: N used channels, later N2. Returns nonzero on success. */
/* behind_obs: the caller reports falling behind (btbb_set_behind) from the
 * 3rd observation until this one: the clock search must wait, then catch
 * up and find the same clock */
static void run_case(uint32_t seed, int n, int n2, int scan, int behind_obs)
{
	int lo = 61, hi = 75;           /* the receiver's view */
	uint32_t lap = 0x5a1c39, uap = 0x6d;   /* an arbitrary address */
	afh_gen g;
	btbb_piconet *pn;
	btbb_packet *pk = btbb_packet_new();
	uint32_t t0, ls, first_true = 0, local0 = 1000;
	int started = 0, clock_at = -1, map_at = -1, change_at = -1, obs = 0, phase = 0;

	rng_state = seed;
	g.addr = (uap << 24 | lap) & 0xfffffff;
	gen_map(&g, n);
	t0 = rnd() & 0x7ffffff;

	pn = btbb_piconet_new();
	btbb_init_piconet(pn, lap);
	btbb_piconet_set_uap(pn, uap);
	btbb_piconet_set_flag(pn, BTBB_CLK6_VALID, 1);
	btbb_piconet_set_flag(pn, BTBB_IS_AFH, 1);

	for (ls = 0; ls < 4000000 && change_at < 0; ls += 2) {
		int sl;
		if (rnd() % 100 >= 2)          /* 2% of slot pairs carry traffic */
			continue;
		for (sl = 0; sl < 2; sl++) {
			uint32_t s = (t0 + ls + sl) & 0x7ffffff;
			uint32_t clkn = local0 + ls + sl;
			int ch = gen_channel(&g, s);
			if (scan) {
				/* 15-channel windows, 100 ms (160 slots) each */
				static const int wlo[] = { 0, 15, 30, 45, 60, 68 };
				lo = wlo[((ls + sl) / 160) % 6];
				hi = lo + 14 > 78 ? 78 : lo + 14;
			}
			if (ch < lo || ch > hi)
				continue;
			if (rnd() % 100 < 5)       /* detected on the wrong channel */
				ch = lo + rnd() % (hi - lo + 1);
			obs++;
			if (behind_obs && obs == behind_obs && started)
				CHECK(pn->winnowed + 10 < pn->packets_observed,
				      "seed %u: nothing waited while behind", seed);
			btbb_set_behind(obs > 2 && obs < behind_obs);
			if (!started) {
				pn->first_pkt_time = clkn;
				first_true = s;
				pn->clk_offset = ((s & 0x3f) - (clkn & 0x3f)) & 0x3f;
				pn->pattern_indices[0] = 0;
				pn->pattern_channels[0] = ch;
				pn->packets_observed = 1;
				btbb_init_hop_reversal(0, pn);
				btbb_winnow(pn);
				started = 1;
			} else if (!btbb_piconet_get_flag(pn, BTBB_CLK27_VALID)) {
				CHECK(pn->packets_observed < MAX_PATTERN_LENGTH, "seed %u: no clock", seed);
				if (pn->packets_observed >= MAX_PATTERN_LENGTH)
					goto out;
				pn->pattern_indices[pn->packets_observed] = clkn - pn->first_pkt_time;
				pn->pattern_channels[pn->packets_observed] = ch;
				pn->packets_observed++;
				btbb_winnow(pn);
			} else {
				pk->clkn = clkn;
				pk->channel = ch;
				afh_map_observe(pn, pk, clkn);
			}
			if (clock_at < 0 && btbb_piconet_get_flag(pn, BTBB_CLK27_VALID)) {
				clock_at = obs;
				CHECK(pn->clock_candidates[0] == first_true,
				      "seed %u: wrong clock 0x%07x (0x%07x)", seed,
				      pn->clock_candidates[0], first_true);
				if (pn->clock_candidates[0] != first_true)
					goto out;
			}
			if (phase == 0 && pn->afh_map_known) {
				map_at = obs;
				CHECK(map_equal(pn, &g), "seed %u: wrong map", seed);
				/* the deduced map's sequence predicts later hops */
				get_hop_pattern(pn);
				{
					int k, hit = 0;
					for (k = 0; k < 1000; k++) {
						uint32_t s2 = (first_true + 4000000 + 2 * k) & 0x7ffffff;
						hit += pn->sequence[s2] == gen_channel(&g, s2);
					}
					CHECK(hit == 1000, "seed %u: %d of 1000 hops predicted", seed, hit);
				}
				gen_map(&g, n2);        /* the Central changes the map */
				phase = 1;
			} else if (phase == 1 && map_equal(pn, &g)) {
				change_at = obs;
				break;
			}
		}
	}
	CHECK(map_at > 0, "seed %u: no map", seed);
	CHECK(change_at > 0, "seed %u: map change not followed", seed);
	printf("seed %u%s: N %d clock after %d packets, map after %d, N %d after %d\n",
	       seed, scan ? " (scanning)" : "", n, clock_at, map_at, n2, change_at);
out:
	btbb_set_behind(0);
	btbb_packet_unref(pk);
	btbb_piconet_unref(pn);
}

int main(void)
{
	run_case(21, 30, 25, 0, 0);
	run_case(22, 45, 60, 0, 0);
	run_case(23, 75, 50, 0, 0);
	run_case(41, 40, 30, 1, 0);
	run_case(32, 20, 50, 1, 0);
	run_case(21, 30, 25, 0, 120);      /* behind for a while */
	if (failures)
		fprintf(stderr, "%d failure(s)\n", failures);
	else
		printf("all AFH blind tests passed\n");
	return failures ? 1 : 0;
}
