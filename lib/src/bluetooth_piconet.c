/* -*- c -*- */
/*
 * Copyright 2007 - 2013 Dominic Spill, Michael Ossmann, Will Code
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

#include "bluetooth_packet.h"
#include "bluetooth_piconet.h"
#include "uthash.h"
#include <stdlib.h>
#include <stdio.h>

#include <string.h>

int perm_table_initialized = 0;
char perm_table[0x20][0x200][0x20];   /* [p_high][p_low][z]: z varies fastest */

static void reset(btbb_piconet *pn);

/* count the number of 1 bits in a uint8_t */
static int count_bits(uint8_t n)
{
	int i = 0;
	for (i = 0; n != 0; i++)
		n &= n - 1;
	return i;
}

btbb_piconet *
btbb_piconet_new(void)
{
	btbb_piconet *pn = (btbb_piconet *)calloc(1, sizeof(btbb_piconet));
	if (pn)
		pn->refcount = 1;
	else
		fprintf(stderr, "Unable to allocate piconet\n");
	return pn;
}

void
btbb_piconet_ref(btbb_piconet *pn)
{
	pn->refcount++;
}

void
btbb_piconet_unref(btbb_piconet *pn)
{
	pn->refcount--;
	if (pn->refcount == 0) {
		free(pn->clock_candidates);
		free(pn->cand_hits);
		free(pn->sequence);
		free(pn);
	}
}

/* A bit of a hack? to set survey mode */
static int survey_mode = 0;
int btbb_init_survey() {
	survey_mode = 1;
	return 0;
}

/* Work that can wait while the caller falls behind (btbb_set_behind):
 * scoring the map-free clock search's candidates (2^21 per packet) and
 * deducing the AFH map. Waiting packets are scored later, up to
 * BLIND_PER_CALL per call, so the search catches up. */
static int behind = 0;
#define BLIND_PER_CALL 2

void btbb_set_behind(int b)
{
	behind = b != 0;
}

void btbb_init_piconet(btbb_piconet *pn, uint32_t lap)
{
	pn->LAP = lap;
	btbb_piconet_set_flag(pn, BTBB_LAP_VALID, 1);
}

void btbb_piconet_set_flag(btbb_piconet *pn, int flag, int val)
{
	uint32_t mask = 1L << flag;
	pn->flags &= ~mask;
	if (val)
		pn->flags |= mask;
}

int btbb_piconet_get_flag(const btbb_piconet *pn, const int flag)
{
	uint32_t mask = 1L << flag;
	return ((pn->flags & mask) != 0);
}

void btbb_piconet_set_uap(btbb_piconet *pn, uint8_t uap)
{
	pn->UAP = uap;
	btbb_piconet_set_flag(pn, BTBB_UAP_VALID, 1);
}

uint8_t btbb_piconet_get_uap(const btbb_piconet *pn)
{
	return pn->UAP;
}

uint32_t btbb_piconet_get_lap(const btbb_piconet *pn)
{
	return pn->LAP;
}

uint16_t btbb_piconet_get_nap(const btbb_piconet *pn)
{
	return pn->NAP;
}

uint64_t btbb_piconet_get_bdaddr(const btbb_piconet *pn)
{
	return ((uint64_t) pn->NAP) << 32 | ((uint32_t) pn->UAP) << 24 | pn->LAP;
}

int btbb_piconet_get_clk_offset(const btbb_piconet *pn)
{
	return pn->clk_offset;
}

void btbb_piconet_set_clk_offset(btbb_piconet *pn, int clk_offset)
{
	pn->clk_offset = clk_offset;
}

void btbb_piconet_set_afh_map(btbb_piconet *pn, uint8_t *afh_map) {
	int i;
	pn->used_channels = 0;
	for(i=0; i<10; i++) {
		pn->afh_map[i] = afh_map[i];
		/* bit 79 is reserved: there are only channels 0-78 */
		if (i == 9)
			pn->afh_map[i] &= 0x7f;
		pn->used_channels += count_bits(pn->afh_map[i]);
	}
	pn->afh_map_known = 1;
	if(btbb_piconet_get_flag(pn, BTBB_UAP_VALID))
		get_hop_pattern(pn);
}

uint8_t *btbb_piconet_get_afh_map(btbb_piconet *pn) {
	return pn->afh_map;
}

uint8_t btbb_piconet_set_channel_seen(btbb_piconet *pn, uint8_t channel)
{
	if (channel >= BT_NUM_CHANNELS)
		return 0;
	if(!(pn->afh_map[channel/8] & 0x1 << (channel % 8))) {
		pn->afh_map[channel/8] |= 0x1 << (channel % 8);
		pn->used_channels++;
		return 1;
	}
	return 0;
}

uint8_t btbb_piconet_clear_channel_seen(btbb_piconet *pn, uint8_t channel)
{
	if (channel >= BT_NUM_CHANNELS)
		return 0;
	if((pn->afh_map[channel/8] & 0x1 << (channel % 8))) {
		pn->afh_map[channel/8] &= ~(0x1 << (channel % 8));
		pn->used_channels--;
		return 1;
	}
	return 0;
}

uint8_t btbb_piconet_get_channel_seen(btbb_piconet *pn, uint8_t channel)
{
	if(channel < BT_NUM_CHANNELS)
		return ( pn->afh_map[channel/8] & (1 << (channel % 8)) ) != 0;
	else
		return 1;
}

/* Adaptive hopping is only possible with at least one used channel; with
 * an empty map fall back to basic hopping instead of dividing by zero.
 * Without the actual map (the channels the piconet was seen on are not
 * its map) the clock is searched for with the basic sequence: see
 * blind_winnow(). */
static int afh_active(const btbb_piconet *pn)
{
	return btbb_piconet_get_flag(pn, BTBB_IS_AFH) && pn->afh_map_known &&
	       (pn->used_channels > 0);
}

static int afh_blind(const btbb_piconet *pn)
{
	return btbb_piconet_get_flag(pn, BTBB_IS_AFH) && !pn->afh_map_known &&
	       !pn->aliased;
}

static int map_bit(const uint8_t *map, int channel)
{
	return (map[channel / 8] >> (channel % 8)) & 1;
}

/* do all the precalculation that can be done before knowing the address */
void precalc(btbb_piconet *pn)
{
	int i = 0;
	int j = 0;
	int chan;

	/* populate frequency register bank */
	/* actual frequency is 2402 + pn->bank[i] MHz */
	if (btbb_piconet_get_flag(pn, BTBB_IS_AFH) && pn->afh_map_known) {
		/* AFH is used: the remapping bank holds only the used channels */
		for (i = 0; i < BT_NUM_CHANNELS; i++) {
			chan = (i * 2) % BT_NUM_CHANNELS;
			if(btbb_piconet_get_channel_seen(pn, chan))
				pn->bank[j++] = chan;
		}
		/* The number of used channels must match the bank exactly,
		 * otherwise bank[] is indexed beyond the entries filled in
		 * above (the map is writable via btbb_piconet_get_afh_map()). */
		pn->used_channels = j;
	}

	if (!afh_active(pn)) {
		/* all channels are used */
		for (i = 0; i < BT_NUM_CHANNELS; i++)
			pn->bank[i] = ((i * 2) % BT_NUM_CHANNELS);
	}
}

/* do precalculation that requires the address */
void address_precalc(int address, btbb_piconet *pn)
{
	/* precalculate some of single_hop()/gen_hop()'s variables */
	pn->a1 = (address >> 23) & 0x1f;
	pn->b = (address >> 19) & 0x0f;
	pn->c1 = ((address >> 4) & 0x10) +
		((address >> 3) & 0x08) +
		((address >> 2) & 0x04) +
		((address >> 1) & 0x02) +
		(address & 0x01);
	pn->d1 = (address >> 10) & 0x1ff;
	pn->e = ((address >> 7) & 0x40) +
		((address >> 6) & 0x20) +
		((address >> 5) & 0x10) +
		((address >> 4) & 0x08) +
		((address >> 3) & 0x04) +
		((address >> 2) & 0x02) +
		((address >> 1) & 0x01);
}

#ifdef WC4
/* These are optimization experiments, which don't help much for
 * x86. Hold on to them to see whether they're useful on ARM. */

#ifdef NEVER
#define BUTTERFLY(z,p,c,a,b)					     \
	if ( ((p&(1<<c))!=0) & (((z&(1<<a))!=0) ^ ((z&(1<<b))!=0)) ) \
		z ^= ((1<<a)|(1<<b))
#endif

#define BUTTERFLY(z,p,c,a,b) \
	if ( (((z>>a)^(z>>b)) & (p>>c)) & 0x1 ) \
		z ^= ((1<<a)|(1<<b))

int perm5(int z, int p_high, int p_low)
{
	int p = (p_high << 5) | p_low;
	BUTTERFLY(z,p,13,1,2);
	BUTTERFLY(z,p,12,0,3);
	BUTTERFLY(z,p,11,1,3);
	BUTTERFLY(z,p,10,2,4);
	BUTTERFLY(z,p, 9,0,3);
	BUTTERFLY(z,p, 8,1,4);
	BUTTERFLY(z,p, 7,3,4);
	BUTTERFLY(z,p, 6,0,2);
	BUTTERFLY(z,p, 5,1,3);
	BUTTERFLY(z,p, 4,0,4);
	BUTTERFLY(z,p, 3,3,4);
	BUTTERFLY(z,p, 2,1,2);
	BUTTERFLY(z,p, 1,2,3);
	BUTTERFLY(z,p, 0,0,1);

	return z;
}
#endif // WC4

/* 5 bit permutation */
/* assumes z is constrained to 5 bits, p_high to 5 bits, p_low to 9 bits */
int perm5(int z, int p_high, int p_low)
{
	int i, tmp, output, z_bit[5], p[14];
	int index1[] = {0, 2, 1, 3, 0, 1, 0, 3, 1, 0, 2, 1, 0, 1};
	int index2[] = {1, 3, 2, 4, 4, 3, 2, 4, 4, 3, 4, 3, 3, 2};

	/* bits of p_low and p_high are control signals */
	for (i = 0; i < 9; i++)
		p[i] = (p_low >> i) & 0x01;
	for (i = 0; i < 5; i++)
		p[i+9] = (p_high >> i) & 0x01;

	/* bit swapping will be easier with an array of bits */
	for (i = 0; i < 5; i++)
		z_bit[i] = (z >> i) & 0x01;

	/* butterfly operations */
	for (i = 13; i >= 0; i--) {
		/* swap bits according to index arrays if control signal tells us to */
		if (p[i]) {
			tmp = z_bit[index1[i]];
			z_bit[index1[i]] = z_bit[index2[i]];
			z_bit[index2[i]] = tmp;
		}
	}

	/* reconstruct output from rearranged bits */
	output = 0;
	for (i = 0; i < 5; i++)
		output += z_bit[i] << i;

	return(output);
}

void perm_table_init(void)
{
	/* populate perm_table for all possible inputs */
	int z, p_high, p_low;
	for (z = 0; z < 0x20; z++)
		for (p_high = 0; p_high < 0x20; p_high++)
			for (p_low = 0; p_low < 0x200; p_low++)
				perm_table[p_high][p_low][z] = perm5(z, p_high, p_low);
}

/* drop-in replacement for perm5() using lookup table */
int fast_perm(int z, int p_high, int p_low)
{
	if (!perm_table_initialized) {
		perm_table_init();
		perm_table_initialized = 1;
	}

	return(perm_table[p_high][p_low][z]);
}

/* generate the complete hopping sequence */
static void gen_hops(btbb_piconet *pn)
{
	/* a, b, c, d, e, f, x, y1, y2 are variable names used in section 2.6 of the spec */
	/* b is already defined */
	/* e is already defined */
	int a, c, d, x;
	uint32_t base_f, f;
	int h, i, j, k, c_flipped, perm_in, perm_out;
	int afh = afh_active(pn);
	/* modulus and frequency offset used for the register bank:
	 * basic hopping: F  = 16 * CLK27-7 mod 79
	 * AFH:           F' = 16 * CLK27-7 mod N  (N = number of used channels) */
	uint32_t n = afh ? pn->used_channels : BT_NUM_CHANNELS;
	int base = pn->e;
	uint32_t f79 = 0;
	char used[BT_NUM_CHANNELS];

	for (i = 0; i < BT_NUM_CHANNELS; i++)
		used[i] = afh ? map_bit(pn->afh_map, i) : 1;

	/* the sums below stay under 320: a channel for each, by table */
	char ch79[320], bankn[320];
	for (i = 0; i < 320; i++) {
		ch79[i] = (char)((i % BT_NUM_CHANNELS) * 2 % BT_NUM_CHANNELS);
		bankn[i] = (char)pn->bank[i % n];
	}
	if (!perm_table_initialized) {
		perm_table_init();
		perm_table_initialized = 1;
	}

	/* sequence index = clock >> 1 */
	/* (hops only happen at every other clock value) */
	int index = 0;
	base_f = 0;
	f = 0;

	/* nested loops for optimization (not recalculating every variable with every clock tick) */
	for (h = 0; h < 0x04; h++) { /* clock bits 26-27 */
		for (i = 0; i < 0x20; i++) { /* clock bits 21-25 */
			a = pn->a1 ^ i;
			for (j = 0; j < 0x20; j++) { /* clock bits 16-20 */
				c = pn->c1 ^ j;
				c_flipped = c ^ 0x1f;
				for (k = 0; k < 0x200; k++) { /* clock bits 7-15 */
					/* PERM5 for the 32 values of X: one table row each
					 * for y1 = 0 and y1 = 1 */
					const char *row0, *row1;
					int o0 = base + f, o1 = base + f + 32, o79 = base + f79;
					char *seq = pn->sequence + index;
					d = pn->d1 ^ k;
					row0 = perm_table[c][d];
					row1 = perm_table[c_flipped][d];
					for (x = 0; x < 0x20; x++) { /* clock bits 2-6 */
						perm_in = ((x + a) & 0x1f) ^ pn->b;
						perm_out = row0[perm_in];
						if (afh) {
							/* adapted hopping: the basic channel if it
							 * is used, else a remapped one; the slave
							 * answers on the master's channel */
							char ch = ch79[perm_out + o79];
							if (!used[(int)ch])
								ch = bankn[perm_out + o0];
							seq[2 * x] = seq[2 * x + 1] = ch;
						} else {
							/* y1 = 0, y2 = 0; then y1 = 1, y2 = 32 */
							seq[2 * x] = bankn[perm_out + o0];
							seq[2 * x + 1] = bankn[row1[perm_in] + o1];
						}
					}
					index += 0x40;
					base_f += 16;
					f = base_f % n;
					f79 = base_f % BT_NUM_CHANNELS;
				}
			}
		}
	}
}

/* Calculate the complete hopping pattern for the piconet's current
 * address and AFH map.  The sequence buffer is owned by the piconet. */
void gen_hop_pattern(btbb_piconet *pn)
{
	printf("\nCalculating complete hopping sequence.\n");
	/* this holds the entire hopping sequence */
	if (pn->sequence == NULL)
		pn->sequence = (char*) malloc(SEQUENCE_LENGTH);
	if (pn->sequence == NULL) {
		fprintf(stderr, "Unable to allocate hopping sequence\n");
		pn->seq_valid = 0;
		return;
	}

	precalc(pn);
	address_precalc((((uint32_t)pn->UAP<<24) | pn->LAP) & 0xfffffff, pn);
	gen_hops(pn);

	pn->seq_valid = 1;
	pn->seq_lap_uap = ((uint32_t)pn->UAP << 24) | pn->LAP;
	pn->seq_afh = afh_active(pn);
	memcpy(pn->seq_afh_map, pn->afh_map, sizeof(pn->seq_afh_map));

	printf("Hopping sequence calculated.\n");
}

/* Make sure pn->sequence holds the hopping pattern for the piconet's
 * current address, AFH flag and AFH channel map.  The (128 MiB) sequence
 * is only regenerated when one of those has changed. */
void get_hop_pattern(btbb_piconet *pn)
{
	uint32_t lap_uap = ((uint32_t)pn->UAP << 24) | pn->LAP;
	int afh = btbb_piconet_get_flag(pn, BTBB_IS_AFH);

	if (afh) {
		int i;
		pn->afh_map[9] &= 0x7f; /* channel 79 does not exist */
		pn->used_channels = 0;
		for (i = 0; i < 10; i++)
			pn->used_channels += count_bits(pn->afh_map[i]);
	}

	afh = afh_active(pn);
	if (pn->sequence && pn->seq_valid &&
	    pn->seq_lap_uap == lap_uap &&
	    pn->seq_afh == afh &&
	    (!pn->seq_afh ||
	     memcmp(pn->seq_afh_map, pn->afh_map, sizeof(pn->seq_afh_map)) == 0)) {
		printf("\nReusing previously calculated hopping sequence.\n");
		return;
	}
	gen_hop_pattern(pn);
}

/* determine channel for a particular hop */
/* borrowed from ubertooth firmware to support AFH */
char single_hop(int clock, btbb_piconet *pn)
{
	int a, c, d, x, y1, y2, perm, next_channel;
	uint32_t base_f, f, f_dash;

	/* following variable names used in section 2.6 of the spec */
	x = (clock >> 2) & 0x1f;
	y1 = (clock >> 1) & 0x01;
	y2 = y1 << 5;
	a = (pn->a1 ^ (clock >> 21)) & 0x1f;
	/* b is already defined */
	c = (pn->c1 ^ (clock >> 16)) & 0x1f;
	d = (pn->d1 ^ (clock >> 7)) & 0x1ff;
	/* e is already defined */
	base_f = (clock >> 3) & 0x1fffff0;
	f = base_f % BT_NUM_CHANNELS;

	perm = fast_perm(
		((x + a) % 32) ^ pn->b,
		(y1 * 0x1f) ^ c,
		d);
	/* hop selection */
	if(afh_active(pn)) {
		/* adapted hopping: the master's slot decides for both slots */
		perm = fast_perm(((x + a) % 32) ^ pn->b, c, d);
		next_channel = ((perm + pn->e + f) % BT_NUM_CHANNELS) * 2 % BT_NUM_CHANNELS;
		if (!map_bit(pn->afh_map, next_channel)) {
			f_dash = base_f % pn->used_channels;
			next_channel = pn->bank[(perm + pn->e + f_dash) % pn->used_channels];
		}
	} else {
		next_channel = pn->bank[(perm + pn->e + f + y2) % BT_NUM_CHANNELS];
	}
	return next_channel;
}

/* look up channel for a particular hop */
char hop(int clock, btbb_piconet *pn)
{
	if (!pn->sequence)
		return -1;
	return pn->sequence[(uint32_t)clock % SEQUENCE_LENGTH];
}

static char aliased_channel(char channel)
{
	return ((channel + 24) % ALIASED_CHANNELS) + 26;
}

/* create list of initial candidate clock values (hops with same channel as first observed hop) */
static int init_candidates(char channel, int known_clock_bits, btbb_piconet *pn)
{
	int i;
	uint32_t count = 0; /* total number of candidates */
	char observable_channel; /* accounts for aliasing if necessary */

	/* only try clock values that match our known bits */
	for (i = known_clock_bits; i < SEQUENCE_LENGTH; i += 0x40) {
		if (pn->aliased)
			observable_channel = aliased_channel(pn->sequence[i]);
		else
			observable_channel = pn->sequence[i];
		if (observable_channel == channel) {
			/* can't happen with max_candidates = SEQUENCE_LENGTH/64,
			 * but never write past the buffer */
			if (count >= pn->max_candidates)
				break;
			pn->clock_candidates[count++] = i;
		}
	}
	return (int) count;
}

/* initialize the hop reversal process */
int btbb_init_hop_reversal(int aliased, btbb_piconet *pn)
{
	uint32_t clock;

	pn->aliased = aliased;
	get_hop_pattern(pn);
	if (!pn->sequence || !pn->seq_valid)
		return 0;

	/* Exact upper bound on the number of candidates: one per 64 clock
	 * values (CLK1-6 is known).  With AFH and few used channels nearly
	 * every position can match the first observed channel, so any
	 * estimate based on 79 (or 25 aliased) channels can overflow. */
	pn->max_candidates = SEQUENCE_LENGTH / 64;
	free(pn->clock_candidates);
	pn->clock_candidates = (uint32_t*) malloc(sizeof(uint32_t) * pn->max_candidates);
	if (!pn->clock_candidates) {
		fprintf(stderr, "Unable to allocate clock candidates\n");
		pn->max_candidates = 0;
		pn->num_candidates = 0;
		return 0;
	}

	clock = (pn->clk_offset + pn->first_pkt_time) & 0x3f;
	if (afh_blind(pn)) {
		/* every clock with the known CLK1-6; the hops sort them out */
		uint32_t i;
		free(pn->cand_hits);
		pn->cand_hits = (uint8_t*) calloc(pn->max_candidates, 1);
		if (!pn->cand_hits) {
			pn->num_candidates = 0;
			return 0;
		}
		for (i = 0; i < pn->max_candidates; i++)
			pn->clock_candidates[i] = clock + (i << 6);
		pn->num_candidates = pn->max_candidates;
		memset(pn->afh_seen, 0, sizeof(pn->afh_seen));
		printf("AFH: channel map unknown, using the map-free clock search\n");
	} else {
		pn->num_candidates = init_candidates(pn->pattern_channels[0], clock, pn);
	}
	pn->winnowed = 0;
	btbb_piconet_set_flag(pn, BTBB_HOP_REVERSAL_INIT, 1);
	btbb_piconet_set_flag(pn, BTBB_CLK27_VALID, 0);
	btbb_piconet_set_flag(pn, BTBB_IS_ALIASED, aliased);

	printf("%d initial CLK1-27 candidates\n", pn->num_candidates);

	return pn->num_candidates;
}

void try_hop(btbb_packet *pkt, btbb_piconet *pn)
{
	uint8_t filter_uap = pn->UAP;

	/* Decode packet - fixing clock drift in the process */
	btbb_decode(pkt);

	if (btbb_piconet_get_flag(pn, BTBB_HOP_REVERSAL_INIT)) {
		/* one packet seen on two channels (a receiver covering several):
		 * keep the first */
		if (pn->packets_observed > 0 &&
		    pn->pattern_indices[pn->packets_observed - 1] ==
		    (int)(pkt->clkn - pn->first_pkt_time))
			return;
		/* only a packet whose header checks with the UAP and CLK1-6 joins
		 * the pattern: a stray or forged access code would rule out the
		 * right clock */
		{
			uint8_t uap = pkt->UAP, type = pkt->packet_type;
			int ok = try_clock((pn->clk_offset + pkt->clkn) & 0x3f, pkt) == pn->UAP;
			pkt->UAP = uap;
			pkt->packet_type = type;
			if (!ok)
				return;
		}
		if (pn->packets_observed >= MAX_PATTERN_LENGTH) {
			printf("Oops. More hops than we can remember.\n");
			reset(pn);
			return;
		}
		pn->pattern_indices[pn->packets_observed] =
			pkt->clkn - pn->first_pkt_time;
		pn->pattern_channels[pn->packets_observed] = pkt->channel;
		pn->packets_observed++;
		pn->total_packets_observed++;
		btbb_winnow(pn);
		if (btbb_piconet_get_flag(pn, BTBB_CLK27_VALID)) {
			printf("got CLK1-27\n");
			printf("clock offset = %d.\n", pn->clk_offset);
		}
	} else {
		if (btbb_piconet_get_flag(pn, BTBB_CLK6_VALID)) {
			btbb_uap_from_header(pkt, pn);
			if (btbb_piconet_get_flag(pn, BTBB_CLK27_VALID)) {
				printf("got CLK1-27\n");
				printf("clock offset = %d.\n", pn->clk_offset);
			}
		} else {
			if (btbb_uap_from_header(pkt, pn)) {
				if (filter_uap == pn->UAP) {
					btbb_init_hop_reversal(0, pn);
					btbb_winnow(pn);
				} else {
					printf("failed to confirm UAP\n");
				}
			}
		}
	}

	if(!btbb_piconet_get_flag(pn, BTBB_UAP_VALID)) {
		btbb_piconet_set_flag(pn, BTBB_UAP_VALID, 1);
		pn->UAP = filter_uap;
	}
}

/* return the observable channel (26-50) for a given channel (0-78) */
/* reset UAP/clock discovery */
static void reset(btbb_piconet *pn)
{
	//printf("no candidates remaining! starting over . . .\n");
	/* a clock search that failed with basic hopping tries adapted hopping
	 * (without the map) next, and back */
	int searched = btbb_piconet_get_flag(pn, BTBB_HOP_REVERSAL_INIT);
	int next_afh = btbb_piconet_get_flag(pn, BTBB_LOOKS_LIKE_AFH) ||
	               (searched ? !btbb_piconet_get_flag(pn, BTBB_IS_AFH)
	                         : btbb_piconet_get_flag(pn, BTBB_IS_AFH));
	if (pn->afh_map_known == 1)
		next_afh = btbb_piconet_get_flag(pn, BTBB_IS_AFH);   /* as given */

	if(btbb_piconet_get_flag(pn, BTBB_HOP_REVERSAL_INIT)) {
		free(pn->clock_candidates);
		pn->clock_candidates = NULL;
		pn->max_candidates = 0;
		pn->num_candidates = 0;
		/* pn->sequence is kept: it is owned by the piconet and is
		 * reused (or regenerated) by get_hop_pattern() */
	}
	btbb_piconet_set_flag(pn, BTBB_GOT_FIRST_PACKET, 0);
	btbb_piconet_set_flag(pn, BTBB_HOP_REVERSAL_INIT, 0);
	btbb_piconet_set_flag(pn, BTBB_UAP_VALID, 0);
	btbb_piconet_set_flag(pn, BTBB_CLK6_VALID, 0);
	btbb_piconet_set_flag(pn, BTBB_CLK27_VALID, 0);
	pn->packets_observed = 0;
	if (pn->afh_map_known == 2) {
		/* a deduced map goes with the clock it was deduced with */
		pn->afh_map_known = 0;
		memset(pn->afh_map, 0, sizeof(pn->afh_map));
		pn->used_channels = 0;
	}

	/*
	 * If we have recently observed two packets in a row on the same
	 * channel, or basic hopping just failed, try AFH next time.
	 */
	btbb_piconet_set_flag(pn, BTBB_IS_AFH, next_afh);
	// btbb_piconet_set_flag(pn, BTBB_LOOKS_LIKE_AFH, 0);
	//int i;
	//for(i=0; i<10; i++)
	//	pn->afh_map[i] = 0;
}

/* narrow a list of candidate clock values based on a single observed hop */
static int channel_winnow(int offset, char channel, btbb_piconet *pn)
{
	int i;
	int new_count = 0; /* number of candidates after winnowing */
	char observable_channel; /* accounts for aliasing if necessary */

	/* check every candidate */
	for (i = 0; i < pn->num_candidates; i++) {
		if (pn->aliased)
			observable_channel = aliased_channel(pn->sequence[(pn->clock_candidates[i] + offset) % SEQUENCE_LENGTH]);
		else
			observable_channel = pn->sequence[(pn->clock_candidates[i] + offset) % SEQUENCE_LENGTH];
		if (observable_channel == channel) {
			/* this candidate matches the latest hop */
			/* blow away old list of candidates with new one */
			/* safe because new_count can never be greater than i */
			pn->clock_candidates[new_count++] = pn->clock_candidates[i];
		}
	}
	pn->num_candidates = new_count;

	if (new_count == 1) {
		// Calculate clock offset for CLKN, not CLK1-27
		pn->clk_offset = ((pn->clock_candidates[0]<<1) - (pn->first_pkt_time<<1));
		printf("\nAcquired CLK1-27 = 0x%07x\n", pn->clock_candidates[0]);
		btbb_piconet_set_flag(pn, BTBB_CLK27_VALID, 1);
	}
	else if (new_count == 0) {
		reset(pn);
	}
	//else {
	//printf("%d CLK1-27 candidates remaining (channel=%d)\n", new_count, channel);
	//}

	return new_count;
}

/*
 * AFH without the channel map.
 *
 * Adapted hopping keeps the basic sequence's channel whenever that channel
 * is used and replaces it (from the map) only when it is not; the slave
 * answers on the master's channel. So for a candidate clock a packet on
 * channel ch in slot i (master slot m = i rounded down to even) says:
 *   basic(m) == ch            a hit: about N/79 of the packets for the right
 *                             clock (N used channels), 1/79 otherwise
 *   basic(m) seen in use      a contradiction: a used channel is never
 *                             remapped, so the clock is wrong (or the packet)
 *   otherwise                 basic(m) may be an unused channel: no evidence
 * A candidate scores 2 per hit and -1 per contradiction (roughly the log
 * likelihood ratio), is dropped when its contradictions outnumber its hits
 * by more than BLIND_MAX_MISSES, and is taken when it leads the next by
 * BLIND_MARGIN with at least BLIND_MIN_SCORE.
 */
#define BLIND_MAX_MISSES  3
#define BLIND_MIN_SCORE   16
#define BLIND_MARGIN      8
#define BLIND_RESCORE_MAX 50000000ULL  /* candidate-hops for a full rescoring */
#define CAND_CLK(c)       ((c) & 0x7ffffff)
#define CAND_MISSES(c)    ((c) >> 27)

static int blind_hop(btbb_piconet *pn, uint32_t cand, int j)
{
	uint32_t slot = (cand + pn->pattern_indices[j]) & ~1u;
	int b = pn->sequence[slot % SEQUENCE_LENGTH];
	if (b == pn->pattern_channels[j])
		return 1;
	return map_bit(pn->afh_seen, b) ? -1 : 0;
}

/* the kernel's channel index before the final addition of F: perm + E
 * (master slot, CLK1 = 0) */
static int kernel_index(uint32_t clk1_27, btbb_piconet *pn)
{
	uint32_t clock = clk1_27 << 1;
	int x = (clock >> 2) & 0x1f;
	int a = (pn->a1 ^ (clock >> 21)) & 0x1f;
	int c = (pn->c1 ^ (clock >> 16)) & 0x1f;
	int d = (pn->d1 ^ (clock >> 7)) & 0x1ff;
	return fast_perm(((x + a) % 32) ^ pn->b, c, d) + pn->e;
}

/* remapped hops a map predicts: (master slot, channel) pairs whose basic
 * channel was not the observed one */
static int remap_score(const char *used, const uint32_t *slot, const uint8_t *chan,
                       const int *kidx, int nobs)
{
	int bank[BT_NUM_CHANNELS], n = 0, i, score = 0;
	for (i = 0; i < BT_NUM_CHANNELS; i++) {
		int ch = (i * 2) % BT_NUM_CHANNELS;
		if (used[ch])
			bank[n++] = ch;
	}
	if (n == 0)
		return -1;
	for (i = 0; i < nobs; i++) {
		uint32_t base_f = (slot[i] >> 6) * 16;
		if (bank[(kidx[i] + base_f % n) % n] == chan[i])
			score++;
	}
	return score;
}

#define DEDUCE_MIN_REMAPS 24   /* remapped packets needed to confirm a map */
#define DEDUCE_EVERY      16   /* packets between attempts */

/* position of a channel in the remapping bank's order 0, 2, ..., 78, 1, ..., 77 */
static int bank_pos(int ch)
{
	return (ch & 1) ? 40 + (ch - 1) / 2 : ch / 2;
}

/*
 * With the clock known, every packet classifies its slot's basic channel:
 * used if the packet is on it, unused if not. A used channel outside the
 * receiver's view never shows up, so that alone leaves channels undecided.
 * A remapped packet adds more: its channel's rank among the used channels
 * (in bank order) is (perm + E + F') mod N. For the right N the ranks of
 * the channels in view agree, and the rank differences say how many used
 * channels lie between them, which the unused votes then place.
 * Returns 1 when the map was set.
 */
static int afh_deduce_map(btbb_piconet *pn, uint32_t clk, int from,
                          uint8_t *map_out, char *head, char *detail, size_t len)
{
	const char *why = NULL;   /* the first reason the map is not certain */
	int votes_used[BT_NUM_CHANNELS] = { 0 }, votes_unused[BT_NUM_CHANNELS] = { 0 };
	int state[BT_NUM_CHANNELS];      /* 1 used, -1 unused, 0 undecided */
	int rank[BT_NUM_CHANNELS], rvotes[BT_NUM_CHANNELS][BT_NUM_CHANNELS];
	int nobs = 0, direct = 0, j, i, n, best_n = 0, best_agree = -1, agree;
	int nused = 0, ambiguous = 0, inconsistent = 0, predicted = 0, done = 0, score;
	int guessed = 0, noise = 0, from_votes = 0;
	char used[BT_NUM_CHANNELS];
	uint32_t *slot = malloc(sizeof(uint32_t) * pn->packets_observed);
	uint8_t *chan = malloc(pn->packets_observed);
	int *kidx = malloc(sizeof(int) * pn->packets_observed);
	uint8_t map[10] = { 0 };

	snprintf(head, len, "unknown");
	snprintf(detail, len, "(out of memory)");
	if (!slot || !chan || !kidx)
		goto out;
	address_precalc(((uint32_t)pn->UAP << 24 | pn->LAP) & 0xfffffff, pn);
	for (j = from; j < pn->packets_observed; j++) {
		uint32_t m = (clk + pn->pattern_indices[j]) & ~1u & 0x7ffffff;
		int ch = pn->pattern_channels[j];
		int ki = kernel_index(m, pn);
		int b = ((ki + (m >> 6) * 16) % BT_NUM_CHANNELS) * 2 % BT_NUM_CHANNELS;
		votes_used[ch]++;
		if (b == ch) {
			direct++;
		} else {
			votes_unused[b]++;
			slot[nobs] = m;
			chan[nobs] = ch;
			kidx[nobs] = ki;
			nobs++;
		}
	}
	{
		/* used channels in view all carry a similar share of the packets;
		 * a trickle (false or misplaced detections) on a channel the
		 * packets also call unused does not make it used */
		int mx = 0, trickle;
		for (i = 0; i < BT_NUM_CHANNELS; i++)
			if (votes_used[i] > mx)
				mx = votes_used[i];
		trickle = mx / 8 > 2 ? mx / 8 : 2;
		for (i = 0; i < BT_NUM_CHANNELS; i++) {
			state[i] = votes_used[i] > votes_unused[i] ? 1 :
			           votes_used[i] < votes_unused[i] ? -1 : 0;
			if (votes_unused[i] > 0 && votes_used[i] < trickle)
				state[i] = -1;
		}
	}
	{
		/* a packet off a used basic channel was not remapped (used channels
		 * never are), nor is one on an unused channel: such packets are
		 * detections on the wrong channel and say nothing about ranks */
		int k = 0;
		for (j = 0; j < nobs; j++) {
			int b = ((kidx[j] + (slot[j] >> 6) * 16) % BT_NUM_CHANNELS) * 2 % BT_NUM_CHANNELS;
			if (state[b] == 1 || state[chan[j]] == -1) {
				noise++;
				continue;
			}
			slot[k] = slot[j];
			chan[k] = chan[j];
			kidx[k] = kidx[j];
			k++;
		}
		nobs = k;
	}

	/* N: the number of used channels whose ranks agree best. Ranks that
	 * agree mod N also agree mod every divisor of N, so the largest N within
	 * 5% of the best agreement */
	int agree_n[BT_NUM_CHANNELS + 1];
	for (n = 20; n <= BT_NUM_CHANNELS; n++) {
		memset(rvotes, 0, sizeof(rvotes));
		for (j = 0; j < nobs; j++)
			rvotes[chan[j]][(kidx[j] + (slot[j] >> 6) * 16 % n) % n]++;
		agree = 0;
		for (i = 0; i < BT_NUM_CHANNELS; i++) {
			int r, mx = 0;
			for (r = 0; r < n; r++)
				if (rvotes[i][r] > mx)
					mx = rvotes[i][r];
			agree += mx;
		}
		agree_n[n] = agree;
		if (agree > best_agree)
			best_agree = agree;
	}
	for (n = 20; n <= BT_NUM_CHANNELS; n++)
		if (agree_n[n] * 20 >= best_agree * 19)
			best_n = n;
	n = best_n;
	memset(rvotes, 0, sizeof(rvotes));
	for (j = 0; j < nobs; j++)
		rvotes[chan[j]][(kidx[j] + (slot[j] >> 6) * 16 % n) % n]++;
	for (i = 0; i < BT_NUM_CHANNELS; i++) {
		int r, mx = 0, tot = 0;
		rank[i] = -1;
		for (r = 0; r < n; r++) {
			tot += rvotes[i][r];
			if (rvotes[i][r] > mx) {
				mx = rvotes[i][r];
				rank[i] = r;
			}
		}
		/* an anchor: a used channel with a clear rank */
		if (state[i] != 1 || mx < 2 || mx * 3 < tot * 2)
			rank[i] = -1;
	}

	/* walk the bank order from anchor to anchor, filling each gap */
	{
		int order[BT_NUM_CHANNELS], na = 0, a, first = -1;
		for (i = 0; i < BT_NUM_CHANNELS; i++)
			order[bank_pos(i)] = i;
		for (i = 0; i < BT_NUM_CHANNELS; i++)
			used[i] = state[i] == 1;
		for (i = 0; i < BT_NUM_CHANNELS; i++)
			if (rank[order[i]] >= 0) {
				na++;
				if (first < 0)
					first = i;
			}
		if (na == 0) {
			ambiguous = 1;
		} else {
			a = first;
			do {
				int b = (a + 1) % BT_NUM_CHANNELS, ku = 0, und = 0, need;
				while (rank[order[b]] < 0) {
					ku += state[order[b]] == 1;
					und += state[order[b]] == 0;
					b = (b + 1) % BT_NUM_CHANNELS;
				}
				need = (rank[order[b]] - rank[order[a]] - 1 + n) % n;
				if (na == 1)
					need = n - 1;
				if (need < ku || need > ku + und) {
					inconsistent++;
				} else if (und > 0) {
					/* all or none of the undecided channels, or else (maps
					 * mark blocks of channels unused) the ones whose
					 * neighbors in frequency look used; the comparison with
					 * nearby maps below has the last word */
					int want = need - ku;
					for (i = (a + 1) % BT_NUM_CHANNELS; i != b; i = (i + 1) % BT_NUM_CHANNELS)
						if (state[order[i]] == 0)
							used[order[i]] = want == und;
					while (want > 0 && want < und) {
						int pick = -1, pick_score = -100, ch, q;
						for (i = (a + 1) % BT_NUM_CHANNELS; i != b; i = (i + 1) % BT_NUM_CHANNELS) {
							int sc = 0;
							ch = order[i];
							if (state[ch] != 0 || used[ch])
								continue;
							for (q = -2; q <= 2; q++)
								if (q && ch + q >= 0 && ch + q < BT_NUM_CHANNELS)
									sc += state[ch + q] ? state[ch + q] : used[ch + q];
							if (sc > pick_score) {
								pick_score = sc;
								pick = ch;
							}
						}
						used[pick] = 1;
						want--;
						guessed++;
					}
				}
				a = b;
			} while (a != first);
		}
	}
	/* The votes alone, when they leave few channels undecided (a receiver
	 * that scans the band sees nearly all of them): the undecided ones by
	 * remap prediction. Taken when the ranks gave no map or a worse one. */
	{
		char vused[BT_NUM_CHANNELS];
		int vund[BT_NUM_CHANNELS], nv = 0, mask, best_mask = 0, vbest = -1, nr = 0;
		for (i = 0; i < BT_NUM_CHANNELS; i++) {
			vused[i] = state[i] == 1;
			if (state[i] == 0)
				vund[nv++] = i;
			nr += used[i];
		}
		if (nv <= 12) {
			for (mask = 0; mask < (1 << nv); mask++) {
				for (i = 0; i < nv; i++)
					vused[vund[i]] = (mask >> i) & 1;
				score = remap_score(vused, slot, chan, kidx, nobs);
				if (score > vbest) {
					vbest = score;
					best_mask = mask;
				}
			}
			for (i = 0; i < nv; i++)
				vused[vund[i]] = (best_mask >> i) & 1;
			if (ambiguous || inconsistent || guessed || nr != n ||
			    vbest > remap_score(used, slot, chan, kidx, nobs)) {
				memcpy(used, vused, sizeof(used));
				from_votes = 1;
			}
		}
	}
	for (i = 0; i < BT_NUM_CHANNELS; i++) {
		if (used[i]) {
			map[i / 8] |= 1 << (i % 8);
			nused++;
		}
	}
	predicted = remap_score(used, slot, chan, kidx, nobs);
	if (from_votes) {
		/* only when every channel has at least two votes, all one way:
		 * remap predictions cannot tell nearby maps apart */
		int firm = 1;
		for (i = 0; i < BT_NUM_CHANNELS; i++)
			if (votes_used[i] + votes_unused[i] < 2 || (votes_used[i] && votes_unused[i]))
				firm = 0;
		why = !firm ? "too few votes per channel" : nused < 20 ? "fewer than 20 channels" : NULL;
	} else {
		why = ambiguous ? "no ranked channels" : inconsistent ? "ranks inconsistent" :
		      guessed ? "gaps inferred" : nused != n ? "channel count mismatch" : NULL;
	}
	if (!why)
		why = nobs < DEDUCE_MIN_REMAPS ? "too few remaps" :
		      predicted * 5 < nobs * 4 ? "poor prediction" : NULL;   /* right maps: 95-99% */
	done = why == NULL;
	if (done && !from_votes) {
		/* A gap filled with a channel the receiver saw (packets within
		 * three channels on both sides) but that carried none, while the
		 * other used channels carry several each, is more likely a swap
		 * the remapped packets cannot see. */
		int sum = 0, cnt = 0, lo, hi, q;
		for (i = 0; i < BT_NUM_CHANNELS; i++)
			if (state[i] == 1) {
				sum += votes_used[i];
				cnt++;
			}
		for (i = 0; i < BT_NUM_CHANNELS && cnt && sum >= 4 * cnt; i++) {
			if (!used[i] || state[i] != 0)
				continue;
			lo = hi = 0;
			for (q = 1; q <= 3; q++) {
				if (i - q >= 0 && votes_used[i - q])
					lo = 1;
				if (i + q < BT_NUM_CHANNELS && votes_used[i + q])
					hi = 1;
			}
			if (lo && hi) {
				done = 0;
				why = "silent channel in a gap";
			}
		}
	}
	if (done) {
		/* and clearly better than every map one or two channels (of one
		 * state) away. A map from the votes only competes with changes to
		 * weakly voted channels: none, one, or votes both ways. */
		char weak[BT_NUM_CHANNELS];
		int rival = 0, k;
		for (i = 0; i < BT_NUM_CHANNELS; i++)
			weak[i] = !from_votes || state[i] == 0 ||
			          votes_used[i] + votes_unused[i] <= 1 ||
			          (votes_used[i] && votes_unused[i]);
		for (i = 0; i < BT_NUM_CHANNELS; i++) {
			used[i] ^= 1;
			if (weak[i]) {
				score = remap_score(used, slot, chan, kidx, nobs);
				if (score > rival)
					rival = score;
			}
			/* and with a second channel of the same state changed too */
			for (k = i + 1; k < BT_NUM_CHANNELS; k++) {
				if (used[k] == used[i] || !(weak[i] || weak[k]))
					continue;
				used[k] ^= 1;
				score = remap_score(used, slot, chan, kidx, nobs);
				if (score > rival)
					rival = score;
				used[k] ^= 1;
			}
			used[i] ^= 1;
		}
		done = predicted >= rival + 3;
		if (!done)
			why = "nearby maps fit as well";
	}
	if (done) {
		/* A swap of a used and an unused channel that the remapped packets
		 * barely notice must be ruled out by the votes: one of the two
		 * channels, if both were in view, voted firmly the deduced way. */
		char seen[BT_NUM_CHANNELS];
		int k, q;
		for (i = 0; i < BT_NUM_CHANNELS; i++) {
			int lo = 0, hi = 0;
			for (q = 0; q <= 3; q++) {
				if (i - q >= 0 && votes_used[i - q])
					lo = 1;
				if (i + q < BT_NUM_CHANNELS && votes_used[i + q])
					hi = 1;
			}
			seen[i] = lo && hi;
		}
		for (i = 0; i < BT_NUM_CHANNELS && done; i++) {
			if (!used[i] || !seen[i] || votes_used[i] - votes_unused[i] >= 2)
				continue;
			for (k = 0; k < BT_NUM_CHANNELS && done; k++) {
				if (used[k] || !seen[k] || votes_unused[k] - votes_used[k] >= 2)
					continue;
				used[i] = 0;
				used[k] = 1;
				score = remap_score(used, slot, chan, kidx, nobs);
				used[i] = 1;
				used[k] = 0;
				if (score > predicted - 3) {
					done = 0;
					why = "swap unresolved";
				}
			}
		}
	}
	snprintf(head, len, "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x: %d channels",
	         map[0], map[1], map[2], map[3], map[4], map[5], map[6], map[7], map[8], map[9],
	         nused);
	snprintf(detail, len, "(%d packets, %d/%d remaps predicted%s%s)",
	         pn->packets_observed - from, predicted, nobs, why ? "; " : "", why ? why : "");
	(void)direct;
	(void)noise;
	memcpy(map_out, map, sizeof(map));
out:
	free(slot);
	free(chan);
	free(kidx);
	return done;
}

/*
 * Masters change the map as interference moves (often every minute or so),
 * so the map is deduced from the most recent packets: the longest of the
 * trailing windows below that gives a certain map (a window across a change
 * comes out inconsistent). Returns 1 when the map was set or changed.
 */
static const int deduce_windows[] = { 64, 128, 256, 512, MAX_PATTERN_LENGTH };

static int afh_update_map(btbb_piconet *pn, uint32_t clk)
{
	uint8_t map[10], best[10];
	char head[120], detail[120], best_head[120], best_detail[120];
	char last_head[120] = "", last_detail[120] = "";
	int i, found = 0;

	for (i = 0; i < (int)(sizeof(deduce_windows) / sizeof(deduce_windows[0])); i++) {
		int from = pn->packets_observed - deduce_windows[i];
		if (from < 0)
			from = 0;
		if (afh_deduce_map(pn, clk, from, map, head, detail, sizeof(head))) {
			memcpy(best, map, sizeof(best));
			memcpy(best_head, head, sizeof(best_head));
			memcpy(best_detail, detail, sizeof(best_detail));
			found = 1;
		} else if (!found) {
			memcpy(last_head, head, sizeof(last_head));
			memcpy(last_detail, detail, sizeof(last_detail));
		}
		if (from == 0)
			break;
	}
	if (!found) {
		if (!pn->afh_map_known && pn->packets_observed % (4 * DEDUCE_EVERY) == 0)
			printf("AFH map %s, tentative %s\n", last_head, last_detail);
		return 0;
	}
	if (pn->afh_map_known && memcmp(best, pn->afh_map, sizeof(best)) == 0)
		return 0;
	printf("AFH map %s, %s %s\n", best_head, pn->afh_map_known ? "changed" : "deduced",
	       best_detail);
	/* the 128 MiB sequence is regenerated only when something asks for it
	 * (get_hop_pattern): doing it here stalled live receivers */
	memcpy(pn->afh_map, best, sizeof(pn->afh_map));
	pn->used_channels = 0;
	for (i = 0; i < 10; i++)
		pn->used_channels += count_bits(pn->afh_map[i]);
	pn->afh_map_known = 2;  /* deduced: dropped again if the clock is lost */
	return 1;
}

/* After the clock: keep the recent packets to deduce the map and follow
 * its changes (a given map is left alone). */
static void afh_map_observe(btbb_piconet *pn, btbb_packet *pkt, uint32_t rx_clkn)
{
	int idx = (int)(rx_clkn - pn->first_pkt_time);
	if (pn->afh_map_known == 1)
		return;
	if (pn->packets_observed > 0 && pn->pattern_indices[pn->packets_observed - 1] == idx)
		return;
	if (pn->packets_observed >= MAX_PATTERN_LENGTH) {
		int keep = MAX_PATTERN_LENGTH / 2;
		memmove(pn->pattern_indices, pn->pattern_indices + pn->packets_observed - keep,
		        keep * sizeof(pn->pattern_indices[0]));
		memmove(pn->pattern_channels, pn->pattern_channels + pn->packets_observed - keep,
		        keep * sizeof(pn->pattern_channels[0]));
		pn->packets_observed = keep;
	}
	pn->pattern_indices[pn->packets_observed] = idx;
	pn->pattern_channels[pn->packets_observed] = pkt->channel;
	pn->packets_observed++;
	if (++pn->since_deduce >= DEDUCE_EVERY && !behind) {
		pn->since_deduce = 0;
		afh_update_map(pn, (pn->clk_offset + (pn->first_pkt_time << 1)) >> 1 & 0x7ffffff);
	}
}

static int blind_winnow(btbb_piconet *pn)
{
	uint32_t i, n;
	int j, s1, s2, best, scored = 0;

	for (; pn->winnowed < pn->packets_observed && !behind && scored < BLIND_PER_CALL;
	       pn->winnowed++, scored++) {
		int w = pn->winnowed;
		int ch = pn->pattern_channels[w];
		int rescore = 0;
		if (!map_bit(pn->afh_seen, ch)) {
			pn->afh_seen[ch / 8] |= 1 << (ch % 8);
			/* a newly seen channel turns earlier "no evidence" hops into
			 * contradictions: score them again while that is cheap */
			rescore = w > 0 &&
			          (unsigned long long)pn->num_candidates * (w + 1) <= BLIND_RESCORE_MAX;
		}
		n = 0;
		for (i = 0; i < (uint32_t)pn->num_candidates; i++) {
			uint32_t c = pn->clock_candidates[i];
			int hits = pn->cand_hits[i], misses = CAND_MISSES(c);
			if (rescore) {
				hits = misses = 0;
				for (j = 0; j <= w; j++) {
					int r = blind_hop(pn, CAND_CLK(c), j);
					hits += r > 0;
					misses += r < 0;
				}
			} else {
				int r = blind_hop(pn, CAND_CLK(c), w);
				hits += r > 0;
				misses += r < 0;
			}
			if (misses > hits + BLIND_MAX_MISSES || misses > 31)
				continue;
			pn->clock_candidates[n] = CAND_CLK(c) | (uint32_t)misses << 27;
			pn->cand_hits[n] = hits > 255 ? 255 : hits;
			n++;
		}
		pn->num_candidates = n;
		if (n == 0) {
			reset(pn);
			return 0;
		}
	}
	if (!scored)
		return pn->num_candidates;

	/* the best scoring candidate, if clearly ahead */
	s1 = s2 = -1000;
	best = 0;
	for (i = 0; i < (uint32_t)pn->num_candidates; i++) {
		int s = 2 * pn->cand_hits[i] - (int)CAND_MISSES(pn->clock_candidates[i]);
		if (s > s1) {
			s2 = s1;
			s1 = s;
			best = i;
		} else if (s > s2) {
			s2 = s;
		}
	}
	if (s1 >= BLIND_MIN_SCORE && s1 >= s2 + BLIND_MARGIN) {
		uint32_t clk = CAND_CLK(pn->clock_candidates[best]);
		pn->clock_candidates[0] = clk;
		pn->num_candidates = 1;
		pn->clk_offset = ((clk << 1) - (pn->first_pkt_time << 1));
		printf("\nAcquired CLK1-27 = 0x%07x (AFH, map unknown; %d packets, score %d vs %d)\n",
		       clk, pn->packets_observed, s1, s2);
		btbb_piconet_set_flag(pn, BTBB_CLK27_VALID, 1);
		afh_update_map(pn, clk);
	}
	return pn->num_candidates;
}

/* narrow a list of candidate clock values based on all observed hops */
int btbb_winnow(btbb_piconet *pn)
{
	int new_count = pn->num_candidates;
	int index, last_index;
	uint8_t channel, last_channel;

	if (afh_blind(pn))
		return blind_winnow(pn);

	for (; pn->winnowed < pn->packets_observed; pn->winnowed++) {
		index = pn->pattern_indices[pn->winnowed];
		channel = pn->pattern_channels[pn->winnowed];
		new_count = channel_winnow(index, channel, pn);
		if (new_count <= 1)
			break;

		if (pn->winnowed > 0) {
			last_index = pn->pattern_indices[pn->winnowed - 1];
			last_channel = pn->pattern_channels[pn->winnowed - 1];
			/*
			 * Two packets in a row on the same channel should only
			 * happen if adaptive frequency hopping is in use.
			 * There can be false positives, though, especially if
			 * there is aliasing.
			 */
			if (!btbb_piconet_get_flag(pn, BTBB_LOOKS_LIKE_AFH)
			    && (index == last_index + 1)
			    && (channel == last_channel)) {
				btbb_piconet_set_flag(pn, BTBB_LOOKS_LIKE_AFH, 1);
				printf("Hopping pattern appears to be AFH\n");
			}
		}
	}

	return new_count;
}

/* use packet headers to determine UAP */
int btbb_uap_from_header(btbb_packet *pkt, btbb_piconet *pn)
{
	uint8_t UAP;
	int count, crc_chk, first_clock = 0;

	int remaining = 0;
	uint32_t clkn = pkt->clkn;

	if (!btbb_piconet_get_flag(pn, BTBB_GOT_FIRST_PACKET))
		pn->first_pkt_time = clkn;

	// Set afh channel map
	if (!pn->afh_map_known)
		btbb_piconet_set_channel_seen(pn, pkt->channel);

	if (pn->packets_observed < MAX_PATTERN_LENGTH) {
		pn->pattern_indices[pn->packets_observed] = clkn - pn->first_pkt_time;
		pn->pattern_channels[pn->packets_observed] = pkt->channel;
	} else {
		printf("Oops. More hops than we can remember.\n");
		reset(pn);
		return 0; //FIXME ought to throw exception
	}
	pn->packets_observed++;
	pn->total_packets_observed++;

	/* try every possible first packet clock value */
	for (count = 0; count < 64; count++) {
		/* skip eliminated candidates unless this is our first time through */
		if (pn->clock6_candidates[count] > -1
			|| !btbb_piconet_get_flag(pn, BTBB_GOT_FIRST_PACKET)) {
			/* clock value for the current packet assuming count was the clock of the first packet */
			int clock = (count + clkn - pn->first_pkt_time) % 64;
			UAP = try_clock(clock, pkt);
			crc_chk = -1;

			/* if this is the first packet: populate the candidate list */
			/* if not: check CRCs if UAPs match */
			if (!btbb_piconet_get_flag(pn, BTBB_GOT_FIRST_PACKET)
				|| UAP == pn->clock6_candidates[count])
				crc_chk = crc_check(clock, pkt);

			if (btbb_piconet_get_flag(pn, BTBB_UAP_VALID) &&
			    (UAP != pn->UAP))
				crc_chk = -1;

			switch(crc_chk) {
			case -1: /* UAP mismatch */
			case 0: /* CRC failure */
				pn->clock6_candidates[count] = -1;
				break;

			case 1: /* inconclusive result */
			case 2: /* Inconclusive, but looks better */
				pn->clock6_candidates[count] = UAP;
				/* remember this count because it may be the correct clock of the first packet */
				first_clock = count;
				remaining++;
				break;

			default: /* CRC success */
				pn->clk_offset = (count - (pn->first_pkt_time & 0x3f)) & 0x3f;
				if (!btbb_piconet_get_flag(pn, BTBB_UAP_VALID))
					printf("Correct CRC! UAP = 0x%x found after %d total packets.\n",
						UAP, pn->total_packets_observed);
				else
					printf("Correct CRC! CLK6 = 0x%x found after %d total packets.\n",
						pn->clk_offset, pn->total_packets_observed);
				pn->UAP = UAP;
				btbb_piconet_set_flag(pn, BTBB_CLK6_VALID, 1);
				btbb_piconet_set_flag(pn, BTBB_UAP_VALID, 1);
				pn->total_packets_observed = 0;
				return 1;
			}
		}
	}

	btbb_piconet_set_flag(pn, BTBB_GOT_FIRST_PACKET, 1);

	//printf("reduced from %d to %d CLK1-6 candidates\n", starting, remaining);

	if (remaining == 1) {
		pn->clk_offset = (first_clock - (pn->first_pkt_time & 0x3f)) & 0x3f;
		if (!btbb_piconet_get_flag(pn, BTBB_UAP_VALID))
			printf("UAP = 0x%x found after %d total packets.\n",
				pn->clock6_candidates[first_clock], pn->total_packets_observed);
		else
			printf("CLK6 = 0x%x found after %d total packets.\n",
				pn->clk_offset, pn->total_packets_observed);
		pn->UAP = pn->clock6_candidates[first_clock];
		btbb_piconet_set_flag(pn, BTBB_CLK6_VALID, 1);
		btbb_piconet_set_flag(pn, BTBB_UAP_VALID, 1);
		pn->total_packets_observed = 0;
		return 1;
	}

	if (remaining == 0) {
		reset(pn);
	}

	return 0;
}

/* FIXME: comment out enqueue and dequeue because they are
 * never used.  Try to find out what tey were meant to be
 * used for before the next release.
 */
///* add a packet to the queue */
//static void enqueue(btbb_packet *pkt, btbb_piconet *pn)
//{
//	pkt_queue *head;
//	//pkt_queue item;
//
//	btbb_packet_ref(pkt);
//	pkt_queue item = {pkt, NULL};
//	head = pn->queue;
//
//	if (head == NULL) {
//		pn->queue = &item;
//	} else {
//		for(; head->next != NULL; head = head->next)
//		  ;
//		head->next = &item;
//	}
//}
//
///* pull the first packet from the queue (FIFO) */
//static btbb_packet *dequeue(btbb_piconet *pn)
//{
//	btbb_packet *pkt;
//
//	if (pn->queue == NULL) {
//		pkt = NULL;
//	} else {
//		pkt = pn->queue->pkt;
//		pn->queue = pn->queue->next;
//		btbb_packet_unref(pkt);
//	}
//
//	return pkt;
//}

/* Print AFH map from observed packets */
void btbb_print_afh_map(btbb_piconet *pn) {
	uint8_t *afh_map;
	afh_map = pn->afh_map;

	/* Print like hcitool does */
	printf("AFH map: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	       afh_map[0], afh_map[1], afh_map[2], afh_map[3], afh_map[4],
	       afh_map[5], afh_map[6], afh_map[7], afh_map[8], afh_map[9]);

	// /* Printed ch78 -> ch0 */
	// printf("\tAFH Map=0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	//        afh_map[9], afh_map[8], afh_map[7], afh_map[6], afh_map[5],
	//        afh_map[4], afh_map[3], afh_map[2], afh_map[1], afh_map[0]);
}

/* Container for survey piconets */
typedef struct {
    uint32_t key; /* LAP */
    btbb_piconet *pn;
    unsigned packets;
    UT_hash_handle hh;
} survey_hash;

static survey_hash *piconet_survey = NULL;

/*
 * Survey entries are bounded: someone transmitting access codes with random
 * LAPs (or noise that looks like them) must not grow the table without
 * limit. A LAP becomes an entry on its second sighting (the first is
 * remembered in a small direct-mapped table), and at SURVEY_MAX entries
 * the entry with the fewest packets makes room.
 */
#define SURVEY_MAX     1024
#define SURVEY_PENDING 4096
#define SURVEY_SEEN    0x80000000u
static uint32_t survey_pending[SURVEY_PENDING];
static unsigned survey_entries;

static void survey_evict_quietest(void)
{
	survey_hash *s, *quietest = NULL;
	for (s = piconet_survey; s != NULL; s = (survey_hash *)s->hh.next)
		if (quietest == NULL || s->packets < quietest->packets)
			quietest = s;
	if (quietest) {
		HASH_DEL(piconet_survey, quietest);
		btbb_piconet_unref(quietest->pn);
		free(quietest);
		survey_entries--;
	}
}

/* Check for existing piconets in survey results */
btbb_piconet *get_piconet(uint32_t lap)
{
	survey_hash *s;
	btbb_piconet *pn;
	HASH_FIND(hh, piconet_survey, &lap, 4, s);

	if (s == NULL) {
		uint32_t *seen = &survey_pending[(lap * 2654435761u) >> 20 & (SURVEY_PENDING - 1)];
		if (*seen != (lap | SURVEY_SEEN)) {
			*seen = lap | SURVEY_SEEN;
			return NULL;
		}
		*seen = 0;
		if (survey_entries >= SURVEY_MAX)
			survey_evict_quietest();

		pn = btbb_piconet_new();
		if (!pn)
			return NULL;
		btbb_init_piconet(pn, lap);

		s = malloc(sizeof(survey_hash));
		if (!s) {
			btbb_piconet_unref(pn);
			return NULL;
		}
		s->key = lap;
		s->pn = pn;
		s->packets = 1;
		HASH_ADD(hh, piconet_survey, key, 4, s);
		survey_entries++;
	} else {
		pn = s->pn;
	}
	s->packets++;
	return pn;
}

/* Destructively iterate over survey results */
btbb_piconet *btbb_next_survey_result() {
	btbb_piconet *pn = NULL;
	survey_hash *tmp;

	if (piconet_survey != NULL) {
		tmp = piconet_survey;
		pn = tmp->pn;
		/* HASH_DEL keeps the hash table consistent (and frees it
		 * with the last element); just advancing the head left freed
		 * entries in the buckets for later HASH_FIND/HASH_ADD. */
		HASH_DEL(piconet_survey, tmp);
		free(tmp);
		survey_entries--;
	}
	return pn;
}

int btbb_process_packet(btbb_packet *pkt, btbb_piconet *pn) {
	/* BR channels are 0-78; the per-channel tables are sized for them */
	if (pkt->channel > 78)
		return 0;
	if (survey_mode) {
		pn = get_piconet(btbb_packet_get_lap(pkt));
		if (!pn)
			return 0;
		btbb_piconet_set_channel_seen(pn, pkt->channel);
		if(btbb_header_present(pkt) && !btbb_piconet_get_flag(pn, BTBB_UAP_VALID))
			btbb_uap_from_header(pkt, pn);
		return 0;
	}

	if(pn && !pn->afh_map_known)
		btbb_piconet_set_channel_seen(pn, pkt->channel);

	/* If piconet structure is given, a LAP is given, and packet
	 * header is readable, do further analysis. If UAP has not yet
	 * been determined, attempt to calculate it from headers. Once
	 * UAP is known, try to determine clk6 and clk27. Once clocks
	 * are known, follow the piconet. */
	if (pn && btbb_piconet_get_flag(pn, BTBB_LAP_VALID) &&
	    btbb_header_present(pkt)) {

		/* Have LAP/UAP/clocks, now hopping along with the piconet. */
		if (btbb_piconet_get_flag(pn, BTBB_FOLLOWING)) {
			uint32_t rx_clkn = pkt->clkn;
			int header_ok;
			btbb_packet_set_uap(pkt, btbb_piconet_get_uap(pn));
			btbb_packet_set_flag(pkt, BTBB_CLK6_VALID, 1);
			btbb_packet_set_flag(pkt, BTBB_CLK27_VALID, 1);

			/* An Ubertooth adds the clock offset to its CLKN when it starts
			 * hopping; a receiver that cannot (a capture file, a HackRF)
			 * delivers its own clock, to which the offset is added here */
			header_ok = btbb_decode_header(pkt);
			if (!header_ok) {
				pkt->clkn = (rx_clkn + (pn->clk_offset >> 1)) & 0x7ffffff;
				header_ok = btbb_decode_header(pkt);
				if (!header_ok)
					pkt->clkn = rx_clkn;
			}
			/* only packets whose header checks are evidence for the map:
			 * a stray or forged access code is not */
			if (header_ok && btbb_piconet_get_flag(pn, BTBB_IS_AFH))
				afh_map_observe(pn, pkt, rx_clkn);

			/* btbb_decode() prints a decoded packet */
			if (!header_ok || !btbb_decode(pkt))
				printf("Failed to decode packet\n");
		}

		/* Have LAP/UAP, need clocks. */
		/* (UAP 0x00 is a valid UAP, so test the flag, not the value) */
		else if (btbb_piconet_get_flag(pn, BTBB_UAP_VALID)) {
			try_hop(pkt, pn);
			if (btbb_piconet_get_flag(pn, BTBB_CLK6_VALID) &&
			    btbb_piconet_get_flag(pn, BTBB_CLK27_VALID)) {
				btbb_piconet_set_flag(pn, BTBB_FOLLOWING, 1);
				return -1;
			}
		}

		/* Have LAP, need UAP. */
		else {
			btbb_uap_from_header(pkt, pn);
		}
	}
	return 0;
}
