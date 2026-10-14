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
#ifndef INCLUDED_BTBB_H
#define INCLUDED_BTBB_H

#include <stdint.h>
#include <stddef.h>

#define BTBB_WHITENED    0
#define BTBB_NAP_VALID   1
#define BTBB_UAP_VALID   2
#define BTBB_LAP_VALID   3
#define BTBB_CLK6_VALID  4
#define BTBB_CLK27_VALID 5
#define BTBB_CRC_CORRECT 6
#define BTBB_HAS_PAYLOAD 7
#define BTBB_IS_EDR      8

#define BTBB_HOP_REVERSAL_INIT 9
#define BTBB_GOT_FIRST_PACKET  10
#define BTBB_IS_AFH            11
#define BTBB_LOOKS_LIKE_AFH    12
#define BTBB_IS_ALIASED        13
#define BTBB_FOLLOWING         14

/* Payload modulation */
#define BTBB_MOD_GFSK              0x00
#define BTBB_MOD_PI_OVER_2_DQPSK   0x01
#define BTBB_MOD_8DPSK             0x02

/* Transport types */
#define BTBB_TRANSPORT_ANY     0x00
#define BTBB_TRANSPORT_SCO     0x01
#define BTBB_TRANSPORT_ESCO    0x02
#define BTBB_TRANSPORT_ACL     0x03
#define BTBB_TRANSPORT_CSB     0x04

#ifdef __cplusplus
extern "C"
{
#endif

/* BT BR/EDR support */

typedef struct btbb_packet btbb_packet;

/* Initialize the library. Compute the syndrome. Return 0 on success,
 * negative on error.
 *
 * The library limits max_ac_errors to 5. A limit of 5 results in a
 * syndrome table of 128 MB and lots of noise; 4 needs 16 MB.  For
 * embedded targets, a value of 2 is reasonable.  Calling btbb_init()
 * again with a larger value rebuilds the table. */
int btbb_init(int max_ac_errors);

const char* btbb_get_release(void);
const char* btbb_get_version(void);

btbb_packet *btbb_packet_new(void);
void btbb_packet_ref(btbb_packet *pkt);
void btbb_packet_unref(btbb_packet *pkt);

/* Search for a packet with specified LAP (or LAP_ANY). The stream
 * must be at least of length serch_length + 72. Limit to
 * 'max_ac_errors' bit errors.
 *
 * Returns offset into 'stream' at which packet was found. If no
 * packet was found, returns a negative number. If LAP_ANY was
 * specified, fills lap. 'ac_errors' must be set as an input, replaced
 * by actual number of errors on output. */
int btbb_find_ac(char *stream,
	       int search_length,
	       uint32_t lap,
	       int max_ac_errors,
	       btbb_packet **pkt);
#define LAP_ANY 0xffffffffUL
#define UAP_ANY 0xff

/* As btbb_find_ac(), but a match found with LAP_ANY must also look like a
 * real packet, which rejects nearly all random matches and so makes higher
 * max_ac_errors usable. stream_length is the number of symbols available
 * from 'stream' (at least search_length + 64). A promiscuous match is kept
 * if it has no bit errors, or its LAP is an inquiry access code (ID packets
 * have no header), or at least 12 of the 18 symbol triplets of the
 * rate-1/3 coded header after it agree, or it has one bit error and the
 * preamble and trailer around it are intact (at most one bad symbol each). */
int btbb_find_ac_checked(char *stream,
	       int search_length,
	       int stream_length,
	       uint32_t lap,
	       int max_ac_errors,
	       btbb_packet **pkt);

void btbb_packet_set_flag(btbb_packet *pkt, int flag, int val);
int btbb_packet_get_flag(const btbb_packet *pkt, int flag);

uint32_t btbb_packet_get_lap(const btbb_packet *pkt);
void btbb_packet_set_uap(btbb_packet *pkt, uint8_t uap);
uint8_t btbb_packet_get_uap(const btbb_packet *pkt);
uint16_t btbb_packet_get_nap(const btbb_packet *pkt);

void btbb_packet_set_modulation(btbb_packet *pkt, uint8_t modulation);
void btbb_packet_set_transport(btbb_packet *pkt, uint8_t transport);
uint8_t btbb_packet_get_modulation(const btbb_packet *pkt);
uint8_t btbb_packet_get_transport(const btbb_packet *pkt);

uint8_t btbb_packet_get_channel(const btbb_packet *pkt);
uint8_t btbb_packet_get_ac_errors(const btbb_packet *pkt);
uint32_t btbb_packet_get_clkn(const btbb_packet *pkt);
uint32_t btbb_packet_get_header_packed(const btbb_packet* pkt);

void btbb_packet_set_data(btbb_packet *pkt,
			  char *syms,      // Symbol data
			  int length,      // Number of symbols
			  uint8_t channel, // Bluetooth channel 0-79
			  uint32_t clkn);  // 312.5us clock (CLK27-0)

/* Get a pointer to packet symbols. */
const char *btbb_get_symbols(const btbb_packet* pkt);

int btbb_packet_get_payload_length(const btbb_packet* pkt);

/* Get a pointer to payload. */
const char *btbb_get_payload(const btbb_packet* pkt);

/* Pack the payload in to bytes */
int btbb_get_payload_packed(const btbb_packet* pkt, char *dst);

uint8_t btbb_packet_get_type(const btbb_packet* pkt);
uint8_t btbb_packet_get_lt_addr(const btbb_packet* pkt);
uint8_t btbb_packet_get_header_flags(const btbb_packet* pkt);
uint8_t btbb_packet_get_hec(const btbb_packet *pkt);

/* Generate Sync Word from an LAP */
uint64_t btbb_gen_syncword(const int LAP);

/* decode the packet header */
int btbb_decode_header(btbb_packet* pkt);

/* decode the packet header */
int btbb_decode_payload(btbb_packet* pkt);

/* print packet information */
void btbb_print_packet(const btbb_packet* pkt);

/* check to see if the packet has a header */
int btbb_header_present(const btbb_packet* pkt);

/* Packet queue (linked list) */
typedef struct pkt_queue {
	btbb_packet *pkt;

	struct pkt_queue *next;

} pkt_queue;

typedef struct btbb_piconet btbb_piconet;

btbb_piconet *btbb_piconet_new(void);
void btbb_piconet_ref(btbb_piconet *pn);
void btbb_piconet_unref(btbb_piconet *pn);

/* initialize the piconet struct */
void btbb_init_piconet(btbb_piconet *pn, uint32_t lap);

void btbb_piconet_set_uap(btbb_piconet *pn, uint8_t uap);
uint8_t btbb_piconet_get_uap(const btbb_piconet *pn);
uint32_t btbb_piconet_get_lap(const btbb_piconet *pn);
uint16_t btbb_piconet_get_nap(const btbb_piconet *pn);
uint64_t btbb_piconet_get_bdaddr(const btbb_piconet *pn);

int btbb_piconet_get_clk_offset(const btbb_piconet *pn);
void btbb_piconet_set_clk_offset(btbb_piconet *pn, int clk_offset);

void btbb_piconet_set_flag(btbb_piconet *pn, int flag, int val);
int btbb_piconet_get_flag(const btbb_piconet *pn, int flag);

uint8_t btbb_piconet_set_channel_seen(btbb_piconet *pn, uint8_t channel);
uint8_t btbb_piconet_clear_channel_seen(btbb_piconet *pn, uint8_t channel);
uint8_t btbb_piconet_get_channel_seen(btbb_piconet *pn, uint8_t channel);
void btbb_piconet_set_afh_map(btbb_piconet *pn, uint8_t *afh_map);
uint8_t *btbb_piconet_get_afh_map(btbb_piconet *pn);

/* Extract as much information (LAP/UAP/CLK) as possible from received packet */
int btbb_process_packet(btbb_packet *pkt, btbb_piconet *pn);

/* The caller is falling behind the incoming data (its queue is filling):
 * work that can wait (the map-free clock search, AFH map deduction) waits
 * until it is not. Packets are kept, not dropped. Default 0. */
void btbb_set_behind(int behind);

/* use packet headers to determine UAP */
int btbb_uap_from_header(btbb_packet *pkt, btbb_piconet *pn);

/* Print hexadecimal representation of the derived AFH map */
void btbb_print_afh_map(btbb_piconet *pn);

/* decode a whole packet from the given piconet */
int btbb_decode(btbb_packet* pkt);


/* initialize the hop reversal process */
/* returns number of initial candidates for CLK1-27 */
int btbb_init_hop_reversal(int aliased, btbb_piconet *pn);

/* narrow a list of candidate clock values based on all observed hops */
int btbb_winnow(btbb_piconet *pn);

int btbb_init_survey(void);
/* Destructively iterate over survey results - optionally remove elements */
btbb_piconet *btbb_next_survey_result(void);

typedef struct btbb_pcapng_handle btbb_pcapng_handle;
/* create a PCAPNG file for BREDR captures */
int btbb_pcapng_create_file(const char *filename, const char *interface_desc, btbb_pcapng_handle ** ph);
/* save a BREDR packet to PCAPNG capture file */
int btbb_pcapng_append_packet(btbb_pcapng_handle * h, const uint64_t ns,
                              const int8_t sigdbm, const int8_t noisedbm,
                              const uint32_t reflap, const uint8_t refuap,
                              const btbb_packet *pkt);
/* record a BDADDR to PCAPNG capture file */
int btbb_pcapng_record_bdaddr(btbb_pcapng_handle * h, const uint64_t bdaddr,
                              const uint8_t uapmask, const uint8_t napvalid);
/* record BT CLOCK to PCAPNG capture file */
int btbb_pcapng_record_btclock(btbb_pcapng_handle * h, const uint64_t bdaddr,
                               const uint64_t ns, const uint32_t clk, const uint32_t clkmask);
int btbb_pcapng_close(btbb_pcapng_handle * h);


/* BLE support */
typedef struct lell_packet lell_packet;

/* Decode and allocate an LE packet from 'len' captured (dewhitened)
 * bytes starting with the access address.  At most 264 bytes (the
 * largest LE packet) are used; bytes not captured read as zero and all
 * printing/pcap output is clamped to the captured length.  Returns 0 on
 * success, -1 if the packet could not be allocated (*pkt is then NULL). */
int lell_allocate_and_decode_len(const uint8_t *stream, size_t len,
                                 uint16_t phys_channel, uint32_t clk100ns,
                                 lell_packet **pkt);
/* Legacy form: reads exactly 64 bytes from 'stream'.  Prefer
 * lell_allocate_and_decode_len() with the real buffer length. */
void lell_allocate_and_decode(const uint8_t *stream, uint16_t phys_channel, uint32_t clk100ns, lell_packet **pkt);
lell_packet *lell_packet_new(void);
void lell_packet_ref(lell_packet *pkt);
void lell_packet_unref(lell_packet *pkt);
uint32_t lell_get_access_address(const lell_packet *pkt);
unsigned lell_get_access_address_offenses(const lell_packet *pkt);
/* Data channel PDU?  Decided by the access address: packets on the
 * secondary advertising channels (0-36) that use the advertising AA
 * (AUX_* PDUs) are advertising PDUs; channels 37-39 only carry
 * advertising PDUs. */
unsigned lell_packet_is_data(const lell_packet *pkt);
unsigned lell_get_channel_index(const lell_packet *pkt);
unsigned lell_get_channel_k(const lell_packet *pkt);
const char * lell_get_adv_type_str(const lell_packet *pkt);
void lell_print(const lell_packet *pkt);

/* PDU payload length from the (8 bit) Length field of the PDU header */
unsigned lell_get_length(const lell_packet *pkt);
/* number of bytes captured, from the access address on */
unsigned lell_get_captured_length(const lell_packet *pkt);
/* 1 if the capture ends before the end of the CRC */
int lell_packet_is_truncated(const lell_packet *pkt);

/* ChSel bit of ADV_IND, ADV_DIRECT_IND and CONNECT_IND PDUs (1 = the
 * advertiser/initiator supports Channel Selection Algorithm #2), or -1
 * if the PDU type has no ChSel bit. */
int lell_get_chsel(const lell_packet *pkt);

/* CTEInfo byte of a data channel PDU with the CP bit set, or -1.
 * Bits 0-4: CTETime (units of 8 us), bits 6-7: CTEType (0 = AoA,
 * 1 = AoD 1 us slots, 2 = AoD 2 us slots). */
int lell_get_cte_info(const lell_packet *pkt);

/* Mark a packet as (not) encrypted, e.g. from a per-packet flag reported
 * by the capture device.  lell_print() then shows the payload as
 * ciphertext followed by a 4 byte MIC instead of decoding it. */
void lell_packet_set_encrypted(lell_packet *pkt, int encrypted);
int lell_packet_is_encrypted(const lell_packet *pkt);

/* PHY the packet was received on: 0 = LE 1M (default), 1 = LE 2M,
 * 2 = LE Coded.  Recorded in the PHY field of LE PHDR pcap headers. */
void lell_packet_set_phy(lell_packet *pkt, int phy);

/* Direction of a data PDU as known to the capture device: 0 unknown,
 * 1 master to slave, 2 slave to master; written to pcap/pcapng. */
void lell_packet_set_direction(lell_packet *pkt, int direction);

/* CRC status as checked by the capture device; written to pcap/pcapng. */
void lell_packet_set_crc_status(lell_packet *pkt, int checked, int valid);

/* Opcode of an unencrypted LL control PDU, or -1 */
int lell_get_ll_opcode(const lell_packet *pkt);
/* Name of an LL control opcode (e.g. "LL_PHY_UPDATE_IND"), never NULL */
const char *lell_get_ll_opcode_str(int opcode);
/* If the packet is an LL_CONNECTION_UPDATE_IND, LL_CHANNEL_MAP_IND or
 * LL_PHY_UPDATE_IND, store its Instant and return 1; otherwise 0. */
int lell_get_instant(const lell_packet *pkt, uint16_t *instant);

/* Extended advertising (Common Extended Advertising Payload Format) */
typedef struct {
	uint8_t channel_index;   /* secondary channel index of the AUX PDU */
	uint8_t clock_accuracy;  /* CA: 0 = 51-500 ppm, 1 = 0-50 ppm */
	uint8_t offset_units;    /* 0 = 30 us, 1 = 300 us */
	uint8_t aux_phy;         /* 0 = LE 1M, 1 = LE 2M, 2 = LE Coded */
	uint16_t aux_offset;     /* AUX Offset, in offset_units */
	uint32_t aux_offset_us;  /* AUX Offset in microseconds */
} lell_aux_ptr;

typedef struct {
	uint16_t sync_packet_offset; /* in offset_units */
	uint8_t offset_units;        /* 0 = 30 us, 1 = 300 us */
	uint8_t offset_adjust;       /* 1: add 2.4576 s to the offset */
	uint16_t interval;           /* units of 1.25 ms */
	uint8_t chm[5];              /* 37 bit channel map, LSB first */
	uint8_t sca;                 /* sleep clock accuracy (0-7) */
	uint32_t access_address;
	uint32_t crc_init;
	uint16_t event_counter;
} lell_sync_info;

/* bits of lell_ext_adv_info.ext_header_flags */
#define LELL_EXT_HDR_ADVA      0x01
#define LELL_EXT_HDR_TARGETA   0x02
#define LELL_EXT_HDR_CTEINFO   0x04
#define LELL_EXT_HDR_ADI       0x08
#define LELL_EXT_HDR_AUXPTR    0x10
#define LELL_EXT_HDR_SYNCINFO  0x20
#define LELL_EXT_HDR_TXPOWER   0x40

typedef struct {
	uint8_t adv_mode;          /* 0 = non-connectable non-scannable,
	                              1 = connectable, 2 = scannable */
	uint8_t ext_header_len;
	uint8_t ext_header_flags;  /* LELL_EXT_HDR_* fields present */
	uint8_t adva[6];           /* in on-air (LSB first) byte order */
	uint8_t adva_random;
	uint8_t targeta[6];        /* in on-air (LSB first) byte order */
	uint8_t targeta_random;
	uint8_t cte_info;
	uint16_t adi_did;          /* Advertising Data ID (12 bits) */
	uint8_t adi_sid;           /* Advertising Set ID (4 bits) */
	lell_aux_ptr aux_ptr;
	lell_sync_info sync_info;
	int8_t tx_power;           /* dBm */
	const uint8_t *acad;       /* Additional Controller Advertising Data */
	uint8_t acad_len;
	const uint8_t *adv_data;   /* AdvData (points into the packet) */
	uint8_t adv_data_len;      /* captured AdvData bytes */
	uint8_t truncated;         /* AdvData was cut short by the capture */
} lell_ext_adv_info;

/* Parse the extended header of an ADV_EXT_IND / AUX_ADV_IND /
 * AUX_SCAN_RSP / AUX_SYNC_IND / AUX_CHAIN_IND / AUX_CONNECT_RSP PDU.
 * Pointers in 'info' point into 'pkt' and stay valid while it does.
 * Returns 0 on success, -1 if the packet is not such a PDU or is
 * malformed, -2 if the extended header was not completely captured. */
int lell_get_ext_adv_info(const lell_packet *pkt, lell_ext_adv_info *info);

/* Encryption tracking.  A caller-owned tracker follows connections (by
 * access address) from their CONNECT_IND and marks the PDUs of a
 * connection as encrypted once encryption starts: the LL_START_ENC_REQ
 * is the last unencrypted PDU, everything after it (including both
 * LL_START_ENC_RSPs) is ciphertext with a 4 byte MIC, until an
 * unencrypted LL_PAUSE_ENC_RSP.  Feed every captured packet, in order,
 * to lell_track() before printing or saving it. */
typedef struct lell_tracker lell_tracker;
lell_tracker *lell_tracker_new(void);
void lell_tracker_free(lell_tracker *tracker);
void lell_track(lell_tracker *tracker, lell_packet *pkt);

typedef struct lell_pcapng_handle lell_pcapng_handle;
/* create a PCAPNG file for LE captures */
int lell_pcapng_create_file(const char *filename, const char *interface_desc, lell_pcapng_handle ** ph);
/* save an LE packet to PCAPNG capture file */
int lell_pcapng_append_packet(lell_pcapng_handle * h, const uint64_t ns,
                              const int8_t sigdbm, const int8_t noisedbm,
                              const uint32_t refAA, const lell_packet *pkt);
/* record LE CONNECT_IND parameters to PCAPNG capture file; 'pdu' points
 * to the 34 byte LLData (InitA, AdvA, AA, CRCInit, ...).  Called
 * automatically by lell_pcapng_append_packet() for CONNECT_INDs. */
int lell_pcapng_record_connect_req(lell_pcapng_handle * h, const uint64_t ns, const uint8_t * pdu);
int lell_pcapng_close(lell_pcapng_handle *h);


/* PCAP Support */
typedef struct btbb_pcap_handle btbb_pcap_handle;
/* create a PCAP file for BREDR captures with LINKTYPE_BLUETOOTH_BREDR_BB */
int btbb_pcap_create_file(const char *filename, btbb_pcap_handle ** ph);
/* write a BREDR packet to PCAP file */
int btbb_pcap_append_packet(btbb_pcap_handle * h, const uint64_t ns,
                            const int8_t sigdbm, const int8_t noisedbm,
                            const uint32_t reflap, const uint8_t refuap,
                            const btbb_packet *pkt);
int btbb_pcap_close(btbb_pcap_handle * h);

typedef struct lell_pcap_handle lell_pcap_handle;
/* create a PCAP file for LE captures using LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR */
int lell_pcap_create_file(const char *filename, lell_pcap_handle ** ph);
/* create a PCAP file for LE captures using LINKTYPE_PPI */
int lell_pcap_ppi_create_file(const char *filename, int btle_ppi_version, lell_pcap_handle ** ph);
/* save an LE packet to PCAP capture file */
int lell_pcap_append_packet(lell_pcap_handle * h, const uint64_t ns,
                            const int8_t sigdbm, const int8_t noisedbm,
                            const uint32_t refAA, const lell_packet *pkt);
int lell_pcap_append_ppi_packet(lell_pcap_handle * h, const uint64_t ns,
                                const uint8_t clkn_high,
                                const int8_t rssi_min, const int8_t rssi_max,
                                const int8_t rssi_avg, const uint8_t rssi_count,
                                const lell_packet *pkt);
int lell_pcap_close(lell_pcap_handle *h);

#ifdef __cplusplus
} // __cplusplus defined.
#endif

#endif /* INCLUDED_BTBB_H */
