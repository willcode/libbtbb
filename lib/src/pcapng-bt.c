/* -*- c -*- */
/*
 * Copyright 2014 Christopher D. Kilgour techie AT whiterocker.com
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

#include "btbb.h"
#include "bluetooth_le_packet.h"
#include "bluetooth_packet.h"
#include "pcapng-bt.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

/* generic section options indicating libbtbb */
const struct {
	struct {
		option_header hdr;
		char libname[8];
	} libopt;
	struct {
		option_header hdr;
	} termopt;
} libbtbb_section_options = {
	.libopt = {
		.hdr = {
			.option_code = SHB_USERAPPL,
			.option_length = 7 },
		.libname = "libbtbb"
	},
	.termopt = {
		.hdr = {
			.option_code = OPT_ENDOFOPT,
			.option_length = 0
		}
	}
};

static PCAPNG_RESULT
check_and_fix_tsresol( PCAPNG_HANDLE * handle,
		       const option_header * interface_options )
{
	PCAPNG_RESULT retval = PCAPNG_OK;
	int got_tsresol = 0;

	while( !got_tsresol &&
	       interface_options &&
	       interface_options->option_code &&
	       interface_options->option_length) {
		if (interface_options->option_code == IF_TSRESOL) {
			got_tsresol = 1;
		}
		else {
			size_t step = 4+4*((interface_options->option_length+3)/4);
			uint8_t * next = &((uint8_t *)interface_options)[step];
			interface_options = (const option_header *) next;
		}
	}

	if (!got_tsresol) {
		const struct {
			option_header hdr;
			uint8_t resol;
		} tsresol = {
			.hdr = {
				.option_code = IF_TSRESOL,
				.option_length = 1,
			},
			.resol = 9 /* 10^-9 is nanoseconds */
		};

		retval = pcapng_append_interface_option( handle, 
							 (const option_header *) &tsresol );
	}

	return retval;
}

/* --------------------------------- BR/EDR ----------------------------- */

static PCAPNG_RESULT
create_bredr_capture_file_single_interface( PCAPNG_HANDLE * handle,
					    const char * filename,
					    const option_header * interface_options )
{
	PCAPNG_RESULT retval = PCAPNG_OK;

	retval = pcapng_create( handle,
				filename,
				(const option_header *) &libbtbb_section_options,
				(size_t) getpagesize( ),
				DLT_BLUETOOTH_BREDR_BB,
				sizeof(pcap_bluetooth_bredr_bb_header),
				interface_options,
				(size_t) getpagesize( ) );

	if (retval == PCAPNG_OK) {
		/* if there is no timestamp resolution alread in the
		   interface options, record nanosecond resolution */
		retval = check_and_fix_tsresol( handle, interface_options );

		if (retval != PCAPNG_OK) {
			(void) pcapng_close( handle );
		}
	}

	return retval;
}

int btbb_pcapng_create_file( const char *filename,
			     const char *interface_desc,
			     btbb_pcapng_handle ** ph )
{
	int retval = PCAPNG_OK;
	PCAPNG_HANDLE * handle = malloc( sizeof(PCAPNG_HANDLE) );
	if (handle) {
		const option_header * popt = NULL;
		/* option list: description followed by opt_endofopt, so
		 * walking the list never runs past the end of the struct
		 * (a 253-255 character description pads to 256 bytes) */
		struct __attribute__((packed)) {
			option_header header;
			char desc[256];
			option_header end;
		} ifopt = {
			.header = {
				.option_code = IF_DESCRIPTION,
			}
		};
		if (interface_desc) {
			(void) strncpy( &ifopt.desc[0], interface_desc, 256 );
			ifopt.desc[255] = '\0';
			ifopt.header.option_length = strlen( ifopt.desc );
			popt = (const option_header *) &ifopt;
		}

		retval = -create_bredr_capture_file_single_interface( handle,
								      filename,
								      popt );
		if (retval == PCAPNG_OK) {
			*ph = (btbb_pcapng_handle *) handle;
		}
		else {
			free( handle );
		}
	}
	else {
		retval = -PCAPNG_NO_MEMORY;
	}
	return retval;
}

static PCAPNG_RESULT
append_bredr_packet( PCAPNG_HANDLE * handle,
		     pcapng_bredr_packet * pkt )
{
	return pcapng_append_packet( handle, ( const enhanced_packet_block *) pkt );
}

static void
assemble_pcapng_bredr_packet( pcapng_bredr_packet * pkt,
			      const uint32_t interface_id,
			      const uint64_t ns,
			      const uint32_t caplen,
			      const uint8_t rf_channel,
			      const int8_t signal_power,
			      const int8_t noise_power,
			      const uint8_t access_code_offenses,
			      const uint8_t payload_transport,
			      const uint8_t payload_rate,
			      const uint8_t corrected_header_bits,
			      const int16_t corrected_payload_bits,
			      const uint32_t lap,
			      const uint32_t ref_lap,
                              const uint8_t ref_uap,
			      const uint32_t bt_header,
			      const uint16_t flags,
			      const char * payload )
{
	uint32_t pcapng_caplen = sizeof(pcap_bluetooth_bredr_bb_header)  
				 - sizeof(pkt->bredr_bb_header.bredr_payload)  
				 + caplen;
	uint32_t block_length  = 4*((36+pcapng_caplen+3)/4);
	uint32_t reflapuap = (ref_lap&0xffffff) | ((uint32_t)ref_uap<<24);

	pkt->blk_header.block_type = BLOCK_TYPE_ENHANCED_PACKET;
	pkt->blk_header.block_total_length = block_length;
	pkt->blk_header.interface_id = interface_id;
	pkt->blk_header.timestamp_high = (uint32_t) (ns >> 32);
	pkt->blk_header.timestamp_low = (uint32_t) (ns & 0x0ffffffffull);
	pkt->blk_header.captured_len = pcapng_caplen;
	pkt->blk_header.packet_len = pcapng_caplen;
	pkt->bredr_bb_header.rf_channel = rf_channel;
	pkt->bredr_bb_header.signal_power = signal_power;
	pkt->bredr_bb_header.noise_power = noise_power;
	pkt->bredr_bb_header.access_code_offenses = access_code_offenses;
	pkt->bredr_bb_header.payload_transport_rate =
		(payload_transport << 4) | payload_rate;
	pkt->bredr_bb_header.corrected_header_bits = corrected_header_bits;
	pkt->bredr_bb_header.corrected_payload_bits = htole16( corrected_payload_bits );
	pkt->bredr_bb_header.lap = htole32( lap );
	pkt->bredr_bb_header.ref_lap_uap = htole32( reflapuap );
	pkt->bredr_bb_header.bt_header = htole32( bt_header );
	pkt->bredr_bb_header.flags = htole16( flags );
	if (caplen) {
		assert(caplen <= sizeof(pkt->bredr_bb_header.bredr_payload)); // caller ensures this, but to be safe..
		(void) memcpy( &pkt->bredr_bb_header.bredr_payload[0], payload, caplen );
		pkt->bredr_bb_header.flags |= htole16( BREDR_PAYLOAD_PRESENT );
	}
	else {
		pkt->bredr_bb_header.flags &= htole16( ~BREDR_PAYLOAD_PRESENT );
	}
	/* zero the alignment padding so no stack garbage reaches the file */
	(void) memset( (uint8_t *)pkt + sizeof(enhanced_packet_block) + pcapng_caplen, 0,
		       block_length - 8 - sizeof(enhanced_packet_block) - pcapng_caplen );
	((uint32_t *)pkt)[block_length/4-2] = 0x00000000; /* no-options */
	((uint32_t *)pkt)[block_length/4-1] = block_length;
}

int btbb_pcapng_append_packet(btbb_pcapng_handle * h, const uint64_t ns,
			      const int8_t sigdbm, const int8_t noisedbm,
			      const uint32_t reflap, const uint8_t refuap, 
			      const btbb_packet *pkt)
{
	uint16_t flags = BREDR_DEWHITENED | BREDR_SIGPOWER_VALID |
		((noisedbm < sigdbm) ? BREDR_NOISEPOWER_VALID : 0) |
		((reflap != LAP_ANY) ? BREDR_REFLAP_VALID : 0) |
		((refuap != UAP_ANY) ? BREDR_REFUAP_VALID : 0);
	int caplen = btbb_packet_get_payload_length(pkt);
	/* payload_length never exceeds the payload buffer of the packet */
	char payload_bytes[MAX_PAYLOAD_LENGTH / 8];
	pcapng_bredr_packet pcapng_pkt;
	if (caplen < 0 || caplen > (int) sizeof(payload_bytes))
		caplen = 0;
	if (caplen)
		btbb_get_payload_packed( pkt, &payload_bytes[0] );
	caplen = MIN(BREDR_MAX_PAYLOAD, caplen);
	assemble_pcapng_bredr_packet( &pcapng_pkt,
				      0,
				      ns,
				      caplen,
				      btbb_packet_get_channel(pkt),
				      sigdbm,
				      noisedbm,
				      btbb_packet_get_ac_errors(pkt),
				      btbb_packet_get_transport(pkt),
				      btbb_packet_get_modulation(pkt),
				      0, /* TODO: corrected header bits */
				      0, /* TODO: corrected payload bits */
				      btbb_packet_get_lap(pkt),
				      reflap,
				      refuap,
				      btbb_packet_get_header_packed(pkt),
				      flags,
				      payload_bytes );
	return -append_bredr_packet( (PCAPNG_HANDLE *)h, &pcapng_pkt );
}

static PCAPNG_RESULT
record_bd_addr_info( PCAPNG_HANDLE * handle,
		     const uint64_t bd_addr,
		     const uint8_t  uap_mask,
                     const uint8_t  nap_valid )
{
	const bredr_br_addr_option bdopt = {
		.header = {
			.option_code = PCAPNG_BREDR_OPTION_BD_ADDR,
			/* option length excludes the option header */
			.option_length = sizeof(bredr_bd_addr_info),
		},
		.bd_addr_info = {
			.bd_addr = {
				((bd_addr>>0)  & 0xff),
				((bd_addr>>8)  & 0xff),
				((bd_addr>>16) & 0xff),
				((bd_addr>>24) & 0xff),
				((bd_addr>>32) & 0xff),
				((bd_addr>>40) & 0xff)
			},
			.uap_mask = uap_mask,
			.nap_valid = nap_valid,
		}
	};
	return pcapng_append_interface_option( handle,
					       (const option_header *) &bdopt );
}

int btbb_pcapng_record_bdaddr(btbb_pcapng_handle * h, const uint64_t bdaddr,
                              const uint8_t uapmask, const uint8_t napvalid)
{
	return -record_bd_addr_info( (PCAPNG_HANDLE *) h,
				     bdaddr, uapmask, napvalid );
}

static PCAPNG_RESULT
record_bredr_master_clock_info( PCAPNG_HANDLE * handle,
				const uint64_t bd_addr,
				const uint64_t ns,
				const uint32_t clk,
	                        const uint32_t clk_mask)
{
	const bredr_clk_option mcopt = {
		.header = {
			.option_code = PCAPNG_BREDR_OPTION_MASTER_CLOCK_INFO,
			/* option length excludes the option header */
			.option_length = sizeof(bredr_clk_info)
		},
		.clock_info = {
			.ts = htole64(ns),
			.lap_uap = htole32(bd_addr & 0xffffffff),
			.clk = htole32(clk),
			.clk_mask = htole32(clk_mask)
		}
	};
	return pcapng_append_interface_option( handle,
					       (const option_header *) &mcopt );
}

int btbb_pcapng_record_btclock(btbb_pcapng_handle * h, const uint64_t bdaddr,
                               const uint64_t ns, const uint32_t clk,
			       const uint32_t clkmask)
{
	return -record_bredr_master_clock_info( (PCAPNG_HANDLE *) h,
						bdaddr, ns, clk, clkmask );
}

int btbb_pcapng_close(btbb_pcapng_handle * h)
{
	int retval;
	if (!h)
		return -PCAPNG_INVALID_HANDLE;
	retval = -pcapng_close( (PCAPNG_HANDLE *) h );
	free( h );
	return retval;
}

/* --------------------------------- Low Energy ---------------------------- */

static PCAPNG_RESULT
create_le_capture_file_single_interface( PCAPNG_HANDLE * handle,
					 const char * filename,
					 const option_header * interface_options )
{
	PCAPNG_RESULT retval = PCAPNG_OK;

	retval = pcapng_create( handle,
				filename,
				(const option_header *) &libbtbb_section_options, 
				(size_t) getpagesize( ),
				DLT_BLUETOOTH_LE_LL_WITH_PHDR,
				sizeof(pcap_bluetooth_le_ll_header) + LE_MAX_PAYLOAD,
				interface_options,
				(size_t) getpagesize( ) );

	if (retval == PCAPNG_OK) {
		/* if there is no timestamp resolution alread in the
		   interface options, record nanosecond resolution */
		retval = check_and_fix_tsresol( handle, interface_options );

		if (retval != PCAPNG_OK) {
			(void) pcapng_close( handle );
		}
	}

	return retval;
}

int
lell_pcapng_create_file(const char *filename, const char *interface_desc,
			lell_pcapng_handle ** ph)
{
	int retval = PCAPNG_OK;
	PCAPNG_HANDLE * handle = malloc( sizeof(PCAPNG_HANDLE) );
	if (handle) {
		const option_header * popt = NULL;
		/* option list: description followed by opt_endofopt, so
		 * walking the list never runs past the end of the struct
		 * (a 253-255 character description pads to 256 bytes) */
		struct __attribute__((packed)) {
			option_header header;
			char desc[256];
			option_header end;
		} ifopt = {
			.header = {
				.option_code = IF_DESCRIPTION,
			}
		};
		if (interface_desc) {
			(void) strncpy( &ifopt.desc[0], interface_desc, 256 );
			ifopt.desc[255] = '\0';
			ifopt.header.option_length = strlen( ifopt.desc );
			popt = (const option_header *) &ifopt;
		}

		retval = -create_le_capture_file_single_interface( handle,
								   filename,
								   popt );
		if (retval == PCAPNG_OK) {
			*ph = (lell_pcapng_handle *) handle;
		}
		else {
			free( handle );
		}
	}
	else {
		retval = -PCAPNG_NO_MEMORY;
	}
	return retval;
}

static PCAPNG_RESULT
append_le_packet( PCAPNG_HANDLE * handle,
		  pcapng_le_packet * pkt )
{
	return pcapng_append_packet( handle, ( const enhanced_packet_block *) pkt );
}

/* Size of a PCAPNG enhanced packet block with no packet data.
   NOTE: The pcap_bluetooth_le_ll_header is part of the packet data of
   the enhanced block. */
#define PCAPNG_ENHANCED_BLK_SZ 36

static void
assemble_pcapng_le_packet( pcapng_le_packet * pkt,
			   const uint32_t interface_id,
			   const uint64_t ns,
			   uint32_t caplen,          /* bytes captured */
			   const uint32_t origlen,   /* length on the air */
			   const uint8_t rf_channel,
			   const int8_t signal_power,
			   const int8_t noise_power,
			   const uint8_t access_address_offenses,
			   const uint32_t ref_access_address,
			   const uint16_t flags,
			   const uint8_t * lepkt )
{
	uint32_t pcapng_caplen, block_length;

	if (caplen > LE_MAX_PAYLOAD)
		caplen = LE_MAX_PAYLOAD;
	pcapng_caplen = sizeof(pcap_bluetooth_le_ll_header)+caplen;
	block_length  = 4*((PCAPNG_ENHANCED_BLK_SZ+pcapng_caplen+3)/4);

	pkt->blk_header.block_type = BLOCK_TYPE_ENHANCED_PACKET;
	pkt->blk_header.block_total_length = block_length;
	pkt->blk_header.interface_id = interface_id;
	pkt->blk_header.timestamp_high = (uint32_t) (ns >> 32);
	pkt->blk_header.timestamp_low = (uint32_t) (ns & 0x0ffffffffull);
	pkt->blk_header.captured_len = pcapng_caplen;
	pkt->blk_header.packet_len = sizeof(pcap_bluetooth_le_ll_header) +
		(origlen > caplen ? origlen : caplen);
	pkt->le_ll_header.rf_channel = rf_channel;
	pkt->le_ll_header.signal_power = signal_power;
	pkt->le_ll_header.noise_power = noise_power;
	pkt->le_ll_header.access_address_offenses = access_address_offenses;
	pkt->le_ll_header.ref_access_address = htole32( ref_access_address );
	pkt->le_ll_header.flags = htole16( flags );
	(void) memcpy( &pkt->le_packet[0], lepkt, caplen );
	/* zero the alignment padding so no stack garbage reaches the file */
	(void) memset( (uint8_t *)pkt + sizeof(enhanced_packet_block) + pcapng_caplen, 0,
		       block_length - 8 - sizeof(enhanced_packet_block) - pcapng_caplen );
	((uint32_t *)pkt)[block_length/4-2] = 0x00000000; /* no-options */
	((uint32_t *)pkt)[block_length/4-1] = block_length;
}

int
lell_pcapng_append_packet(lell_pcapng_handle * h, const uint64_t ns,
			  const int8_t sigdbm, const int8_t noisedbm,
			  const uint32_t refAA, const lell_packet *pkt)
{
	uint16_t flags = LE_DEWHITENED | LE_AA_OFFENSES_VALID |
		LE_SIGPOWER_VALID |
		((noisedbm < sigdbm) ? LE_NOISEPOWER_VALID : 0) |
		(lell_packet_is_data(pkt) ? 0 : LE_REF_AA_VALID) |
		le_phdr_flags(pkt);
	pcapng_le_packet pcapng_pkt;

	/* The packet is the Access Address (4), PDU header (2, or 3 with
	   CTEInfo), payload and CRC (3), as far as it was captured. */
	assemble_pcapng_le_packet( &pcapng_pkt,
				   0,
				   ns,
				   le_pdu_avail_len(pkt),
				   le_pdu_total_len(pkt),
				   pkt->channel_k,
				   sigdbm,
				   noisedbm,
				   pkt->access_address_offenses,
				   refAA,
				   flags,
				   &pkt->symbols[0] );
	int retval = -append_le_packet( (PCAPNG_HANDLE *) h, &pcapng_pkt );
	/* Record the connection parameters of plausible CONNECT_INDs only
	 * (valid advertising AA, correct length).  The options live in the
	 * fixed size interface description block; once it is full further
	 * connections are simply not recorded. */
	if ((retval == 0) && !lell_packet_is_data(pkt) &&
	    (pkt->adv_type == CONNECT_REQ) && (pkt->length == 34) &&
	    pkt->flags.as_bits.access_address_ok) {
		/* LLData (InitA, AdvA, AA, ...) starts after AA and header */
		(void) lell_pcapng_record_connect_req(h, ns, &pkt->symbols[6]);
	}
	return retval;
}

static PCAPNG_RESULT
record_le_connect_req_info( PCAPNG_HANDLE * handle,
			    const uint64_t ns,
			    const uint8_t * pdu )
{
	le_ll_connection_info_option cropt = {
		.header = {
			.option_code = PCAPNG_LE_LL_CONNECTION_INFO,
			/* option length excludes the option header */
			.option_length = sizeof(le_ll_connection_info)
		},
		.connection_info = {
			.ns = htole64(ns)
		}
	};
	if (!pdu)
		return PCAPNG_INVALID_HANDLE;
	(void) memcpy( &cropt.connection_info.pdu.bytes[0], pdu, 34 );
	return pcapng_append_interface_option( handle,
					       (const option_header *) &cropt );
}

int
lell_pcapng_record_connect_req(lell_pcapng_handle * h, const uint64_t ns, 
			       const uint8_t * pdu)
{
	return -record_le_connect_req_info( (PCAPNG_HANDLE *) h, ns, pdu );
}

int lell_pcapng_close(lell_pcapng_handle *h)
{
	int retval;
	if (!h)
		return -PCAPNG_INVALID_HANDLE;
	retval = -pcapng_close( (PCAPNG_HANDLE *) h );
	free( h );
	return retval;
}
