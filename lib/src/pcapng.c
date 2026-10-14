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

#include "pcapng.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Option code used for the padding option that fills the space reserved
 * for options added later (0xffff is in the local-use range). */
#define PADOPT_CODE 0xffff

/*
 * Space needed after the next option offset in a block for an option of
 * 'optsz' bytes (header + value): the padded option itself, the padding
 * option header (4), opt_endofopt (4) and the trailing block length (4).
 */
static int option_fits( size_t next_offset, size_t optsz, size_t block_size )
{
	size_t padded = 4*((optsz+3)/4);
	return next_offset + padded + 12 <= block_size;
}

/* Write the padding option at 'offset' covering the rest of the block. */
static void write_padopt( uint8_t * block, size_t offset, size_t block_size )
{
	option_header padopt;
	padopt.option_code = PADOPT_CODE;
	padopt.option_length = (uint16_t) (block_size - offset - 12);
	(void) memcpy( &block[offset], &padopt, sizeof( padopt ) );
}

/* Write 'count' zero bytes (in chunks rather than one byte per call). */
static ssize_t write_zeroes( int fd, size_t count )
{
	static const uint8_t zeroes[4096];
	ssize_t result = 0;
	while (count > 0) {
		size_t chunk = count < sizeof(zeroes) ? count : sizeof(zeroes);
		result = write( fd, zeroes, chunk );
		if (result <= 0)
			return -1;
		count -= (size_t) result;
	}
	return result;
}

/* write() all of 'len' bytes, returns -1 on error */
static ssize_t write_all( int fd, const void * buf, size_t len )
{
	const uint8_t * p = (const uint8_t *) buf;
	size_t done = 0;
	while (done < len) {
		ssize_t result = write( fd, p + done, len - done );
		if (result < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (result == 0)
			return -1;
		done += (size_t) result;
	}
	return (ssize_t) done;
}

PCAPNG_RESULT pcapng_create( PCAPNG_HANDLE * handle,
			     const char * filename,
			     const option_header * section_options,
			     const size_t section_options_space,
			     const uint16_t link_type,
			     const uint32_t snaplen,
			     const option_header * interface_options,
			     const size_t interface_options_space )
{
	PCAPNG_RESULT retval = PCAPNG_OK;
	int PGSZ = getpagesize( );
	size_t zeroes = 0;
	ssize_t result = -1;

	handle->section_header = NULL;
	handle->interface_description = NULL;
	handle->section_header_size = handle->next_section_option_offset =
		handle->interface_description_size =
		handle->next_interface_option_offset = 0;

	handle->fd = open( filename, O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP );
	if (handle->fd == -1) {
		switch( errno ) {
		case EEXIST:
			retval = PCAPNG_FILE_EXISTS;
			break;
		case EMFILE:
		case ENFILE:
			retval = PCAPNG_TOO_MANY_FILES_OPEN;
			break;
		case ENOMEM:
		case ENOSPC:
			retval = PCAPNG_NO_MEMORY;
			break;
		default:
			retval = PCAPNG_FILE_NOT_ALLOWED;
		}
	}

	if (retval == PCAPNG_OK) {
		/* section header */
		const section_header_block shb = {
			.block_type = BLOCK_TYPE_SECTION_HEADER,
			.block_total_length = 28,
			.byte_order_magic = SECTION_HEADER_BYTE_ORDER_MAGIC,
			.major_version = 1,
			.minor_version = 0,
			.section_length = (uint64_t) -1,
		};
		handle->section_header_size = sizeof( shb );
		result = write_all( handle->fd, &shb, sizeof( shb ) );
		/* write initial section options */
		while ((result != -1) &&
		       section_options &&
		       section_options->option_code &&
		       section_options->option_length) {
			size_t paddedsz = 4*((section_options->option_length+3)/4);
			zeroes = paddedsz - section_options->option_length;
			result = write_all( handle->fd, section_options, 4+section_options->option_length );
			if ((result != -1) && zeroes)
				result = write_zeroes( handle->fd, zeroes );
			section_options = (const option_header *) &((uint8_t *)section_options)[4+paddedsz];
			handle->section_header_size += (4+paddedsz);
		}
		handle->next_section_option_offset = handle->section_header_size;
	}

	if (retval != PCAPNG_OK) {
		/* keep the open() error */
	}
	else if (result == -1) {
		retval = PCAPNG_FILE_WRITE_ERROR;
	}
	else {
		/* determine the size of section header with desired space
		 * (room for the padding option, opt_endofopt and the
		 * trailing block length) */
		zeroes = (size_t) PGSZ*((handle->section_header_size + 12 +
					 section_options_space + PGSZ - 1)/PGSZ) -
			handle->section_header_size;
		handle->section_header_size += zeroes;
		if (zeroes)
			result = write_zeroes( handle->fd, zeroes );

		/* mmap the section header */
		handle->section_header = mmap( NULL, handle->section_header_size, 
					       PROT_READ|PROT_WRITE,
					       MAP_SHARED,
					       handle->fd, 0 );
	}

	if (retval == PCAPNG_OK) {
		if (result == -1) {
			retval = PCAPNG_FILE_WRITE_ERROR;
		}
		else if (handle->section_header == MAP_FAILED) {
			retval = PCAPNG_MMAP_FAILED;
		}
		else {
			/* write the interface header */
			const interface_description_block idb = {
				.block_type = BLOCK_TYPE_INTERFACE,
				.block_total_length = 0,
				.link_type = link_type,
				.snaplen = snaplen
			};
			handle->interface_description_size = sizeof( idb );
			result = write_all( handle->fd, &idb, sizeof( idb ) );

			/* write interface options */
			while ((result != -1) &&
			       interface_options &&
			       interface_options->option_code &&
			       interface_options->option_length) {
				size_t paddedsz = 4*((interface_options->option_length+3)/4);
				zeroes = paddedsz - interface_options->option_length;
				result = write_all( handle->fd, interface_options, 4+interface_options->option_length );
				if ((result != -1) && zeroes)
					result = write_zeroes( handle->fd, zeroes );
				interface_options = (const option_header *) &((uint8_t *)interface_options)[4+paddedsz];
				handle->interface_description_size += (4+paddedsz);
			}
			handle->next_interface_option_offset = handle->interface_description_size;
		}
	}

	if (retval == PCAPNG_OK) {
		if (result == -1) {
			retval = PCAPNG_FILE_WRITE_ERROR;
		}
		else {
			/* determine the size of interface description with desired space */
			zeroes = (size_t) PGSZ*((handle->interface_description_size + 12 +
						 interface_options_space + PGSZ - 1)/PGSZ) -
				handle->interface_description_size;
			handle->interface_description_size += zeroes;
			if (zeroes)
				result = write_zeroes( handle->fd, zeroes );

			/* mmap the interface description */
			handle->interface_description = mmap( NULL, handle->interface_description_size, 
							      PROT_READ|PROT_WRITE,
							      MAP_SHARED,
							      handle->fd,
							      handle->section_header_size );
		}
	}

	if (retval == PCAPNG_OK) {
		if (result == -1) {
			retval = PCAPNG_FILE_WRITE_ERROR;
		}
		else if (handle->interface_description == MAP_FAILED) {
			retval = PCAPNG_MMAP_FAILED;
		}
		else {
			/* Add padding options, update the header sizes. */
			write_padopt( (uint8_t *)handle->section_header,
				      handle->next_section_option_offset,
				      handle->section_header_size );
			handle->section_header->block_total_length =
				(uint32_t) handle->section_header_size;
			((uint32_t*)handle->section_header)[handle->section_header_size/4-1] =
				(uint32_t) handle->section_header_size;

			write_padopt( (uint8_t *)handle->interface_description,
				      handle->next_interface_option_offset,
				      handle->interface_description_size );
			handle->interface_description->block_total_length =
				(uint32_t) handle->interface_description_size;
			((uint32_t*)handle->interface_description)[handle->interface_description_size/4-1] =
				(uint32_t) handle->interface_description_size;

			handle->section_header->section_length = (uint64_t) handle->interface_description_size;
		}
	}

	if (retval != PCAPNG_OK) {
		(void) pcapng_close( handle );
	}

	return retval;
}

PCAPNG_RESULT pcapng_append_section_option( PCAPNG_HANDLE * handle,
					    const option_header * section_option )
{
	PCAPNG_RESULT retval = PCAPNG_OK;
	if (handle && (handle->fd != -1)) {
		if (handle->section_header &&
		    (handle->section_header != MAP_FAILED) &&
		    handle->next_section_option_offset &&
		    section_option) {
			size_t copysz = 4+section_option->option_length;
			uint8_t * dest = &((uint8_t *)handle->section_header)[handle->next_section_option_offset];
			/* the section header is a fixed size mapping */
			if (!option_fits( handle->next_section_option_offset, copysz,
					  handle->section_header_size ))
				return PCAPNG_NO_MEMORY;
			(void) memcpy( dest, section_option, copysz );
			/* zero the alignment padding of the option value */
			(void) memset( dest + copysz, 0, 4*((copysz+3)/4) - copysz );
			handle->next_section_option_offset += 4*((copysz+3)/4);

			/* update padding option */
			write_padopt( (uint8_t *)handle->section_header,
				      handle->next_section_option_offset,
				      handle->section_header_size );
		}
		else {
			retval = PCAPNG_NO_MEMORY;
		}
	}
	else {
		retval = PCAPNG_INVALID_HANDLE;
	}
	return retval;
}

PCAPNG_RESULT pcapng_append_interface_option( PCAPNG_HANDLE * handle,
					      const option_header * interface_option )
{
	PCAPNG_RESULT retval = PCAPNG_OK;
	if (handle && (handle->fd != -1)) {
		if (handle->interface_description &&
		    (handle->interface_description != MAP_FAILED) &&
		    handle->next_interface_option_offset &&
		    interface_option) {
			size_t copysz = 4+interface_option->option_length;
			uint8_t * dest = &((uint8_t *)handle->interface_description)[handle->next_interface_option_offset];
			/* the interface description is a fixed size mapping:
			 * refuse options that do not fit instead of writing
			 * past its end */
			if (!option_fits( handle->next_interface_option_offset, copysz,
					  handle->interface_description_size ))
				return PCAPNG_NO_MEMORY;
			(void) memcpy( dest, interface_option, copysz );
			/* zero the alignment padding of the option value */
			(void) memset( dest + copysz, 0, 4*((copysz+3)/4) - copysz );
			handle->next_interface_option_offset += 4*((copysz+3)/4);

			/* update padding option */
			write_padopt( (uint8_t *)handle->interface_description,
				      handle->next_interface_option_offset,
				      handle->interface_description_size );
		}
		else {
			retval = PCAPNG_NO_MEMORY;
		}
	}
	else {
		retval = PCAPNG_INVALID_HANDLE;
	}
	return retval;
}

PCAPNG_RESULT pcapng_append_packet( PCAPNG_HANDLE * handle,
				    const enhanced_packet_block * packet )
{
	PCAPNG_RESULT retval = PCAPNG_OK;
	if (handle && (handle->fd != -1)) {
		size_t writesz = packet->block_total_length;
		ssize_t result = write_all( handle->fd, packet, writesz );
		if (result == -1) {
			retval = PCAPNG_FILE_WRITE_ERROR;
		}
		else if (handle->section_header &&
			 (handle->section_header != MAP_FAILED)) {
			handle->section_header->section_length += writesz;
		}
	}
	else {
		retval = PCAPNG_INVALID_HANDLE;
	}
	return retval;
}

PCAPNG_RESULT pcapng_close( PCAPNG_HANDLE * handle )
{
	PCAPNG_RESULT retval = PCAPNG_OK;

	if (!handle)
		return PCAPNG_INVALID_HANDLE;
	if (handle->interface_description &&
	    (handle->interface_description != MAP_FAILED)) {
		(void) munmap( handle->interface_description,
			       handle->interface_description_size );
	}
	handle->interface_description = NULL;
	if (handle->section_header &&
	    (handle->section_header != MAP_FAILED)) {
		(void) munmap( handle->section_header,
			       handle->section_header_size );
	}
	handle->section_header = NULL;
	if (handle->fd != -1) {
		if (close( handle->fd ) != 0)
			retval = PCAPNG_FILE_WRITE_ERROR;
	}
	handle->fd = -1;
	return retval;
}
