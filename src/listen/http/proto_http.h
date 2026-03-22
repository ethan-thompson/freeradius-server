#pragma once
/*
 * proto_http.h	HTTP virtual server.
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * @copyright 2026 The FreeRADIUS server project
 * @copyright 2026 Ethan Thompson (ethan.thompson@inkbridge.io)
 */

#include <freeradius-devel/io/master.h>
#include <freeradius-devel/http/http.h>

/** An instance of a proto_http listen section
 *
 */
typedef struct {
	fr_io_instance_t	io;				//!< Wrapper for IO abstraction

	char const		**allowed_types;		//!< Names for 'type = ...'
	bool			allowed[FR_HTTP_CODE_MAX];	//!< Indexed by fr_http_packet_code_t value

	uint32_t		max_packet_size;		//!< For message ring buffer.
	uint32_t		num_messages;			//!< For message ring buffer.

	uint32_t		priorities[FR_HTTP_CODE_MAX];	//!< Priorities for individual packet types
} proto_http_t;
