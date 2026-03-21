#pragma once
/*
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
 */

/**
 * $Id$
 * @file src/protocols/http/attrs.h
 * @brief HTTP attributes
 *
 * @copyright 2026 The FreeRADIUS server project
 * @copyright 2026 Ethan Thompson (ethan.thompson@inkbridge.io)
 */
RCSIDH(http_attrs_h, "$Id$")

#include <freeradius-devel/util/dict.h>

extern HIDDEN fr_dict_t const		*dict_http;

extern HIDDEN fr_dict_attr_t const	*attr_packet_type;

extern HIDDEN fr_dict_attr_t const	*attr_http_request;
extern HIDDEN fr_dict_attr_t const	*attr_http_request_method;
extern HIDDEN fr_dict_attr_t const	*attr_http_request_path;
extern HIDDEN fr_dict_attr_t const	*attr_http_request_version;

extern HIDDEN fr_dict_attr_t const	*attr_http_response;
extern HIDDEN fr_dict_attr_t const	*attr_http_response_version;
extern HIDDEN fr_dict_attr_t const	*attr_http_response_status_code;
extern HIDDEN fr_dict_attr_t const	*attr_http_response_reason_phrase;

extern HIDDEN fr_dict_attr_t const	*attr_http_header;
extern HIDDEN fr_dict_attr_t const	*attr_http_header_name;
extern HIDDEN fr_dict_attr_t const	*attr_http_header_value;

extern HIDDEN fr_dict_attr_t const	*attr_http_body;
