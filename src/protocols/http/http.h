#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file protocols/http/http.h
 * @brief Implementation of the HTTP protocol.
 *
 * @copyright 2026 The FreeRADIUS server project
 * @copyright 2026 Ethan Thompson (ethan.thompson@inkbridge.io)
 */
RCSIDH(protocols_http_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/packet.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/protocol/http/rfc9112.h>

#define HTTP_MAX_ATTRIBUTES	256

/** HTTP request methods and synthetic response packet types
 *
 * Request types (1-9) correspond to the Method enum values in the dictionary.
 * Response types are the request type + 16, mirroring the DNS convention.
 */
typedef enum {
	FR_HTTP_UNKNOWN		= 0,

	FR_HTTP_GET			= 1,
	FR_HTTP_POST		= 2,
	FR_HTTP_PUT			= 3,
	FR_HTTP_DELETE		= 4,
	FR_HTTP_PATCH		= 5,
	FR_HTTP_HEAD		= 6,
	FR_HTTP_OPTIONS		= 7,
	FR_HTTP_CONNECT		= 8,
	FR_HTTP_TRACE		= 9,
	FR_HTTP_CODE_MAX	= 10,

	FR_HTTP_GET_RESPONSE		= 17,
	FR_HTTP_POST_RESPONSE		= 18,
	FR_HTTP_PUT_RESPONSE		= 19,
	FR_HTTP_DELETE_RESPONSE		= 20,
	FR_HTTP_PATCH_RESPONSE		= 21,
	FR_HTTP_HEAD_RESPONSE		= 22,
	FR_HTTP_OPTIONS_RESPONSE	= 23,

	FR_HTTP_DO_NOT_RESPOND	= 256,
} fr_http_packet_code_t;

#define FR_HTTP_PACKET_CODE_VALID(_code) \
	(((_code) > 0 && (_code) < FR_HTTP_CODE_MAX) || \
	 ((_code) >= FR_HTTP_GET_RESPONSE && (_code) <= FR_HTTP_OPTIONS_RESPONSE) || \
	 ((_code) == FR_HTTP_DO_NOT_RESPOND))

typedef enum {
	FR_HTTP_VERSION_UNKNOWN = -1,

	FR_HTTP_VERSION_1_0 = 0,
	FR_HTTP_VERSION_1_1 = 1,
} fr_http_version_t;

#define FR_HTTP_VERSION_VALID(_ver) \
	(((_ver) == FR_HTTP_VERSION_1_0) || ((_ver) == FR_HTTP_VERSION_1_1))

typedef struct {
	fr_http_packet_code_t	request_method;	//!< Request method (set by decoder; used by encoder to suppress body for HEAD)
	bool					close;		//!< Encoder should emit "Connection: close" (HTTP/1.0 default, or the
										///< request explicitly asked for it).  The listener is responsible
										///< for actually closing the socket after writing this response.
} fr_http_ctx_t;

int		fr_http_global_init(void);
void	fr_http_global_free(void);

extern char const		*fr_http_packet_names[FR_HTTP_CODE_MAX];

extern fr_table_num_ordered_t const	fr_http_method_table[];
extern size_t fr_http_method_table_len;

extern fr_table_num_ordered_t const	fr_http_version_table[];
extern size_t fr_http_version_table_len;

ssize_t fr_http_length(uint8_t const *buffer, size_t buffer_len);

ssize_t		fr_http_decode(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dbuff_t *in);

ssize_t	fr_http_encode(fr_dbuff_t *dbuff, fr_pair_list_t *vps, fr_http_ctx_t *encode_ctx);

uint8_t const *fr_http_find_crlf(fr_sbuff_t *in);

bool fr_http_has_bare_cr(fr_sbuff_t *in);

bool fr_http_header_line_split(fr_sbuff_t *in, fr_sbuff_t *name_out, fr_sbuff_t *value_out);

bool	fr_http_host_valid(uint8_t const *value, size_t len);

#ifdef __cplusplus
}
#endif
