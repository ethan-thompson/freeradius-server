/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file protocols/http/base.c
 * @brief Functions to send/receive HTTP packets.
 *
 * @copyright 2026 The FreeRADIUS server project
 * @copyright 2026 Ethan Thompson (ethan.thompson@inkbridge.io)
 */
RCSID("$Id$")

#include <freeradius-devel/util/table.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "http.h"
#include "attrs.h"

static uint32_t instance_count = 0;
static bool	instantiated = false;

fr_dict_t const *dict_http;

extern fr_dict_autoload_t http_dict[];
fr_dict_autoload_t http_dict[] = {
	{ .out = &dict_http, .proto = "http" },
	DICT_AUTOLOAD_TERMINATOR
};

fr_dict_attr_t const *attr_packet_type;

fr_dict_attr_t const *attr_http_request;
fr_dict_attr_t const *attr_http_request_method;
fr_dict_attr_t const *attr_http_request_path;
fr_dict_attr_t const *attr_http_request_version;

fr_dict_attr_t const *attr_http_response;
fr_dict_attr_t const *attr_http_response_version;
fr_dict_attr_t const *attr_http_response_status_code;
fr_dict_attr_t const *attr_http_response_reason_phrase;

fr_dict_attr_t const *attr_http_header;
fr_dict_attr_t const *attr_http_header_name;
fr_dict_attr_t const *attr_http_header_value;

fr_dict_attr_t const *attr_http_body;

extern fr_dict_attr_autoload_t http_dict_attr[];
fr_dict_attr_autoload_t http_dict_attr[] = {
	{ .out = &attr_packet_type,			.name = "Packet-Type",			.type = FR_TYPE_UINT32,	.dict = &dict_http },

	{ .out = &attr_http_request,			.name = "Request",			.type = FR_TYPE_STRUCT,	.dict = &dict_http },
	{ .out = &attr_http_request_method,		.name = "Request.Method",		.type = FR_TYPE_UINT32,	.dict = &dict_http },
	{ .out = &attr_http_request_path,		.name = "Request.Path",			.type = FR_TYPE_STRING,	.dict = &dict_http },
	{ .out = &attr_http_request_version,		.name = "Request.Version",		.type = FR_TYPE_UINT8,	.dict = &dict_http },

	{ .out = &attr_http_response,			.name = "Response",			.type = FR_TYPE_STRUCT,	.dict = &dict_http },
	{ .out = &attr_http_response_version,		.name = "Response.Version",		.type = FR_TYPE_UINT8,	.dict = &dict_http },
	{ .out = &attr_http_response_status_code,	.name = "Response.Status-Code",		.type = FR_TYPE_UINT16,	.dict = &dict_http },
	{ .out = &attr_http_response_reason_phrase,	.name = "Response.Reason-Phrase",	.type = FR_TYPE_STRING,	.dict = &dict_http },

	{ .out = &attr_http_header,			.name = "Header",			.type = FR_TYPE_STRUCT,	.dict = &dict_http },
	{ .out = &attr_http_header_name,		.name = "Header.Name",			.type = FR_TYPE_STRING,	.dict = &dict_http },
	{ .out = &attr_http_header_value,		.name = "Header.Value",			.type = FR_TYPE_STRING,	.dict = &dict_http },

	{ .out = &attr_http_body,			.name = "Body",				.type = FR_TYPE_OCTETS,	.dict = &dict_http },
	DICT_AUTOLOAD_TERMINATOR
};

/*
 *  Names for request methods, indexed by fr_http_packet_code_t.
 *  Response types and Do-Not-Respond are not in this table; they are
 *  handled separately by the process layer.
 */
char const *fr_http_packet_names[FR_HTTP_CODE_MAX] = {
	[FR_HTTP_UNKNOWN]	= NULL,
	[FR_HTTP_GET]		= "GET",
	[FR_HTTP_POST]		= "POST",
	[FR_HTTP_PUT]		= "PUT",
	[FR_HTTP_DELETE]	= "DELETE",
	[FR_HTTP_PATCH]		= "PATCH",
	[FR_HTTP_HEAD]		= "HEAD",
	[FR_HTTP_OPTIONS]	= "OPTIONS",
	[FR_HTTP_CONNECT]	= "CONNECT",
	[FR_HTTP_TRACE]		= "TRACE",
};

/*
 *  Forward map: HTTP method name string -> fr_http_packet_code_t.
 *  Used by the decoder to convert the method token on the request line.
 *  The complementary reverse map is fr_http_packet_names[] above.
 */
fr_table_num_ordered_t const fr_http_method_table[] = {
	{ L("CONNECT"),		FR_HTTP_CONNECT	},
	{ L("DELETE"),		FR_HTTP_DELETE	},
	{ L("GET"),		FR_HTTP_GET	},
	{ L("HEAD"),		FR_HTTP_HEAD	},
	{ L("OPTIONS"),		FR_HTTP_OPTIONS	},
	{ L("PATCH"),		FR_HTTP_PATCH	},
	{ L("POST"),		FR_HTTP_POST	},
	{ L("PUT"),		FR_HTTP_PUT	},
	{ L("TRACE"),		FR_HTTP_TRACE	},
};
size_t fr_http_method_table_len = NUM_ELEMENTS(fr_http_method_table);

/** Determine the total expected byte length of an HTTP/1.1 request message
 *
 * Scans for the end-of-headers marker (\r\n\r\n) and, if found, adds the
 * value of the Content-Length header to get the total message length.
 *
 * Used by the TCP transport to know when it has a complete message in the
 * read buffer before handing it off to fr_http_decode().
 *
 * @param[in] buffer		Raw bytes read from the TCP socket.
 * @param[in] buffer_len	Number of bytes currently in the buffer.
 * @return
 *	- > 0  expected total length of this HTTP message in bytes.
 *	- 0    not enough data yet to determine length (headers incomplete).
 *	- < 0  malformed request (e.g. non-numeric Content-Length); close the connection.
 */
ssize_t fr_http_length(uint8_t const *buffer, size_t buffer_len)
{
	uint8_t const	*p, *end, *headers_end;
	size_t		 content_length = 0;

	if (buffer_len < 4) return 0;

	p   = buffer;
	end = buffer + buffer_len;
	headers_end = NULL;

	/*
	 *  Scan for the blank line (\r\n\r\n) that ends the header section.
	 */
	/*
	 * @todo There may be a way to simplify this with our tools
	 */
	while (p <= end - 4) {
		if (p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n') {
			headers_end = p + 4;
			break;
		}
		p++;
	}

	if (!headers_end) return 0; /* incomplete headers, need more data */

	/*
	 *  Scan header lines for Content-Length.
	 */
	p = buffer;
	while (p < headers_end) {
		uint8_t const	*line_end = p;
		uint8_t const	*val;
		char		 tmp[24];
		size_t		 num_len;
		char		*ep;
		unsigned long	 val_ul;

		/* Find the CRLF at the end of this line */
		while (line_end < headers_end - 1 &&
		       !(line_end[0] == '\r' && line_end[1] == '\n')) line_end++;

		if (line_end >= headers_end - 1) break;

		if ((size_t)(line_end - p) > 15 &&
		    strncasecmp((char const *)p, "Content-Length:", 15) == 0) {
			val = p + 15;
			while (val < line_end && (*val == ' ' || *val == '\t')) val++;

			/* Strip trailing OWS, mirroring decode_header_line in decode.c */
			while (line_end > val && (*(line_end - 1) == ' ' || *(line_end - 1) == '\t')) line_end--;

			num_len = line_end - val;
			if (num_len == 0 || num_len >= sizeof(tmp)) return -1;

			memcpy(tmp, val, num_len);
			tmp[num_len] = '\0';

			errno = 0;
			val_ul = strtoul(tmp, &ep, 10);
			if (*ep != '\0') return -1;                        /* non-numeric */
			if (errno == ERANGE || val_ul > (unsigned long)SSIZE_MAX) return -1; /* overflow */

			content_length = (size_t)val_ul;
			break;
		}

		p = line_end + 2; /* advance past CRLF */
	}

	return (ssize_t)((headers_end - buffer) + content_length);
}

/** Resolve/cache attributes in the HTTP dictionary
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_http_global_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	instance_count++;

	if (fr_dict_autoload(http_dict) < 0) {
	fail:
		instance_count--;
		return -1;
	}
	if (fr_dict_attr_autoload(http_dict_attr) < 0) {
		fr_dict_autofree(http_dict);
		goto fail;
	}

	instantiated = true;
	return 0;
}

void fr_http_global_free(void)
{
	if (!instantiated) return;

	fr_assert(instance_count > 0);

	if (--instance_count > 0) return;

	fr_dict_autofree(http_dict);
	instantiated = false;
}

static bool attr_valid(fr_dict_attr_t *da)
{
	if (da->flags.array) {
		fr_strerror_const("The 'array' flag cannot be used with HTTP");
		return false;
	}

	if (da->type == FR_TYPE_ATTR) {
		fr_strerror_const("The 'attribute' data type cannot be used with HTTP");
		return false;
	}

	return true;
}

extern fr_dict_protocol_t libfreeradius_http_dict_protocol;
fr_dict_protocol_t libfreeradius_http_dict_protocol = {
	.name = "http",
	.default_type_size = 0,
	.default_type_length = 0,
	.attr = {
		.valid = attr_valid,
	},

	.init = fr_http_global_init,
	.free = fr_http_global_free,
};
