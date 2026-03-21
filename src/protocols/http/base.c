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

#include <freeradius-devel/util/sbuff.h>
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

/*
 * Forward map: HTTP version string -> dictionary enum value.
 * Used by the decoder to convert the HTTP-version token on the request/response line.
 */
fr_table_num_ordered_t const fr_http_version_table[] = {
	{ L("HTTP/1.0"),	FR_HTTP_VERSION_1_0 },
	{ L("HTTP/1.1"),	FR_HTTP_VERSION_1_1 },
};
size_t fr_http_version_table_len = NUM_ELEMENTS(fr_http_version_table);

/** Find the next CRLF in a sbuff, returning a pointer to the '\r'
 *
 * Purely a search: doesn't advance @p in.
 *
 * @param[in] in	sbuff bounding the range to search.
 * @return pointer to '\r', or NULL if not found before the end of the range.
 */

uint8_t const *fr_http_find_crlf(fr_sbuff_t *in)
{
	fr_sbuff_t	sbuff = FR_SBUFF(in);

	return (uint8_t const *)fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "\r\n", 2);
}

/** Check a delineated line for a bare CR
 *
 * fr_http_find_crlf() has already located the line's terminating CRLF, and @p in is
 * expected to be bound to end just before it.  RFC 9112 §2.2 forbids a bare CR (one
 * not immediately followed by LF) anywhere in a protocol element, so any '\r' still
 * present in that range can only be a bare one, and the element MUST be treated as
 * invalid.
 *
 * @param[in] in	sbuff bounding the line to check.
 * @return true if a bare CR is present.
 */
bool fr_http_has_bare_cr(fr_sbuff_t *in)
{
	fr_sbuff_t	sbuff = FR_SBUFF(in);

	return fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, '\r') != NULL;
}

/** Validate the structure of one header line and locate its field-name span
 *
 * Checks obs-fold, bare CR, a colon exists, non-empty name, and no
 * whitespace before the colon (RFC 9112 §5.1).  Doesn't touch the value.
 *
 * @param[in]  in		sbuff bounding the header line.
 * @param[out] name_out		If non-NULL, set to a sbuff spanning the field-name (the
 *				line's start up to, but not including, the colon).
 * @return true if the line is structurally valid.
 */
static bool header_line_valid(fr_sbuff_t *in, fr_sbuff_t *name_out)
{
	uint8_t const *colon;
	fr_sbuff_t     sbuff;

	/*
	*  RFC 9112 §5.1: a header line that begins with whitespace is
	*  obsolete line folding.  A recipient MUST either reject the
	*  message or ignore such lines entirely; parsing it as an
	*  ordinary header field would silently fold the leading
	*  whitespace into the field name, while a downstream recipient
	*  that instead treats it as a continuation of the *previous*
	*  field's value would parse the message differently (request
	*  smuggling / response splitting).  We reject outright.
	*/
	if (fr_sbuff_is_char(in, ' ') || fr_sbuff_is_char(in, '\t')) {
		fr_strerror_const("Malformed HTTP header line: begins with whitespace (obsolete line folding)");
		return false;
	}

	if (fr_http_has_bare_cr(in)) {
		fr_strerror_const("Malformed HTTP header line: contains a bare CR");
		return false;
	}

	sbuff = FR_SBUFF(in);
	colon = (uint8_t const *)fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, ':');
	if (!colon) {
		fr_strerror_printf("Malformed HTTP header line (no colon): %.*s",
				   (int)fr_sbuff_remaining(in), fr_sbuff_current(in));
		return false;
	}

	if (fr_sbuff_used(&sbuff) == 0) {
		fr_strerror_const("Malformed HTTP header line: empty field name");
		return false;
	}

	/*
	 *  RFC 9112 §5.1: "No whitespace is allowed between the field name and
	 *  colon.  In the past, differences in the handling of such whitespace
	 *  have led to security vulnerabilities in request routing and response
	 *  handling.  A server MUST reject ... any received request message
	 *  that contains whitespace between a header field name and colon."
	 */
	if (*(colon - 1) == ' ' || *(colon - 1) == '\t') {
		fr_strerror_const("Malformed HTTP header line: whitespace between field name and colon");
		return false;
	}

	if (name_out) *name_out = FR_SBUFF_IN(fr_sbuff_start(&sbuff), fr_sbuff_used(&sbuff));
	return true;
}

/** Split one delineated header line into field-name and field-value spans
 *
 * Performs the structural validation a header line must pass before it can
 * be trusted, rejecting obsolete line folding (RFC 9112 §5.1), a bare CR,
 * a missing colon, an empty field name, and whitespace between the field
 * name and colon (RFC 9112 §5.1).  The returned value span has OWS
 * stripped from both ends (RFC 9112 §5.1).
 *
 * @param[in]  in		sbuff bounding the header line (no leading or trailing CRLF).
 * @param[out] name_out		If non-NULL, set to a sbuff spanning the field-name.
 * @param[out] value_out	If non-NULL, set to a sbuff spanning the field-value, after
 *				OWS stripping.
 * @return
 *	- true on success.
 *	- false if the line is malformed; the output parameters are left unset.
 */
bool fr_http_header_line_split(fr_sbuff_t *in, fr_sbuff_t *name_out, fr_sbuff_t *value_out)
{
	uint8_t const *end = (uint8_t const *)fr_sbuff_end(in);
	uint8_t const *colon, *value, *value_end;
	fr_sbuff_t     name;

	if (!header_line_valid(in, &name)) return false;

	colon = (uint8_t const *)fr_sbuff_end(&name);

	/*
	 *  RFC 9112 §5.1: strip optional whitespace (OWS) from value.
	 */
	value = colon + 1;
	while (value < end && (*value == ' ' || *value == '\t')) value++;

	value_end = end;
	while (value_end > value && (*(value_end - 1) == ' ' || *(value_end - 1) == '\t')) value_end--;

	if (name_out) *name_out = name;
	if (value_out) *value_out = FR_SBUFF_IN((char const *)value, (size_t)(value_end - value));
	return true;
}

/** Basic sanity check for a Host header value (RFC 9110 §7.2: host = uri-host [ ":" port ])
 *
 * Deliberately doesn't implement the full RFC 3986 "host" grammar (reg-name
 * percent-encoding, full IP-literal syntax, etc.) since we're an origin server
 * and never need to reconstruct or compare against a target-URI authority
 * component.  Rejects the realistic malformed/injection cases instead: empty
 * values, embedded whitespace or control characters, and a ":port" suffix
 * that isn't all digits.
 *
 * @param[in] value		Host header value to validate.
 * @param[in] len		Length of the value.
 * @return true if the value looks like a valid Host.
 */
bool fr_http_host_valid(uint8_t const *value, size_t len)
{
	fr_sbuff_t	sbuff;
	uint8_t const	*end;
	uint8_t const	*host_end;
	uint8_t const	*port_start = NULL;
	uint8_t const	*p;

	if (len == 0) return false;

	sbuff = FR_SBUFF_IN((char const *)value, len);
	end = (uint8_t const *)fr_sbuff_end(&sbuff);

	if (value[0] == '[') {
		uint8_t const *close;
		fr_sbuff_t search = FR_SBUFF(&sbuff);

		close = (uint8_t const *)fr_sbuff_adv_to_chr(&search, SIZE_MAX, ']');
		if (!close) return false;

		host_end = close + 1;
		if (host_end < end) {
			if (*host_end != ':') return false;
			port_start = host_end + 1;
		}
	} else {
		uint8_t const *colon;
		fr_sbuff_t search = FR_SBUFF(&sbuff);

		colon = (uint8_t const *)fr_sbuff_adv_to_chr(&search, SIZE_MAX, ':');
		host_end = colon ? colon : end;
		if (colon) port_start = colon + 1;
	}

	for (p = value; p < host_end; p++) {
		if (*p <= 0x20 || *p == 0x7f) return false;
	}

	if (!port_start) return true;
	if (port_start == end) return false;	/* trailing ':' with no port digits */

	for (p = port_start; p < end; p++) {
		if (*p < '0' || *p > '9') return false;
	}

	return true;
}

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
 *	- < 0  malformed request (e.g. non-numeric Content-Length, whitespace
 *	       between a header field name and colon, or a missing/duplicate/
 *	       invalid Host header); the caller should reject the connection
 *	       with 400 Bad Request.
 */
ssize_t fr_http_length(uint8_t const *buffer, size_t buffer_len)
{
	fr_sbuff_t	our_in = FR_SBUFF_IN((char const *)buffer, buffer_len);
	fr_sbuff_t	headers_in, line_in;
	uint8_t const	*request_line_end, *headers_end;
	size_t		 content_length = 0;
	size_t		 host_count = 0;
	bool		 found_content_length = false;

	if (buffer_len < 4) return 0;

	/*
	 *  Scan for the blank line (\r\n\r\n) that ends the header section.
	 */
	{
		fr_sbuff_t sbuff = FR_SBUFF(&our_in);

		headers_end = (uint8_t const *)fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "\r\n\r\n", 4);
	}
	if (!headers_end) return 0; /* incomplete headers, need more data */
	headers_end += 4;

	headers_in = FR_SBUFF_IN((char const *)buffer, (size_t)(headers_end - buffer));

	/* Find the end of the request line (first CRLF) */
	request_line_end = fr_http_find_crlf(&headers_in);
	if (!request_line_end) {
		fr_strerror_const("HTTP packet has no CRLF after request line");
		return -1;
	}

	line_in = FR_SBUFF_IN((char const *)buffer, (size_t)(request_line_end - buffer));

	if (fr_http_has_bare_cr(&line_in)) {
		fr_strerror_const("Malformed HTTP request line: contains a bare CR");
		return -1;
	}

	/*
	 *  Scan header lines for Content-Length and Host, checking for malformed headers along the way.
	 */
	fr_sbuff_set(&headers_in, (char const *)(request_line_end + 2)); /* skip CRLF */
	while ((uint8_t const *)fr_sbuff_current(&headers_in) < headers_end) {
		uint8_t const	*p = (uint8_t const *)fr_sbuff_current(&headers_in);
		uint8_t const	*line_end;

		/*
		 *  A bare CRLF is the blank line separating headers from body.
		 */
		if (fr_sbuff_is_str_literal(&headers_in, "\r\n")) {
			fr_sbuff_advance(&headers_in, 2);
			break;
		}

		/* Find the CRLF at the end of this line */
		line_end = fr_http_find_crlf(&headers_in);
		fr_assert(line_end != NULL); /* shouldn't happen, we already found the end of headers */
		if (!line_end) {
			fr_strerror_const("Internal error: no CRLF found after end-of-headers was already determined");
			return -1;
		}

		line_in = FR_SBUFF_IN((char const *)p, (size_t)(line_end - p));

		if (!found_content_length && (size_t)(line_end - p) > 15 &&
		    strncasecmp((char const *)p, "Content-Length:", 15) == 0) {
			fr_sbuff_t		value;
			char			cl_buf[24];
			size_t			num_len;
			char			*ep;
			unsigned long		val_ul;

			if (!fr_http_header_line_split(&line_in, NULL, &value)) {
				return -1;
			}

			num_len = fr_sbuff_remaining(&value);
			if (num_len == 0 || num_len >= sizeof(cl_buf)) return -1;

			memcpy(cl_buf, fr_sbuff_start(&value), num_len);
			cl_buf[num_len] = '\0';

			errno = 0;
			val_ul = strtoul(cl_buf, &ep, 10);
			if (*ep != '\0') return -1; /* non-numeric */
			if (errno == ERANGE || val_ul > (unsigned long)SSIZE_MAX) return -1; /* overflow */

			content_length = (size_t)val_ul;
			found_content_length = true;

		} else if ((size_t)(line_end - p) > 5 &&
			   strncasecmp((char const *)p, "Host:", 5) == 0) {
			fr_sbuff_t value;

			if (!fr_http_header_line_split(&line_in, NULL, &value)) {
				return -1;
			}

			/*
			 *  RFC 9112 §3.2: "A server MUST respond with a 400 (Bad
			 *  Request) status code to any HTTP/1.1 request message
			 *  that lacks a Host header field and to any request
			 *  message that contains more than one Host header field
			 *  line or a Host header field with an invalid field value."
			 */
			host_count++;
			if (host_count > 1) return -1;
			if (!fr_http_host_valid((uint8_t const *)fr_sbuff_start(&value), fr_sbuff_remaining(&value))) return -1;
		} else if (!header_line_valid(&line_in, NULL)) {
			return -1;
		}

		fr_sbuff_set(&headers_in, (char const *)(line_end + 2)); /* advance past CRLF */
	}

	if (host_count == 0) return -1;

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
