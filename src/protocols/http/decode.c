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
 * @file protocols/http/decode.c
 * @brief Functions to decode HTTP/1.1 packets into fr_pair_t lists.
 *
 * Parses a raw HTTP/1.1 request into the following pairs:
 *
 *   Request = { Method = GET, Path = "/api/foo", Version = HTTP-1-1 }
 *   Header  = { Name = "Host", Value = "example.com" }
 *   Header  = { Name = "Content-Type", Value = "application/json" }
 *   Body    = <raw octets>
 *
 * Packet-Type is synthesized by the listener from Request.Method.
 *
 * @copyright 2026 The FreeRADIUS server project
 * @copyright 2026 Ethan Thompson (ethan.thompson@inkbridge.io)
 */
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/sbuff.h>

#include "http.h"
#include "attrs.h"

/** Map an HTTP method string to its fr_http_packet_code_t value
 *
 * @return method code, or FR_HTTP_UNKNOWN if unrecognised.
 */
static fr_http_packet_code_t parse_method(uint8_t const *p, size_t len)
{
	return fr_table_value_by_substr(fr_http_method_table, (char const *)p, len, FR_HTTP_UNKNOWN);
}

/** Map an HTTP version string (e.g. "HTTP/1.1") to its dictionary enum value
 *
 * @return version code, or FR_HTTP_VERSION_UNKNOWN if unrecognised.
 */
static fr_http_version_t parse_version(uint8_t const *p, size_t len)
{
	return fr_table_value_by_substr(fr_http_version_table, (char const *)p, len, FR_HTTP_VERSION_UNKNOWN);
}

/** Decode the HTTP request line into a Request struct pair
 *
 * Expects a buffer containing exactly the first line, without the trailing CRLF.
 * e.g. "GET /api/foo HTTP/1.1"
 *
 * @param[in] ctx	Talloc context for new pairs.
 * @param[out] out	List to append the Request pair to.
 * @param[in] in	sbuff bounding the request line (no CRLF).  Consumed as a side effect.
 * @return
 *	- > 0 number of bytes consumed on success.
 *	- < 0 on error.
 */
static ssize_t decode_request_line(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_sbuff_t *in)
{
	uint8_t const		*p = (uint8_t const *)fr_sbuff_current(in);
	uint8_t const		*method_start, *method_end, *path_start, *path_end, *version_start;
	fr_http_packet_code_t	method;
	fr_http_version_t		version;
	fr_pair_t	*request_vp, *method_vp, *path_vp, *version_vp;

	/*
	 *  Request-line format: METHOD SP path SP HTTP-version
	 *  Find the two spaces, consuming as we go.
	 */
	method_start = p;
	method_end = (uint8_t const *)fr_sbuff_adv_to_chr(in, SIZE_MAX, ' ');
	if (!method_end) {
		fr_strerror_const("Malformed HTTP request line: missing SP after method");
		return -1;
	}
	fr_sbuff_advance(in, 1); /* skip the space */

	method = parse_method(method_start, method_end - method_start);
	if (method == FR_HTTP_UNKNOWN) {
		fr_strerror_printf("Unknown HTTP method: %.*s", (int)(method_end - method_start), method_start);
		return -1;
	}

	path_start = (uint8_t const *)fr_sbuff_current(in);
	path_end = (uint8_t const *)fr_sbuff_adv_to_chr(in, SIZE_MAX, ' ');
	if (!path_end) {
		fr_strerror_const("Malformed HTTP request line: missing SP after path");
		return -1;
	}
	fr_sbuff_advance(in, 1); /* skip the space */

	if (path_end == path_start) {
		fr_strerror_const("Malformed HTTP request line: empty request path");
		return -1;
	}

	version_start = (uint8_t const *)fr_sbuff_current(in);
	version = parse_version(version_start, fr_sbuff_remaining(in));
	if (version == FR_HTTP_VERSION_UNKNOWN) {
		fr_strerror_printf("Unknown HTTP version: %.*s (supported: HTTP/1.0, HTTP/1.1)",
		    (int)fr_sbuff_remaining(in), version_start);
		return -1;
	}

	fr_sbuff_advance(in, fr_sbuff_remaining(in)); /* consume the version token */

	/*
	 *  Build the Request struct pair and its three children.
	 */
	request_vp = fr_pair_afrom_da(ctx, attr_http_request);
	if (!request_vp) return PAIR_DECODE_OOM;

	method_vp = fr_pair_afrom_da(request_vp, attr_http_request_method);
	if (!method_vp) {
		talloc_free(request_vp);
		return PAIR_DECODE_OOM;
	}
	method_vp->vp_uint32 = method;
	fr_pair_append(&request_vp->vp_group, method_vp);

	path_vp = fr_pair_afrom_da(request_vp, attr_http_request_path);
	if (!path_vp) {
		talloc_free(request_vp);
		return PAIR_DECODE_OOM;
	}
	if (fr_pair_value_bstrndup(path_vp, (char const *)path_start, path_end - path_start, true) < 0) {
		talloc_free(request_vp);
		return -1;
	}
	fr_pair_append(&request_vp->vp_group, path_vp);

	version_vp = fr_pair_afrom_da(request_vp, attr_http_request_version);
	if (!version_vp) {
		talloc_free(request_vp);
		return PAIR_DECODE_OOM;
	}
	version_vp->vp_uint8 = version;
	fr_pair_append(&request_vp->vp_group, version_vp);

	fr_pair_append(out, request_vp);

	return (ssize_t)fr_sbuff_used(in); /* number of bytes consumed */
}

/** Decode a single HTTP header line into a Header struct pair
 *
 * Expects a buffer containing exactly one header line, without the trailing CRLF.
 * e.g. "Content-Type: application/json"
 *
 * Leading and trailing whitespace is stripped from the value per RFC 9112 §5.1.
 *
 * @param[in] ctx	Talloc context for new pairs.
 * @param[out] out	List to append the Header pair to.
 * @param[in] in	sbuff bounding the header line (no CRLF).
 * @return
 *	- > 0 number of bytes consumed on success.
 *	- < 0 on error.
 */
static ssize_t decode_header_line(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_sbuff_t *in)
{
	fr_sbuff_t	name, value;
	fr_pair_t	*header_vp, *name_vp, *value_vp;

	if (!fr_http_header_line_split(in, &name, &value)) {
		return -1;
	}

	header_vp = fr_pair_afrom_da(ctx, attr_http_header);
	if (!header_vp) return PAIR_DECODE_OOM;

	name_vp = fr_pair_afrom_da(header_vp, attr_http_header_name);
	if (!name_vp) {
		talloc_free(header_vp);
		return PAIR_DECODE_OOM;
	}
	if (fr_pair_value_bstrndup(name_vp, fr_sbuff_start(&name), fr_sbuff_remaining(&name), true) < 0) {
		talloc_free(header_vp);
		return -1;
	}
	fr_pair_append(&header_vp->vp_group, name_vp);

	value_vp = fr_pair_afrom_da(header_vp, attr_http_header_value);
	if (!value_vp) {
		talloc_free(header_vp);
		return PAIR_DECODE_OOM;
	}
	if (fr_pair_value_bstrndup(value_vp, fr_sbuff_start(&value), fr_sbuff_remaining(&value), true) < 0) {
		talloc_free(header_vp);
		return -1;
	}
	fr_pair_append(&header_vp->vp_group, value_vp);

	fr_pair_append(out, header_vp);

	return fr_sbuff_remaining(in);
}

/** Decode a complete HTTP/1.1 request packet into fr_pair_t list
 *
 * @param[in] ctx	Talloc context for new pairs.
 * @param[out] out	Where to write decoded pairs.
 * @param[in] in	dbuff wrapping the raw packet bytes.
 * @return
 *	- length of the packet consumed on success.
 *	- < 0 on error, value is the negative offset of the problem byte.
 */
ssize_t fr_http_decode(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dbuff_t *in)
{
	fr_sbuff_t	our_in = FR_SBUFF_IN((char const *)fr_dbuff_current(in), fr_dbuff_remaining(in));
	uint8_t const	*packet = (uint8_t const *)fr_sbuff_current(&our_in);
	uint8_t const	*p, *line_end;
	fr_sbuff_t	line_in;
	ssize_t		slen;

	if (fr_sbuff_remaining(&our_in) == 0) {
		fr_strerror_const("HTTP packet is empty");
		return -1;
	}

	/*
	 *  RFC 9112 §2.2: for robustness, ignore any leading empty lines (CRLF)
	 *  received before the request-line, e.g. a spurious blank line left
	 *  over from a client that just finished sending a previous request's
	 *  body on the same connection.
	 */
	while (fr_sbuff_is_str_literal(&our_in, "\r\n")) fr_sbuff_advance(&our_in, 2);

	if (fr_sbuff_remaining(&our_in) == 0) {
		fr_strerror_const("HTTP packet is empty");
		return -((uint8_t const *)fr_sbuff_current(&our_in) - packet);
	}

	/*
	 *  Decode the request line (first line up to the first CRLF).
	 */
	p = (uint8_t const *)fr_sbuff_current(&our_in);
	line_end = fr_http_find_crlf(&our_in);
	if (!line_end) {
		fr_strerror_const("HTTP packet has no CRLF after request line");
		return -1;
	}

	line_in = FR_SBUFF_IN((char const *)p, (size_t)(line_end - p));

	if (fr_http_has_bare_cr(&line_in)) {
		fr_strerror_const("Malformed HTTP request line: contains a bare CR");
		return -(p - packet);
	}

	slen = decode_request_line(ctx, out, &line_in);
	if (slen < 0) return slen - (p - packet);

	/*
	 *  Skip the request line's own CRLF.  See refactor.txt: this should
	 *  eventually advance based on slen instead of the independently-found
	 *  line_end, once decode_header_line() gets the same treatment.
	 */
	fr_sbuff_set(&our_in, (char const *)(line_end + 2));

	/*
	 *  Decode header lines until we hit the blank line (CRLF CRLF).
	 */
	while ((uint8_t const *)fr_sbuff_current(&our_in) < (uint8_t const *)fr_sbuff_end(&our_in)) {
		p = (uint8_t const *)fr_sbuff_current(&our_in);

		/*
		 *  A bare CRLF here is the blank line separating headers from body.
		 *  The previous iteration (or the request line, on the first pass)
		 *  already consumed the CRLF before this one, so checking for a
		 *  single CRLF at this position is equivalent to checking for the
		 *  "\r\n\r\n" that RFC 9112 uses to end the header section, just
		 *  split across the two consumption points instead of matched in
		 *  one go.
		 */
		if (fr_sbuff_is_str_literal(&our_in, "\r\n")) {
			fr_sbuff_advance(&our_in, 2);
			break;
		}

		line_end = fr_http_find_crlf(&our_in);
		if (!line_end) {
			fr_strerror_const("HTTP header section is not terminated with a blank line");
			return -(p - packet);
		}

		line_in = FR_SBUFF_IN((char const *)p, (size_t)(line_end - p));

		slen = decode_header_line(ctx, out, &line_in);
		if (slen < 0) return slen - (p - packet);

		fr_sbuff_set(&our_in, (char const *)(line_end + 2)); /* skip CRLF */
	}

	/*
	 *  RFC 9110 §5.2 treats multiple same-name headers as a comma-separated
	 *  list.  RFC 9112 §6.3(5) requires rejecting an "invalid" Content-Length,
	 *  which includes a list whose values are not all identical (e.g. "5, 10").
	 *  Scan for a second Content-Length with a different value and reject it.
	 */
	{
		fr_dcursor_t	cl_cursor;
		fr_pair_t	*header_vp;
		char const	*first_cl = NULL;

		for (header_vp = fr_pair_dcursor_by_da_init(&cl_cursor, out, attr_http_header);
		     header_vp != NULL;
		     header_vp = fr_dcursor_next(&cl_cursor)) {
			fr_pair_t *name_vp  = fr_pair_find_by_da(&header_vp->vp_group, NULL, attr_http_header_name);
			fr_pair_t *value_vp = fr_pair_find_by_da(&header_vp->vp_group, NULL, attr_http_header_value);

			if (!name_vp || !value_vp) continue;
			if (strcasecmp(name_vp->vp_strvalue, "Content-Length") != 0) continue;

			if (!first_cl) {
				first_cl = value_vp->vp_strvalue;
			} else if (strcmp(first_cl, value_vp->vp_strvalue) != 0) {
				fr_strerror_const("Duplicate Content-Length headers with conflicting values");
				return -1;
			}
		}
	}

	/*
	 *  RFC 9112 §3.2: "A server MUST respond with a 400 (Bad Request) status
	 *  code to any HTTP/1.1 request message that lacks a Host header field
	 *  and to any request message that contains more than one Host header
	 *  field line or a Host header field with an invalid field value."
	 */
	{
		fr_dcursor_t	host_cursor;
		fr_pair_t	*header_vp;
		unsigned int	host_count = 0;

		for (header_vp = fr_pair_dcursor_by_da_init(&host_cursor, out, attr_http_header);
		     header_vp != NULL;
		     header_vp = fr_dcursor_next(&host_cursor)) {
			fr_pair_t *name_vp  = fr_pair_find_by_da(&header_vp->vp_group, NULL, attr_http_header_name);
			fr_pair_t *value_vp = fr_pair_find_by_da(&header_vp->vp_group, NULL, attr_http_header_value);

			if (!name_vp || !value_vp) continue;
			if (strcasecmp(name_vp->vp_strvalue, "Host") != 0) continue;

			host_count++;
			if (host_count > 1) {
				fr_strerror_const("Duplicate Host header");
				return -1;
			}

			if (!fr_http_host_valid((uint8_t const *)value_vp->vp_strvalue, value_vp->vp_length)) {
				fr_strerror_const("Invalid Host header value");
				return -1;
			}
		}

		if (host_count == 0) {
			fr_strerror_const("Missing required Host header");
			return -1;
		}
	}

	/*
	 *  Everything remaining is the body.
	 */
	if (fr_sbuff_remaining(&our_in) != 0) {
		fr_pair_t *body_vp;
		size_t body_len = fr_sbuff_remaining(&our_in);

		body_vp = fr_pair_afrom_da(ctx, attr_http_body);
		if (!body_vp) return PAIR_DECODE_OOM;
		if (fr_pair_value_memdup(body_vp, (uint8_t const *)fr_sbuff_current(&our_in), body_len, true) < 0) {
			talloc_free(body_vp);
			return -((uint8_t const *)fr_sbuff_current(&our_in) - packet);
		}
		fr_sbuff_advance(&our_in, body_len); /* consume the body */
		fr_pair_append(out, body_vp);
	}

	return fr_dbuff_set(in, (uint8_t const *)fr_sbuff_current(&our_in));
}

static ssize_t decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *out,
			    uint8_t const *data, size_t data_len, UNUSED void *proto_ctx)
{
	fr_dbuff_t	dbuff = FR_DBUFF_TMP(data, data_len);

	return fr_http_decode(ctx, out, &dbuff);
}

extern fr_test_point_proto_decode_t http_tp_decode_proto;
fr_test_point_proto_decode_t http_tp_decode_proto = {
	.test_ctx	= NULL,
	.func		= decode_proto
};
