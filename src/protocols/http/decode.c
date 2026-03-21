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
#include <freeradius-devel/util/proto.h>

#include "http.h"
#include "attrs.h"

/** Find the next CRLF in the buffer, returning a pointer to the '\r'
 *
 * @return pointer to '\r', or NULL if not found before end.
 */
static uint8_t const *find_crlf(uint8_t const *p, uint8_t const *end)
{
	while (p < (end - 1)) {
		if (p[0] == '\r' && p[1] == '\n') return p;
		p++;
	}
	return NULL;
}

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
 * @return 0 for HTTP/1.0, 1 for HTTP/1.1, -1 if unrecognised.
 */
static int parse_version(uint8_t const *p, size_t len)
{
	if (len != 8 || memcmp(p, "HTTP/1.", 7) != 0) return -1;

	if (p[7] == '0') return 0;	/* HTTP-1-0 */
	if (p[7] == '1') return 1;	/* HTTP-1-1 */

	return -1;
}

/** Decode the HTTP request line into a Request struct pair
 *
 * Expects a buffer containing exactly the first line, without the trailing CRLF.
 * e.g. "GET /api/foo HTTP/1.1"
 *
 * @param[in] ctx	Talloc context for new pairs.
 * @param[out] out	List to append the Request pair to.
 * @param[in] p		Start of the request line.
 * @param[in] end	One past the last byte of the request line (no CRLF).
 * @return
 *	- > 0 number of bytes consumed on success.
 *	- < 0 on error.
 */
static ssize_t decode_request_line(TALLOC_CTX *ctx, fr_pair_list_t *out,
				   uint8_t const *p, uint8_t const *end)
{
	uint8_t const		*method_end, *path_start, *path_end, *version_start;
	fr_http_packet_code_t	method;
	int			version;
	fr_pair_t		*request_vp, *child;

	/*
	 *  METHOD SP path SP version
	 *  Find the two spaces.
	 */
	method_end = memchr(p, ' ', end - p);
	if (!method_end) {
		fr_strerror_const("Malformed HTTP request line: missing SP after method");
		return -1;
	}

	method = parse_method(p, method_end - p);
	if (method == FR_HTTP_UNKNOWN) {
		fr_strerror_printf("Unknown HTTP method: %.*s", (int)(method_end - p), p);
		return -1;
	}

	path_start = method_end + 1;
	path_end = memchr(path_start, ' ', end - path_start);
	if (!path_end) {
		fr_strerror_const("Malformed HTTP request line: missing SP after path");
		return -1;
	}

	if (path_end == path_start) {
		fr_strerror_const("Malformed HTTP request line: empty request path");
		return -1;
	}

	version_start = path_end + 1;
	version = parse_version(version_start, end - version_start);
	if (version < 0) {
		fr_strerror_printf("Unknown HTTP version: %.*s", (int)(end - version_start), version_start);
		return -1;
	}

	/*
	 *  Build the Request struct pair and its three children.
	 */
	request_vp = fr_pair_afrom_da(ctx, attr_http_request);
	if (!request_vp) return PAIR_DECODE_OOM;

	child = fr_pair_afrom_da(request_vp, attr_http_request_method);
	if (!child) {
		talloc_free(request_vp);
		return PAIR_DECODE_OOM;
	}
	child->vp_uint32 = method;
	fr_pair_append(&request_vp->vp_group, child);

	child = fr_pair_afrom_da(request_vp, attr_http_request_path);
	if (!child) {
		talloc_free(request_vp);
		return PAIR_DECODE_OOM;
	}
	if (fr_pair_value_bstrndup(child, (char const *)path_start, path_end - path_start, true) < 0) {
		talloc_free(request_vp);
		return -1;
	}
	fr_pair_append(&request_vp->vp_group, child);

	child = fr_pair_afrom_da(request_vp, attr_http_request_version);
	if (!child) {
		talloc_free(request_vp);
		return PAIR_DECODE_OOM;
	}
	child->vp_uint8 = version;
	fr_pair_append(&request_vp->vp_group, child);

	fr_pair_append(out, request_vp);

	return end - p;
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
 * @param[in] p		Start of the header line.
 * @param[in] end	One past the last byte (no CRLF).
 * @return
 *	- > 0 number of bytes consumed on success.
 *	- < 0 on error.
 */
static ssize_t decode_header_line(TALLOC_CTX *ctx, fr_pair_list_t *out,
				  uint8_t const *p, uint8_t const *end)
{
	uint8_t const	*colon, *value_start, *value_end;
	fr_pair_t	*header_vp, *child;

	colon = memchr(p, ':', end - p);
	if (!colon) {
		fr_strerror_printf("Malformed HTTP header line (no colon): %.*s", (int)(end - p), p);
		return -1;
	}

	if (colon == p) {
		fr_strerror_const("Malformed HTTP header line: empty field name");
		return -1;
	}

	/*
	 *  RFC 9112 §5.1: strip optional whitespace (OWS) from value.
	 */
	value_start = colon + 1;
	while (value_start < end && (*value_start == ' ' || *value_start == '\t')) value_start++;

	value_end = end;
	while (value_end > value_start && (*(value_end - 1) == ' ' || *(value_end - 1) == '\t')) value_end--;

	header_vp = fr_pair_afrom_da(ctx, attr_http_header);
	if (!header_vp) return PAIR_DECODE_OOM;

	child = fr_pair_afrom_da(header_vp, attr_http_header_name);
	if (!child) {
		talloc_free(header_vp);
		return PAIR_DECODE_OOM;
	}
	if (fr_pair_value_bstrndup(child, (char const *)p, colon - p, true) < 0) {
		talloc_free(header_vp);
		return -1;
	}
	fr_pair_append(&header_vp->vp_group, child);

	child = fr_pair_afrom_da(header_vp, attr_http_header_value);
	if (!child) {
		talloc_free(header_vp);
		return PAIR_DECODE_OOM;
	}
	if (fr_pair_value_bstrndup(child, (char const *)value_start, value_end - value_start, true) < 0) {
		talloc_free(header_vp);
		return -1;
	}
	fr_pair_append(&header_vp->vp_group, child);

	fr_pair_append(out, header_vp);

	return end - p;
}

/** Decode a complete HTTP/1.1 request packet into fr_pair_t list
 *
 * @param[in] ctx		Talloc context for new pairs.
 * @param[out] out		Where to write decoded pairs.
 * @param[in] packet		Raw packet bytes.
 * @param[in] packet_len	Length of packet.
 * @param[in] packet_ctx	Per-packet context.
 * @return
 *	- packet_len on success.
 *	- < 0 on error, value is the negative offset of the problem byte.
 */
ssize_t fr_http_decode(TALLOC_CTX *ctx, fr_pair_list_t *out,
		       uint8_t const *packet, size_t packet_len, fr_http_ctx_t *packet_ctx)
{
	uint8_t const	*p, *end, *line_end;
	ssize_t		slen;

	if (packet_len == 0) {
		fr_strerror_const("HTTP packet is empty");
		return -1;
	}

	p   = packet;
	end = packet + packet_len;

	/*
	 *  Decode the request line (first line up to the first CRLF).
	 */
	line_end = find_crlf(p, end);
	if (!line_end) {
		fr_strerror_const("HTTP packet has no CRLF after request line");
		return -1;
	}

	slen = decode_request_line(ctx, out, p, line_end);
	if (slen < 0) return slen - (p - packet);

	/*
	 *  Record the request method so the encoder can suppress the body
	 *  for HEAD responses (RFC 9110 §9.3.2).
	 */
	if (packet_ctx) {
		fr_pair_t *request_vp = fr_pair_find_by_da(out, NULL, attr_http_request);
		if (request_vp) {
			fr_pair_t *method_vp = fr_pair_find_by_da(&request_vp->vp_group, NULL, attr_http_request_method);
			if (method_vp) packet_ctx->request_method = (fr_http_packet_code_t)method_vp->vp_uint32;
		}
	}

	p = line_end + 2; /* skip CRLF */

	/*
	 *  Decode header lines until we hit the blank line (CRLF CRLF).
	 */
	while (p < end) {
		/*
		 *  A bare CRLF is the blank line separating headers from body.
		 */
		if ((end - p) >= 2 && p[0] == '\r' && p[1] == '\n') {
			p += 2;
			break;
		}

		line_end = find_crlf(p, end);
		if (!line_end) {
			fr_strerror_const("HTTP header section is not terminated with a blank line");
			return -(p - packet);
		}

		slen = decode_header_line(ctx, out, p, line_end);
		if (slen < 0) return slen - (p - packet);

		p = line_end + 2; /* skip CRLF */
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
	 *  Everything remaining is the body.
	 */
	if (p < end) {
		fr_pair_t *body_vp;

		body_vp = fr_pair_afrom_da(ctx, attr_http_body);
		if (!body_vp) return PAIR_DECODE_OOM;
		if (fr_pair_value_memdup(body_vp, p, end - p, true) < 0) {
			talloc_free(body_vp);
			return -(p - packet);
		}
		fr_pair_append(out, body_vp);
	}

	return packet_len;
}

/*
 *  Test point boilerplate
 */
static int decode_test_ctx(void **out, TALLOC_CTX *ctx,
			   UNUSED fr_dict_t const *dict, UNUSED fr_dict_attr_t const *root_da)
{
	fr_http_ctx_t *test_ctx;

	test_ctx = talloc_zero(ctx, fr_http_ctx_t);
	if (!test_ctx) return -1;
	test_ctx->tmp_ctx = talloc(test_ctx, uint8_t);
	if (!test_ctx->tmp_ctx) {
		talloc_free(test_ctx);
		return -1;
	}

	*out = test_ctx;
	return 0;
}

static ssize_t decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *out,
			    uint8_t const *data, size_t data_len, void *proto_ctx)
{
	fr_http_ctx_t *packet_ctx = proto_ctx;

	packet_ctx->packet     = data;
	packet_ctx->packet_len = data_len;

	return fr_http_decode(ctx, out, data, data_len, packet_ctx);
}

extern fr_test_point_proto_decode_t http_tp_decode_proto;
fr_test_point_proto_decode_t http_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= decode_proto
};
