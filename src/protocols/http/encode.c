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
 * @file protocols/http/encode.c
 * @brief Functions to encode fr_pair_t lists into HTTP/1.1 packets.
 *
 * The inverse of decode.c.  Given a pair list containing a Request or
 * Response struct (plus zero or more Header pairs and an optional Body),
 * writes a well-formed HTTP/1.1 message to an fr_dbuff_t.
 *
 * @copyright 2026 The FreeRADIUS server project
 * @copyright 2026 Ethan Thompson (ethan.thompson@inkbridge.io)
 */
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/proto.h>

#include "http.h"
#include "attrs.h"

/** HTTP version strings indexed by the Version enum value (0 = HTTP/1.0, 1 = HTTP/1.1)
 */
static char const *http_version_str[] = {
	[0] = "HTTP/1.0",
	[1] = "HTTP/1.1",
};

/** Encode the HTTP request line: METHOD SP path SP HTTP-version CRLF
 */
static ssize_t encode_request_line(fr_dbuff_t *dbuff, fr_pair_t *request_vp)
{
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);
	fr_pair_t	*method_vp, *path_vp, *version_vp;
	char const	*method_str;
	uint8_t		version;

	method_vp  = fr_pair_find_by_da(&request_vp->vp_group, NULL, attr_http_request_method);
	path_vp    = fr_pair_find_by_da(&request_vp->vp_group, NULL, attr_http_request_path);
	version_vp = fr_pair_find_by_da(&request_vp->vp_group, NULL, attr_http_request_version);

	if (!method_vp || !path_vp || !version_vp) {
		fr_strerror_const("HTTP Request struct is missing required members (Method, Path, or Version)");
		return -1;
	}

	method_str = fr_table_str_by_value(fr_http_method_table, method_vp->vp_uint32, NULL);
	if (!method_str) {
		fr_strerror_printf("Unknown HTTP method code %u", method_vp->vp_uint32);
		return -1;
	}

	version = version_vp->vp_uint8;
	if (version >= NUM_ELEMENTS(http_version_str) || !http_version_str[version]) {
		fr_strerror_printf("Unknown HTTP version %u", version);
		return -1;
	}

	FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, method_str, strlen(method_str));
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, ' ');
	FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, path_vp->vp_strvalue, path_vp->vp_length);
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, ' ');
	FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, http_version_str[version], 8);
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, '\r', '\n');

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode the HTTP response (status) line: HTTP-version SP status-code SP reason-phrase CRLF
 */
static ssize_t encode_response_line(fr_dbuff_t *dbuff, fr_pair_t *response_vp)
{
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);
	fr_pair_t	*version_vp, *status_vp, *reason_vp;
	char		status_str[6]; /* up to 5 digits + NUL */
	uint8_t		version;

	version_vp = fr_pair_find_by_da(&response_vp->vp_group, NULL, attr_http_response_version);
	status_vp  = fr_pair_find_by_da(&response_vp->vp_group, NULL, attr_http_response_status_code);
	reason_vp  = fr_pair_find_by_da(&response_vp->vp_group, NULL, attr_http_response_reason_phrase);

	if (!version_vp || !status_vp) {
		fr_strerror_const("HTTP Response struct is missing required members (Version or Status-Code)");
		return -1;
	}

	version = version_vp->vp_uint8;
	if (version >= NUM_ELEMENTS(http_version_str) || !http_version_str[version]) {
		fr_strerror_printf("Unknown HTTP version %u", version);
		return -1;
	}

	snprintf(status_str, sizeof(status_str), "%u", status_vp->vp_uint16);

	/*
	 *  RFC 9112 §4: status-line = HTTP-version SP status-code SP [ reason-phrase ] CRLF
	 *  The SP before reason-phrase is always written; the reason-phrase itself is optional.
	 */
	FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, http_version_str[version], 8);
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, ' ');
	FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, status_str, strlen(status_str));
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, ' ');
	if (reason_vp) FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, reason_vp->vp_strvalue, reason_vp->vp_length);
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, '\r', '\n');

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode all Header pairs as "Name: Value\r\n" lines
 */
static ssize_t encode_headers(fr_dbuff_t *dbuff, fr_pair_list_t *vps)
{
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);
	fr_dcursor_t	cursor;
	fr_pair_t	*header_vp;

	for (header_vp = fr_pair_dcursor_by_da_init(&cursor, vps, attr_http_header);
	     header_vp != NULL;
	     header_vp = fr_dcursor_next(&cursor)) {
		fr_pair_t *name_vp, *value_vp;

		name_vp  = fr_pair_find_by_da(&header_vp->vp_group, NULL, attr_http_header_name);
		value_vp = fr_pair_find_by_da(&header_vp->vp_group, NULL, attr_http_header_value);

		if (!name_vp || !value_vp) continue; /* skip malformed header pairs */

		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, name_vp->vp_strvalue, name_vp->vp_length);
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, ':', ' ');
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, value_vp->vp_strvalue, value_vp->vp_length);
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, '\r', '\n');
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode the Body pair as raw octets (written after the blank line)
 */
static ssize_t encode_body(fr_dbuff_t *dbuff, fr_pair_list_t *vps)
{
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);
	fr_pair_t	*body_vp;

	body_vp = fr_pair_find_by_da(vps, NULL, attr_http_body);
	if (!body_vp) return 0;

	FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, body_vp->vp_octets, body_vp->vp_length);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode a complete HTTP/1.1 message from a fr_pair_t list
 *
 * Looks for a Request or Response struct pair to determine the message type,
 * then writes the first line, all headers, the blank line, and the body.
 *
 * @param[out] dbuff		Output buffer.
 * @param[in] vps		Pair list to encode.
 * @param[in] encode_ctx	Per-packet context (unused for now).
 * @return
 *	- > 0 number of bytes written on success.
 *	- < 0 on error.
 */
ssize_t fr_http_encode(fr_dbuff_t *dbuff, fr_pair_list_t *vps, fr_http_ctx_t *encode_ctx)
{
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);
	fr_pair_t	*line_vp, *body_vp, *header_vp;
	fr_dcursor_t	cursor;
	ssize_t		slen;
	size_t		body_len;
	bool		is_response, has_content_length = false, no_body = false, head_request = false;
	char		cl_buf[32];
	size_t		cl_len;

	/*
	 *  Determine message type and write the first line.
	 */
	line_vp = fr_pair_find_by_da(vps, NULL, attr_http_request);
	if (line_vp) {
		is_response = false;
		slen = encode_request_line(&work_dbuff, line_vp);
	} else {
		line_vp = fr_pair_find_by_da(vps, NULL, attr_http_response);
		if (!line_vp) {
			fr_strerror_const("HTTP pair list contains neither a Request nor a Response struct");
			return -1;
		}
		is_response = true;
		slen = encode_response_line(&work_dbuff, line_vp);
	}
	if (slen < 0) return slen;

	/*
	 *  RFC 9110 §6.3 / §8.6: 204 (No Content) and 304 (Not Modified) MUST NOT
	 *  carry a message body.  RFC 9110 §8.6 also forbids Content-Length on 204.
	 *  Suppress both regardless of what the operator put in the reply pairs.
	 */
	if (is_response) {
		fr_pair_t *status_vp = fr_pair_find_by_da(&line_vp->vp_group, NULL, attr_http_response_status_code);
		if (status_vp) {
			uint16_t sc = status_vp->vp_uint16;
			no_body = (sc == FR_STATUS_CODE_VALUE_NO_CONTENT ||
			   sc == FR_STATUS_CODE_VALUE_NOT_MODIFIED ||
			   (sc >= FR_STATUS_CODE_VALUE_CONTINUE && sc < FR_STATUS_CODE_VALUE_OK)); /* RFC 9110 §8.2.1: 1xx MUST NOT include Content-Length */
		}
	}

	/*
	 *  RFC 9110 §9.3.2: HEAD responses MUST NOT include a message body,
	 *  but SHOULD include the same Content-Length as the equivalent GET
	 *  response.  Track HEAD separately from no_body so that Content-Length
	 *  is still emitted (with the would-be body length), while body bytes
	 *  are suppressed.
	 */
	head_request = (encode_ctx && encode_ctx->request_method == FR_HTTP_HEAD);

	/*
	 *  Measure the body length.  For 204/304/1xx (no_body) or HEAD
	 *  (head_request) we send zero body bytes on the wire, so report
	 *  zero.  Injecting a non-zero Content-Length in a HEAD response
	 *  causes some clients (curl) to wait for body bytes that never
	 *  arrive, hanging the connection.
	 */
	body_vp = fr_pair_find_by_da(vps, NULL, attr_http_body);
	body_len = (body_vp && !no_body && !head_request) ? body_vp->vp_length : 0;

	for (header_vp = fr_pair_dcursor_by_da_init(&cursor, vps, attr_http_header);
	     header_vp != NULL;
	     header_vp = fr_dcursor_next(&cursor)) {
		fr_pair_t *name_vp = fr_pair_find_by_da(&header_vp->vp_group, NULL, attr_http_header_name);
		if (name_vp && (strcasecmp(name_vp->vp_strvalue, "Content-Length") == 0)) {
			has_content_length = true;
			break;
		}
	}

	/*
	 *  Write all headers.
	 */
	slen = encode_headers(&work_dbuff, vps);
	if (slen < 0) return slen;

	/*
	 *  Auto-inject Content-Length when absent (RFC 9112 §6.3).
	 *  Always injected for responses (clients need it to know body boundaries).
	 *  For requests, only injected when there is a body — methods like GET/HEAD
	 *  should not carry Content-Length when they have no payload (RFC 9110 §8.6).
	 */
	if (!has_content_length && !no_body && (is_response || body_len > 0)) {
		cl_len = (size_t)snprintf(cl_buf, sizeof(cl_buf), "Content-Length: %zu\r\n", body_len);
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, cl_buf, cl_len);
	}

	/*
	 *  Blank line separating headers from body.
	 */
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, '\r', '\n');

	/*
	 *  Write the body if present (suppressed for 204/304/1xx per RFC 9110 §6.3
	 *  and for HEAD responses per RFC 9110 §9.3.2).
	 */
	if (!no_body && !head_request) {
		slen = encode_body(&work_dbuff, vps);
		if (slen < 0) return slen;
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/*
 *  Test point boilerplate
 */
static int encode_test_ctx(void **out, TALLOC_CTX *ctx,
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

static ssize_t encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps,
			    uint8_t *data, size_t data_len, void *proto_ctx)
{
	fr_http_ctx_t	*packet_ctx = proto_ctx;
	fr_dbuff_t	dbuff;

	fr_dbuff_init(&dbuff, data, data_len);

	return fr_http_encode(&dbuff, vps, packet_ctx);
}

extern fr_test_point_proto_encode_t http_tp_encode_proto;
fr_test_point_proto_encode_t http_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= encode_proto
};
